#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Curtis Galloway
# SPDX-License-Identifier: Apache-2.0
"""Supervised bridge to an untrusted OpenRouter model.

Text in, text out. No tools are ever registered with the model, so it has no
way to run a command, read a file it was not handed, or write to disk. Every
request and response is logged for audit. The caller reviews the output before
anything touches a real tree.
"""

import argparse
import hashlib
import json
import os
import re
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

# Where a request may be sent, and which key goes with it.
#
# The pairing is the point. `ox` sends the key as a Bearer token to whatever URL
# it is pointed at, so one `--base-url` flag over one hardcoded key would mean a
# mistyped host receives your OpenRouter credential. Binding each venue to its
# own environment variable makes that impossible by construction: asking for
# zenmux reads ZENMUX_API_KEY and nothing else.
#
# Every venue below speaks the OpenAI chat-completions shape. That was verified
# rather than assumed — OpenCode's own docs advertise /responses and /messages,
# and /chat/completions works anyway.
VENUES = {
    "openrouter": {
        "url": "https://openrouter.ai/api/v1/chat/completions",
        "key_env": "OPENROUTER_API_KEY",
        "default_model": "stealth/ox-alpha",
    },
    "zenmux": {
        "url": "https://zenmux.ai/api/v1/chat/completions",
        "key_env": "ZENMUX_API_KEY",
        "default_model": None,
    },
    "opencode": {
        "url": "https://opencode.ai/zen/v1/chat/completions",
        "key_env": "OPENCODE_ZEN_API_KEY",
        "default_model": None,
    },
    "requesty": {
        "url": "https://router.requesty.ai/v1/chat/completions",
        "key_env": "REQUESTY_API_KEY",
        "default_model": None,
    },
}
DEFAULT_VENUE = "openrouter"
DEFAULT_MODEL = VENUES[DEFAULT_VENUE]["default_model"]
HERE = os.path.dirname(os.path.abspath(__file__))
# One VERSION per tool, all four equal — wiretest enforces the agreement, and
# the release workflow checks the tag matches. Packaged installs make "which
# oxbox do I have" a real question; --version is the answer.
VERSION = "0.1.0"
USER_AGENT = "oxbox (+https://github.com/curtisgalloway/oxbox)"
MAX_PAYLOAD_BYTES = 400_000
TIMEOUT_SECONDS = 900
DEFAULT_MAX_TOKENS = 100000
MANIFEST_VERSION = 0

SECRET_PATTERNS = [
    (r"sk-[A-Za-z0-9_\-]{20,}", "OpenAI-style API key"),
    (r"sk-ant-[A-Za-z0-9_\-]{20,}", "Anthropic API key"),
    (r"ghp_[A-Za-z0-9]{36}", "GitHub personal access token"),
    (r"github_pat_[A-Za-z0-9_]{50,}", "GitHub fine-grained token"),
    (r"AKIA[0-9A-Z]{16}", "AWS access key id"),
    (r"xox[baprs]-[A-Za-z0-9\-]{10,}", "Slack token"),
    (r"-----BEGIN [A-Z ]*PRIVATE KEY-----", "private key block"),
    (r"(?i)\b(api[_\-]?key|secret|password|token)\b\s*[:=]\s*[\"'][^\"'\s]{16,}[\"']",
     "hardcoded credential assignment"),
]

SYSTEM_PROMPTS = {
    "diff": (
        "You are a software engineer. Produce a fix for the task described.\n"
        "\n"
        "Output contract, strictly:\n"
        "1. A short plain-text explanation of what you changed and why (max 10 lines).\n"
        "2. Then a single fenced block tagged `diff` containing a unified diff.\n"
        "\n"
        "Diff rules:\n"
        "- Use `--- a/<path>` and `+++ b/<path>` headers with the exact paths given to you.\n"
        "- Include at least 3 lines of context per hunk so the patch applies cleanly.\n"
        "- Change only what the task requires. Do not reformat, rename, or tidy\n"
        "  unrelated code. Do not add dependencies unless the task requires it, and\n"
        "  if you do, say so explicitly in the explanation.\n"
        "- If you cannot solve it, say so plainly instead of guessing."
    ),
    "review": (
        "You are reviewing code. Report concrete defects only: correctness bugs,\n"
        "security issues, resource leaks, race conditions, incorrect error handling.\n"
        "\n"
        "For each finding give: file and line, a one-sentence statement of the defect,\n"
        "and a concrete failure scenario (specific inputs or state leading to the wrong\n"
        "outcome). If you are not confident a finding is real, label it UNCERTAIN.\n"
        "Do not report style preferences. If the code is fine, say so."
    ),
    "ask": (
        "Answer the question directly and concretely. If you are uncertain about an\n"
        "API, a version, or a behavior, say that you are uncertain rather than\n"
        "presenting a guess as fact."
    ),
}


class NoRedirects(urllib.request.HTTPRedirectHandler):
    """Refuse to follow redirects, so the credential cannot be re-aimed.

    urllib follows 3xx automatically and its default handler rebuilds the
    follow-up request keeping every original header — including
    `Authorization`. A 302 from a provider therefore hands the Bearer token to
    whatever host the `Location` line names, on any scheme, and ox would then
    print that host's reply as the model's answer. curl and requests strip the
    header on a cross-host redirect; urllib does not.

    Returning None turns the 3xx into an HTTPError, which the caller already
    logs to error.txt and reports cleanly. Verified by experiment: before this,
    a 302 to another host forwarded the key and the attacker's content was
    printed as model output.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class AttemptFailed(Exception):
    """A post-send failure: the request went out and came back unusable.

    Raised instead of exiting so that --failover can move to the next
    manifest entry; without --failover the caller turns it into the same
    sys.exit it always was. Pre-send refusals (secret scan, payload size,
    bad arguments) stay as exits — they would fail identically everywhere.
    """


def write_lf(path, text):
    """Write text with LF endings on every platform.

    Audit artifacts should be byte-identical regardless of host; Python's text
    mode would translate to CRLF on Windows. Uses open() rather than
    Path.write_text(newline=...), which only exists on Python 3.10+ -- the
    system python3 on macOS is still 3.9.
    """
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)


def scan_for_secrets(text, label):
    hits = []
    for pattern, description in SECRET_PATTERNS:
        for match in re.finditer(pattern, text):
            line_no = text.count("\n", 0, match.start()) + 1
            hits.append(f"{label}:{line_no}: possible {description}")
    return hits


def build_context(paths, force, task=""):
    blocks = []
    # The task string goes to the provider exactly like file bodies do, so it
    # gets scanned exactly like file bodies do. Scanning only --files left
    # `cat creds.txt | ox --stdin "explain this"` sending them unchecked.
    findings = scan_for_secrets(task, "<task text>") if task else []
    total = 0
    for raw in paths:
        path = Path(raw)
        if not path.is_file():
            sys.exit(f"ox: not a file: {raw}")
        try:
            body = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            sys.exit(f"ox: not a text file: {raw}")
        total += len(body.encode("utf-8"))
        findings.extend(scan_for_secrets(body, raw))
        suffix = path.suffix.lstrip(".") or "text"
        blocks.append(f"### File: {raw}\n```{suffix}\n{body}\n```")

    if findings and not force:
        sys.stderr.write("ox: refusing to send; possible secrets detected:\n")
        for finding in findings:
            sys.stderr.write(f"  {finding}\n")
        sys.stderr.write(
            "ox: this model logs prompts and shares them with the provider.\n"
            "ox: remove the secrets, or re-run with --force if these are false positives.\n"
        )
        sys.exit(2)

    if total > MAX_PAYLOAD_BYTES and not force:
        sys.exit(
            f"ox: refusing to send {total} bytes of context "
            f"(limit {MAX_PAYLOAD_BYTES}); narrow --files or pass --force"
        )

    return "\n\n".join(blocks), total, findings


SKILL_NAME = "ox-review"
# The path the runbook uses to name its own scripts. It is written for a
# checkout, where the skill sits where Claude Code looks for it; --skill
# rewrites it to wherever this tool actually found the skill.
SKILL_PATH_IN_TEXT = ".claude/skills/" + SKILL_NAME


def find_skill():
    """The ox-review runbook, wherever this tool is installed.

    Same two-location rule as oxbox's seatbelt profile: a source checkout
    carries it at .claude/skills/ox-review next to the script, where Claude
    Code finds it on its own; a package installs the script into <prefix>/bin
    and the skill into <prefix>/share/oxbox/ox-review. Code assets anchor at
    the script — only state anchors at the working directory.

    All four tools carry this, the way all four carry VERSION: each is a
    standalone script, so sharing it would mean shipping a module and a
    sys.path to find it on. wiretest asserts the four print the same bytes,
    which is what keeps four copies of one document from drifting.
    """
    candidates = [
        os.path.join(HERE, ".claude", "skills", SKILL_NAME),
        os.path.normpath(os.path.join(HERE, "..", "share", "oxbox", SKILL_NAME)),
    ]
    for directory in candidates:
        if os.path.isfile(os.path.join(directory, "SKILL.md")):
            return directory
    sys.exit("ox: the %s skill was not found; looked in:\n" % SKILL_NAME
             + "\n".join("ox:   " + path for path in candidates)
             + "\nox: a Homebrew install may predate the skill; reinstall or "
               "read it at https://github.com/curtisgalloway/oxbox")


def print_skill():
    """Print the runbook, with the paths this installation actually uses.

    An agent finds this through --help, so the copy it reads has to be
    runnable where it is standing. The text names its scripts by their
    checkout path; an installed tool keeps them under a prefix instead, and a
    runbook whose commands do not exist is worse than no runbook. Provenance
    goes to stderr and the document to stdout, the same split these tools use
    everywhere else, so piping this into a file yields the document alone.
    """
    directory = find_skill()
    path = os.path.join(directory, "SKILL.md")
    try:
        with open(path, encoding="utf-8") as handle:
            text = handle.read()
    except OSError as error:
        sys.exit("ox: cannot read %s: %s" % (path, error))
    sys.stderr.write("ox: skill -> %s\n" % path)
    sys.stdout.write(text.replace(SKILL_PATH_IN_TEXT, directory))


def load_manifest(path, allow_paid):
    """Read a survey manifest and decide which entries this run may use.

    The manifest chooses provider and model; it never chooses where a
    credential goes. `venue` must name an entry in ox's own VENUES table —
    the URL and key variable come from there — and a `base_url` in the file
    is documentation only: cross-checked, warned about, never honored. A
    tampered manifest therefore cannot re-aim a key; the worst it can do is
    pick a venue the operator already listed and keyed.

    Entries the run may not use are kept, with the reason, rather than
    dropped: the skip list is part of the answer to "why did my code go
    where it went", so it belongs in the status record and on stderr.
    """
    try:
        raw = Path(path).read_bytes()
    except OSError as error:
        sys.exit("ox: cannot read manifest %s: %s" % (path, error))
    digest = hashlib.sha256(raw).hexdigest()
    try:
        data = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as error:
        sys.exit("ox: manifest %s is not valid JSON: %s" % (path, error))

    version = data.get("manifest_version")
    if not isinstance(version, int) or version > MANIFEST_VERSION:
        sys.exit("ox: manifest version %r is newer than this ox understands "
                 "(%d); update ox, or use an older manifest" % (version, MANIFEST_VERSION))

    defaults = data.get("defaults") or {}
    unknown = sorted(set(defaults) - {"max_tokens"})
    if unknown:
        sys.stderr.write("ox: ignoring unrecognized manifest defaults: %s\n"
                         % ", ".join(unknown))

    recs = data.get("recommendations")
    if not isinstance(recs, list) or not recs:
        sys.exit("ox: manifest %s has no recommendations" % path)

    entries = []
    for index, rec in enumerate(recs):
        entry = {
            "position": index + 1,
            "venue": rec.get("venue"),
            "model": rec.get("model"),
            # Omitted cost means unknown, and unknown behaves as paid: the
            # survey never asserts free-status it has not measured, and ox
            # never spends on the strength of an absence.
            "cost": rec.get("cost") or "unknown",
            "why": rec.get("why") or "",
            "params": rec.get("params") or {},
            "skip": None,
            "url": None,
            "key_env": None,
        }
        rank = rec.get("rank")
        if rank not in (None, index + 1):
            sys.stderr.write("ox: manifest rank %r disagrees with position %d; "
                             "position is authoritative\n" % (rank, index + 1))
        spec = VENUES.get(entry["venue"])
        if spec is None:
            entry["skip"] = "unknown venue %r" % (entry["venue"],)
        elif not entry["model"]:
            entry["skip"] = "no model named"
        elif entry["cost"] != "free" and not allow_paid:
            entry["skip"] = "cost=%s (pass --allow-paid to use it)" % entry["cost"]
        elif not os.environ.get(spec["key_env"]):
            entry["skip"] = "%s not set" % spec["key_env"]
        else:
            entry["url"] = spec["url"]
            entry["key_env"] = spec["key_env"]
            base = (rec.get("base_url") or "").rstrip("/")
            if base and entry["url"] != base and not entry["url"].startswith(base + "/"):
                sys.stderr.write(
                    "ox: WARNING: manifest base_url %r for venue %s disagrees "
                    "with ox's table (%s); the table wins — a manifest never "
                    "chooses where a credential goes\n"
                    % (rec.get("base_url"), entry["venue"], entry["url"]))
        entries.append(entry)

    info = {"path": str(path), "sha256": digest,
            "issue_date": data.get("issue_date"), "defaults": defaults}
    return entries, info


def make_log_dir(base):
    """Claim a fresh directory for one request.

    The stamp has one-second resolution, so two runs started in the same
    second — trivially reachable from a script driving several models at
    once, or from failover attempts inside one run — used to share a
    directory under exist_ok=True and overwrite each other's request.json
    and response.json. Losing an audit record to a name collision is the
    one failure this log must not have, so claim the directory exclusively
    and suffix on collision rather than merging into it.
    """
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H-%M-%SZ")
    base.mkdir(parents=True, exist_ok=True)
    log_dir = base / stamp
    attempt = 1
    while True:
        try:
            log_dir.mkdir(exist_ok=False)
            return stamp, log_dir
        except FileExistsError:
            attempt += 1
            log_dir = base / ("%s-%d" % (stamp, attempt))


def write_status(status):
    """Write the run summary everywhere it belongs.

    Two destinations: `status.json` beside the other audit artifacts once the
    log directory exists, and the path named by --status-file if the caller
    gave one. A failed write warns rather than raises — this runs on the way
    out, and clobbering the real exit status with an OSError would replace the
    diagnosis with a symptom.
    """
    record = {key: value for key, value in status.items() if key != "status_file"}
    targets = []
    if status.get("log_dir"):
        targets.append(Path(status["log_dir"]) / "status.json")
    if status.get("status_file"):
        targets.append(Path(status["status_file"]))
    for target in targets:
        try:
            write_lf(target, json.dumps(record, indent=2))
        except OSError as error:
            sys.stderr.write("ox: could not write status to %s: %s\n" % (target, error))


def send_and_parse(api_url, api_key, payload, log_dir):
    """Send one request and extract the answer, or raise AttemptFailed.

    Every outcome leaves evidence in log_dir — response.json on any JSON
    reply, error.txt on an HTTP error or a non-JSON body, reasoning.txt and
    content.md on success — so a failed attempt is as auditable as a
    successful one.
    """
    request = urllib.request.Request(
        api_url,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "X-Title": "oxbox supervised bridge",
            # Not cosmetic. urllib defaults to `Python-urllib/3.x`, which
            # OpenCode Zen's Cloudflare rejects outright with `403 error code:
            # 1010` before the request reaches any route. Identifying the client
            # is the difference between that venue working and not.
            "User-Agent": USER_AGENT,
        },
        method="POST",
    )

    try:
        opener = urllib.request.build_opener(NoRedirects)
        with opener.open(request, timeout=TIMEOUT_SECONDS) as response:
            raw = response.read()
        try:
            body = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as error:
            # A 200 carrying HTML — a proxy error page, a captive portal, an
            # auth gateway — is not a protocol error, so nothing above catches
            # it. Without this it surfaced as a raw JSONDecodeError traceback
            # with no error.txt, which is the one shape an audit trail must not
            # take. Keep the bytes; they are the evidence.
            write_lf(log_dir / "error.txt",
                     "non-JSON response body\n%s\n\n%s"
                     % (error, raw[:2000].decode("utf-8", "replace")))
            raise AttemptFailed(
                "ox: provider returned a non-JSON body (%s); raw bytes in %s"
                % (error, log_dir / "error.txt"))
    except urllib.error.HTTPError as error:
        detail = error.read().decode("utf-8", "replace")
        write_lf(log_dir / "error.txt", f"{error.code}\n{detail}")
        raise AttemptFailed(f"ox: HTTP {error.code}: {detail[:500]}")
    except urllib.error.URLError as error:
        raise AttemptFailed(f"ox: network error: {error.reason}")

    write_lf(log_dir / "response.json", json.dumps(body, indent=2))

    if "error" in body and body["error"]:
        raise AttemptFailed(f"ox: api error: {json.dumps(body['error'])[:500]}")

    choices = body.get("choices") or []
    # Some providers return an empty choices list on a content filter. That
    # is a real response, not a crash, and the log already holds the raw body.
    if not choices:
        raise AttemptFailed("ox: provider returned no choices "
                            "(see response.json in the log)")
    choice = choices[0]
    message = choice.get("message", {}) or {}
    reasoning = message.get("reasoning") or ""
    content = message.get("content") or ""

    if reasoning:
        write_lf(log_dir / "reasoning.txt", reasoning)
    write_lf(log_dir / "content.md", content)

    if message.get("tool_calls"):
        sys.stderr.write(
            "ox: WARNING: model emitted tool_calls despite no tools being offered; "
            "logged but ignored\n"
        )

    usage = body.get("usage", {}) or {}
    sys.stderr.write(
        f"ox: finish={choice.get('finish_reason')} "
        f"prompt_tokens={usage.get('prompt_tokens')} "
        f"completion_tokens={usage.get('completion_tokens')} "
        f"reasoning_chars={len(reasoning)}\n"
    )

    # An empty completion is a failure for every caller, and the API called it
    # a success. Without this, content.md is a 0-byte file with no error beside
    # it and a script reading it gets a silent no-op that looks like a clean
    # run. Seen in practice: a reasoning model spent 31,995 of 32,000
    # completion tokens thinking and emitted nothing, twice, at two different
    # budgets. The usage numbers are the diagnosis, so include them.
    if not content.strip():
        detail = ""
        if usage.get("completion_tokens_details", {}).get("reasoning_tokens"):
            detail = (" — %s of %s completion tokens went to reasoning"
                      % (usage["completion_tokens_details"]["reasoning_tokens"],
                         usage.get("completion_tokens")))
        raise AttemptFailed(
            "ox: model returned no content (finish=%s)%s\n"
            "ox: the raw response and any reasoning are in %s"
            % (choice.get("finish_reason"), detail, log_dir)
        )

    return choice, usage, reasoning, content


def main():
    # ox reports failure in its exit code, but the common scripted pattern
    # (`./ox ... | tee review.md`) reports the last command's status, so a
    # failed run reads as success unless the caller remembered pipefail. The
    # status record turns that shell trivia into a checkable fact: every exit
    # after argument parsing — success, refusal, HTTP error, empty content —
    # lands here and writes how the run ended. sys.exit() raises SystemExit,
    # so one wrapper catches every path without threading a result through.
    status = {
        "ox_version": VERSION,
        "ok": False,
        "exit_code": None,
        "error": None,
        "venue": None,
        "model": None,
        "mode": None,
        "dry_run": False,
        "log_dir": None,
        "output": None,
        "finish_reason": None,
        "prompt_tokens": None,
        "completion_tokens": None,
        "reasoning_tokens": None,
        "reasoning_chars": None,
        "truncated": None,
        "manifest": None,
        "attempts": None,
        "status_file": None,
    }
    try:
        run(status)
    except SystemExit as exc:
        if exc.code is None or exc.code == 0:
            status["ok"] = True
            status["exit_code"] = 0
        elif isinstance(exc.code, int):
            status["exit_code"] = exc.code
        else:
            # sys.exit("message") — Python prints it to stderr and exits 1.
            status["error"] = str(exc.code)
            status["exit_code"] = 1
        write_status(status)
        raise
    status["ok"] = True
    status["exit_code"] = 0
    write_status(status)


def run(status):
    parser = argparse.ArgumentParser(
        prog="ox",
        description="Send a task to an untrusted model. No tools, full audit log.",
    )
    parser.add_argument("task", nargs="?", help="the task or question (or use --stdin)")
    parser.add_argument("--version", action="version", version="ox %s" % VERSION)
    parser.add_argument("--files", default="",
                        help="comma-separated files to include as context")
    parser.add_argument("--mode", choices=sorted(SYSTEM_PROMPTS), default="diff",
                        help="output contract (default: diff)")
    # --venue and --max-tokens default to None so that "explicitly given"
    # is distinguishable from "defaulted": explicit flags beat a manifest,
    # which beats the built-in defaults, and that precedence needs to know
    # which one it is looking at.
    parser.add_argument("--venue", choices=sorted(VENUES), default=None,
                        help="where to send the request; each venue uses its own "
                             "API key variable (default: %s)" % DEFAULT_VENUE)
    parser.add_argument("--manifest", default=None,
                        help="pick venue and model from a survey manifest file "
                             "(first permitted entry). The manifest chooses "
                             "provider and model only; credentials always come "
                             "from the venue's own environment variable.")
    parser.add_argument("--allow-paid", action="store_true",
                        help="let --manifest use entries whose cost is not "
                             "confirmed free (paid or unknown)")
    parser.add_argument("--failover", action="store_true",
                        help="with --manifest: on a failure after the request "
                             "is sent, move to the next permitted entry instead "
                             "of stopping (default: probe mode — one request, "
                             "one destination)")
    parser.add_argument("--base-url", default=None,
                        help="send to an arbitrary chat-completions endpoint. "
                             "Requires --api-key-env, so a credential is never "
                             "sent to an unlisted host by default.")
    parser.add_argument("--api-key-env", default=None,
                        help="environment variable holding the key for --base-url")
    parser.add_argument("--model", default=None)
    parser.add_argument("--effort", choices=["low", "high", "max"], default="high")
    # Reasoning tokens bill against max_tokens, and current reasoning models
    # spend most of the budget thinking before they answer. At the old 32,000
    # default two different models ran out mid-answer: one truncated a review
    # after 122,707 characters of reasoning (the identical request at 100,000
    # finished, with nearly four times the findings), the other spent 99.9% of
    # the budget reasoning and returned empty content. The cap costs nothing
    # unless tokens are actually generated, so the default errs high; pass a
    # lower value for models whose completion limit rejects it.
    parser.add_argument("--max-tokens", type=int, default=None,
                        help="completion budget; reasoning tokens count "
                             "against it (default: %d, or the manifest's "
                             "value when --manifest is given)" % DEFAULT_MAX_TOKENS)
    parser.add_argument("--temperature", type=float, default=0.2)
    parser.add_argument("--stdin", action="store_true",
                        help="read the task from stdin instead of an argument")
    # Anchored to the working directory, not the script's: an installed ox
    # lives in /usr/bin or a Homebrew Cellar, where a script-relative logs/
    # is unwritable or worse. The working directory is the project; running
    # from a source checkout's root behaves exactly as before.
    parser.add_argument("--log-dir", default=str(Path.cwd() / "logs"))
    parser.add_argument("--output", default=None,
                        help="write the model's answer to this file instead of "
                             "stdout; written only when the run succeeds")
    parser.add_argument("--status-file", default=None,
                        help="write a JSON run summary here on every exit, "
                             "success or failure, so a script checks a fact "
                             "instead of relying on pipeline exit codes")
    parser.add_argument("--force", action="store_true",
                        help="send even if the secret scan or size guard trips")
    parser.add_argument("--dry-run", action="store_true",
                        help="build and log the request, print it, send nothing")
    parser.add_argument("--skill", action="store_true",
                        help="print the %s agent skill — a runbook for driving a "
                             "review from an agent, with the script paths this "
                             "installation actually uses — and exit" % SKILL_NAME)
    args = parser.parse_args()

    if args.skill:
        # Answered before the status record is touched, because this is a
        # question about the installation rather than a run: no destination,
        # no payload, nothing to audit.
        print_skill()
        sys.exit(0)

    status["mode"] = args.mode
    status["dry_run"] = args.dry_run
    status["output"] = args.output
    status["status_file"] = args.status_file
    if args.status_file:
        # Mark the run in progress immediately, so a crash or kill can never
        # leave a stale success record from an earlier run for a script to
        # read. The exit path overwrites this with the real outcome.
        write_status(status)
    if args.output and os.path.exists(args.output):
        # Same hazard, other file: a leftover answer from a previous run must
        # not read as this run's. Naming the path hands ox the file, like -o
        # anywhere else.
        os.remove(args.output)

    task = sys.stdin.read() if args.stdin else args.task
    if not task or not task.strip():
        sys.exit("ox: no task given")

    # Resolve destination and credential together. They are never chosen
    # independently: an unlisted host requires you to name the variable whose
    # key it may have, and a manifest may only name venues from ox's own
    # table, so no credential travels somewhere by default.
    manifest_info = None
    if args.failover and not args.manifest:
        sys.exit("ox: --failover requires --manifest; a single destination "
                 "has nothing to fail over to")
    if args.manifest:
        # The manifest chooses provider and model; every other destination
        # flag conflicts with it rather than silently mixing.
        for value, name in ((args.venue, "--venue"), (args.model, "--model"),
                            (args.base_url, "--base-url"),
                            (args.api_key_env, "--api-key-env")):
            if value:
                sys.exit("ox: %s conflicts with --manifest; the manifest "
                         "chooses the destination" % name)
        entries, manifest_info = load_manifest(args.manifest, args.allow_paid)
        status["manifest"] = {"path": manifest_info["path"],
                              "sha256": manifest_info["sha256"]}
    elif args.base_url:
        if not args.api_key_env:
            sys.exit("ox: --base-url requires --api-key-env, so a key is never "
                     "sent to an unlisted host by accident")
        # https only. A plaintext endpoint puts the Bearer token on the wire in
        # cleartext, which defeats the point of pairing it with a host at all.
        # Validated here rather than at request time so a bad URL is a clean
        # error instead of a ValueError traceback after the logs are written.
        if not args.base_url.startswith("https://"):
            sys.exit("ox: --base-url must be an https:// URL (got %r); a "
                     "credential must not travel in cleartext" % args.base_url)
        if not args.model:
            sys.exit("ox: --model is required for venue 'custom' (no default)")
        entries = [{"position": 1, "venue": "custom", "model": args.model,
                    "cost": None, "why": "", "params": {}, "skip": None,
                    "url": args.base_url, "key_env": args.api_key_env}]
    else:
        if args.api_key_env:
            sys.exit("ox: --api-key-env only applies with --base-url; "
                     "a named venue already carries its own key variable")
        venue = args.venue or DEFAULT_VENUE
        model = args.model or VENUES[venue]["default_model"]
        if not model:
            sys.exit("ox: --model is required for venue %r (no default)" % venue)
        entries = [{"position": 1, "venue": venue, "model": model,
                    "cost": None, "why": "", "params": {}, "skip": None,
                    "url": VENUES[venue]["url"],
                    "key_env": VENUES[venue]["key_env"]}]

    if not args.manifest and not os.environ.get(entries[0]["key_env"]) \
            and not args.dry_run:
        sys.exit("ox: %s not set (run under: op run --env-file .env -- ./ox ...)"
                 % entries[0]["key_env"])

    paths = [p.strip() for p in args.files.split(",") if p.strip()]
    context, total_bytes, findings = build_context(paths, args.force, task)

    user_content = f"{task.strip()}\n\n{context}" if context else task.strip()

    attempts = [] if manifest_info else None
    total = len(entries)
    chosen = None
    for entry in entries:
        label = ("manifest[%d/%d] %s/%s" % (entry["position"], total,
                                            entry["venue"], entry["model"])
                 if manifest_info else "%s/%s" % (entry["venue"], entry["model"]))
        if entry["skip"]:
            sys.stderr.write("ox: %s skipped: %s\n" % (label, entry["skip"]))
            attempts.append({"position": entry["position"],
                             "venue": entry["venue"], "model": entry["model"],
                             "skipped": entry["skip"]})
            continue

        # Explicit flag beats the entry's params, which beat the manifest's
        # issue-wide defaults, which beat the built-in default.
        if args.max_tokens is not None:
            max_tokens = args.max_tokens
        elif entry["params"].get("max_tokens"):
            max_tokens = entry["params"]["max_tokens"]
        elif manifest_info and manifest_info["defaults"].get("max_tokens"):
            max_tokens = manifest_info["defaults"]["max_tokens"]
        else:
            max_tokens = DEFAULT_MAX_TOKENS

        payload = {
            "model": entry["model"],
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPTS[args.mode]},
                {"role": "user", "content": user_content},
            ],
            "max_tokens": max_tokens,
            "temperature": args.temperature,
            "reasoning": {"effort": args.effort},
            "include_reasoning": True,
        }

        stamp, log_dir = make_log_dir(Path(args.log_dir))
        status["log_dir"] = str(log_dir)
        status["venue"] = entry["venue"]
        status["model"] = entry["model"]
        meta = {
            "timestamp": stamp,
            "ox_version": VERSION,
            "model": entry["model"],
            "venue": entry["venue"],
            "endpoint": entry["url"],
            "key_env": entry["key_env"],
            "mode": args.mode,
            "effort": args.effort,
            "max_tokens": max_tokens,
            "files": paths,
            "context_bytes": total_bytes,
            "secret_scan_hits": findings,
            "forced": args.force,
        }
        if manifest_info:
            # An audit trail that says where the code went but not why the
            # destination was chosen is incomplete: record which manifest,
            # byte-exactly, and which entry.
            meta["manifest"] = {"path": manifest_info["path"],
                                "sha256": manifest_info["sha256"],
                                "entry_position": entry["position"]}
        write_lf(log_dir / "request.json", json.dumps(payload, indent=2))
        write_lf(log_dir / "meta.json", json.dumps(meta, indent=2))

        sys.stderr.write(f"ox: log -> {log_dir}\n")
        if manifest_info:
            why = " — %s" % entry["why"] if entry["why"] else ""
            sys.stderr.write("ox: %s%s\n" % (label, why))
        sys.stderr.write("ox: venue=%s model=%s mode=%s effort=%s "
                         "context=%dB files=%d\n"
                         % (entry["venue"], entry["model"], args.mode,
                            args.effort, total_bytes, len(paths)))

        if args.dry_run:
            sys.stderr.write("ox: dry run, nothing sent\n")
            print(json.dumps(payload, indent=2))
            return

        record = {"position": entry["position"], "venue": entry["venue"],
                  "model": entry["model"], "log_dir": str(log_dir)}
        try:
            choice, usage, reasoning, content = send_and_parse(
                entry["url"], os.environ.get(entry["key_env"]), payload, log_dir)
        except AttemptFailed as failure:
            if attempts is not None:
                record["error"] = str(failure)
                attempts.append(record)
                status["attempts"] = attempts
            if not args.failover:
                sys.exit(str(failure))
            sys.stderr.write("%s\nox: %s failed; trying the next entry\n"
                             % (failure, label))
            continue

        details = usage.get("completion_tokens_details") or {}
        status["finish_reason"] = choice.get("finish_reason")
        status["prompt_tokens"] = usage.get("prompt_tokens")
        status["completion_tokens"] = usage.get("completion_tokens")
        status["reasoning_tokens"] = details.get("reasoning_tokens")
        status["reasoning_chars"] = len(reasoning)
        status["truncated"] = choice.get("finish_reason") == "length"
        if attempts is not None:
            record["finish_reason"] = choice.get("finish_reason")
            attempts.append(record)
        chosen = content
        break

    status["attempts"] = attempts
    if chosen is None:
        # Only reachable with --manifest: every entry was skipped, or (under
        # --failover) every attempted entry failed after sending. Without
        # --failover the first failure already exited above, message intact.
        lines = []
        for item in attempts or []:
            reason = item.get("skipped") or item.get("error") or "not attempted"
            lines.append("  [%s] %s/%s: %s"
                         % (item.get("position"), item.get("venue"),
                            item.get("model"), reason.splitlines()[0]))
        sys.exit("ox: no manifest entry produced an answer:\n" + "\n".join(lines))
    content = chosen

    # Truncation with content is quieter than truncation without: the answer
    # reads as complete unless you notice the missing tail. Seen in practice
    # as a review cut off mid-sentence at the old default budget, four
    # findings into what turned out to be fifteen. Warn rather than fail —
    # a partial answer has value in front of a human — and let scripts
    # check `truncated` in the status record instead.
    if status["truncated"]:
        sys.stderr.write(
            "ox: WARNING: output truncated at the max_tokens cap "
            "(finish=length); raise --max-tokens\n"
        )

    if args.output:
        # Match stdout byte-for-byte: print() appends the trailing newline.
        write_lf(args.output, content if content.endswith("\n") else content + "\n")
        sys.stderr.write("ox: answer -> %s\n" % args.output)
    else:
        print(content)


if __name__ == "__main__":
    main()
