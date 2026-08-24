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
USER_AGENT = "oxbox (+https://github.com/curtisgalloway/oxbox)"
MAX_PAYLOAD_BYTES = 400_000
TIMEOUT_SECONDS = 900

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


def main():
    parser = argparse.ArgumentParser(
        prog="ox",
        description="Send a task to an untrusted model. No tools, full audit log.",
    )
    parser.add_argument("task", nargs="?", help="the task or question (or use --stdin)")
    parser.add_argument("--files", default="",
                        help="comma-separated files to include as context")
    parser.add_argument("--mode", choices=sorted(SYSTEM_PROMPTS), default="diff",
                        help="output contract (default: diff)")
    parser.add_argument("--venue", choices=sorted(VENUES), default=DEFAULT_VENUE,
                        help="where to send the request; each venue uses its own "
                             "API key variable (default: %s)" % DEFAULT_VENUE)
    parser.add_argument("--base-url", default=None,
                        help="send to an arbitrary chat-completions endpoint. "
                             "Requires --api-key-env, so a credential is never "
                             "sent to an unlisted host by default.")
    parser.add_argument("--api-key-env", default=None,
                        help="environment variable holding the key for --base-url")
    parser.add_argument("--model", default=None)
    parser.add_argument("--effort", choices=["low", "high", "max"], default="high")
    parser.add_argument("--max-tokens", type=int, default=32000)
    parser.add_argument("--temperature", type=float, default=0.2)
    parser.add_argument("--stdin", action="store_true",
                        help="read the task from stdin instead of an argument")
    parser.add_argument("--log-dir", default=str(Path(__file__).resolve().parent / "logs"))
    parser.add_argument("--force", action="store_true",
                        help="send even if the secret scan or size guard trips")
    parser.add_argument("--dry-run", action="store_true",
                        help="build and log the request, print it, send nothing")
    args = parser.parse_args()

    task = sys.stdin.read() if args.stdin else args.task
    if not task or not task.strip():
        sys.exit("ox: no task given")

    # Resolve destination and credential together. They are never chosen
    # independently: an unlisted host requires you to name the variable whose
    # key it may have, so no credential travels somewhere by default.
    if args.base_url:
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
        api_url = args.base_url
        key_env = args.api_key_env
        venue = "custom"
    else:
        if args.api_key_env:
            sys.exit("ox: --api-key-env only applies with --base-url; "
                     "a named venue already carries its own key variable")
        venue = args.venue
        api_url = VENUES[venue]["url"]
        key_env = VENUES[venue]["key_env"]

    model = args.model or (VENUES[venue]["default_model"] if venue != "custom" else None)
    if not model:
        sys.exit("ox: --model is required for venue %r (no default)" % venue)

    api_key = os.environ.get(key_env)
    if not api_key and not args.dry_run:
        sys.exit("ox: %s not set (run under: op run --env-file .env -- ./ox ...)" % key_env)

    paths = [p.strip() for p in args.files.split(",") if p.strip()]
    context, total_bytes, findings = build_context(paths, args.force, task)

    user_content = f"{task.strip()}\n\n{context}" if context else task.strip()

    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPTS[args.mode]},
            {"role": "user", "content": user_content},
        ],
        "max_tokens": args.max_tokens,
        "temperature": args.temperature,
        "reasoning": {"effort": args.effort},
        "include_reasoning": True,
    }

    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H-%M-%SZ")
    log_dir = Path(args.log_dir) / stamp
    log_dir.mkdir(parents=True, exist_ok=True)
    write_lf(log_dir / "request.json", json.dumps(payload, indent=2))
    write_lf(log_dir / "meta.json", json.dumps({
        "timestamp": stamp,
        "model": model,
        "venue": venue,
        "endpoint": api_url,
        "key_env": key_env,
        "mode": args.mode,
        "effort": args.effort,
        "files": paths,
        "context_bytes": total_bytes,
        "secret_scan_hits": findings,
        "forced": args.force,
    }, indent=2))

    sys.stderr.write(f"ox: log -> {log_dir}\n")
    sys.stderr.write(f"ox: venue={venue} model={model} mode={args.mode} effort={args.effort} "
                     f"context={total_bytes}B files={len(paths)}\n")

    if args.dry_run:
        sys.stderr.write("ox: dry run, nothing sent\n")
        print(json.dumps(payload, indent=2))
        return

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
            body = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as error:
        detail = error.read().decode("utf-8", "replace")
        write_lf(log_dir / "error.txt", f"{error.code}\n{detail}")
        sys.exit(f"ox: HTTP {error.code}: {detail[:500]}")
    except urllib.error.URLError as error:
        sys.exit(f"ox: network error: {error.reason}")

    write_lf(log_dir / "response.json", json.dumps(body, indent=2))

    if "error" in body and body["error"]:
        sys.exit(f"ox: api error: {json.dumps(body['error'])[:500]}")

    choices = body.get("choices") or []
    # Some providers return an empty choices list on a content filter. That
    # is a real response, not a crash, and the log already holds the raw body.
    if not choices:
        sys.exit("ox: provider returned no choices (see response.json in the log)")
    choice = choices[0]
    message = choice.get("message", {}) or {}
    reasoning = message.get("reasoning") or ""
    content = message.get("content") or ""

    if reasoning:
        write_lf(log_dir / "reasoning.txt", reasoning)
    write_lf(log_dir / "content.md", content)

    tool_calls = message.get("tool_calls")
    if tool_calls:
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

    # An empty completion is a failure for every caller, and the API called it a
    # success. Without this, content.md is a 0-byte file with no error beside it
    # and a script reading it gets a silent no-op that looks like a clean run.
    #
    # Seen in practice: a reasoning model spent 31,995 of 32,000 completion
    # tokens thinking and emitted nothing, twice, at two different budgets. The
    # usage numbers are the diagnosis, so print them rather than a bare failure.
    if not content.strip():
        detail = ""
        if usage.get("completion_tokens_details", {}).get("reasoning_tokens"):
            detail = (" — %s of %s completion tokens went to reasoning"
                      % (usage["completion_tokens_details"]["reasoning_tokens"],
                         usage.get("completion_tokens")))
        sys.exit(
            "ox: model returned no content (finish=%s)%s\n"
            "ox: the raw response and any reasoning are in %s"
            % (choice.get("finish_reason"), detail, log_dir)
        )

    print(content)


if __name__ == "__main__":
    main()
