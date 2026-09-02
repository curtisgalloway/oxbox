#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Curtis Galloway
# SPDX-License-Identifier: Apache-2.0
"""Answer the three questions that must be settled before any code is sent.

  1. Is ox here, and which one?
  2. Which manifest is current, and where would it actually send this?
  3. Is this project already public, or would sending it publish it?

The destination question is put to `ox` itself, with `--dry-run`, rather
than re-deriving the permit rules here. oxbox learned that lesson in
wiretest.py: a check that rebuilds the logic it is checking passes even
after the real code changes, because it is asserting a property of itself.
Asking ox what it would do is the only answer that stays true.

Exit codes, so a caller can branch on a fact:
  0  ready, and the project is publicly readable — proceed
  10 ready, but the exposure gate needs a human decision first
  1  not runnable: no ox, no manifest, or no entry this run may use
"""

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import exposure  # noqa: E402  (sibling script, deliberately local)

MANIFEST_GLOB = "oxbox-manifest-*.json"
# Where a downloaded survey manifest plausibly lands. The working directory
# comes first because oxbox anchors state at the working directory and the
# README's own example runs ox from the project root with the manifest beside
# it.
SEARCH_DIRS = [
    Path.cwd(),
    Path.cwd() / "manifests",
    Path.home() / ".config" / "oxbox",
    Path.home() / ".config" / "oxbox" / "manifests",
    Path.home() / ".local" / "share" / "oxbox" / "manifests",
]
# A manifest may also be named by URL; the survey serves its current one at
# https://oxbox.ai/manifests/latest.json. The fetch here only renders the
# listing. The destination is still decided by ox, which fetches the same
# URL under its own rules: https only, no redirects, no credential, and the
# bytes kept as manifest.json in the run's log directory. Those rules are
# mirrored rather than shared -- ox is a script with no module to import --
# so a mismatch surfaces as a listing ox then refuses, never as a
# destination preflight approved on its own.
MANIFEST_MAX_BYTES = 1_048_576
MANIFEST_TIMEOUT = 30
USER_AGENT = "oxbox ox-review preflight (+https://github.com/curtisgalloway/oxbox)"
# Where the venue keys live when they live in 1Password: a .env of op://
# references. Set, it wraps every ox call in `op run --env-file <file> --`.
ENV_FILE_VAR = "OXBOX_ENV_FILE"


def is_url(source):
    return "://" in str(source)


class NoRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def fetch_manifest(url):
    """Return (bytes, None) for a manifest URL, or (None, why not).

    A GET carrying nothing: no Authorization header, no key variable read.
    """
    if not url.startswith("https://"):
        return None, "manifest URL must be https:// (ox refuses cleartext)"
    request = urllib.request.Request(url, headers={"Accept": "application/json",
                                                   "User-Agent": USER_AGENT})
    try:
        opener = urllib.request.build_opener(NoRedirects)
        with opener.open(request, timeout=MANIFEST_TIMEOUT) as response:
            raw = response.read(MANIFEST_MAX_BYTES + 1)
    except urllib.error.HTTPError as error:
        if 300 <= error.code < 400:
            return None, ("redirected (HTTP %d); ox reads a manifest from where "
                          "it was named or not at all" % error.code)
        return None, "HTTP %d" % error.code
    except (OSError, ValueError) as error:
        return None, str(getattr(error, "reason", None) or error)
    if len(raw) > MANIFEST_MAX_BYTES:
        return None, "body larger than %d bytes" % MANIFEST_MAX_BYTES
    return raw, None


def with_env_file(command, env_file):
    """Run ox under `op run --env-file <file> --` when the keys live in 1Password.

    The venue key variables then exist only inside ox's own process: not in
    the agent's environment, not in this script's, nothing a subagent could
    print. `op run` passes the child's exit status and streams through, so
    ox's status file, output file and stderr diagnosis are unchanged.

    Returns (command, None), or (None, why not).
    """
    if not env_file:
        return list(command), None
    if not Path(env_file).is_file():
        return None, "env file %s does not exist" % env_file
    if not shutil.which("op"):
        return None, ("an env file is named (%s) but the 1Password CLI `op` is "
                      "not on PATH; install it, or export the venue keys another "
                      "way and unset it" % env_file)
    return ["op", "run", "--env-file", str(env_file), "--"] + list(command), None


def as_command(path):
    """Run ox directly when it is executable, through this interpreter when
    it is not — a checkout on Windows or a copied file loses the exec bit,
    and "Permission denied" is a confusing way to learn that."""
    path = str(path)
    return ([path] if os.access(path, os.X_OK) else [sys.executable, path]), path


def find_ox(explicit):
    for candidate in (explicit, os.environ.get("OX")):
        if candidate and Path(candidate).exists():
            return as_command(candidate)
    found = shutil.which("ox")
    if found:
        return as_command(found)
    for base in (Path.cwd(), Path(os.environ.get("OXBOX_HOME") or Path.cwd())):
        if (base / "ox").exists():
            return as_command(base / "ox")
    return None, None


def manifest_candidates(explicit):
    """Collect manifests, newest issue first.

    "Current" means the newest issue the operator actually has, not the
    newest file: a manifest carries its own issue_date, and a re-download
    with a fresh mtime does not make an old issue current. mtime is only
    the tiebreaker for files that never say.
    """
    if explicit:
        return [describe_manifest(explicit)]
    named = os.environ.get("OXBOX_MANIFEST")
    if named:
        return [describe_manifest(named)]
    found = {}
    for directory in SEARCH_DIRS:
        try:
            for path in sorted(directory.glob(MANIFEST_GLOB)):
                found.setdefault(path.resolve(), describe_manifest(path))
        except OSError:
            continue
    return sorted(found.values(),
                  key=lambda m: (m.get("issue_date") or "", m.get("mtime") or 0),
                  reverse=True)


def describe_manifest(source):
    """Describe a manifest named by path or by https URL."""
    record = {"path": str(source), "readable": False, "issue_date": None,
              "sha256": None, "entries": [], "mtime": None, "error": None,
              "fetched": is_url(source)}
    if record["fetched"]:
        raw, error = fetch_manifest(str(source))
        if raw is None:
            record["error"] = error
            return record
    else:
        path = Path(source)
        try:
            raw = path.read_bytes()
            record["mtime"] = path.stat().st_mtime
        except OSError as error:
            record["error"] = str(error)
            return record
    record["sha256"] = hashlib.sha256(raw).hexdigest()
    try:
        data = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as error:
        record["error"] = "not valid JSON: %s" % error
        return record
    record["readable"] = True
    record["issue_date"] = data.get("issue_date")
    record["manifest_version"] = data.get("manifest_version")
    for index, rec in enumerate(data.get("recommendations") or []):
        record["entries"].append({
            "position": index + 1,
            "venue": rec.get("venue"),
            "model": rec.get("model"),
            "cost": rec.get("cost") or "unknown",
            "why": rec.get("why") or "",
        })
    return record


SKIP_LINE = re.compile(r"^ox: manifest\[(\d+)/\d+\] (\S+) skipped: (.+)$")
PICK_LINE = re.compile(r"^ox: venue=(\S+) model=(\S+) mode=")


def ask_ox_where(ox_command, manifest, allow_paid):
    """Let ox resolve the manifest and report the destination it chose.

    --dry-run builds and logs the request and sends nothing, so this costs
    a directory and no bytes on the wire. The log goes to a temporary
    directory: preflight probes are not part of the audit trail of what
    was actually sent, and mixing them in would dilute it.
    """
    result = {"chosen": None, "skipped": [], "ok": False, "stderr": ""}
    with tempfile.TemporaryDirectory(prefix="ox-preflight-") as scratch:
        command = list(ox_command) + [
            "--manifest", str(manifest), "--mode", "review",
            "--log-dir", scratch, "--dry-run",
        ]
        if allow_paid:
            command.append("--allow-paid")
        command.append("preflight: which entry would this run use?")
        try:
            done = subprocess.run(command, stdout=subprocess.DEVNULL,
                                  stderr=subprocess.PIPE, timeout=120)
        except (OSError, subprocess.SubprocessError) as error:
            result["stderr"] = str(error)
            return result
    result["stderr"] = done.stderr.decode("utf-8", "replace")
    for line in result["stderr"].splitlines():
        skip = SKIP_LINE.match(line)
        if skip:
            result["skipped"].append({"position": int(skip.group(1)),
                                      "entry": skip.group(2),
                                      "reason": skip.group(3)})
            continue
        pick = PICK_LINE.match(line)
        if pick:
            result["chosen"] = {"venue": pick.group(1), "model": pick.group(2)}
    result["ok"] = done.returncode == 0 and result["chosen"] is not None
    return result


def main():
    parser = argparse.ArgumentParser(
        description="Check ox, the current manifest, and whether this project is public.")
    parser.add_argument("--path", default=".", help="the project to review (default: .)")
    parser.add_argument("--manifest", help="use this manifest instead of searching")
    parser.add_argument("--allow-paid", action="store_true",
                        help="let the manifest use entries not confirmed free")
    parser.add_argument("--ox", help="path to the ox executable")
    parser.add_argument("--env-file", default=os.environ.get(ENV_FILE_VAR),
                        help="a .env of 1Password op:// references holding the "
                             "venue keys; ox then runs under `op run --env-file` "
                             "(default: $%s)" % ENV_FILE_VAR)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    report = {"ok": False, "ox": None, "manifest": None, "other_manifests": [],
              "destination": None, "exposure": None, "blockers": []}

    ox_command, ox_path = find_ox(args.ox)
    if ox_command is None:
        report["blockers"].append(
            "ox not found: install the package, set OX=/path/to/ox, or run from a "
            "checkout containing ./ox")
    else:
        # --version needs no key, so it runs unwrapped; everything that
        # resolves a destination goes through the env file from here on.
        version = subprocess.run(ox_command + ["--version"], stdout=subprocess.PIPE,
                                 stderr=subprocess.STDOUT)
        report["ox"] = {"path": ox_path,
                        "version": version.stdout.decode("utf-8", "replace").strip(),
                        "env_file": args.env_file}
        ox_command, problem = with_env_file(ox_command, args.env_file)
        if problem:
            report["blockers"].append(problem)

    manifests = manifest_candidates(args.manifest)
    usable = [m for m in manifests if m["readable"]]
    if not usable:
        detail = "; ".join("%s: %s" % (m["path"], m["error"])
                           for m in manifests if m.get("error"))
        report["blockers"].append(
            "no readable survey manifest found%s. Point --manifest or OXBOX_MANIFEST "
            "at the issue's file or its https URL (the survey serves the current one "
            "at https://oxbox.ai/manifests/latest.json), or drop the file beside the "
            "project as %s. Searched: %s"
            % (" (%s)" % detail if detail else "", MANIFEST_GLOB,
               ", ".join(str(d) for d in SEARCH_DIRS)))
    else:
        report["manifest"] = usable[0]
        report["other_manifests"] = usable[1:]

    if ox_command and report["manifest"]:
        where = ask_ox_where(ox_command, report["manifest"]["path"], args.allow_paid)
        report["destination"] = where
        if not where["ok"]:
            reasons = "\n".join(
                "    [%d] %s: %s" % (skip["position"], skip["entry"], skip["reason"])
                for skip in where["skipped"]) or "    " + (where["stderr"].strip()
                                                           or "ox gave no reason")
            report["blockers"].append(
                "ox would not send: no manifest entry is usable. Its reasons:\n%s" % reasons)

    gate = subprocess.run(
        [sys.executable, str(Path(__file__).resolve().parent / "exposure.py"),
         "--path", args.path, "--json"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        report["exposure"] = json.loads(gate.stdout.decode("utf-8", "replace"))
    except ValueError:
        report["exposure"] = {"verdict": "unknown",
                              "summary": "the exposure probe failed: %s"
                                         % gate.stderr.decode("utf-8", "replace").strip()}

    report["ok"] = not report["blockers"]
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        render(report)

    if report["blockers"]:
        return 1
    return 0 if report["exposure"].get("verdict") == "public" else 10


def render(report):
    print("== ox ==")
    if report["ox"]:
        print("%s  (%s)" % (report["ox"]["version"], report["ox"]["path"]))
        if report["ox"].get("env_file"):
            print("keys: op run --env-file %s" % report["ox"]["env_file"])
    else:
        print("not found")

    print("\n== manifest ==")
    manifest = report["manifest"]
    if not manifest:
        print("none found")
    else:
        print("current: %s" % manifest["path"])
        print("issue_date=%s  sha256=%s" % (manifest["issue_date"], manifest["sha256"]))
        if manifest.get("fetched"):
            print("fetched by URL; ox keeps the bytes it uses as manifest.json in "
                  "each run's log directory")
        for entry in manifest["entries"]:
            print("  [%d] %-11s %-28s cost=%-7s %s"
                  % (entry["position"], entry["venue"], entry["model"],
                     entry["cost"], entry["why"]))
        for other in report["other_manifests"]:
            print("  also on disk (older): %s (issue_date=%s)"
                  % (other["path"], other["issue_date"]))

    print("\n== destination ==")
    where = report["destination"]
    if not where:
        print("not resolved")
    else:
        for skip in where["skipped"]:
            print("  skipped [%d] %s: %s" % (skip["position"], skip["entry"], skip["reason"]))
        if where["chosen"]:
            print("ox would send to: %s / %s"
                  % (where["chosen"]["venue"], where["chosen"]["model"]))
            print("Everything sent there is logged and shared with whoever owns that "
                  "model. Under --failover, later manifest entries are also possible "
                  "destinations, in order.")
        else:
            print("ox would refuse to send — see the reasons above")

    print("\n== exposure ==")
    print("verdict: %s" % report["exposure"].get("verdict"))
    print(report["exposure"].get("summary", ""))
    for remote in report["exposure"].get("remotes", []):
        for note in remote.get("notes", []):
            print("  note: %s" % note)
    for note in report["exposure"].get("local", []):
        print("  local: %s" % note)

    print("\n== verdict ==")
    if report["blockers"]:
        for blocker in report["blockers"]:
            print("BLOCKED: %s" % blocker)
    elif report["exposure"].get("verdict") == "public":
        print("ready: the project is publicly readable and ox has a destination")
    else:
        print("ready to run, but the project is not confirmed public — ask the "
              "operator before sending anything")


if __name__ == "__main__":
    sys.exit(main())
