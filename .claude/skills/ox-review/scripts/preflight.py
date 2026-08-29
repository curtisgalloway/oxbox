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
        return [describe_manifest(Path(explicit))]
    named = os.environ.get("OXBOX_MANIFEST")
    if named:
        return [describe_manifest(Path(named))]
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


def describe_manifest(path):
    record = {"path": str(path), "readable": False, "issue_date": None,
              "sha256": None, "entries": [], "mtime": None, "error": None}
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
        version = subprocess.run(ox_command + ["--version"], stdout=subprocess.PIPE,
                                 stderr=subprocess.STDOUT)
        report["ox"] = {"path": ox_path,
                        "version": version.stdout.decode("utf-8", "replace").strip()}

    manifests = manifest_candidates(args.manifest)
    usable = [m for m in manifests if m["readable"]]
    if not usable:
        report["blockers"].append(
            "no readable survey manifest found. Point --manifest or OXBOX_MANIFEST at "
            "the issue's file, or drop it beside the project as %s. Searched: %s"
            % (MANIFEST_GLOB, ", ".join(str(d) for d in SEARCH_DIRS)))
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
    else:
        print("not found")

    print("\n== manifest ==")
    manifest = report["manifest"]
    if not manifest:
        print("none found")
    else:
        print("current: %s" % manifest["path"])
        print("issue_date=%s  sha256=%s" % (manifest["issue_date"], manifest["sha256"]))
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
