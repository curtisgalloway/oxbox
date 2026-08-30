#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Curtis Galloway
# SPDX-License-Identifier: Apache-2.0
"""Run one `ox --mode review` batch, one at a time, machine-wide.

Several review subagents working at once is a good idea for reading and
verifying findings, and a bad idea for talking to the venue. The free
cloaked listings share a single upstream quota across everyone using them,
and oxbox measured the consequence: a serial queue with a 120-second retry
floor cleared every 429 within three attempts, while three concurrent
requests were all refused immediately. Concurrency is the trigger, not
volume.

So the fan-out happens above this script and stops at it. Every subagent
calls this; a lock lets exactly one request be in flight at a time and
makes the others wait. That keeps the batches pipelined — one batch's
verification overlaps the next batch's request — without ever putting two
requests on the wire together.

Retries live here rather than in `ox` on purpose. `ox` exits non-zero with
the provider's error text intact, which is what makes the failure class
diagnosable; the timed backoff belongs to the caller, and this is the
caller.
"""

import argparse
import json
import os
import random
import shutil
import subprocess
import sys
import time
from pathlib import Path

# One ox request can legitimately take 900 seconds (ox's own socket timeout)
# on a long reasoning review, so a lock younger than that is presumed alive.
OX_REQUEST_TIMEOUT = 900
LOCK_SLACK = 120
# Measured, not guessed: 120 seconds is the floor that cleared every 429 in
# oxbox's own 18-batch run. Going faster is what caused them.
RETRY_FLOOR = 120
DEFAULT_ATTEMPTS = 3


def as_command(path):
    """Turn a path to ox into an argv prefix.

    An executable file runs directly; anything else goes through this
    interpreter. That matters more than it looks: a checkout on Windows, a
    copy through a zip, or a file restored from a package cache can all
    arrive without the executable bit, and "Permission denied" is a
    confusing way to learn that.
    """
    path = str(path)
    if os.access(path, os.X_OK):
        return [path]
    return [sys.executable, path]


def find_ox(explicit):
    """Locate the ox executable, preferring what the caller named."""
    for candidate in (explicit, os.environ.get("OX")):
        if candidate and Path(candidate).exists():
            return as_command(candidate)
    found = shutil.which("ox")
    if found:
        return as_command(found)
    for base in (Path.cwd(), Path(os.environ.get("OXBOX_HOME") or Path.cwd())):
        if (base / "ox").exists():
            return as_command(base / "ox")
    sys.exit("oxreview: cannot find ox — install it, set OX=/path/to/ox, or run "
             "from a checkout that contains ./ox")


class Queue:
    """A machine-wide mutex for "one ox request at a time".

    Directory creation is the primitive because it is atomic on every
    platform oxbox supports, needs no third-party library, and leaves a
    readable record of who holds it. Liveness is expressed as an expiry the
    holder refreshes rather than a pid check: `os.kill(pid, 0)` is a
    liveness probe on Unix and a *terminate* on Windows, and a queue that
    can kill the process it was waiting for is worse than one that waits.
    """

    def __init__(self, state_dir, wait_timeout, label):
        self.path = Path(state_dir) / "queue.lock"
        self.holder = self.path / "holder.json"
        self.wait_timeout = wait_timeout
        self.label = label
        self.held = False
        self.waited = 0.0

    def _write_holder(self, seconds_from_now):
        record = {"pid": os.getpid(), "label": self.label,
                  "acquired": time.time(),
                  "expires_at": time.time() + seconds_from_now}
        # Write-then-rename, because a waiter reads this file to decide whether
        # the lock is dead. A plain write truncates first, and a reader landing
        # in that window sees an unparseable record, falls back to the lock
        # directory's mtime — which is old, since a long request keeps the same
        # lock — and breaks a lock whose holder is very much alive. os.replace
        # is atomic on every platform here, so the file is only ever whole.
        temporary = self.path / ("holder.%d.tmp" % os.getpid())
        try:
            temporary.write_text(json.dumps(record), encoding="utf-8")
            os.replace(str(temporary), str(self.holder))
        except OSError:
            try:
                temporary.unlink()
            except OSError:
                pass

    def refresh(self, seconds_from_now):
        """Extend the expiry — call before anything that will take a while."""
        if self.held:
            self._write_holder(seconds_from_now)

    def _expired(self):
        try:
            record = json.loads(self.holder.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            # A lock directory with no readable holder record is either
            # mid-creation or debris. Give it one full window before
            # deciding, using the directory's own mtime as the clock.
            try:
                return time.time() - self.path.stat().st_mtime > OX_REQUEST_TIMEOUT + LOCK_SLACK
            except OSError:
                return False
        return time.time() > record.get("expires_at", 0)

    def _break_stale(self):
        """Remove a dead holder's lock directory, debris and all.

        Unlinking holder.json alone is not enough. _write_holder stages
        holder.<pid>.tmp and renames it, so a run killed between those two
        steps leaves the temp file behind, and rmdir refuses a directory that
        still holds one. Raises OSError if the directory could not be cleared.
        """
        try:
            entries = list(self.path.iterdir())
        except OSError:
            entries = []
        for entry in entries:
            try:
                entry.unlink()
            except OSError:
                pass
        self.path.rmdir()

    def acquire(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        started = time.time()
        announced = False
        complained = False
        while True:
            try:
                self.path.mkdir()
            except FileExistsError:
                if self._expired():
                    if not complained:
                        sys.stderr.write(
                            "oxreview: breaking a stale queue lock at %s "
                            "(its holder is past its expiry)\n" % self.path)
                    try:
                        self._break_stale()
                        continue
                    except OSError as error:
                        # Fall through to the ordinary wait instead of retrying
                        # straight away. Neither a failed unlink nor a failed
                        # rmdir moves the directory's mtime, so _expired stays
                        # true, and an immediate `continue` here has no sleep
                        # and never reaches the timeout check below: it spins at
                        # full CPU forever. Measured before this was fixed --
                        # 82MB of "breaking a stale queue lock" in 20 seconds,
                        # against a 5-second --wait-timeout.
                        if not complained:
                            sys.stderr.write(
                                "oxreview: could not clear %s (%s); waiting for "
                                "it instead\n" % (self.path, error))
                            complained = True
                waited = time.time() - started
                if waited > self.wait_timeout:
                    sys.exit("oxreview: waited %ds for the request queue and gave up; "
                             "another batch still holds %s"
                             % (int(waited), self.path))
                if not announced:
                    sys.stderr.write(
                        "oxreview: another batch is talking to the venue; waiting "
                        "(requests are serialized on purpose — a shared free pool "
                        "refuses concurrent calls)\n")
                    announced = True
                # Jitter so releases don't hand the lock to the same waiter
                # every time and starve the rest.
                time.sleep(random.uniform(1.5, 4.0))
                continue
            self.held = True
            self.waited = time.time() - started
            self._write_holder(OX_REQUEST_TIMEOUT + LOCK_SLACK)
            return

    def release(self):
        if not self.held:
            return
        self.held = False
        try:
            self.holder.unlink()
        except OSError:
            pass
        try:
            self.path.rmdir()
        except OSError as error:
            sys.stderr.write("oxreview: could not release %s: %s\n" % (self.path, error))


def classify(error_text):
    """Name the failure so the retry decision is about facts, not vibes.

    The two cloaked-endpoint failures look alike and want opposite moves.
    A 429 from the shared pool clears by waiting and nothing else; a 404
    about guardrails and data policy means prompt logging is off, and no
    amount of backoff will fix it. Telling the caller to go change a
    privacy setting that is already correct is the wrong advice, so the
    codes are read, not guessed.
    """
    text = error_text or ""
    if "HTTP 429" in text or "rate-limited upstream" in text or "shared_pool" in text:
        return "pool-busy", (
            "the venue's shared free pool is busy — this is neither your key nor "
            "your account, and only backing off clears it")
    if "HTTP 404" in text and ("No endpoints available" in text or "data policy" in text):
        return "guardrail", (
            "the endpoint refused on guardrail/data-policy grounds. Cloaked free "
            "listings require prompt logging to be enabled at "
            "https://openrouter.ai/settings/privacy — which is also the toggle "
            "that hands over your prompts. Do not confuse this with a 429; "
            "waiting will not help")
    for code in ("HTTP 500", "HTTP 502", "HTTP 503", "HTTP 504"):
        if code in text:
            return "server-error", "the venue returned a server error"
    if "network error" in text:
        return "network", "the request did not reach the venue"
    if "empty" in text.lower() and "content" in text.lower():
        return "empty", "the model returned no content"
    return "fatal", "the run failed for a reason retrying will not change"


RETRYABLE = {"pool-busy", "server-error", "network", "empty"}


def read_status(path):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def main():
    parser = argparse.ArgumentParser(
        description="Run one serialized ox review batch, with measured backoff.")
    parser.add_argument("--out", required=True,
                        help="directory for this batch's review.md, status.json and run.json")
    parser.add_argument("--file", action="append", default=[], dest="files",
                        required=True, help="a file to review (repeat per file)")
    parser.add_argument("--manifest", help="survey manifest choosing venue and model")
    parser.add_argument("--task", help="the review task text")
    parser.add_argument("--task-file", help="read the review task from this file")
    parser.add_argument("--label", default="batch", help="name for this batch in logs")
    parser.add_argument("--failover", action="store_true",
                        help="let ox move to the next permitted manifest entry on a "
                             "failure after the request is sent. This is consent to "
                             "send the payload to any permitted entry, so only pass "
                             "it once the operator has seen the full entry list.")
    parser.add_argument("--attempts", type=int, default=DEFAULT_ATTEMPTS,
                        help="total tries for a retryable failure (default: %d)" % DEFAULT_ATTEMPTS)
    parser.add_argument("--retry-floor", type=int, default=RETRY_FLOOR,
                        help="minimum seconds between tries (default: %d, measured)" % RETRY_FLOOR)
    parser.add_argument("--wait-timeout", type=int, default=7200,
                        help="how long to wait for the request queue before giving up")
    parser.add_argument("--effort", choices=["low", "high", "max"])
    parser.add_argument("--max-tokens", type=int)
    parser.add_argument("--venue")
    parser.add_argument("--model")
    parser.add_argument("--state-dir", default=".ox-review",
                        help="where the queue lock lives. Every batch that must not "
                             "collide at the venue has to name the same directory "
                             "(default: .ox-review, beside the batch outputs)")
    parser.add_argument("--ox", help="path to the ox executable")
    parser.add_argument("--dry-run", action="store_true",
                        help="build and log the request without sending it")
    args = parser.parse_args()

    if args.task_file:
        task = Path(args.task_file).read_text(encoding="utf-8")
    elif args.task:
        task = args.task
    else:
        sys.exit("oxreview: give the batch a review task with --task or --task-file")

    bad = [f for f in args.files if "," in f]
    if bad:
        # ox takes --files as one comma-separated string, so a comma in a path
        # would silently split it into two files that do not exist.
        sys.exit("oxreview: ox separates files with commas, so these paths cannot "
                 "be sent: %s" % ", ".join(bad))
    missing = [f for f in args.files if not Path(f).exists()]
    if missing:
        sys.exit("oxreview: no such file(s): %s" % ", ".join(missing))

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    review_path = out / "review.md"
    status_path = out / "status.json"

    command = find_ox(args.ox) + [
        "--mode", "review",
        "--files", ",".join(args.files),
        "--output", str(review_path),
        "--status-file", str(status_path),
    ]
    if args.manifest:
        command += ["--manifest", args.manifest]
    if args.failover:
        command.append("--failover")
    if args.venue:
        command += ["--venue", args.venue]
    if args.model:
        command += ["--model", args.model]
    if args.effort:
        command += ["--effort", args.effort]
    if args.max_tokens:
        command += ["--max-tokens", str(args.max_tokens)]
    if args.dry_run:
        command.append("--dry-run")
    command.append(task)

    record = {"label": args.label, "files": args.files, "out": str(out),
              "ok": False, "attempts": [], "queue_wait_seconds": None,
              "review": None, "diagnosis": None}

    queue = Queue(args.state_dir, args.wait_timeout, args.label)
    queue.acquire()
    record["queue_wait_seconds"] = round(queue.waited, 1)
    try:
        for attempt in range(1, args.attempts + 1):
            queue.refresh(OX_REQUEST_TIMEOUT + LOCK_SLACK)
            sys.stderr.write("oxreview: [%s] attempt %d/%d — %d file(s)\n"
                             % (args.label, attempt, args.attempts, len(args.files)))
            started = time.time()
            # stdout is swallowed only under --dry-run, where ox prints the whole
            # payload; otherwise --output already put the answer in a file and
            # nothing is piped, so ox's exit status reaches us intact.
            try:
                done = subprocess.run(
                    command, stdout=subprocess.DEVNULL if args.dry_run else None)
            except OSError as error:
                record["diagnosis"] = "could not run ox (%s): %s" % (command[0], error)
                # Record the try as an attempt. run.json's attempt list is the
                # audit trail for what this batch actually did, and breaking out
                # without appending leaves "attempts": [] -- which reads like the
                # loop never ran rather than like ox could not be started.
                record["attempts"].append(
                    {"attempt": attempt, "exit_code": None,
                     "seconds": round(time.time() - started, 1),
                     "error": record["diagnosis"], "kind": "no-ox"})
                sys.stderr.write("oxreview: [%s] %s\n" % (args.label, record["diagnosis"]))
                break
            elapsed = round(time.time() - started, 1)
            status = read_status(status_path)
            entry = {"attempt": attempt, "exit_code": done.returncode,
                     "seconds": elapsed, "log_dir": status.get("log_dir"),
                     "venue": status.get("venue"), "model": status.get("model"),
                     "error": status.get("error"), "truncated": status.get("truncated")}
            record["attempts"].append(entry)

            if done.returncode == 0:
                record["ok"] = True
                record["review"] = str(review_path) if review_path.exists() else None
                if status.get("truncated"):
                    record["diagnosis"] = (
                        "the answer was cut off at the token cap — findings past the "
                        "cut are missing; re-run this batch with a larger --max-tokens "
                        "or fewer files")
                break

            kind, explanation = classify(status.get("error") or "")
            entry["kind"] = kind
            record["diagnosis"] = explanation
            if kind not in RETRYABLE or attempt == args.attempts:
                sys.stderr.write("oxreview: [%s] giving up: %s\n" % (args.label, explanation))
                break
            # Hold the lock across the backoff. Releasing it would let the next
            # waiter fire immediately into a pool that just said it was busy,
            # which is the exact behaviour the floor exists to prevent.
            delay = args.retry_floor + random.uniform(0, 15)
            sys.stderr.write("oxreview: [%s] %s; waiting %ds before retrying\n"
                             % (args.label, explanation, int(delay)))
            queue.refresh(delay + OX_REQUEST_TIMEOUT + LOCK_SLACK)
            time.sleep(delay)
    finally:
        queue.release()

    (out / "run.json").write_text(json.dumps(record, indent=2), encoding="utf-8")
    if record["ok"]:
        sys.stderr.write("oxreview: [%s] %s\n" % (
            args.label,
            "review -> %s" % review_path if record["review"]
            else "ox exited clean but wrote no review (a dry run does not send)"))
        return 0
    sys.stderr.write("oxreview: [%s] no review produced; see %s\n"
                     % (args.label, out / "run.json"))
    return 1


if __name__ == "__main__":
    sys.exit(main())
