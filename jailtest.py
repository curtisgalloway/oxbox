# SPDX-FileCopyrightText: 2026 Curtis Galloway
# SPDX-License-Identifier: Apache-2.0
"""Self-test for the jail. Run it INSIDE the jail:

    ./oxbox -- python3 jailtest.py

Every probe asserts a containment property. Anything reported FAIL means the
jail leaks and model-generated code must not be run in it.

The list of sensitive paths comes from OXBOX_EXISTING_PATHS, which oxbox
computes before the jail starts. That indirection is load-bearing: inside the
jail stat() is denied, so a probe that checked whether a path exists would see
"absent" for every hidden path and skip instead of testing -- passing by not
looking. That happened once already.
"""

import os
import socket
import sys

WORK = os.environ.get("HOME", "")
REAL_HOME = os.environ.get("REAL_HOME", "")
REPO_ROOT = os.environ.get("REPO_ROOT", "")
PLATFORM = os.environ.get("OXBOX_PLATFORM", sys.platform)
EXISTING = [line for line in os.environ.get("OXBOX_EXISTING_PATHS", "").splitlines() if line]
# Also decided outside: whether the host has a route out at all. Inside the
# jail a denied connect and an unreachable network raise the same errors, so
# on an offline host the network probes would pass by not being able to fail.
# oxbox says which it is; absent the variable, assume online and probe.
HOST_HAS_ROUTE = os.environ.get("OXBOX_HOST_HAS_ROUTE", "1") != "0"

# Reading a root-owned file proves nothing about the jail when you ARE root.
# What keeps /etc/shadow unreadable is file permissions, and uid 0 bypasses
# them, so the probe reports a leak when what leaked is the account you ran as.
# It cannot tell the two apart, and a probe that cannot test should skip rather
# than answer vacuously -- the same rule that moved existence checks out to
# oxbox. Everything else in EXISTING lives under the real home, which the jail
# never binds in at all: absence blocks those, not permissions, so they stay
# meaningful at any uid.
IS_ROOT = getattr(os, "geteuid", lambda: -1)() == 0
DAC_DEPENDENT = ("/etc/shadow",)

results = []
skipped = []


def label_for(path):
    if REAL_HOME and path.startswith(REAL_HOME + os.sep):
        return "~/" + os.path.relpath(path, REAL_HOME)
    return path


def probe(name, fn, expect_blocked=True):
    try:
        fn()
        blocked, detail = False, "succeeded"
    except Exception as error:  # noqa: BLE001 - any denial counts as containment
        blocked, detail = True, type(error).__name__
    results.append((blocked if expect_blocked else not blocked, name, detail))


def read_probe(path):
    def action():
        if os.path.isdir(path):
            os.listdir(path)
        else:
            with open(path, "rb") as handle:
                handle.read(1)
    return action


def write_probe(path):
    def action():
        with open(path, "w") as handle:
            handle.write("jail breach")
    return action


# `with` rather than a trailing close(): inside the jail these calls are
# *expected* to raise, so the close was the one line that never ran on the
# path this file exists to exercise.
def tcp_connect():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(5)
        sock.connect(("1.1.1.1", 443))


def dns_lookup():
    socket.getaddrinfo("example.com", 443)


def udp_send():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(5)
        sock.sendto(b"\x00", ("1.1.1.1", 53))


def stat_outside(path):
    def action():
        os.stat(path)
    return action


def env_canary():
    """The launching shell frequently holds provider keys (via `op run`).
    Anything visible here means the parent environment crossed the boundary.

    Every venue in ox's VENUES table contributes a variable here. A key that ox
    can send is a key the jail must not see, so the two lists move together."""
    leaked = [name for name in
              ("OXBOX_CANARY", "OP_SERVICE_ACCOUNT_TOKEN",
               "OPENROUTER_API_KEY", "ZENMUX_API_KEY",
               "OPENCODE_ZEN_API_KEY", "REQUESTY_API_KEY")
              if os.environ.get(name)]
    if leaked:
        raise AssertionError("inherited: " + ", ".join(leaked))


def write_inside():
    with open(os.path.join(WORK, "jailtest-ok.txt"), "w") as handle:
        handle.write("expected")


def read_inside():
    with open(os.path.join(WORK, "jailtest-ok.txt"), "rb") as handle:
        handle.read()


if HOST_HAS_ROUTE:
    probe("network: outbound TCP to 1.1.1.1:443", tcp_connect)
    probe("network: DNS resolution", dns_lookup)
    probe("network: outbound UDP", udp_send)
else:
    skipped.append("network probes (the host has no route out, so a blocked "
                   "connect and an unreachable network are indistinguishable "
                   "from in here; rerun online)")

if EXISTING:
    for path in EXISTING:
        if IS_ROOT and path in DAC_DEPENDENT:
            skipped.append(
                f"fs read: {label_for(path)} (uid 0 bypasses the file "
                "permissions this probe tests; rerun as an ordinary user)")
            continue
        probe(f"fs read: {label_for(path)}", read_probe(path))
    # The oracle needs a path the jail hides by absence or denial, never one
    # that file permissions protect. stat() on /etc/shadow needs only search
    # permission on /etc, which every uid has, and /etc is inside the jail on
    # both backends -- so on a host where nothing under the real home exists
    # (a CI runner is one), the first entry is /etc/shadow, the stat succeeds,
    # and a jail that holds is reported as leaking. Found by a baseline run on
    # 2026-09-02; ubuntu-latest was one missing ~/.docker/config.json away.
    oracle = next((p for p in EXISTING if p not in DAC_DEPENDENT), None)
    if oracle:
        probe(f"fs metadata: stat {label_for(oracle)} (oracle)", stat_outside(oracle))
    else:
        skipped.append("fs metadata oracle (every sensitive path present is "
                       "permission-protected; stat() on those succeeds at any "
                       "uid and proves nothing about the jail)")
else:
    skipped.append("fs reads (oxbox reported no sensitive paths present)")

# Escape-WRITE verification deliberately does not live here; see guardtest.py.
#
# From inside the jail the two backends disagree in a way that makes the result
# meaningless. seatbelt denies the open() outright, so a write to ~/ESCAPED.txt
# raises. bubblewrap instead materializes the work dir's parent directories as
# ephemeral tmpfs, so the same write SUCCEEDS -- into a throwaway layer the host
# never sees. Judged from in here, identical containment looks like a pass on
# macOS and a failure on Linux.
#
# The property that actually matters is "the host filesystem outside the work
# dir is unchanged", and only something running outside the jail can check that.
# guardtest.py does exactly that, and is decisive on both platforms.

probe("env: parent environment not inherited", env_canary, expect_blocked=False)
probe("fs write: inside work dir", write_inside, expect_blocked=False)
probe("fs read: inside work dir", read_inside, expect_blocked=False)

width = max(len(name) for _, name, _ in results)
failed = 0
for ok, name, detail in results:
    status = "PASS" if ok else "FAIL"
    if not ok:
        failed += 1
    print(f"[{status}] {name.ljust(width)}  ({detail})")

for note in skipped:
    print(f"[SKIP] {note}")

print()
print(f"platform: {PLATFORM}")
if failed:
    print(f"JAIL LEAKS: {failed} of {len(results)} probes failed")
    sys.exit(1)
print(f"jail holds: {len(results)}/{len(results)} probes passed, {len(skipped)} skipped")
