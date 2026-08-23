# SPDX-FileCopyrightText: 2026 Curtis Galloway
# SPDX-License-Identifier: Apache-2.0
"""Self-test for the seatbelt jail. Run it INSIDE the jail:

    ./oxbox -- python3 jailtest.py

Every probe asserts a containment property. Anything reported FAIL means the
jail leaks, and model-generated code must not be run in it.

`oxbox` passes REAL_HOME and REPO_ROOT so the probes can aim at paths that
actually exist on this machine rather than hardcoded ones.
"""

import os
import socket
import sys

WORK = os.environ.get("HOME", "")
REAL_HOME = os.environ.get("REAL_HOME", "")
REPO_ROOT = os.environ.get("REPO_ROOT", "")

results = []
skipped = []


def probe(name, fn, expect_blocked=True):
    try:
        fn()
        blocked = False
        detail = "succeeded"
    except Exception as error:  # noqa: BLE001 - any denial counts as containment
        blocked = True
        detail = type(error).__name__

    results.append((blocked if expect_blocked else not blocked, name, detail))


EXISTING = {line for line in os.environ.get("OXBOX_EXISTING_PATHS", "").splitlines() if line}


def probe_path(name, path, mode="read"):
    """Probe a path only if it exists outside the jail; otherwise skip honestly.

    Existence comes from OXBOX_EXISTING_PATHS, computed by oxbox before the jail
    starts. Checking it in here would be worse than useless: stat() is denied,
    so every hidden path would look absent and the probe would skip instead of
    testing -- passing by not looking.
    """
    if not path:
        skipped.append(f"{name} (path not supplied)")
        return
    if mode == "read" and path not in EXISTING:
        skipped.append(f"{name} (does not exist on this host)")
        return

    if mode == "read":
        def action():
            if os.path.isdir(path):
                os.listdir(path)
            else:
                with open(path, "rb") as handle:
                    handle.read(1)
    else:
        def action():
            with open(path, "w") as handle:
                handle.write("jail breach")

    probe(name, action)


def tcp_connect():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    sock.connect(("1.1.1.1", 443))
    sock.close()


def dns_lookup():
    socket.getaddrinfo("example.com", 443)


def udp_send():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5)
    sock.sendto(b"\x00", ("1.1.1.1", 53))
    sock.close()


def write_inside():
    with open(os.path.join(WORK, "jailtest-ok.txt"), "w") as handle:
        handle.write("expected")


def read_inside():
    with open(os.path.join(WORK, "jailtest-ok.txt"), "rb") as handle:
        handle.read()


probe("network: outbound TCP to 1.1.1.1:443", tcp_connect)
probe("network: DNS resolution", dns_lookup)
probe("network: outbound UDP", udp_send)

probe_path("fs read: ~/.ssh", os.path.join(REAL_HOME, ".ssh") if REAL_HOME else "")
probe_path("fs read: ~/.aws", os.path.join(REAL_HOME, ".aws") if REAL_HOME else "")
probe_path("fs read: ~/.claude", os.path.join(REAL_HOME, ".claude") if REAL_HOME else "")
probe_path("fs read: ~/.zsh_history",
           os.path.join(REAL_HOME, ".zsh_history") if REAL_HOME else "")
probe_path("fs read: ~/Library/Keychains",
           os.path.join(REAL_HOME, "Library", "Keychains") if REAL_HOME else "")
probe_path("fs read: repo .env", os.path.join(REPO_ROOT, ".env") if REPO_ROOT else "")

probe_path("fs write: repo root (escape)",
           os.path.join(REPO_ROOT, "ESCAPED.txt") if REPO_ROOT else "", mode="write")
probe_path("fs write: home dir (escape)",
           os.path.join(REAL_HOME, "ESCAPED.txt") if REAL_HOME else "", mode="write")

def stat_outside():
    os.stat(os.path.join(REAL_HOME, ".ssh"))


def env_canary():
    """The launching shell frequently holds OPENROUTER_API_KEY (via `op run`).
    If a canary set outside the jail is visible here, the parent environment
    crossed the boundary and any secret in it is readable by jailed code."""
    leaked = [name for name in
              ("OXBOX_CANARY", "OPENROUTER_API_KEY", "OP_SERVICE_ACCOUNT_TOKEN")
              if os.environ.get(name)]
    if leaked:
        raise AssertionError("inherited: " + ", ".join(leaked))


if REAL_HOME and os.path.join(REAL_HOME, ".ssh") in EXISTING:
    probe("fs metadata: stat ~/.ssh (oracle)", stat_outside)
else:
    skipped.append("fs metadata: stat ~/.ssh (does not exist on this host)")

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
if failed:
    print(f"JAIL LEAKS: {failed} of {len(results)} probes failed")
    sys.exit(1)
print(f"jail holds: {len(results)}/{len(results)} probes passed, {len(skipped)} skipped")
