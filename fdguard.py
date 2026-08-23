# SPDX-FileCopyrightText: 2026 Curtis Galloway
# SPDX-License-Identifier: Apache-2.0
"""Report whether stdout/stderr point at regular files outside the sandbox.

Seatbelt gates open(), not writes to an already-open descriptor. So
`oxbox -- cmd > ~/notes.md` hands jailed code a writable handle to ~/notes.md:
the shell opened it before the jail existed. The path is the operator's choice,
but the bytes are the model's, which makes "no writes outside the sandbox"
false unless we check.

Run BEFORE entering the jail, inheriting oxbox's own descriptors. Findings go
to a file named on the command line -- capturing stdout would replace the very
descriptor being inspected.

    python3 fdguard.py <sandbox_root> <report_path>

Exit 0 = clean, 3 = at least one descriptor escapes, 1 = usage error.
"""

import fcntl
import os
import stat
import sys

F_GETPATH = 50  # macOS fcntl: resolve a descriptor back to a path


def target_of(fd):
    """Absolute path a descriptor points at, or None if it isn't a regular file."""
    try:
        info = os.fstat(fd)
    except OSError:
        return None
    # Pipes, ttys and /dev/null cannot be written to a location of the
    # attacker's choosing, and a pipe's far end is the operator's business.
    if not stat.S_ISREG(info.st_mode):
        return None
    try:
        raw = fcntl.fcntl(fd, F_GETPATH, b"\0" * 1024)
    except OSError:
        return None
    path = raw.split(b"\0")[0].decode("utf-8", "replace")
    return os.path.realpath(path) if path else None


def main():
    if len(sys.argv) != 3:
        sys.stderr.write("usage: fdguard.py <sandbox_root> <report_path>\n")
        return 1

    root = os.path.realpath(sys.argv[1])
    report_path = sys.argv[2]

    escaping = []
    for fd, name in ((1, "stdout"), (2, "stderr")):
        target = target_of(fd)
        if target is None:
            continue
        if target != root and not target.startswith(root + os.sep):
            escaping.append(f"{name} -> {target}")

    with open(report_path, "w", encoding="utf-8") as handle:
        handle.write("\n".join(escaping))

    return 3 if escaping else 0


if __name__ == "__main__":
    sys.exit(main())
