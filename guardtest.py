# SPDX-FileCopyrightText: 2026 Curtis Galloway
# SPDX-License-Identifier: Apache-2.0
"""Exercise the containment checks that run OUTSIDE the jail.

jailtest.py cannot reach these: argument validation, patch validation, the
secret scanner, and the inherited-descriptor guard all run before the sandbox
exists. Every case corresponds to a defect that was actually found and
reproduced -- these are regression tests, not hypotheticals.

    python3 guardtest.py

NOTE: re-seeds sandbox/work. Run ./oxseed --clean afterwards if you care.
"""

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
SANDBOX = HERE / "sandbox"
WORK = SANDBOX / "work"

# Invoke via the interpreter rather than the shebang: Windows does not honour
# shebang lines, and these tools must be testable there too.
OX = [sys.executable, str(HERE / "ox")]
OXBOX = [sys.executable, str(HERE / "oxbox")]
OXSEED = [sys.executable, str(HERE / "oxseed")]
OXAPPLY = [sys.executable, str(HERE / "oxapply")]

passed = 0
failed = 0
skipped = 0


def report(ok, label, note=""):
    global passed, failed
    if ok:
        passed += 1
        print(f"[PASS] {label}")
    else:
        failed += 1
        print(f"[FAIL] {label}{(' - ' + note) if note else ''}")


def skip(label, why):
    global skipped
    skipped += 1
    print(f"[SKIP] {label} ({why})")


def run(argv, stdout=None):
    """Run a command with output discarded by default.

    Output must NOT go to a regular file outside the sandbox: oxbox's own
    inherited-descriptor guard would refuse it and every oxbox case would fail
    for the wrong reason. os.devnull is a character device, so the guard ignores
    it. This bit the first version of this suite.
    """
    if stdout is None:
        with open(os.devnull, "w") as sink:
            return subprocess.run(argv, stdout=sink, stderr=sink).returncode
    return subprocess.run(argv, stdout=stdout, stderr=subprocess.STDOUT).returncode


def expect_refused(label, argv):
    report(run(argv) != 0, label, "command succeeded; it should have refused")


def expect_allowed(label, argv):
    report(run(argv) == 0, label, "refused; it should have been allowed")


def main():
    # The tools anchor sandbox/ and logs/ at their working directory, and this
    # suite's expectations are all HERE-relative — so stand in the repo root
    # regardless of where the suite was invoked from.
    os.chdir(HERE)
    temp = Path(tempfile.mkdtemp(prefix="oxbox-guardtest"))
    source = temp / "src"
    source.mkdir()
    (source / "mod.py").write_text("def f():\n    return 1\n", encoding="utf-8")

    jail_supported = sys.platform in ("darwin", "linux")

    print("=== seed guards ===")
    expect_refused("oxseed refuses parent traversal",
                   OXSEED + [str(source), "../../../etc/hosts"])
    expect_refused("oxseed refuses absolute path",
                   OXSEED + [str(source), "/etc/hosts"])
    # Windows-shaped roots. Path.is_absolute() returns False for "/etc/hosts"
    # on Windows (root but no drive), so these need textual checks and are
    # worth asserting on every platform, not just win32.
    expect_refused("oxseed refuses a drive-letter path",
                   OXSEED + [str(source), "C:/Windows/System32/drivers/etc/hosts"])
    expect_refused("oxseed refuses a UNC path",
                   OXSEED + [str(source), "\\\\server\\share\\payload"])
    expect_refused("oxseed refuses backslash traversal",
                   OXSEED + [str(source), "..\\..\\payload"])
    expect_allowed("oxseed accepts a normal file",
                   OXSEED + [str(source), "mod.py"])

    print("\n=== jail argument guards ===")
    if jail_supported:
        expect_refused("oxbox refuses --work outside sandbox/",
                       OXBOX + ["--work", str(HERE), "--", "python3", "-c", "pass"])
        expect_allowed("oxbox runs with the default work dir",
                       OXBOX + ["--", sys.executable, "-c", "pass"])
    else:
        expect_refused("oxbox refuses to run without a sandbox backend",
                       OXBOX + ["--", sys.executable, "-c", "pass"])
        skip("oxbox --work confinement", f"no jail backend on {sys.platform}")

    print("\n=== inherited descriptor guard ===")
    if jail_supported:
        outside = temp / "outside.txt"
        with open(outside, "w") as handle:
            code = run(OXBOX + ["--", sys.executable, "-c", "pass"], stdout=handle)
        report(code != 0, "oxbox refuses stdout redirected outside the sandbox")

        WORK.mkdir(parents=True, exist_ok=True)
        with open(WORK / "inside.txt", "w") as handle:
            code = run(OXBOX + ["--", sys.executable, "-c", "pass"], stdout=handle)
        report(code == 0, "oxbox allows stdout redirected inside the sandbox")

        with open(temp / "optin.txt", "w") as handle:
            code = run(OXBOX + ["--allow-external-output", "--",
                                sys.executable, "-c", "pass"], stdout=handle)
        report(code == 0, "oxbox honours --allow-external-output")
    else:
        skip("inherited descriptor guard", f"no jail backend on {sys.platform}")

    print("\n=== escape verification (host filesystem) ===")
    if jail_supported:
        canaries = [HERE / "ESCAPED-guardtest.txt",
                    Path.home() / "ESCAPED-guardtest.txt"]
        for canary in canaries:
            if canary.exists():
                canary.unlink()

        # Proof of execution. Without it this whole section passes vacuously if
        # oxbox fails to start: no canary appears, every assertion holds, and
        # the suite reports containment it never actually exercised.
        WORK.mkdir(parents=True, exist_ok=True)
        marker = WORK / "escape-attempt-ran.txt"
        if marker.exists():
            marker.unlink()

        targets = ", ".join(repr(str(c)) for c in canaries)
        run(OXBOX + ["--", sys.executable, "-c",
                     f"open({str(marker)!r}, 'w').write('ran')\n"
                     f"for p in [{targets}]:\n"
                     "    try:\n"
                     "        open(p, 'w').write('breach')\n"
                     "    except Exception:\n"
                     "        pass\n"])

        report(marker.exists(), "escape attempt actually executed in the jail",
               "jailed command never ran; the checks below would be vacuous")

        # The write may well have "succeeded" inside the sandbox -- on Linux it
        # lands in tmpfs. What matters is whether it reached the host.
        for canary in canaries:
            escaped = canary.exists()
            report(not escaped, f"host unchanged: {canary}",
                   "file was created on the host")
            if escaped:
                canary.unlink()
    else:
        skip("escape verification", f"no jail backend on {sys.platform}")

    print("\n=== patch guards ===")
    (temp / "rename.patch").write_text(
        "diff --git a/mod.py b/../../../../tmp/pwned\n"
        "similarity index 100%\n"
        "rename from mod.py\n"
        "rename to ../../../../tmp/pwned\n", encoding="utf-8")
    expect_refused("oxapply refuses traversal in rename headers",
                   OXAPPLY + ["--diff", str(temp / "rename.patch")])

    (temp / "symlink.patch").write_text(
        "diff --git a/leak b/leak\n"
        "new file mode 120000\n"
        "--- /dev/null\n"
        "+++ b/leak\n"
        "@@ -0,0 +1 @@\n"
        "+/etc/passwd\n", encoding="utf-8")
    expect_refused("oxapply refuses symlink-creating patches",
                   OXAPPLY + ["--diff", str(temp / "symlink.patch")])

    (temp / "absolute.patch").write_text(
        "--- a/etc/passwd\n"
        "+++ b//etc/passwd\n"
        "@@ -1 +1 @@\n"
        "-x\n"
        "+y\n", encoding="utf-8")
    expect_refused("oxapply refuses absolute paths",
                   OXAPPLY + ["--diff", str(temp / "absolute.patch")])

    (temp / "drive.patch").write_text(
        "--- a/mod.py\n"
        "+++ b/C:/Windows/System32/drivers/etc/hosts\n"
        "@@ -1 +1 @@\n"
        "-x\n"
        "+y\n", encoding="utf-8")
    expect_refused("oxapply refuses drive-letter paths",
                   OXAPPLY + ["--diff", str(temp / "drive.patch")])

    print("\n=== patch application (positive control) ===")
    # Refusal tests alone are not enough: a validator that rejects everything
    # passes all of them. This asserts a good patch still lands, and is written
    # in the platform's native text mode on purpose, so a CRLF patch file on
    # Windows is exercised the way a real one would be. That is precisely the
    # bug this section was added for -- oxapply wrote its temp patch in text
    # mode, turning LF into CRLF on Windows, and git rejected every patch with
    # an error that looked like a malformed diff.
    run(OXSEED + [str(source), "mod.py"])
    valid = temp / "valid.patch"
    valid.write_text(
        "--- a/mod.py\n"
        "+++ b/mod.py\n"
        "@@ -1,2 +1,2 @@\n"
        " def f():\n"
        "-    return 1\n"
        "+    return 2\n", encoding="utf-8")
    code = run(OXAPPLY + ["--diff", str(valid)])
    landed = False
    try:
        landed = "return 2" in (WORK / "mod.py").read_text(encoding="utf-8")
    except OSError:
        pass
    report(code == 0 and landed, "oxapply applies a valid patch",
           f"exit={code} landed={landed}")

    print("\n=== secret scanner ===")
    expect_refused("ox refuses a key in the task argument",
                   OX + ["--dry-run", "--mode", "ask",
                         "my key is sk-abcdefghijklmnopqrstuvwxyz012345"])
    creds = temp / "creds.txt"
    creds.write_text("AKIAIOSFODNN7EXAMPLE\n", encoding="utf-8")
    expect_refused("ox refuses a key in a --files body",
                   OX + ["--dry-run", "--mode", "ask", "--files", str(creds),
                         "explain this"])
    expect_allowed("ox accepts an ordinary prompt",
                   OX + ["--dry-run", "--mode", "ask",
                         "explain what a unified diff is"])

    print("\n=== --skill ===")
    # --skill answers a question about the installation, not about a run, so
    # it must not open one. The hazard is ordering: move the handler below
    # the status/log setup in ox and --skill starts leaving audit artifacts
    # for a request that was never built, which is a lie in the audit trail.
    # Naming both destinations here means the case fails if that happens.
    skill_out = temp / "skill.md"
    skill_logs = temp / "skill-logs"
    skill_status = temp / "skill-status.json"
    with open(skill_out, "w", encoding="utf-8") as sink:
        code = subprocess.run(OX + ["--skill", "--log-dir", str(skill_logs),
                                    "--status-file", str(skill_status)],
                              stdout=sink, stderr=subprocess.DEVNULL).returncode
    text = skill_out.read_text(encoding="utf-8") if skill_out.exists() else ""
    report(code == 0 and text.startswith("---") and "name: ox-review" in text,
           "ox --skill prints the runbook", f"exit={code} bytes={len(text)}")
    # The printed copy has to name scripts where this ox found them, or the
    # commands an agent reads are commands it cannot run.
    report(str(HERE / ".claude" / "skills" / "ox-review") in text,
           "ox --skill rewrites the script paths to this installation")
    report(not skill_logs.exists() and not skill_status.exists(),
           "ox --skill opens no run: no log directory, no status record",
           f"logs={skill_logs.exists()} status={skill_status.exists()}")

    # oxseed's rule is that it validates everything before destroying
    # anything, and --skill destroys nothing at all: it answers a question
    # about the installation. The hazard is ordering again — put the handler
    # after the --clean branch or the seeding path and asking for the runbook
    # wipes the sandbox you were working in.
    marker = WORK / "skill-canary.txt"
    marker.write_text("still here\n", encoding="utf-8")
    code = run(OXSEED + ["--skill"])
    survived = marker.is_file()
    report(code == 0 and survived, "oxseed --skill destroys nothing",
           f"exit={code} sandbox_intact={survived}")

    shutil.rmtree(temp, ignore_errors=True)

    print()
    print(f"platform: {sys.platform}")
    if failed:
        print(f"GUARDS LEAK: {passed} passed, {failed} FAILED, {skipped} skipped")
        return 1
    print(f"guards hold: {passed}/{passed} passed, {skipped} skipped")
    return 0


if __name__ == "__main__":
    sys.exit(main())
