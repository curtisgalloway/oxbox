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

    # os.walk does not descend into a symlinked directory, so one never shows
    # up in its `files` list -- while copytree(symlinks=False) dereferences it
    # and copies the target in. The link in an intermediate component is the
    # same hole reached a different way: the named path is then neither a
    # symlink nor a directory, so every per-path check passes and copy2 reads
    # straight through. Both put outside content inside the work tree.
    linked = temp / "linksrc"
    (linked / "pkg").mkdir(parents=True)
    # Deliberately a SIBLING of the source root, not a child: a link pointing
    # somewhere still inside the tree is not an escape, and containment is
    # right to allow it.
    beyond = temp / "beyond"
    beyond.mkdir()
    (beyond / "key.txt").write_text("SECRET\n", encoding="utf-8")
    (linked / "mod.py").write_text("def f():\n    return 1\n", encoding="utf-8")
    try:
        os.symlink(str(beyond), str(linked / "pkg" / "link"),
                   target_is_directory=True)
        os.symlink(str(beyond), str(linked / "gate"),
                   target_is_directory=True)
        symlinks_available = True
    except (OSError, NotImplementedError, AttributeError):
        # Windows needs Developer Mode or admin to create one at all.
        symlinks_available = False
    if symlinks_available:
        expect_refused("oxseed refuses a symlinked directory inside a tree",
                       OXSEED + [str(linked), "pkg"])
        expect_refused("oxseed refuses a symlink in an intermediate component",
                       OXSEED + [str(linked), "gate/key.txt"])
        expect_allowed("oxseed still accepts a tree with no links in it",
                       OXSEED + [str(linked), "mod.py"])
    else:
        skip("oxseed symlink containment", "cannot create symlinks here")

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

    # oxapply promises in its docstring that it "Never touches a real
    # repository", and for a long time nothing enforced it: any directory with
    # a .git in it was accepted. unsafe_paths cannot cover this -- it
    # constrains where a patch writes *relative to* the work dir and says
    # nothing about where that is. Unlike the oxbox case above this needs no
    # jail backend, so it is the one --work confinement check that also runs
    # on Windows.
    # A *real* repo holding a file the patch would cleanly apply to. An empty
    # .git directory is not enough: git apply would fail on its own and the
    # case would pass without the containment check existing at all.
    real = temp / "realrepo"
    real.mkdir()
    (real / "mod.py").write_text("def f():\n    return 1\n", encoding="utf-8")
    git_ready = True
    for argv in (["git", "init", "-q", str(real)],
                 ["git", "-C", str(real), "add", "-A"],
                 ["git", "-C", str(real), "-c", "user.email=g@t.invalid",
                  "-c", "user.name=guardtest", "commit", "-qm", "init"]):
        if run(argv) != 0:
            git_ready = False
            break
    (temp / "harmless.patch").write_text(
        "--- a/mod.py\n"
        "+++ b/mod.py\n"
        "@@ -1,2 +1,2 @@\n"
        " def f():\n"
        "-    return 1\n"
        "+    return 2\n", encoding="utf-8")
    if git_ready:
        code = run(OXAPPLY + ["--diff", str(temp / "harmless.patch"),
                              "--work", str(real)])
        # Exit code alone would not prove much; what matters is that the real
        # tree was left alone.
        untouched = (real / "mod.py").read_text(encoding="utf-8") == \
            "def f():\n    return 1\n"
        report(code != 0 and untouched,
               "oxapply refuses --work outside sandbox/",
               f"exit={code} untouched={untouched}")
    else:
        skip("oxapply --work confinement", "git unavailable for the fixture")

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
    # "_" is a word character, so the old \bsecret\b never matched inside
    # client_secret -- and the value half demanded quotes that .env files and
    # shell exports do not write. Both shapes reached the provider unflagged.
    underscored = temp / "underscored.txt"
    underscored.write_text('client_secret = "wJalrXUtnFEMIK7MDENGbPxRfiCY"\n',
                           encoding="utf-8")
    expect_refused("ox refuses an underscore-prefixed credential name",
                   OX + ["--dry-run", "--mode", "ask", "--files",
                         str(underscored), "explain this"])
    unquoted = temp / "unquoted.env"
    unquoted.write_text("DB_PASSWORD=supersecretvalue12345\n", encoding="utf-8")
    expect_refused("ox refuses an unquoted credential value",
                   OX + ["--dry-run", "--mode", "ask", "--files",
                         str(unquoted), "explain this"])
    # The counterweight: a scanner that refuses everything passes every case
    # above. max_tokens contains "token" and must not trip it, or ox cannot
    # read its own source.
    tokens = temp / "tokens.py"
    tokens.write_text("max_tokens = DEFAULT_MAX_TOKENS\n"
                      "completion_tokens = usage.get(\"completion_tokens\")\n",
                      encoding="utf-8")
    expect_allowed("ox does not mistake max_tokens for a credential",
                   OX + ["--dry-run", "--mode", "ask", "--files",
                         str(tokens), "explain this"])
    expect_allowed("ox accepts an ordinary prompt",
                   OX + ["--dry-run", "--mode", "ask",
                         "explain what a unified diff is"])

    print("\n=== exposure gate (the check that decides if code may leave) ===")
    # The gate is a containment check like the rest of this file, just one
    # layer earlier: it decides whether anything is sent at all. Its worst
    # failure is a false "public", and unchecked redirects were a route to
    # one -- a host answering /info/refs with a 302 to any public repo's ref
    # advertisement made a private repo read as world-clonable, while the
    # report still named the original host.
    gate = HERE / ".claude" / "skills" / "ox-review" / "scripts" / "exposure.py"
    if not gate.is_file():
        skip("exposure gate redirect containment", "skill scripts not in this tree")
    else:
        import http.server
        import importlib.util
        import threading

        spec = importlib.util.spec_from_file_location("exposure_under_test", gate)
        exposure = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(exposure)

        advert = b"001e# service=git-upload-pack\n0000"

        def send_advert(handler):
            handler.send_response(200)
            handler.send_header(
                "Content-Type", "application/x-git-upload-pack-advertisement")
            handler.send_header("Content-Length", str(len(advert)))
            handler.end_headers()
            handler.wfile.write(advert)

        def serve(handler_class):
            server = http.server.HTTPServer(("127.0.0.1", 0), handler_class)
            threading.Thread(target=server.serve_forever, daemon=True).start()
            servers.append(server)
            return server.server_address[1]

        servers = []

        class Advertiser(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                send_advert(self)

            def log_message(self, *args):
                pass

        class Renamed(http.server.BaseHTTPRequestHandler):
            """A same-host redirect, the ordinary case that must keep working."""

            def do_GET(self):
                if self.path.startswith("/old"):
                    self.send_response(301)
                    self.send_header("Location", "/new")
                    self.end_headers()
                    return
                send_advert(self)

            def log_message(self, *args):
                pass

        try:
            elsewhere = serve(Advertiser)

            class Offsite(http.server.BaseHTTPRequestHandler):
                def do_GET(self):
                    self.send_response(302)
                    self.send_header(
                        "Location", "http://127.0.0.1:%d/elsewhere" % elsewhere)
                    self.end_headers()

                def log_message(self, *args):
                    pass

            offsite = serve(Offsite)
            renamed = serve(Renamed)

            status, detail, _body, _final = exposure.fetch(
                "http://127.0.0.1:%d/acme/secret/info/refs" % offsite, accept="*/*")
            report(status is None and "another host" in (detail or ""),
                   "exposure refuses a redirect to another host",
                   "status=%r detail=%r" % (status, detail))

            status, _ct, body, final = exposure.fetch(
                "http://127.0.0.1:%d/old" % renamed, accept="*/*")
            report(status == 200 and body == advert and final.endswith("/new"),
                   "exposure still follows a same-host redirect",
                   "status=%r final=%r" % (status, final))
        finally:
            for server in servers:
                server.shutdown()

        # The note asserts "the code is publicly readable". Emitting it before
        # the verdict was consulted meant a private repo got a report saying it
        # was not publicly readable and, two lines later, that it was.
        saved = (exposure.probe_provider_api, exposure.probe_anonymous_clone)
        try:
            exposure.probe_provider_api = lambda h, o, n: {
                "reachable": True, "private": True, "license": None,
                "archived": False}
            exposure.probe_anonymous_clone = lambda h, o, n: {
                "ok": False, "detail": "HTTP 404", "url": "x"}
            verdict = exposure.assess_remote(
                "origin", "https://github.com/acme/private.git")
            contradictory = [n for n in verdict["notes"] if "publicly readable" in n]
            report(verdict["verdict"] == "not-public" and not contradictory,
                   "exposure does not call a private repo publicly readable",
                   "verdict=%s notes=%r" % (verdict["verdict"], verdict["notes"]))
        finally:
            exposure.probe_provider_api, exposure.probe_anonymous_clone = saved

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
    raw = skill_out.read_bytes() if skill_out.exists() else b""
    # The runbook is UTF-8 with LF endings on disk and has to arrive that way
    # whatever the host's locale codepage is. Windows text-mode stdout used to
    # re-encode it -- cp1252 renders SKILL.md's em dashes as 0x97 -- and turn
    # every newline into CRLF, so `--skill > runbook.md` there wrote a file no
    # UTF-8 reader could open. Assert the bytes rather than just decoding them:
    # a decode that raises reports this as a traceback, and a traceback is a
    # worse failure report than a red line naming the contract that broke.
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        text = ""
    report(bool(raw) and b"\r\n" not in raw and "—" in text,
           "ox --skill emits UTF-8 with LF endings",
           "bytes=%d crlf=%s decoded=%s" % (len(raw), b"\r\n" in raw, bool(text)))
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
