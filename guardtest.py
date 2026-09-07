# SPDX-FileCopyrightText: 2026 Curtis Galloway
# SPDX-License-Identifier: Apache-2.0
"""Exercise the containment checks that run OUTSIDE the jail.

jailtest.py cannot reach these: argument validation, patch validation, the
secret scanner, and the inherited-descriptor guard all run before the sandbox
exists. Every case corresponds to a defect that was actually found and
reproduced -- these are regression tests, not hypotheticals.

    python3 guardtest.py

NOTE: re-seeds sandbox/work. Run ./oxbox sandbox --destroy afterwards if you care.
"""

import os
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
SANDBOX = HERE / "sandbox"
WORK = SANDBOX / "work"

# Two implementations, one suite. By default this drives the Python scripts
# in the checkout, via the interpreter rather than the shebang (Windows does
# not honor shebang lines). With OXBOX_UNDER_TEST naming a directory of built
# executables -- a Cargo target dir, an unpacked package -- it drives those
# instead, unchanged: the suite is the acceptance test for the port.
UNDER_TEST = os.environ.get("OXBOX_UNDER_TEST")


def tool_path(name):
    if UNDER_TEST:
        return Path(UNDER_TEST) / (name + (".exe" if sys.platform == "win32" else ""))
    return HERE / name


def tool_argv(name):
    """argv prefix that runs the named tool, in whichever implementation."""
    return [str(tool_path(name))] if UNDER_TEST else [sys.executable, str(tool_path(name))]


OX = tool_argv("oxbox-send")
# The front door: jail cases go through it, the way a user's do.
OXBOX = tool_argv("oxbox")
OXSANDBOX = tool_argv("oxbox-sandbox")
OXAPPLY = tool_argv("oxbox-patch")

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
    expect_refused("oxbox-sandbox refuses parent traversal",
                   OXSANDBOX + ["--create", str(source), "../../../etc/hosts"])
    expect_refused("oxbox-sandbox refuses absolute path",
                   OXSANDBOX + ["--create", str(source), "/etc/hosts"])
    # Windows-shaped roots. Path.is_absolute() returns False for "/etc/hosts"
    # on Windows (root but no drive), so these need textual checks and are
    # worth asserting on every platform, not just win32.
    expect_refused("oxbox-sandbox refuses a drive-letter path",
                   OXSANDBOX + ["--create", str(source), "C:/Windows/System32/drivers/etc/hosts"])
    expect_refused("oxbox-sandbox refuses a UNC path",
                   OXSANDBOX + ["--create", str(source), "\\\\server\\share\\payload"])
    expect_refused("oxbox-sandbox refuses backslash traversal",
                   OXSANDBOX + ["--create", str(source), "..\\..\\payload"])
    expect_allowed("oxbox-sandbox accepts a normal file",
                   OXSANDBOX + ["--create", str(source), "mod.py"])

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
        expect_refused("oxbox-sandbox refuses a symlinked directory inside a tree",
                       OXSANDBOX + ["--create", str(linked), "pkg"])
        expect_refused("oxbox-sandbox refuses a symlink in an intermediate component",
                       OXSANDBOX + ["--create", str(linked), "gate/key.txt"])
        expect_allowed("oxbox-sandbox still accepts a tree with no links in it",
                       OXSANDBOX + ["--create", str(linked), "mod.py"])
    else:
        skip("oxbox-sandbox symlink containment", "cannot create symlinks here")

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
        report(code == 0, "oxbox honors --allow-external-output")
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
    expect_refused("oxbox-patch refuses traversal in rename headers",
                   OXAPPLY + ["--diff", str(temp / "rename.patch")])

    (temp / "symlink.patch").write_text(
        "diff --git a/leak b/leak\n"
        "new file mode 120000\n"
        "--- /dev/null\n"
        "+++ b/leak\n"
        "@@ -0,0 +1 @@\n"
        "+/etc/passwd\n", encoding="utf-8")
    expect_refused("oxbox-patch refuses symlink-creating patches",
                   OXAPPLY + ["--diff", str(temp / "symlink.patch")])

    (temp / "absolute.patch").write_text(
        "--- a/etc/passwd\n"
        "+++ b//etc/passwd\n"
        "@@ -1 +1 @@\n"
        "-x\n"
        "+y\n", encoding="utf-8")
    expect_refused("oxbox-patch refuses absolute paths",
                   OXAPPLY + ["--diff", str(temp / "absolute.patch")])

    (temp / "drive.patch").write_text(
        "--- a/mod.py\n"
        "+++ b/C:/Windows/System32/drivers/etc/hosts\n"
        "@@ -1 +1 @@\n"
        "-x\n"
        "+y\n", encoding="utf-8")
    expect_refused("oxbox-patch refuses drive-letter paths",
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
               "oxbox-patch refuses --work outside sandbox/",
               f"exit={code} untouched={untouched}")
    else:
        skip("oxbox-patch --work confinement", "git unavailable for the fixture")

    print("\n=== patch application (positive control) ===")
    # Refusal tests alone are not enough: a validator that rejects everything
    # passes all of them. This asserts a good patch still lands, and is written
    # in the platform's native text mode on purpose, so a CRLF patch file on
    # Windows is exercised the way a real one would be. That is precisely the
    # bug this section was added for -- oxapply wrote its temp patch in text
    # mode, turning LF into CRLF on Windows, and git rejected every patch with
    # an error that looked like a malformed diff.
    run(OXSANDBOX + ["--create", str(source), "mod.py"])
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
    report(code == 0 and landed, "oxbox-patch applies a valid patch",
           f"exit={code} landed={landed}")

    print("\n=== secret scanner ===")
    expect_refused("oxbox-send refuses a key in the task argument",
                   OX + ["--dry-run", "--model", "test-model", "--mode", "ask",
                         "my key is sk-abcdefghijklmnopqrstuvwxyz012345"])
    creds = temp / "creds.txt"
    creds.write_text("AKIAIOSFODNN7EXAMPLE\n", encoding="utf-8")
    expect_refused("oxbox-send refuses a key in a --files body",
                   OX + ["--dry-run", "--model", "test-model", "--mode", "ask", "--files", str(creds),
                         "explain this"])
    # "_" is a word character, so the old \bsecret\b never matched inside
    # client_secret -- and the value half demanded quotes that .env files and
    # shell exports do not write. Both shapes reached the provider unflagged.
    underscored = temp / "underscored.txt"
    underscored.write_text('client_secret = "wJalrXUtnFEMIK7MDENGbPxRfiCY"\n',
                           encoding="utf-8")
    expect_refused("oxbox-send refuses an underscore-prefixed credential name",
                   OX + ["--dry-run", "--model", "test-model", "--mode", "ask", "--files",
                         str(underscored), "explain this"])
    unquoted = temp / "unquoted.env"
    unquoted.write_text("DB_PASSWORD=supersecretvalue12345\n", encoding="utf-8")
    expect_refused("oxbox-send refuses an unquoted credential value",
                   OX + ["--dry-run", "--model", "test-model", "--mode", "ask", "--files",
                         str(unquoted), "explain this"])
    # The counterweight: a scanner that refuses everything passes every case
    # above. max_tokens contains "token" and must not trip it, or ox cannot
    # read its own source.
    tokens = temp / "tokens.py"
    tokens.write_text("max_tokens = DEFAULT_MAX_TOKENS\n"
                      "completion_tokens = usage.get(\"completion_tokens\")\n",
                      encoding="utf-8")
    expect_allowed("oxbox-send does not mistake max_tokens for a credential",
                   OX + ["--dry-run", "--model", "test-model", "--mode", "ask", "--files",
                         str(tokens), "explain this"])
    expect_allowed("oxbox-send accepts an ordinary prompt",
                   OX + ["--dry-run", "--model", "test-model", "--mode", "ask",
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
           "oxbox-send --skill emits UTF-8 with LF endings",
           "bytes=%d crlf=%s decoded=%s" % (len(raw), b"\r\n" in raw, bool(text)))
    report(code == 0 and text.startswith("---") and "name: ox-review" in text,
           "oxbox-send --skill prints the runbook", f"exit={code} bytes={len(text)}")
    # The printed copy has to name scripts where this ox found them, or the
    # commands an agent reads are commands it cannot run.
    report(str(HERE / ".claude" / "skills" / "ox-review") in text,
           "oxbox-send --skill rewrites the script paths to this installation")
    report(not skill_logs.exists() and not skill_status.exists(),
           "oxbox-send --skill opens no run: no log directory, no status record",
           f"logs={skill_logs.exists()} status={skill_status.exists()}")

    # oxseed's rule is that it validates everything before destroying
    # anything, and --skill destroys nothing at all: it answers a question
    # about the installation. The hazard is ordering again — put the handler
    # after the --clean branch or the seeding path and asking for the runbook
    # wipes the sandbox you were working in.
    marker = WORK / "skill-canary.txt"
    marker.write_text("still here\n", encoding="utf-8")
    code = run(OXSANDBOX + ["--skill"])
    survived = marker.is_file()
    report(code == 0 and survived, "oxbox-sandbox --skill destroys nothing",
           f"exit={code} sandbox_intact={survived}")

    print("\n=== sandbox tending ===")
    # --add, --remove, --list, --read and --write take paths from the
    # operator, so they get the seeding checks' refusals (traversal,
    # absolute, .git) and one more property: only --create, --add and
    # --remove touch the baseline commit, and each commits only what it was
    # asked about, so an edit the operator --wrote (or a patch the model
    # produced) is never swept into "pristine" by a later --remove.
    def tend(argv, stdin=b""):
        return subprocess.run(OXSANDBOX + argv, input=stdin, capture_output=True)

    tend_src = temp / "tend-src"
    (tend_src / "pkg").mkdir(parents=True)
    # Bytes, not text: on Windows text mode would put CRLF on disk, and the
    # --read case below asserts the tool returns exactly what is there.
    (tend_src / "a.py").write_bytes(b"a = 1\n")
    (tend_src / "pkg" / "b.py").write_bytes(b"b = 2\n")
    (tend_src / "c.py").write_bytes(b"c = 3\n")
    expect_allowed("sandbox --create seeds a tree",
                   OXSANDBOX + ["--create", str(tend_src), "a.py", "pkg"])
    done = tend(["--list"])
    report(done.returncode == 0 and done.stdout.split() == [b"a.py", b"pkg/b.py"],
           "sandbox --list names the seeded files", repr(done.stdout))
    expect_allowed("sandbox --add copies from the recorded source",
                   OXSANDBOX + ["--add", "c.py"])
    done = tend(["--read", "c.py"])
    report(done.returncode == 0 and done.stdout == b"c = 3\n",
           "sandbox --read prints the file's bytes", repr(done.stdout))
    done = tend(["--write", "c.py"], stdin=b"c = 4\r\n")
    report(done.returncode == 0 and (WORK / "c.py").read_bytes() == b"c = 4\r\n",
           "sandbox --write stores stdin byte for byte", f"exit={done.returncode}")
    changed = subprocess.run(["git", "-C", str(WORK), "diff", "--name-only", "HEAD"],
                             capture_output=True, text=True).stdout.split()
    report(changed == ["c.py"], "sandbox --write is not committed", repr(changed))
    expect_allowed("sandbox --remove deletes a seeded file",
                   OXSANDBOX + ["--remove", "pkg/b.py"])
    changed = subprocess.run(["git", "-C", str(WORK), "diff", "--name-only", "HEAD"],
                             capture_output=True, text=True).stdout.split()
    report(changed == ["c.py"] and not (WORK / "pkg" / "b.py").exists(),
           "sandbox --remove commits only the removal, leaving the edit alone",
           repr(changed))
    done = tend(["--list"])
    report(done.stdout.split() == [b"a.py", b"c.py"],
           "sandbox --list reflects the removal", repr(done.stdout))
    expect_refused("sandbox --read refuses parent traversal",
                   OXSANDBOX + ["--read", "../tend-src/a.py"])
    expect_refused("sandbox --remove refuses an absolute path",
                   OXSANDBOX + ["--remove", str(tend_src / "a.py")])
    report(tend(["--write", ".git/config"], stdin=b"x").returncode == 78,
           "sandbox --write refuses a path inside .git")
    report(tend(["--write", "./.git/hooks/pre-commit"], stdin=b"x").returncode == 78,
           "sandbox --write refuses .git behind a ./ prefix")
    report(tend(["--write", ".GIT/hooks/pre-commit"], stdin=b"x").returncode == 78,
           "sandbox --write refuses .git in any letter case")
    if sys.platform == "win32":
        skip("sandbox cleanup never chmods through a symlink",
             "creating symlinks needs a privilege on Windows")
    else:
        # What jailed code can leave behind: a read-only directory that makes
        # the first removal fail, and links aimed at a file outside. The
        # cleanup must still succeed, and the file outside must keep its mode.
        victim = temp / "victim.txt"
        victim.write_bytes(b"outside\n")
        victim.chmod(0o644)
        locked = WORK / "locked"
        locked.mkdir()
        (locked / "f").write_bytes(b"x")
        os.symlink(str(victim), str(locked / "link"))
        os.symlink(str(victim), str(WORK / "link"))
        locked.chmod(0o555)
        code = run(OXSANDBOX + ["--destroy"])
        mode = stat.S_IMODE(victim.stat().st_mode)
        report(code == 0 and mode == 0o644 and not WORK.exists(),
               "sandbox cleanup never chmods through a symlink",
               f"exit={code} mode={mode:o} work_exists={WORK.exists()}")
        expect_allowed("sandbox --create rebuilds the tree after the cleanup",
                       OXSANDBOX + ["--create", str(tend_src), "a.py", "pkg"])
    report(tend(["--read", "nope.py"]).returncode == 3,
           "sandbox --read exits 3 for a file that is not there")
    report(tend(["--list", "--destroy"]).returncode == 2,
           "sandbox refuses two operations at once")
    expect_allowed("sandbox --destroy removes the tree", OXSANDBOX + ["--destroy"])
    report(not SANDBOX.exists() and tend(["--list"]).returncode == 3,
           "sandbox --list exits 3 once there is no sandbox")

    print("\n=== sandbox root and names ===")
    # oxbox-sandbox, oxbox-patch and oxbox-jail each carry their own copy of
    # the root resolution (env, config file, default). Three copies of one
    # rule drift unless something drives all three under one setting and
    # checks they met in the same tree -- that is this section. PATH-style
    # isolation again: HOME/XDG_CONFIG_HOME/APPDATA point at a temp dir so a
    # real config file on this machine cannot leak into the run.
    cfg_home = temp / "cfg"
    (cfg_home / "oxbox").mkdir(parents=True)
    cfg_root = temp / "cfg-root"
    (cfg_home / "oxbox" / "config.ini").write_text(
        "[sandbox]\nroot = %s\n" % cfg_root, encoding="utf-8")
    base_env = {k: v for k, v in os.environ.items() if k != "OXBOX_SANDBOX_ROOT"}
    base_env.update(XDG_CONFIG_HOME=str(cfg_home), APPDATA=str(cfg_home))
    env_root = temp / "env-root"
    env_env = dict(base_env, OXBOX_SANDBOX_ROOT=str(env_root))
    src2 = temp / "root-src"
    src2.mkdir()
    (src2 / "mod.py").write_text("def f():\n    return 1\n", encoding="utf-8")

    def rooted(argv, env, stdin=None):
        return subprocess.run(argv, env=env, capture_output=True, text=True,
                              input=stdin)

    done = rooted(OXSANDBOX + ["--create", str(src2), "mod.py"], base_env)
    report(done.returncode == 0 and (cfg_root / "work" / "mod.py").is_file(),
           "the config file's root is honored when the env var is unset",
           f"exit={done.returncode} stderr={done.stderr.strip()!r}")
    done = rooted(OXSANDBOX + ["--create", str(src2), "mod.py"], env_env)
    report(done.returncode == 0 and (env_root / "work" / "mod.py").is_file()
           and not (env_root / "alt").exists(),
           "OXBOX_SANDBOX_ROOT wins over the config file",
           f"exit={done.returncode} stderr={done.stderr.strip()!r}")
    done = rooted(OXSANDBOX + ["--sandbox", "alt", "--create", str(src2), "mod.py"], env_env)
    report(done.returncode == 0 and (env_root / "alt" / "mod.py").is_file()
           and (env_root / "work" / "mod.py").is_file(),
           "--sandbox NAME makes a second sandbox beside the first",
           f"exit={done.returncode} stderr={done.stderr.strip()!r}")
    done = rooted(OXSANDBOX + ["--status"], env_env)
    lines = done.stdout.splitlines()
    # The header prints the resolved root, and a macOS temp dir is a symlink
    # into /private/var, so compare resolved with resolved.
    report(done.returncode == 0 and lines
           and lines[0].startswith("root %s" % os.path.realpath(env_root))
           and [line.split()[0] for line in lines[1:]] == ["alt", "work"],
           "--status names the root and every sandbox under it", repr(done.stdout))
    # The same root, seen from oxbox-patch: the patch lands in alt, not work.
    done = rooted(OXAPPLY + ["--sandbox", "alt", "--diff", str(valid)], env_env)
    patched_alt = "return 2" in (env_root / "alt" / "mod.py").read_text(encoding="utf-8")
    untouched_work = "return 1" in (env_root / "work" / "mod.py").read_text(encoding="utf-8")
    report(done.returncode == 0 and patched_alt and untouched_work,
           "oxbox-patch --sandbox resolves the same root and tree",
           f"exit={done.returncode} stderr={done.stderr.strip()!r}")
    done = rooted(OXSANDBOX + ["--status"], env_env)
    states = {line.split()[0]: line.split()[3] for line in done.stdout.splitlines()[1:]}
    report(states == {"alt": "modified", "work": "clean"},
           "--status tells a patched sandbox from a clean one", repr(states))
    # And from oxbox-jail: --sandbox alt is inside the configured root, while
    # the checkout's own ./sandbox/work is now outside it and refused. The
    # directory has to exist for the refusal to be about the root rather than
    # about a missing path -- and oxbox-patch's refusal below needs it too,
    # on Windows, where the jail cases skip.
    WORK.mkdir(parents=True, exist_ok=True)
    if jail_supported:
        done = rooted(OXBOX + ["--sandbox", "alt", "--", sys.executable, "-c", "pass"], env_env)
        report(done.returncode == 0, "oxbox-jail --sandbox runs in the configured root",
               f"exit={done.returncode} stderr={done.stderr.strip()!r}")
        done = rooted(OXBOX + ["--work", str(WORK), "--", sys.executable, "-c", "pass"], env_env)
        report(done.returncode == 78 and "OXBOX_SANDBOX_ROOT" in done.stderr,
               "oxbox-jail refuses a work dir outside the configured root, naming the setting",
               f"exit={done.returncode} stderr={done.stderr.strip()!r}")
    else:
        skip("oxbox-jail under a configured root", f"no jail backend on {sys.platform}")
    done = rooted(OXAPPLY + ["--work", str(WORK), "--diff", str(valid)], env_env)
    report(done.returncode == 2 and "OXBOX_SANDBOX_ROOT" in done.stderr,
           "oxbox-patch refuses a work dir outside the configured root, naming the setting",
           f"exit={done.returncode} stderr={done.stderr.strip()!r}")
    for bad in ("../x", "a/b", ".hidden", ""):
        done = rooted(OXSANDBOX + ["--sandbox", bad, "--list"], env_env)
        report(done.returncode == 2, f"a sandbox name of {bad!r} is refused",
               f"exit={done.returncode}")
    done = rooted(OXSANDBOX + ["--sandbox", "alt", "--destroy"], env_env)
    report(done.returncode == 0 and not (env_root / "alt").exists()
           and (env_root / "work" / "mod.py").is_file(),
           "--destroy removes only the named sandbox", f"exit={done.returncode}")
    done = rooted(OXSANDBOX + ["--destroy", "--all"], env_env)
    report(done.returncode == 0 and not env_root.exists(),
           "--destroy --all removes the root", f"exit={done.returncode}")
    done = rooted(OXSANDBOX + ["--status"], env_env)
    report(done.returncode == 1, "--status exits 1 with no sandboxes", f"exit={done.returncode}")

    print("\n=== the front door ===")
    # The project is called oxbox, so oxbox is what a reader types first --
    # and the first thing one typed was ox's --manifest, which the jail
    # answered with "unexpected argument". Now it names the command that
    # takes the flag, and exits 2 so a script can tell a usage error from a
    # refusal.
    done = subprocess.run(OXBOX + ["--manifest", "x"], capture_output=True,
                          text=True)
    report(done.returncode == 2 and "oxbox send --manifest" in done.stderr,
           "oxbox --manifest says the flag belongs to send",
           f"exit={done.returncode} stderr={done.stderr.strip()!r}")
    done = subprocess.run(OXBOX + ["pytest", "-q"], capture_output=True, text=True)
    report(done.returncode == 2 and "oxbox -- pytest" in done.stderr,
           "oxbox <word> names the commands and the -- form",
           f"exit={done.returncode} stderr={done.stderr.strip()!r}")

    # Positive controls: each subcommand reaches its helper, and the helper
    # is the one beside this oxbox, not whatever an old install left on
    # PATH. --version is the cheapest question that proves which script
    # answered.
    versions = {}
    for tool, argv in (("oxbox-send", OX), ("oxbox-sandbox", OXSANDBOX),
                       ("oxbox-patch", OXAPPLY),
                       ("oxbox-jail", tool_argv("oxbox-jail"))):
        versions[tool] = subprocess.run(argv + ["--version"], capture_output=True,
                                        text=True).stdout.strip()
    for sub, tool in (("send", "oxbox-send"), ("sandbox", "oxbox-sandbox"),
                      ("patch", "oxbox-patch"), ("jail", "oxbox-jail")):
        done = subprocess.run(OXBOX + [sub, "--version"], capture_output=True,
                              text=True)
        report(done.returncode == 0 and done.stdout.strip() == versions[tool],
               f"oxbox {sub} runs {tool}",
               f"exit={done.returncode} stdout={done.stdout.strip()!r}")
    done = subprocess.run(OXBOX + ["helper", "send", "--version"],
                          capture_output=True, text=True)
    report(done.returncode == 0 and done.stdout.strip() == versions["oxbox-send"],
           "oxbox helper send runs oxbox-send", f"stdout={done.stdout.strip()!r}")
    done = subprocess.run(OXBOX + ["helper"], capture_output=True, text=True)
    listed = [line.split()[0] for line in done.stdout.splitlines() if line.strip()]
    report(done.returncode == 0
           and listed == ["oxbox-sandbox", "oxbox-send", "oxbox-patch", "oxbox-jail"],
           "oxbox helper lists the four scripts", f"stdout={done.stdout!r}")
    expect_refused("oxbox helper refuses a name that is not a helper",
                   OXBOX + ["helper", "python3", "-c", "pass"])

    # The installed layouts, staged for real: oxbox in <prefix>/bin with the
    # helpers in <prefix>/libexec/bin (Homebrew keg, macOS tarball, MSI) or
    # <prefix>/libexec/oxbox/bin (the .deb), and the skill under
    # <prefix>/share/oxbox. PATH is emptied so the only way to find ox is the
    # layout; a lookup that quietly fell back to the checkout or to an
    # installed copy would pass for the wrong reason. The release workflow
    # proves the same thing against real packages, but only on a tag.
    skill_source = HERE / ".claude" / "skills" / "ox-review" / "SKILL.md"
    for label, helper_sub in (("keg", ("libexec", "bin")),
                              ("fhs", ("libexec", "oxbox", "bin"))):
        prefix = temp / ("prefix-" + label)
        (prefix / "bin").mkdir(parents=True)
        shutil.copy(tool_path("oxbox"), prefix / "bin" / tool_path("oxbox").name)
        helper_dir = prefix.joinpath(*helper_sub)
        helper_dir.mkdir(parents=True)
        shutil.copy(tool_path("oxbox-send"), helper_dir / tool_path("oxbox-send").name)
        skill_dir = prefix / "share" / "oxbox" / "ox-review"
        skill_dir.mkdir(parents=True)
        shutil.copy(skill_source, skill_dir / "SKILL.md")
        empty = temp / "empty-path"
        empty.mkdir(exist_ok=True)
        env = dict(os.environ, PATH=str(empty))
        staged_oxbox = prefix / "bin" / tool_path("oxbox").name
        staged = [str(staged_oxbox)] if UNDER_TEST else [sys.executable, str(staged_oxbox)]
        done = subprocess.run(staged + ["send", "--version"], capture_output=True,
                              text=True, env=env)
        report(done.returncode == 0 and done.stdout.strip() == versions["oxbox-send"],
               f"oxbox send finds oxbox-send in the {label} layout with nothing on PATH",
               f"exit={done.returncode} stderr={done.stderr.strip()!r}")
        # Homebrew's shape: bin/oxbox is a symlink to the keg's file, and the
        # keg is where libexec lives. The FILE has to be resolved before its
        # directory is taken, or the lookup stays beside the link. 1.0.0
        # shipped with exactly that defect and brew could not run a helper.
        if sys.platform == "win32":
            skip(f"a symlinked front door finds the {label} helpers",
                 "creating symlinks needs a privilege on Windows")
        else:
            linkbin = temp / ("linkbin-" + label)
            linkbin.mkdir()
            os.symlink(str(staged_oxbox), str(linkbin / staged_oxbox.name))
            linked = [str(linkbin / staged_oxbox.name)] if UNDER_TEST \
                else [sys.executable, str(linkbin / staged_oxbox.name)]
            done = subprocess.run(linked + ["send", "--version"], capture_output=True,
                                  text=True, env=env)
            report(done.returncode == 0 and done.stdout.strip() == versions["oxbox-send"],
                   f"a symlinked front door finds the {label} helpers",
                   f"exit={done.returncode} stderr={done.stderr.strip()!r}")
        done = subprocess.run(staged + ["helper", "send", "--skill"],
                              capture_output=True, text=True, env=env)
        # The provenance line carries the resolved path: oxbox resolves its
        # own location before walking up, so the script prints the long form
        # of a directory that tempfile may have handed us as a symlink
        # (macOS /var -> /private/var) or an 8.3 short name (GitHub's Windows
        # runner: RUNNER~1 for runneradmin). Compare resolved with resolved.
        report(done.returncode == 0 and os.path.realpath(skill_dir) in done.stderr,
               f"a helper in the {label} layout finds the skill under share/",
               f"exit={done.returncode} stderr={done.stderr.strip()!r}")
        (helper_dir / tool_path("oxbox-send").name).unlink()
        done = subprocess.run(staged + ["send", "--version"], capture_output=True,
                              text=True, env=env)
        report(done.returncode == 3,
               f"oxbox send exits 3 when the {label} layout has no oxbox-send",
               f"exit={done.returncode}")

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
