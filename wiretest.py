#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Curtis Galloway
# SPDX-License-Identifier: Apache-2.0
"""What ox actually puts on the wire, and where it puts it.

guardtest.py covers the refusals before a request is built. jailtest.py probes
outward from inside the jail. Neither has ever looked at the request itself, so
the README's first containment claim -- "ox sends a chat completion with no
`tools` array" -- was asserted and never tested. If someone added a tools key
tomorrow, every existing suite would stay green.

Everything here runs against a local http.server on 127.0.0.1. No network, no
API key, no provider, so it runs in CI on every platform. Where a test needs a
non-https URL (a loopback listener cannot be https), it exercises ox through an
in-process import rather than relaxing the https guard in the shipped file.

Python 3.9 floor, same as the rest of the repo.
"""

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import threading
import http.server
from pathlib import Path

HERE = Path(__file__).resolve().parent

# Two implementations, one suite. By default this drives the Python scripts
# in the checkout's python/ directory; with OXBOX_UNDER_TEST naming a directory of built
# executables it drives those instead. The Python source is still read as the
# reference (load_ox, the VERSION check), and the binary's behavior is held
# to it. The binary has to be built with the `test-overrides` feature, which
# compiles in the same knobs this suite patches into a copy of the Python
# source: venue URLs aimed at a loopback listener, the https guards relaxed,
# the manifest size cap lowered.
UNDER_TEST = os.environ.get("OXBOX_UNDER_TEST")
# The tools read `[send] manifest` from ~/.config/oxbox/config.ini, and a
# developer's own setting would turn every "no destination named" refusal
# this suite asserts into a run. Every ox the suite starts gets an empty
# config home; the cases that test the setting supply their own.
CONFIG_HOME = tempfile.mkdtemp(prefix="wiretest-cfg-")


def tool_path(name):
    if UNDER_TEST:
        return Path(UNDER_TEST) / (name + (".exe" if sys.platform == "win32" else ""))
    return HERE / "python" / name


def tool_argv(name):
    return [str(tool_path(name))] if UNDER_TEST else [sys.executable, str(tool_path(name))]


OX = tool_argv("oxbox-send")

FAILURES = []
PASSES = 0
SKIPPED = 0


def report(ok, label, note=""):
    global PASSES
    if ok:
        PASSES += 1
        print("[PASS] %s" % label)
    else:
        FAILURES.append(label)
        print("[FAIL] %s%s" % (label, ("  (%s)" % note) if note else ""))


def skip(label, why):
    global SKIPPED
    SKIPPED += 1
    print("[SKIP] %s (%s)" % (label, why))


def header(headers, name):
    """Case-insensitive lookup. Header names are case-insensitive on the
    wire, and the two implementations spell them differently: urllib sends
    them as written, the Rust client lowercases them."""
    for key, value in (headers or {}).items():
        if key.lower() == name.lower():
            return value
    return None


def serve(handler):
    """Start a throwaway HTTP server on a free loopback port."""
    server = http.server.HTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def capture_handler(store, status=200, body=None, headers=None):
    """A handler that records the request and replies with a canned body."""
    if body is None:
        body = json.dumps({
            "choices": [{"finish_reason": "stop",
                         "message": {"content": "ok", "role": "assistant"}}],
            "usage": {"prompt_tokens": 1, "completion_tokens": 1},
        }).encode()

    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.0"

        def do_POST(self):
            length = int(self.headers.get("Content-Length") or 0)
            store["body"] = self.rfile.read(length) if length else b""
            store["headers"] = dict(self.headers.items())
            store["path"] = self.path
            self.send_response(status)
            for key, value in (headers or {"Content-Type": "application/json"}).items():
                self.send_header(key, value)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        do_GET = do_POST

        def log_message(self, *args):
            pass

    return Handler


def load_ox():
    """Import ox as a module without running main()."""
    source = (HERE / "python" / "oxbox-send").read_text(encoding="utf-8")
    source = source.replace('if __name__ == "__main__":', "if False:")
    # __file__ too, not just __name__: a real import provides both, and ox
    # anchors its script-relative asset lookup (find_skill) on __file__ the
    # way oxbox anchors find_profile. A namespace missing it does not fail
    # like the real module, it fails at import with a NameError.
    namespace = {"__name__": "oxmod", "__file__": str(HERE / "python" / "oxbox-send")}
    exec(compile(source, str(HERE / "python" / "oxbox-send"), "exec"), namespace)
    return namespace


def canary_key(venue):
    """A fake credential for one venue, assembled rather than written out.

    ox scans a file for secrets before sending it anywhere, and a literal
    OPENROUTER_API_KEY = "sk-..." is precisely the shape it refuses. That is
    correct behaviour on real code and it made this file unreviewable by the
    tool it tests: a review batch waited 790 seconds in the queue on
    2026-09-03 and was then refused pre-send over these two lines, so
    wiretest.py went unreviewed while every other file did not.

    Assembling the value keeps it byte-identical at runtime -- the tests
    still assert on the exact string that reaches the wire -- while the
    source stops carrying something shaped like a credential. The scanner
    is not being weakened or worked around; there is simply no longer a
    fake key here for it to find. Build expected values with this too, so
    the assertion and the environment cannot drift apart.
    """
    return "sk-" + "canary-" + venue


def run_ox(argv, env=None, timeout=60):
    environ = dict(os.environ, XDG_CONFIG_HOME=CONFIG_HOME, APPDATA=CONFIG_HOME)
    environ.update(env or {})
    return subprocess.run(OX + argv, capture_output=True, text=True,
                          timeout=timeout, env=environ)


def rewired_ox(tmp, name, allow_http=False, venue_urls=None, manifest_cap=None):
    """An ox with its wiring changed for a loopback listener.

    Returns (argv, env): for the Python reference, a copy of the source with
    the named lines rewritten and an empty env; under OXBOX_UNDER_TEST, the
    binary and the OXBOX_TEST_* variables its test-overrides feature reads.
    Either way the guards are relaxed only here, in a copy or a test build --
    the real program keeps them, and separate cases assert that.
    """
    if UNDER_TEST:
        env = {}
        if allow_http:
            env["OXBOX_TEST_ALLOW_HTTP"] = "1"
        if venue_urls:
            env["OXBOX_TEST_VENUE_URLS"] = json.dumps(venue_urls)
        if manifest_cap is not None:
            env["OXBOX_TEST_MANIFEST_MAX_BYTES"] = str(manifest_cap)
        return list(OX), env
    source = (HERE / "python" / "oxbox-send").read_text(encoding="utf-8")
    if allow_http:
        source = source.replace('if not args.base_url.startswith("https://"):', "if False:")
        source = source.replace('if not url.startswith("https://"):', "if False:")
    for venue, url in (venue_urls or {}).items():
        source = source.replace(REFERENCE_URLS[venue], url)
    if manifest_cap is not None:
        source = source.replace("MANIFEST_MAX_BYTES = 1_048_576",
                                "MANIFEST_MAX_BYTES = %d" % manifest_cap)
    patched = tmp / name
    patched.write_text(source, encoding="utf-8")
    return [sys.executable, str(patched)], {}


REFERENCE_URLS = {
    "openrouter": "https://openrouter.ai/api/v1/chat/completions",
    "opencode": "https://opencode.ai/zen/v1/chat/completions",
}


def run_rewired(rewired, argv, env=None, cwd=None):
    command, overrides = rewired
    environ = dict(os.environ, XDG_CONFIG_HOME=CONFIG_HOME, APPDATA=CONFIG_HOME)
    environ.update(overrides)
    environ.update(env or {})
    return subprocess.run(command + argv, capture_output=True, text=True,
                          timeout=60, env=environ, cwd=cwd)


def send_to_local(store, tmp, extra_argv=None, **kwargs):
    """Drive ox at a local listener, bypassing only the https scheme guard.

    The guard is a separate, directly tested behavior; relaxing it here is what
    lets every other wire assertion run without a real provider.
    """
    server = serve(capture_handler(store, **kwargs))
    url = "http://127.0.0.1:%d/v1/chat/completions" % server.server_address[1]
    rewired = rewired_ox(tmp, "ox_local", allow_http=True)
    argv = ["--base-url", url,
            "--api-key-env", "OX_TEST_KEY", "--model", "test-model",
            "--log-dir", str(tmp / "logs")] + (extra_argv or ["--mode", "ask", "hello"])
    result = run_rewired(rewired, argv, env={"OX_TEST_KEY": "sk-test-canary"})
    server.shutdown()
    return result


def main():
    import tempfile
    tmp = Path(tempfile.mkdtemp(prefix="wiretest-"))
    ox = load_ox()

    print("=== one version, declared five times, all equal ===")

    # Each tool is a standalone script, so each carries its own VERSION
    # constant. Four copies of one fact drift unless something checks; this
    # is the check, same pattern as the env_canary list agreement below.
    import re as _re
    versions = {}
    for tool in ("oxbox", "oxbox-send", "oxbox-patch", "oxbox-sandbox", "oxbox-jail"):
        match = _re.search(r'^VERSION = "([^"]+)"', (HERE / "python" / tool).read_text(encoding="utf-8"),
                           _re.MULTILINE)
        versions[tool] = match.group(1) if match else None
    report(len(set(versions.values())) == 1 and None not in versions.values(),
           "all five tools declare the same VERSION", repr(versions))
    result = run_ox(["--version"])
    report(result.returncode == 0
           and result.stdout.strip() == "oxbox-send %s" % ox["VERSION"],
           "oxbox-send --version prints it", repr(result.stdout))

    # Same hazard, bigger payload: find_skill/print_skill is carried by each
    # tool because each is a standalone script, and four copies of one
    # document drift unless something compares them. Compare the output
    # rather than the source — that is what a caller actually receives, and
    # it catches a lookup that silently resolves somewhere else as well as a
    # block someone edited in one file only.
    skills = {}
    for tool in ("oxbox", "oxbox-send", "oxbox-patch", "oxbox-sandbox", "oxbox-jail"):
        done = subprocess.run(tool_argv(tool) + ["--skill"],
                              capture_output=True, text=True, timeout=30)
        skills[tool] = (done.returncode, done.stdout)
    codes = {tool: code for tool, (code, _) in skills.items()}
    report(set(codes.values()) == {0},
           "every tool exits 0 for --skill", repr(codes))
    bodies = {text for _, text in skills.values()}
    report(len(bodies) == 1 and next(iter(bodies)).startswith("---"),
           "all five tools print the same skill",
           "%d distinct outputs, lengths %r"
           % (len(bodies), sorted(len(text) for _, text in skills.values())))
    # The provenance line is the one part that differs, and it has to name the
    # tool you actually ran or an error message points at the wrong program.
    prefixes = {}
    for tool in ("oxbox", "oxbox-send", "oxbox-patch", "oxbox-sandbox", "oxbox-jail"):
        done = subprocess.run(tool_argv(tool) + ["--skill"],
                              capture_output=True, text=True, timeout=30)
        prefixes[tool] = done.stderr.startswith("%s: skill -> " % tool)
    report(all(prefixes.values()),
           "each tool names itself on the provenance line", repr(prefixes))

    # Third copy of the same hazard: the ox-review batch script re-declares
    # ox's effort ladder because it is standalone, and a run that passes
    # --effort through a level ox no longer accepts dies at argparse after
    # the queue lock is taken. Compare what each program advertises, not
    # the two source lines: --help is what a caller reads.
    oxreview = HERE / ".claude" / "skills" / "ox-review" / "scripts" / "oxreview.py"
    ladders = {}
    for name, argv in (("ox", OX), ("oxreview", [sys.executable, str(oxreview)])):
        done = subprocess.run(argv + ["--help"], capture_output=True,
                              text=True, timeout=30)
        found = _re.search(r"--effort \{([^}]*)\}", done.stdout)
        ladders[name] = found.group(1) if found else None
    report(ladders["ox"] == ",".join(ox["EFFORTS"])
           and ladders["oxreview"] == ladders["ox"],
           "ox and the review batcher offer the same effort ladder",
           repr(ladders))

    # Installed tools anchor state at the working directory, not the script's:
    # /usr/bin/logs is not a thing. A dry run from a scratch directory must
    # leave its log there and nothing in the repo.
    scratch = tmp / "scratch-cwd"
    scratch.mkdir()
    # --model is explicit because no venue has a default any more; this case
    # is about where the log lands, not about how the model is chosen.
    result = subprocess.run(
        OX + ["--mode", "ask", "--dry-run", "--model", "test-model", "t"],
        capture_output=True, text=True, timeout=60, cwd=str(scratch))
    logged = sorted((scratch / "logs").glob("*/meta.json"))
    report(result.returncode == 0 and len(logged) == 1,
           "the default log dir is the working directory's logs/",
           "exit=%s found=%d" % (result.returncode, len(logged)))

    print("\n=== the request ox builds ===")

    store = {}
    result = send_to_local(store, tmp)
    payload = json.loads(store.get("body") or b"{}")
    headers = store.get("headers") or {}

    # The headline containment claim. If this ever fails, the model has been
    # handed a way to ask for actions rather than only emit text.
    report("tools" not in payload,
           "no `tools` key on the wire (containment layer 1)",
           "payload keys: %s" % sorted(payload))
    report("functions" not in payload and "tool_choice" not in payload,
           "no `functions` or `tool_choice` either")

    report(header(headers, "Authorization") == "Bearer sk-test-canary",
           "Authorization carries the value of the named env var",
           repr(header(headers, "Authorization")))
    report(header(headers, "Content-Type") == "application/json",
           "Content-Type is application/json")

    # urllib defaults to Python-urllib/3.x, which OpenCode Zen's Cloudflare
    # rejects with 403 before routing. That shipped once; it does not again.
    agent = header(headers, "User-Agent") or ""
    report(agent == ox["USER_AGENT"] and "Python-urllib" not in agent,
           "User-Agent is ox's own, not urllib's default", repr(agent))

    report(payload.get("model") == "test-model", "model is passed through")
    report(result.returncode == 0, "a normal exchange exits 0", result.stderr[-160:])

    print("\n=== the system prompt matches --mode ===")
    for mode in sorted(ox["SYSTEM_PROMPTS"]):
        store = {}
        send_to_local(store, tmp, extra_argv=["--mode", mode, "task"])
        payload = json.loads(store.get("body") or b"{}")
        messages = payload.get("messages") or [{}]
        report(messages[0].get("content") == ox["SYSTEM_PROMPTS"][mode],
               "--mode %s sends the %s system prompt" % (mode, mode))

    print("\n=== the credential never leaves its venue ===")

    # Every venue must read its own variable and no other. Poison all of them
    # with a distinguishable value and check which one is actually sent.
    for venue, spec in sorted(ox["VENUES"].items()):
        env = dict((s["key_env"], "sk-canary-" + name)
                   for name, s in ox["VENUES"].items())
        result = run_ox(["--venue", venue, "--model", "m", "--mode", "ask",
                         "--dry-run", "--log-dir", str(tmp / "logs"), "t"], env=env)
        meta_dirs = sorted((tmp / "logs").glob("*/meta.json"))
        meta = json.loads(meta_dirs[-1].read_text()) if meta_dirs else {}
        report(meta.get("key_env") == spec["key_env"]
               and meta.get("endpoint") == spec["url"],
               "--venue %s pairs %s with its own URL" % (venue, spec["key_env"]),
               "%s / %s" % (meta.get("key_env"), meta.get("endpoint")))

    report(all(spec["url"].startswith("https://") for spec in ox["VENUES"].values()),
           "every venue URL is https")

    # No venue names a default model. The one that did carried
    # stealth/ox-alpha long after the listing was revealed and delisted, so a
    # bare `ox "question"` aimed at a model that had not existed for weeks.
    # The refusal has to name where a current one comes from, or it just moves
    # the dead end one step later.
    defaulted = [name for name, spec in ox["VENUES"].items()
                 if spec["default_model"]]
    report(not defaulted,
           "no venue ships a default model", repr(defaulted))
    # --dry-run so the case cannot reach the network even when it fails: the
    # no-model exit happens before the dry-run branch, so the assertion is
    # unchanged, but a regression that restores a default sends nothing.
    result = run_ox(["--mode", "ask", "--dry-run", "hello"],
                    env={"OPENROUTER_API_KEY": "sk-should-not-be-used"})
    report(result.returncode != 0
           and "no model chosen" in result.stderr
           and "oxbox.ai" in result.stderr,
           "a run with no model refuses and says where to get one",
           repr(result.stderr.strip()[:90]))

    # A key ox can send is a key the jail must not see. AGENTS.md says these two
    # lists move together; this is what makes that a check rather than a hope.
    canary_source = (HERE / "jailtest.py").read_text(encoding="utf-8")
    missing = [spec["key_env"] for spec in ox["VENUES"].values()
               if spec["key_env"] not in canary_source]
    report(not missing,
           "every venue key variable appears in jailtest's env_canary",
           "missing: %s" % missing)

    print("\n=== redirects cannot re-aim the credential ===")

    # Drive ox itself, not a hand-built opener. An earlier version of this test
    # constructed the opener with NoRedirects directly, which meant it passed
    # even when ox had stopped using it -- it asserted a property of the test,
    # not of the program. Mutation-checked: reverting ox to build_opener() must
    # turn these red.
    leaked = {}
    collector = serve(capture_handler(
        leaked, body=json.dumps({"choices": [{"message": {"content": "pwned"}}]}).encode()))

    class Redirector(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.0"

        def do_POST(self):
            self.send_response(302)
            self.send_header("Location", "http://127.0.0.1:%d/collect"
                             % collector.server_address[1])
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *args):
            pass

    redirector = serve(Redirector)
    result = run_rewired(
        rewired_ox(tmp, "ox_local", allow_http=True),
        ["--base-url", "http://127.0.0.1:%d/v1" % redirector.server_address[1],
         "--api-key-env", "OX_TEST_KEY", "--model", "m", "--mode", "ask",
         "--log-dir", str(tmp / "redirlogs"), "task"],
        env={"OX_TEST_KEY": "sk-test-canary"})

    got = leaked.get("headers") or {}
    report(header(got, "Authorization") is None,
           "ox does not forward Authorization across a redirect",
           "leaked: %r" % header(got, "Authorization"))
    report("pwned" not in result.stdout,
           "ox does not print a redirect target's content as the model's answer")
    report(result.returncode != 0 and "Traceback" not in result.stderr,
           "ox exits non-zero on a redirect, without a traceback",
           "exit=%s" % result.returncode)
    for server in (collector, redirector):
        server.shutdown()

    print("\n=== bad responses fail loudly, with the audit record intact ===")

    cases = [
        ("empty content exits non-zero",
         json.dumps({"choices": [{"finish_reason": "length",
                                  "message": {"content": ""}}],
                     "usage": {"completion_tokens": 32000,
                               "completion_tokens_details": {"reasoning_tokens": 31995}}}).encode(),
         200, "no content"),
        ("empty choices list exits cleanly",
         json.dumps({"choices": []}).encode(), 200, "no choices"),
        ("a non-JSON 200 body exits cleanly, no traceback",
         b"<html>gateway error</html>", 200, "non-JSON"),
    ]
    for label, body, status, expect in cases:
        store = {}
        result = send_to_local(store, tmp, body=body, status=status)
        ok = (result.returncode != 0
              and "Traceback" not in result.stderr
              and expect in result.stderr)
        report(ok, label, "exit=%s stderr=%r" % (result.returncode, result.stderr[-120:]))

    print("\n=== scripted runs check facts, not pipeline exit codes ===")

    # `ox | tee review.md` reports tee's status, so a failed run reads as
    # success unless the caller remembered pipefail. --output and
    # --status-file exist so nothing needs to be piped and nothing needs to
    # be remembered. Success first: the answer lands in the file, stdout
    # stays quiet, and the status record says how the run ended.
    out_file = tmp / "answer.md"
    status_file = tmp / "status.json"
    store = {}
    result = send_to_local(store, tmp, extra_argv=[
        "--mode", "ask", "--output", str(out_file),
        "--status-file", str(status_file), "hello"])
    report(out_file.exists() and out_file.read_text() == "ok\n",
           "--output writes the answer to the named file",
           repr(out_file.read_text() if out_file.exists() else None))
    report(result.stdout.strip() == "",
           "--output leaves stdout quiet", repr(result.stdout[:80]))
    stat = json.loads(status_file.read_text()) if status_file.exists() else {}
    report("venue_cost" in stat and stat.get("venue_cost") is None,
           "a venue that reports no cost leaves venue_cost null, not zero",
           repr(stat.get("venue_cost")))
    report("route" in stat and stat.get("route") is None,
           "a venue that names no upstream provider leaves route null",
           repr(stat.get("route")))
    report(stat.get("ok") is True and stat.get("exit_code") == 0
           and stat.get("finish_reason") == "stop",
           "--status-file records a successful run",
           json.dumps(stat)[:160])
    report(bool(stat.get("log_dir"))
           and (Path(stat["log_dir"]) / "status.json").exists(),
           "status.json also lands beside the audit log")

    # The record has to survive an exit nobody planned for. SystemExit used
    # to be the only net in main(), so an OSError -- a full disk, a log
    # directory that cannot be created -- ended the run with a traceback and
    # a status file still holding the in-progress placeholder written before
    # the request. A caller checking a fact instead of a pipeline exit code
    # learned nothing at all, which is the one shape this file must not take.
    blocked = tmp / "not-a-directory"
    blocked.write_text("this is a file\n", encoding="utf-8")
    crash_status = tmp / "crash-status.json"
    result = run_ox(["--model", "m", "--mode", "ask", "--dry-run",
                     "--log-dir", str(blocked / "logs"),
                     "--status-file", str(crash_status), "hello"],
                    env={"OPENROUTER_API_KEY": "sk-unused"})
    crashed = json.loads(crash_status.read_text()) if crash_status.exists() else {}
    # Python reaches this through its catch-all ("unhandled OSError: ...");
    # the Rust port diagnoses the failed mkdir by name. Either way the record
    # says the run failed and why, which is the property.
    crash_error = crashed.get("error") or ""
    report(result.returncode != 0
           and crashed.get("ok") is False
           and crashed.get("exit_code") == 1
           and ("unhandled" in crash_error or "log directory" in crash_error),
           "an unplanned exception still writes the status record",
           repr((crashed.get("exit_code"), (crashed.get("error") or "")[:44])))

    # is_file() passing is not permission to read. The shortest path to an
    # uncaught traceback in the whole tool was a mode-000 file in --files.
    if os.name == "nt":
        skip("an unreadable --files entry is a diagnosis, not a traceback",
             "chmod does not deny the owner on Windows")
        unreadable = None
    elif hasattr(os, "geteuid") and os.geteuid() == 0:
        # Same rule jailtest holds to: at uid 0 the probe cannot tell a
        # working diagnosis from a process that bypasses file permissions,
        # so it would report a defect that is really a privilege. Say so
        # rather than answer vacuously.
        skip("an unreadable --files entry is a diagnosis, not a traceback",
             "mode 000 does not deny root")
        unreadable = None
    else:
        unreadable = tmp / "unreadable.py"
        unreadable.write_text("x = 1\n", encoding="utf-8")
        unreadable.chmod(0o000)
        result = run_ox(["--model", "m", "--mode", "ask", "--dry-run",
                         "--files", str(unreadable),
                         "--log-dir", str(tmp / "ulogs"), "hello"],
                        env={"OPENROUTER_API_KEY": "sk-unused"})
        unreadable.chmod(0o600)
        report(result.returncode != 0
               and "cannot read" in result.stderr
               and "Traceback" not in result.stderr,
               "an unreadable --files entry is a diagnosis, not a traceback",
               repr(result.stderr.strip()[-70:]))

    # OpenRouter sends usage.cost on every response although ox never
    # asks for it, so a run's own price is available without pricing it
    # from a catalog afterwards. It is the venue's claim and is passed
    # through unconverted: assert the value survives, not that it is
    # right, because ox is in no position to know that.
    # It also names the upstream provider it routed to, in a top-level
    # "provider". The cost is the price of that route -- the survey saw the
    # same model billed at double the card price when OpenRouter routed it
    # to a different provider -- so the two are recorded side by side.
    priced = json.dumps({
        "provider": "SiliconFlow",
        "choices": [{"finish_reason": "stop",
                     "message": {"content": "ok", "role": "assistant"}}],
        "usage": {"prompt_tokens": 11793, "completion_tokens": 3375,
                  "cost": 0.021501},
    }).encode()
    cost_status = tmp / "cost-status.json"
    result = send_to_local({}, tmp, body=priced, extra_argv=[
        "--mode", "ask", "--status-file", str(cost_status), "hello"])
    cstat = json.loads(cost_status.read_text()) if cost_status.exists() else {}
    report(cstat.get("venue_cost") == 0.021501,
           "the venue's own reported cost is recorded verbatim",
           repr(cstat.get("venue_cost")))
    report(cstat.get("route") == "SiliconFlow" and "route=SiliconFlow" in result.stderr,
           "the upstream provider the venue routed to is recorded and announced",
           repr((cstat.get("route"), result.stderr[-120:])))
    # A provider field that is not a string is not a route; do not record
    # a dict or a number as one.
    odd = json.dumps({
        "provider": {"name": "Somewhere"},
        "choices": [{"finish_reason": "stop",
                     "message": {"content": "ok", "role": "assistant"}}],
        "usage": {"prompt_tokens": 1, "completion_tokens": 1},
    }).encode()
    odd_status = tmp / "odd-status.json"
    send_to_local({}, tmp, body=odd, extra_argv=[
        "--mode", "ask", "--status-file", str(odd_status), "hello"])
    ostat = json.loads(odd_status.read_text()) if odd_status.exists() else {}
    report(ostat.get("ok") is True and ostat.get("route") is None,
           "a non-string provider field is left null rather than recorded",
           repr(ostat.get("route")))

    # Failure: pre-seed both files with a previous run's leftovers, then fail
    # with empty content. The stale answer must be gone — a script must never
    # read an old answer as this run's — and the status must say failed, why,
    # and where the evidence is.
    out_file.write_text("stale answer from an earlier run")
    empty = json.dumps({"choices": [{"finish_reason": "length",
                                     "message": {"content": ""}}],
                        "usage": {"completion_tokens": 100000}}).encode()
    store = {}
    result = send_to_local(store, tmp, body=empty, extra_argv=[
        "--mode", "ask", "--output", str(out_file),
        "--status-file", str(status_file), "hello"])
    stat = json.loads(status_file.read_text()) if status_file.exists() else {}
    report(result.returncode != 0 and stat.get("ok") is False
           and stat.get("exit_code") == result.returncode
           and "no content" in (stat.get("error") or ""),
           "--status-file records a failed run with the error",
           json.dumps(stat)[:160])
    report(not out_file.exists(),
           "--output never leaves a stale answer behind a failed run")

    # Truncation with content is the quiet failure: the answer reads as
    # complete unless you notice the missing tail. It stays exit 0 — a
    # partial answer has value in front of a human — but the status record
    # and stderr both say so.
    truncated = json.dumps({"choices": [{"finish_reason": "length",
                                         "message": {"content": "partial"}}],
                            "usage": {"completion_tokens": 100000}}).encode()
    store = {}
    result = send_to_local(store, tmp, body=truncated, extra_argv=[
        "--mode", "ask", "--status-file", str(status_file), "hello"])
    stat = json.loads(status_file.read_text()) if status_file.exists() else {}
    report(result.returncode == 0 and stat.get("truncated") is True
           and "truncated" in result.stderr,
           "a truncated answer is flagged in status and on stderr",
           "exit=%s stderr=%r" % (result.returncode, result.stderr[-120:]))

    print("\n=== a manifest picks the destination, never the credential ===")

    # Two local venues: "openrouter" always answers 429, "opencode" answers
    # properly. The patched ox has its VENUES table pointed at them, which is
    # the point — a manifest names venues, and the table maps venue to URL
    # and key variable. The manifest's own base_url is never consulted.
    flaky = {}
    flaky_server = serve(capture_handler(
        flaky, status=429,
        body=json.dumps({"error": {"message": "rate-limited", "code": 429}}).encode()))
    solid = {}
    solid_server = serve(capture_handler(solid))
    local_venues = {
        "openrouter": "http://127.0.0.1:%d/or/v1/chat/completions" % flaky_server.server_address[1],
        "opencode": "http://127.0.0.1:%d/oc/v1/chat/completions" % solid_server.server_address[1],
    }
    # Venue URLs rewired to the listeners; the https guards stay in force,
    # which is what the plaintext-manifest case below relies on.
    manifest_ox = rewired_ox(tmp, "ox_manifest", venue_urls=local_venues)

    manifest = tmp / "manifest.json"
    manifest.write_text(json.dumps({
        "manifest_version": 0,
        "issue_date": "2026-08-27",
        "defaults": {"max_tokens": 55555, "effort": "low"},
        "recommendations": [
            {"rank": 1, "venue": "openrouter", "model": "top-paid",
             "cost": "paid", "why": "best, but costs money"},
            {"rank": 2, "venue": "acme", "model": "x", "cost": "free"},
            {"rank": 3, "venue": "openrouter", "model": "flaky-free",
             "cost": "free", "params": {"max_tokens": 4242, "effort": "xhigh"}},
            {"rank": 4, "venue": "opencode", "model": "solid-free",
             "cost": "free", "params": {"effort": "turbo"}},
        ],
    }), encoding="utf-8")
    menv = dict(os.environ,
                OPENROUTER_API_KEY=canary_key("openrouter"),
                OPENCODE_ZEN_API_KEY=canary_key("opencode"))
    sfile = tmp / "manifest-status.json"

    result = run_rewired(manifest_ox, ["--manifest", str(manifest),
         "--failover", "--mode", "ask", "--status-file", str(sfile),
         "--log-dir", str(tmp / "mlogs"), "hello"], env=menv)
    stat = json.loads(sfile.read_text()) if sfile.exists() else {}
    report(result.returncode == 0 and result.stdout.strip() == "ok",
           "--failover lands on the first working entry",
           "exit=%s stderr=%r" % (result.returncode, result.stderr[-160:]))
    report(header(flaky.get("headers"), "Authorization")
           == "Bearer " + canary_key("openrouter")
           and header(solid.get("headers"), "Authorization")
           == "Bearer " + canary_key("opencode"),
           "each attempt carries its own venue's key, never another's",
           "%r / %r" % (header(flaky.get("headers"), "Authorization"),
                        header(solid.get("headers"), "Authorization")))
    flaky_payload = json.loads(flaky.get("body") or b"{}")
    solid_payload = json.loads(solid.get("body") or b"{}")
    report(flaky_payload.get("max_tokens") == 4242
           and solid_payload.get("max_tokens") == 55555,
           "entry params beat manifest defaults, which beat built-ins",
           "%s / %s" % (flaky_payload.get("max_tokens"),
                        solid_payload.get("max_tokens")))
    efforts = ((flaky_payload.get("reasoning") or {}).get("effort"),
               (solid_payload.get("reasoning") or {}).get("effort"))
    report(efforts == ("xhigh", "low"),
           "effort resolves by the same three rungs as max_tokens",
           repr(efforts))
    # Entry 4 asks for "turbo", which no venue serves. A manifest is an
    # outside document: the level is dropped with a warning naming it, and
    # the run falls back through the rungs rather than sending it.
    report("turbo" in result.stderr and "unrecognized effort" in result.stderr
           and efforts[1] == "low",
           "an effort no venue serves is named and dropped, not forwarded",
           repr([line for line in result.stderr.splitlines()
                 if "effort" in line]))
    kinds = [(a.get("skipped") and "skip") or (a.get("error") and "error")
             or a.get("finish_reason") for a in stat.get("attempts") or []]
    report(kinds == ["skip", "skip", "error", "stop"],
           "the status record audits every entry: skip, skip, error, success",
           repr(kinds))
    report(bool((stat.get("manifest") or {}).get("sha256"))
           and stat.get("model") == "solid-free",
           "the winning entry and the manifest's sha256 are recorded")

    # Probe mode is the default: the first permitted entry's failure is the
    # run's failure, and no other venue is contacted.
    solid.clear()
    result = run_rewired(manifest_ox, ["--manifest", str(manifest),
         "--mode", "ask", "--status-file", str(sfile),
         "--log-dir", str(tmp / "mlogs"), "hello"], env=menv)
    report(result.returncode != 0 and "HTTP 429" in result.stderr and not solid,
           "without --failover the first permitted entry's failure stops the run",
           "exit=%s contacted=%r" % (result.returncode, bool(solid)))

    result = run_rewired(manifest_ox, ["--manifest", str(manifest),
         "--model", "m", "--mode", "ask",
         "--log-dir", str(tmp / "mlogs"), "hello"], env=menv)
    report(result.returncode != 0 and "conflicts" in result.stderr,
           "--model conflicts with --manifest instead of silently mixing")

    result = run_rewired(manifest_ox, ["--failover", "--mode", "ask",
         "--log-dir", str(tmp / "mlogs"), "hello"], env=menv)
    report(result.returncode != 0 and "requires --manifest" in result.stderr,
           "--failover without --manifest is refused")

    newer = tmp / "manifest-v99.json"
    newer.write_text(json.dumps({"manifest_version": 99,
                                 "recommendations": [{}]}), encoding="utf-8")
    result = run_rewired(manifest_ox, ["--manifest", str(newer),
         "--mode", "ask", "--log-dir", str(tmp / "mlogs"), "hello"], env=menv)
    report(result.returncode != 0 and "newer than this ox understands" in result.stderr,
           "a manifest from the future is refused, not misread")

    # The survey has more than one manifest-shaped document, and the one
    # ox does not read (corpus_version, projects) used to be refused as
    # though it were from the future -- advice that sends the operator
    # looking for an older copy of a file that was never a manifest.
    not_a_manifest = tmp / "corpus-shaped.json"
    not_a_manifest.write_text(json.dumps({
        "corpus_version": 1,
        "defaults": {"mode": "review", "effort": "high"},
        "projects": [{"id": "oxbox", "tasks": [{"id": "t1"}]}],
    }), encoding="utf-8")
    result = run_rewired(manifest_ox, ["--manifest", str(not_a_manifest),
         "--mode", "ask", "--log-dir", str(tmp / "mlogs"), "hello"], env=menv)
    report(result.returncode != 0
           and "is not a recommendations manifest" in result.stderr
           and "newer than this ox understands" not in result.stderr,
           "a document that is not a manifest is refused for that reason",
           repr(result.stderr.strip()[-120:]))

    paid_only = tmp / "manifest-paid.json"
    paid_only.write_text(json.dumps({
        "manifest_version": 0,
        "recommendations": [{"rank": 1, "venue": "openrouter",
                             "model": "top-paid", "cost": "paid"}],
    }), encoding="utf-8")
    result = run_rewired(manifest_ox, ["--manifest", str(paid_only),
         "--mode", "ask", "--log-dir", str(tmp / "mlogs"), "hello"], env=menv)
    # Match the summary's own per-entry line, not the reason text: ox also
    # prints a progress line per attempt, and both strings the old
    # assertion looked for appear there. Gutting the summary block left it
    # green while an operator lost which entries failed and why. The
    # summary is the only place those are aggregated under --failover.
    summary = [line for line in result.stderr.splitlines()
               if line.startswith("  [")]
    report(result.returncode != 0
           and "no manifest entry produced an answer" in result.stderr
           and summary == ["  [1] openrouter/top-paid: cost=paid "
                           "(pass --allow-paid to use it)"],
           "an all-skipped manifest exits with each entry's reason",
           repr(summary))
    print("\n=== a configured manifest stands in for --manifest ===")

    # `manifest` under [send] in config.ini is the manifest a run uses when
    # nothing on the command line names a destination. A typed --model or
    # --venue is a choice the config file does not overrule.
    cfg_home = tmp / "cfg-home"
    (cfg_home / "oxbox").mkdir(parents=True)
    (cfg_home / "oxbox" / "config.ini").write_text(
        "[send]\nmanifest = %s\n" % manifest, encoding="utf-8")
    cfg_env = dict(menv, XDG_CONFIG_HOME=str(cfg_home), APPDATA=str(cfg_home))
    solid.clear()
    result = run_rewired(manifest_ox, ["--failover", "--mode", "ask",
         "--status-file", str(sfile), "--log-dir", str(tmp / "mlogs"), "hello"],
         env=cfg_env)
    stat = json.loads(sfile.read_text()) if sfile.exists() else {}
    report(result.returncode == 0 and stat.get("model") == "solid-free"
           and (stat.get("manifest") or {}).get("path") == str(manifest)
           and "manifest from" in result.stderr,
           "with nothing typed, the configured manifest chooses and is announced",
           "exit=%s model=%r stderr=%r" % (result.returncode, stat.get("model"),
                                            result.stderr[-160:]))
    result = run_rewired(manifest_ox, ["--model", "typed", "--mode", "ask", "--dry-run",
         "--status-file", str(sfile), "--log-dir", str(tmp / "mlogs"), "hello"],
         env=cfg_env)
    stat = json.loads(sfile.read_text()) if sfile.exists() else {}
    report(result.returncode == 0 and stat.get("model") == "typed"
           and stat.get("manifest") is None,
           "a typed --model beats the configured manifest",
           "exit=%s model=%r manifest=%r" % (result.returncode, stat.get("model"),
                                             stat.get("manifest")))

    print("\n=== a provider pin rides through verbatim, or is refused ===")

    # An OpenRouter model id is a pool of endpoints, and price, output cap
    # and failure mode belong to the endpoint. The provider object is how a
    # caller says which; ox passes it through without reading it, sends it
    # only where the venue honors it, and never sends a pinned request
    # unpinned. OpenRouter is that venue, so here its URL points at the
    # listener that answers.
    pinned_venues = dict(local_venues, openrouter="http://127.0.0.1:%d/or/v1/chat/completions"
                         % solid_server.server_address[1])
    pin_ox = rewired_ox(tmp, "ox_pinned", venue_urls=pinned_venues)
    pin = {"only": ["novita"], "allow_fallbacks": False}
    pfile = tmp / "pinned-status.json"

    solid.clear()
    result = run_rewired(pin_ox, ["--venue", "openrouter", "--model", "m",
         "--provider", json.dumps(pin), "--mode", "ask", "--status-file", str(pfile),
         "--log-dir", str(tmp / "plogs"), "hello"], env=menv)
    body = json.loads(solid.get("body") or b"{}")
    pstat = json.loads(pfile.read_text()) if pfile.exists() else {}
    report(result.returncode == 0 and body.get("provider") == pin,
           "--provider lands in the request body verbatim",
           "exit=%s provider=%r" % (result.returncode, body.get("provider")))
    pmeta = {}
    if pstat.get("log_dir"):
        pmeta = json.loads((Path(pstat["log_dir"]) / "meta.json").read_text(encoding="utf-8"))
    report(pmeta.get("provider") == pin,
           "meta.json records the pin the request went out with",
           repr(pmeta.get("provider")))

    solid.clear()
    result = run_rewired(pin_ox, ["--venue", "openrouter", "--model", "m",
         "--mode", "ask", "--status-file", str(pfile),
         "--log-dir", str(tmp / "plogs"), "hello"], env=menv)
    body = json.loads(solid.get("body") or b"{}")
    pmeta = {}
    if pstat.get("log_dir"):
        pstat = json.loads(pfile.read_text())
        pmeta = json.loads((Path(pstat["log_dir"]) / "meta.json").read_text(encoding="utf-8"))
    report(result.returncode == 0 and "provider" not in body
           and "provider" in pmeta and pmeta["provider"] is None,
           "without a pin the request carries no provider key and meta.json says null",
           "keys=%r meta=%r" % (sorted(body), pmeta.get("provider", "absent")))

    # A manifest entry carries the pin the survey measured with. One whose
    # venue cannot honor it, or whose pin is not an object, is skipped with
    # the reason rather than sent unpinned; the first entry that can carry
    # its pin is the one that goes out, with the pin on it.
    pinned = tmp / "manifest-pinned.json"
    pinned.write_text(json.dumps({
        "manifest_version": 1,
        "recommendations": [
            {"rank": 1, "venue": "opencode", "model": "oc/pinned", "cost": "free",
             "provider": pin},
            {"rank": 2, "venue": "openrouter", "model": "or/badpin", "cost": "free",
             "provider": "novita"},
            {"rank": 3, "venue": "openrouter", "model": "or/pinned", "cost": "free",
             "provider": pin},
        ],
    }), encoding="utf-8")
    solid.clear()
    result = run_rewired(pin_ox, ["--manifest", str(pinned), "--mode", "ask",
         "--status-file", str(pfile), "--log-dir", str(tmp / "plogs"), "hello"], env=menv)
    pstat = json.loads(pfile.read_text()) if pfile.exists() else {}
    body = json.loads(solid.get("body") or b"{}")
    report(result.returncode == 0 and pstat.get("model") == "or/pinned"
           and body.get("model") == "or/pinned" and body.get("provider") == pin,
           "a version-1 manifest entry's pin rides with its request",
           "exit=%s model=%r provider=%r" % (result.returncode, body.get("model"),
                                             body.get("provider")))
    skips = [a.get("skipped") for a in pstat.get("attempts") or []][:2]
    report(skips == ["provider pin on venue opencode, which does not honor one",
                     "provider is not an object"],
           "an entry whose pin cannot be honored is skipped with the reason, not sent unpinned",
           repr(skips))

    solid.clear()
    override = {"order": ["deepinfra"], "allow_fallbacks": False}
    result = run_rewired(pin_ox, ["--manifest", str(pinned), "--provider",
         json.dumps(override), "--mode", "ask", "--log-dir", str(tmp / "plogs"),
         "hello"], env=menv)
    body = json.loads(solid.get("body") or b"{}")
    report(result.returncode == 0 and body.get("provider") == override,
           "--provider beats the manifest entry's own pin",
           "exit=%s provider=%r" % (result.returncode, body.get("provider")))

    solid.clear()
    result = run_rewired(pin_ox, ["--venue", "opencode", "--model", "m",
         "--provider", json.dumps(pin), "--mode", "ask",
         "--log-dir", str(tmp / "plogs"), "hello"], env=menv)
    report(result.returncode == 1 and "does not honor one" in result.stderr and not solid,
           "--provider on a venue that cannot honor it is refused before anything is sent",
           "exit=%s sent=%r stderr=%r" % (result.returncode, bool(solid), result.stderr[-120:]))

    result = run_rewired(pin_ox, ["--model", "m", "--provider", "novita",
         "--mode", "ask", "--log-dir", str(tmp / "plogs"), "hello"], env=menv)
    report(result.returncode == 2 and "argument --provider" in result.stderr,
           "--provider that is not a JSON object is a usage error, not a request",
           "exit=%s stderr=%r" % (result.returncode, result.stderr[-120:]))

    print("\n=== a manifest may be fetched by URL, carrying nothing ===")

    # The survey publishes latest.json at a stable URL. Fetching it must behave
    # like reading a file, except for what a download can add: a cleartext
    # path, a redirect, a body that is not a manifest, and a credential riding
    # along. Each is refused or absent, and each is tested.
    served = {}
    manifest_bytes = json.dumps({
        "manifest_version": 0,
        "issue_date": "2026-09-01",
        "recommendations": [{"rank": 1, "venue": "opencode",
                             "model": "solid-free", "cost": "free"}],
    }).encode("utf-8")
    manifest_server = serve(capture_handler(
        served, body=manifest_bytes, headers={"Content-Type": "application/json"}))
    manifest_url = ("http://127.0.0.1:%d/manifests/latest.json"
                    % manifest_server.server_address[1])

    result = run_rewired(manifest_ox, ["--manifest", manifest_url,
         "--mode", "ask", "--log-dir", str(tmp / "ulogs"), "hello"], env=menv)
    report(result.returncode != 0 and "https://" in result.stderr and not served,
           "a plaintext manifest URL is refused before anything is fetched",
           "exit=%s served=%r stderr=%r" % (result.returncode, bool(served),
                                             result.stderr[-160:]))

    # As with send_to_local: relax only the scheme guard, in a copy or a test
    # build, so the loopback listener can stand in for the survey's https host.
    reference = (HERE / "python" / "oxbox-send").read_text(encoding="utf-8")
    guard = 'if not url.startswith("https://"):'
    report(reference.count(guard) == 1, "the manifest scheme guard is one line, patchable")
    url_ox = rewired_ox(tmp, "ox_manifest_url", allow_http=True, venue_urls=local_venues)

    solid.clear()
    ufile = tmp / "url-status.json"
    result = run_rewired(url_ox, ["--manifest", manifest_url,
         "--mode", "ask", "--status-file", str(ufile),
         "--log-dir", str(tmp / "ulogs"), "hello"], env=menv)
    stat = json.loads(ufile.read_text()) if ufile.exists() else {}
    report(result.returncode == 0 and result.stdout.strip() == "ok"
           and stat.get("model") == "solid-free",
           "a manifest fetched by URL picks the destination like a file",
           "exit=%s stderr=%r" % (result.returncode, result.stderr[-160:]))
    fetch_headers = {k.lower(): v for k, v in (served.get("headers") or {}).items()}
    report(served.get("path") == "/manifests/latest.json"
           and "authorization" not in fetch_headers
           and fetch_headers.get("user-agent", "").startswith("oxbox"),
           "the manifest fetch carries no credential and names its client",
           repr(fetch_headers))
    log_dir = Path(stat.get("log_dir") or tmp / "nowhere")
    meta_path = log_dir / "meta.json"
    meta = json.loads(meta_path.read_text()) if meta_path.exists() else {}
    copy = log_dir / "manifest.json"
    recorded = meta.get("manifest") or {}
    report(copy.exists() and copy.read_bytes() == manifest_bytes
           and recorded.get("path") == manifest_url
           and recorded.get("fetched") is True
           and recorded.get("sha256") == hashlib.sha256(manifest_bytes).hexdigest(),
           "the fetched bytes are kept beside the request, named by URL and digest",
           "copy=%s recorded=%r" % (copy.exists(), recorded))

    class Bouncer(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(302)
            self.send_header("Location", manifest_url)
            self.end_headers()

        def log_message(self, *args):
            pass

    bouncer = serve(Bouncer)
    result = run_rewired(url_ox, ["--manifest",
         "http://127.0.0.1:%d/moved.json" % bouncer.server_address[1],
         "--mode", "ask", "--log-dir", str(tmp / "ulogs"), "hello"], env=menv)
    report(result.returncode != 0 and "redirected" in result.stderr
           and "Traceback" not in result.stderr,
           "a redirecting manifest URL is refused, not followed",
           "exit=%s stderr=%r" % (result.returncode, result.stderr[-160:]))

    missing = serve(capture_handler({}, status=404, body=b"not here",
                                    headers={"Content-Type": "text/plain"}))
    result = run_rewired(url_ox, ["--manifest",
         "http://127.0.0.1:%d/manifests/gone.json" % missing.server_address[1],
         "--mode", "ask", "--log-dir", str(tmp / "ulogs"), "hello"], env=menv)
    report(result.returncode != 0 and "HTTP 404" in result.stderr
           and "Traceback" not in result.stderr,
           "a missing manifest URL fails in one line, not a traceback",
           "exit=%s stderr=%r" % (result.returncode, result.stderr[-160:]))

    cap = "MANIFEST_MAX_BYTES = 1_048_576"
    report(reference.count(cap) == 1, "the manifest size cap is one line, patchable")
    small_ox = rewired_ox(tmp, "ox_manifest_small", allow_http=True,
                          venue_urls=local_venues, manifest_cap=32)
    result = run_rewired(small_ox, ["--manifest", manifest_url,
                                    "--mode", "ask", "--log-dir", str(tmp / "ulogs"), "hello"],
                         env=menv)
    report(result.returncode != 0 and "larger than" in result.stderr,
           "a manifest body past the size cap is refused",
           "exit=%s stderr=%r" % (result.returncode, result.stderr[-160:]))
    for server in (manifest_server, bouncer, missing, flaky_server, solid_server):
        server.shutdown()

    print("\n=== the audit log survives collisions ===")

    logs = tmp / "collide"
    logs.mkdir(parents=True, exist_ok=True)
    # Three runs in the same second must not share a directory, because a
    # shared one overwrites request.json. Each run carries a task nobody
    # else sends, which is what lets the second assertion below check that
    # every record survived rather than merely that some file is present.
    tasks = ["collide-one", "collide-two", "collide-three"]
    for task in tasks:
        store = {}
        server = serve(capture_handler(store))
        url = "http://127.0.0.1:%d/v1" % server.server_address[1]
        run_rewired(rewired_ox(tmp, "ox_local", allow_http=True),
                    ["--base-url", url, "--api-key-env", "OX_TEST_KEY", "--model", "m",
                     "--mode", "ask", "--log-dir", str(logs), task],
                    env={"OX_TEST_KEY": "sk-test-canary"})
        server.shutdown()
    dirs = [d for d in logs.iterdir() if d.is_dir()]
    stamps = set(d.name for d in dirs)
    report(len(dirs) == 3 and len(stamps) == 3,
           "three rapid runs get three distinct log directories",
           "got %d: %s" % (len(dirs), sorted(stamps)))
    # Existence was the old assertion and it could not fail: a directory
    # that survived a collision still holds a request.json -- the last
    # writer's. Reverting make_log_dir to mkdir(exist_ok=True) turned the
    # case above red and left this one green, which is the whole point of
    # the pair. Read the tasks back instead: three distinct tasks recorded
    # means three records survived, and an overwrite loses one.
    recorded = set()
    for d in dirs:
        request = d / "request.json"
        if not request.exists():
            continue
        payload = json.loads(request.read_text(encoding="utf-8"))
        recorded.add(payload["messages"][-1]["content"].strip())
    report(recorded == set(tasks),
           "every run kept its own request.json, not just some file",
           "recorded %s" % sorted(recorded))

    print("\nplatform: %s" % sys.platform)
    total = PASSES + len(FAILURES)
    tail = ", %d skipped" % SKIPPED if SKIPPED else ""
    if FAILURES:
        print("wire contract broken: %d/%d passed%s" % (PASSES, total, tail))
        for label in FAILURES:
            print("  - %s" % label)
        return 1
    print("wire contract holds: %d/%d passed%s" % (PASSES, total, tail))
    return 0


if __name__ == "__main__":
    sys.exit(main())
