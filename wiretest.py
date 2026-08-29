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

import json
import os
import subprocess
import sys
import threading
import http.server
from pathlib import Path

HERE = Path(__file__).resolve().parent
OX = [sys.executable, str(HERE / "ox")]

FAILURES = []
PASSES = 0


def report(ok, label, note=""):
    global PASSES
    if ok:
        PASSES += 1
        print("[PASS] %s" % label)
    else:
        FAILURES.append(label)
        print("[FAIL] %s%s" % (label, ("  (%s)" % note) if note else ""))


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
    source = (HERE / "ox").read_text(encoding="utf-8")
    source = source.replace('if __name__ == "__main__":', "if False:")
    # __file__ too, not just __name__: a real import provides both, and ox
    # anchors its script-relative asset lookup (find_skill) on __file__ the
    # way oxbox anchors find_profile. A namespace missing it does not fail
    # like the real module, it fails at import with a NameError.
    namespace = {"__name__": "oxmod", "__file__": str(HERE / "ox")}
    exec(compile(source, str(HERE / "ox"), "exec"), namespace)
    return namespace


def run_ox(argv, env=None, timeout=60):
    environ = dict(os.environ)
    environ.update(env or {})
    return subprocess.run(OX + argv, capture_output=True, text=True,
                          timeout=timeout, env=environ)


def send_to_local(store, tmp, extra_argv=None, **kwargs):
    """Drive ox at a local listener, bypassing only the https scheme guard.

    The guard is a separate, directly tested behaviour; relaxing it here is what
    lets every other wire assertion run without a real provider.
    """
    server = serve(capture_handler(store, **kwargs))
    url = "http://127.0.0.1:%d/v1/chat/completions" % server.server_address[1]
    patched = tmp / "ox_local"
    source = (HERE / "ox").read_text(encoding="utf-8")
    source = source.replace('if not args.base_url.startswith("https://"):', "if False:")
    patched.write_text(source, encoding="utf-8")
    argv = [sys.executable, str(patched), "--base-url", url,
            "--api-key-env", "OX_TEST_KEY", "--model", "test-model",
            "--log-dir", str(tmp / "logs")] + (extra_argv or ["--mode", "ask", "hello"])
    result = subprocess.run(argv, capture_output=True, text=True, timeout=60,
                            env=dict(os.environ, OX_TEST_KEY="sk-test-canary"))
    server.shutdown()
    return result


def main():
    import tempfile
    tmp = Path(tempfile.mkdtemp(prefix="wiretest-"))
    ox = load_ox()

    print("=== one version, declared four times, all equal ===")

    # Each tool is a standalone script, so each carries its own VERSION
    # constant. Four copies of one fact drift unless something checks; this
    # is the check, same pattern as the env_canary list agreement below.
    import re as _re
    versions = {}
    for tool in ("ox", "oxbox", "oxapply", "oxseed"):
        match = _re.search(r'^VERSION = "([^"]+)"', (HERE / tool).read_text(encoding="utf-8"),
                           _re.MULTILINE)
        versions[tool] = match.group(1) if match else None
    report(len(set(versions.values())) == 1 and None not in versions.values(),
           "all four tools declare the same VERSION", repr(versions))
    result = run_ox(["--version"])
    report(result.returncode == 0
           and result.stdout.strip() == "ox %s" % ox["VERSION"],
           "ox --version prints it", repr(result.stdout))

    # Same hazard, bigger payload: find_skill/print_skill is carried by each
    # tool because each is a standalone script, and four copies of one
    # document drift unless something compares them. Compare the output
    # rather than the source — that is what a caller actually receives, and
    # it catches a lookup that silently resolves somewhere else as well as a
    # block someone edited in one file only.
    skills = {}
    for tool in ("ox", "oxbox", "oxapply", "oxseed"):
        done = subprocess.run([sys.executable, str(HERE / tool), "--skill"],
                              capture_output=True, text=True, timeout=30)
        skills[tool] = (done.returncode, done.stdout)
    codes = {tool: code for tool, (code, _) in skills.items()}
    report(set(codes.values()) == {0},
           "every tool exits 0 for --skill", repr(codes))
    bodies = {text for _, text in skills.values()}
    report(len(bodies) == 1 and next(iter(bodies)).startswith("---"),
           "all four tools print the same skill",
           "%d distinct outputs, lengths %r"
           % (len(bodies), sorted(len(text) for _, text in skills.values())))
    # The provenance line is the one part that differs, and it has to name the
    # tool you actually ran or an error message points at the wrong program.
    prefixes = {}
    for tool in ("ox", "oxbox", "oxapply", "oxseed"):
        done = subprocess.run([sys.executable, str(HERE / tool), "--skill"],
                              capture_output=True, text=True, timeout=30)
        prefixes[tool] = done.stderr.startswith("%s: skill -> " % tool)
    report(all(prefixes.values()),
           "each tool names itself on the provenance line", repr(prefixes))

    # Installed tools anchor state at the working directory, not the script's:
    # /usr/bin/logs is not a thing. A dry run from a scratch directory must
    # leave its log there and nothing in the repo.
    scratch = tmp / "scratch-cwd"
    scratch.mkdir()
    result = subprocess.run(OX + ["--mode", "ask", "--dry-run", "t"],
                            capture_output=True, text=True, timeout=60,
                            cwd=str(scratch))
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

    report(headers.get("Authorization") == "Bearer sk-test-canary",
           "Authorization carries the value of the named env var",
           repr(headers.get("Authorization")))
    report(headers.get("Content-Type") == "application/json",
           "Content-Type is application/json")

    # urllib defaults to Python-urllib/3.x, which OpenCode Zen's Cloudflare
    # rejects with 403 before routing. That shipped once; it does not again.
    agent = headers.get("User-Agent", "")
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
    patched = tmp / "ox_local"
    source = (HERE / "ox").read_text(encoding="utf-8")
    source = source.replace('if not args.base_url.startswith("https://"):', "if False:")
    patched.write_text(source, encoding="utf-8")
    result = subprocess.run(
        [sys.executable, str(patched),
         "--base-url", "http://127.0.0.1:%d/v1" % redirector.server_address[1],
         "--api-key-env", "OX_TEST_KEY", "--model", "m", "--mode", "ask",
         "--log-dir", str(tmp / "redirlogs"), "task"],
        capture_output=True, text=True, timeout=60,
        env=dict(os.environ, OX_TEST_KEY="sk-test-canary"))

    got = leaked.get("headers") or {}
    report("Authorization" not in got,
           "ox does not forward Authorization across a redirect",
           "leaked: %r" % got.get("Authorization"))
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
    report(stat.get("ok") is True and stat.get("exit_code") == 0
           and stat.get("finish_reason") == "stop",
           "--status-file records a successful run",
           json.dumps(stat)[:160])
    report(bool(stat.get("log_dir"))
           and (Path(stat["log_dir"]) / "status.json").exists(),
           "status.json also lands beside the audit log")

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
    source = (HERE / "ox").read_text(encoding="utf-8")
    source = source.replace(
        "https://openrouter.ai/api/v1/chat/completions",
        "http://127.0.0.1:%d/or/v1/chat/completions" % flaky_server.server_address[1])
    source = source.replace(
        "https://opencode.ai/zen/v1/chat/completions",
        "http://127.0.0.1:%d/oc/v1/chat/completions" % solid_server.server_address[1])
    patched = tmp / "ox_manifest"
    patched.write_text(source, encoding="utf-8")

    manifest = tmp / "manifest.json"
    manifest.write_text(json.dumps({
        "manifest_version": 0,
        "issue_date": "2026-08-27",
        "defaults": {"max_tokens": 55555},
        "recommendations": [
            {"rank": 1, "venue": "openrouter", "model": "top-paid",
             "cost": "paid", "why": "best, but costs money"},
            {"rank": 2, "venue": "acme", "model": "x", "cost": "free"},
            {"rank": 3, "venue": "openrouter", "model": "flaky-free",
             "cost": "free", "params": {"max_tokens": 4242}},
            {"rank": 4, "venue": "opencode", "model": "solid-free",
             "cost": "free"},
        ],
    }), encoding="utf-8")
    menv = dict(os.environ,
                OPENROUTER_API_KEY="sk-canary-openrouter",
                OPENCODE_ZEN_API_KEY="sk-canary-opencode")
    sfile = tmp / "manifest-status.json"

    result = subprocess.run(
        [sys.executable, str(patched), "--manifest", str(manifest),
         "--failover", "--mode", "ask", "--status-file", str(sfile),
         "--log-dir", str(tmp / "mlogs"), "hello"],
        capture_output=True, text=True, timeout=60, env=menv)
    stat = json.loads(sfile.read_text()) if sfile.exists() else {}
    report(result.returncode == 0 and result.stdout.strip() == "ok",
           "--failover lands on the first working entry",
           "exit=%s stderr=%r" % (result.returncode, result.stderr[-160:]))
    report((flaky.get("headers") or {}).get("Authorization") == "Bearer sk-canary-openrouter"
           and (solid.get("headers") or {}).get("Authorization") == "Bearer sk-canary-opencode",
           "each attempt carries its own venue's key, never another's",
           "%r / %r" % ((flaky.get("headers") or {}).get("Authorization"),
                        (solid.get("headers") or {}).get("Authorization")))
    flaky_payload = json.loads(flaky.get("body") or b"{}")
    solid_payload = json.loads(solid.get("body") or b"{}")
    report(flaky_payload.get("max_tokens") == 4242
           and solid_payload.get("max_tokens") == 55555,
           "entry params beat manifest defaults, which beat built-ins",
           "%s / %s" % (flaky_payload.get("max_tokens"),
                        solid_payload.get("max_tokens")))
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
    result = subprocess.run(
        [sys.executable, str(patched), "--manifest", str(manifest),
         "--mode", "ask", "--status-file", str(sfile),
         "--log-dir", str(tmp / "mlogs"), "hello"],
        capture_output=True, text=True, timeout=60, env=menv)
    report(result.returncode != 0 and "HTTP 429" in result.stderr and not solid,
           "without --failover the first permitted entry's failure stops the run",
           "exit=%s contacted=%r" % (result.returncode, bool(solid)))

    result = subprocess.run(
        [sys.executable, str(patched), "--manifest", str(manifest),
         "--model", "m", "--mode", "ask",
         "--log-dir", str(tmp / "mlogs"), "hello"],
        capture_output=True, text=True, timeout=60, env=menv)
    report(result.returncode != 0 and "conflicts" in result.stderr,
           "--model conflicts with --manifest instead of silently mixing")

    result = subprocess.run(
        [sys.executable, str(patched), "--failover", "--mode", "ask",
         "--log-dir", str(tmp / "mlogs"), "hello"],
        capture_output=True, text=True, timeout=60, env=menv)
    report(result.returncode != 0 and "requires --manifest" in result.stderr,
           "--failover without --manifest is refused")

    newer = tmp / "manifest-v99.json"
    newer.write_text(json.dumps({"manifest_version": 99,
                                 "recommendations": [{}]}), encoding="utf-8")
    result = subprocess.run(
        [sys.executable, str(patched), "--manifest", str(newer),
         "--mode", "ask", "--log-dir", str(tmp / "mlogs"), "hello"],
        capture_output=True, text=True, timeout=60, env=menv)
    report(result.returncode != 0 and "newer than this ox understands" in result.stderr,
           "a manifest from the future is refused, not misread")

    paid_only = tmp / "manifest-paid.json"
    paid_only.write_text(json.dumps({
        "manifest_version": 0,
        "recommendations": [{"rank": 1, "venue": "openrouter",
                             "model": "top-paid", "cost": "paid"}],
    }), encoding="utf-8")
    result = subprocess.run(
        [sys.executable, str(patched), "--manifest", str(paid_only),
         "--mode", "ask", "--log-dir", str(tmp / "mlogs"), "hello"],
        capture_output=True, text=True, timeout=60, env=menv)
    report(result.returncode != 0
           and "no manifest entry produced an answer" in result.stderr
           and "--allow-paid" in result.stderr,
           "an all-skipped manifest exits with each entry's reason")
    for server in (flaky_server, solid_server):
        server.shutdown()

    print("\n=== the audit log survives collisions ===")

    logs = tmp / "collide"
    store = {}
    for _ in range(3):
        send_to_local(store, tmp.__class__(str(tmp)), extra_argv=["--mode", "ask", "x"])
    # Directly exercise the collision path: three runs in the same second must
    # not share a directory, because a shared one overwrites request.json.
    stamps = set()
    logs.mkdir(parents=True, exist_ok=True)
    for _ in range(3):
        store = {}
        server = serve(capture_handler(store))
        url = "http://127.0.0.1:%d/v1" % server.server_address[1]
        patched = tmp / "ox_local"
        subprocess.run([sys.executable, str(patched), "--base-url", url,
                        "--api-key-env", "OX_TEST_KEY", "--model", "m",
                        "--mode", "ask", "--log-dir", str(logs), "x"],
                       capture_output=True, text=True, timeout=60,
                       env=dict(os.environ, OX_TEST_KEY="sk-test-canary"))
        server.shutdown()
    dirs = [d for d in logs.iterdir() if d.is_dir()]
    stamps = set(d.name for d in dirs)
    report(len(dirs) == 3 and len(stamps) == 3,
           "three rapid runs get three distinct log directories",
           "got %d: %s" % (len(dirs), sorted(stamps)))
    report(all((d / "request.json").exists() for d in dirs),
           "every run kept its own request.json")

    print("\nplatform: %s" % sys.platform)
    total = PASSES + len(FAILURES)
    if FAILURES:
        print("wire contract broken: %d/%d passed" % (PASSES, total))
        for label in FAILURES:
            print("  - %s" % label)
        return 1
    print("wire contract holds: %d/%d passed" % (PASSES, total))
    return 0


if __name__ == "__main__":
    sys.exit(main())
