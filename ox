#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Curtis Galloway
# SPDX-License-Identifier: Apache-2.0
"""Supervised bridge to an untrusted OpenRouter model.

Text in, text out. No tools are ever registered with the model, so it has no
way to run a command, read a file it was not handed, or write to disk. Every
request and response is logged for audit. The caller reviews the output before
anything touches a real tree.
"""

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

API_URL = "https://openrouter.ai/api/v1/chat/completions"
DEFAULT_MODEL = "stealth/ox-alpha"
MAX_PAYLOAD_BYTES = 400_000
TIMEOUT_SECONDS = 900

SECRET_PATTERNS = [
    (r"sk-[A-Za-z0-9_\-]{20,}", "OpenAI-style API key"),
    (r"sk-ant-[A-Za-z0-9_\-]{20,}", "Anthropic API key"),
    (r"ghp_[A-Za-z0-9]{36}", "GitHub personal access token"),
    (r"github_pat_[A-Za-z0-9_]{50,}", "GitHub fine-grained token"),
    (r"AKIA[0-9A-Z]{16}", "AWS access key id"),
    (r"xox[baprs]-[A-Za-z0-9\-]{10,}", "Slack token"),
    (r"-----BEGIN [A-Z ]*PRIVATE KEY-----", "private key block"),
    (r"(?i)\b(api[_\-]?key|secret|password|token)\b\s*[:=]\s*[\"'][^\"'\s]{16,}[\"']",
     "hardcoded credential assignment"),
]

SYSTEM_PROMPTS = {
    "diff": (
        "You are a software engineer. Produce a fix for the task described.\n"
        "\n"
        "Output contract, strictly:\n"
        "1. A short plain-text explanation of what you changed and why (max 10 lines).\n"
        "2. Then a single fenced block tagged `diff` containing a unified diff.\n"
        "\n"
        "Diff rules:\n"
        "- Use `--- a/<path>` and `+++ b/<path>` headers with the exact paths given to you.\n"
        "- Include at least 3 lines of context per hunk so the patch applies cleanly.\n"
        "- Change only what the task requires. Do not reformat, rename, or tidy\n"
        "  unrelated code. Do not add dependencies unless the task requires it, and\n"
        "  if you do, say so explicitly in the explanation.\n"
        "- If you cannot solve it, say so plainly instead of guessing."
    ),
    "review": (
        "You are reviewing code. Report concrete defects only: correctness bugs,\n"
        "security issues, resource leaks, race conditions, incorrect error handling.\n"
        "\n"
        "For each finding give: file and line, a one-sentence statement of the defect,\n"
        "and a concrete failure scenario (specific inputs or state leading to the wrong\n"
        "outcome). If you are not confident a finding is real, label it UNCERTAIN.\n"
        "Do not report style preferences. If the code is fine, say so."
    ),
    "ask": (
        "Answer the question directly and concretely. If you are uncertain about an\n"
        "API, a version, or a behavior, say that you are uncertain rather than\n"
        "presenting a guess as fact."
    ),
}


def scan_for_secrets(text, label):
    hits = []
    for pattern, description in SECRET_PATTERNS:
        for match in re.finditer(pattern, text):
            line_no = text.count("\n", 0, match.start()) + 1
            hits.append(f"{label}:{line_no}: possible {description}")
    return hits


def build_context(paths, force):
    blocks = []
    findings = []
    total = 0
    for raw in paths:
        path = Path(raw)
        if not path.is_file():
            sys.exit(f"ox: not a file: {raw}")
        try:
            body = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            sys.exit(f"ox: not a text file: {raw}")
        total += len(body.encode("utf-8"))
        findings.extend(scan_for_secrets(body, raw))
        suffix = path.suffix.lstrip(".") or "text"
        blocks.append(f"### File: {raw}\n```{suffix}\n{body}\n```")

    if findings and not force:
        sys.stderr.write("ox: refusing to send; possible secrets detected:\n")
        for finding in findings:
            sys.stderr.write(f"  {finding}\n")
        sys.stderr.write(
            "ox: this model logs prompts and shares them with the provider.\n"
            "ox: remove the secrets, or re-run with --force if these are false positives.\n"
        )
        sys.exit(2)

    if total > MAX_PAYLOAD_BYTES and not force:
        sys.exit(
            f"ox: refusing to send {total} bytes of context "
            f"(limit {MAX_PAYLOAD_BYTES}); narrow --files or pass --force"
        )

    return "\n\n".join(blocks), total, findings


def main():
    parser = argparse.ArgumentParser(
        prog="ox",
        description="Send a task to an untrusted model. No tools, full audit log.",
    )
    parser.add_argument("task", nargs="?", help="the task or question (or use --stdin)")
    parser.add_argument("--files", default="",
                        help="comma-separated files to include as context")
    parser.add_argument("--mode", choices=sorted(SYSTEM_PROMPTS), default="diff",
                        help="output contract (default: diff)")
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument("--effort", choices=["low", "high", "max"], default="high")
    parser.add_argument("--max-tokens", type=int, default=32000)
    parser.add_argument("--temperature", type=float, default=0.2)
    parser.add_argument("--stdin", action="store_true",
                        help="read the task from stdin instead of an argument")
    parser.add_argument("--log-dir", default=str(Path(__file__).resolve().parent / "logs"))
    parser.add_argument("--force", action="store_true",
                        help="send even if the secret scan or size guard trips")
    parser.add_argument("--dry-run", action="store_true",
                        help="build and log the request, print it, send nothing")
    args = parser.parse_args()

    task = sys.stdin.read() if args.stdin else args.task
    if not task or not task.strip():
        sys.exit("ox: no task given")

    api_key = os.environ.get("OPENROUTER_API_KEY")
    if not api_key and not args.dry_run:
        sys.exit("ox: OPENROUTER_API_KEY not set (run under: op run --env-file .env -- ./ox ...)")

    paths = [p.strip() for p in args.files.split(",") if p.strip()]
    context, total_bytes, findings = build_context(paths, args.force)

    user_content = f"{task.strip()}\n\n{context}" if context else task.strip()

    payload = {
        "model": args.model,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPTS[args.mode]},
            {"role": "user", "content": user_content},
        ],
        "max_tokens": args.max_tokens,
        "temperature": args.temperature,
        "reasoning": {"effort": args.effort},
        "include_reasoning": True,
    }

    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H-%M-%SZ")
    log_dir = Path(args.log_dir) / stamp
    log_dir.mkdir(parents=True, exist_ok=True)
    (log_dir / "request.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")
    (log_dir / "meta.json").write_text(json.dumps({
        "timestamp": stamp,
        "model": args.model,
        "mode": args.mode,
        "effort": args.effort,
        "files": paths,
        "context_bytes": total_bytes,
        "secret_scan_hits": findings,
        "forced": args.force,
    }, indent=2), encoding="utf-8")

    sys.stderr.write(f"ox: log -> {log_dir}\n")
    sys.stderr.write(f"ox: model={args.model} mode={args.mode} effort={args.effort} "
                     f"context={total_bytes}B files={len(paths)}\n")

    if args.dry_run:
        sys.stderr.write("ox: dry run, nothing sent\n")
        print(json.dumps(payload, indent=2))
        return

    request = urllib.request.Request(
        API_URL,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "X-Title": "sketchy-ai supervised bridge",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:
            body = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as error:
        detail = error.read().decode("utf-8", "replace")
        (log_dir / "error.txt").write_text(f"{error.code}\n{detail}", encoding="utf-8")
        sys.exit(f"ox: HTTP {error.code}: {detail[:500]}")
    except urllib.error.URLError as error:
        sys.exit(f"ox: network error: {error.reason}")

    (log_dir / "response.json").write_text(json.dumps(body, indent=2), encoding="utf-8")

    if "error" in body and body["error"]:
        sys.exit(f"ox: api error: {json.dumps(body['error'])[:500]}")

    choice = body.get("choices", [{}])[0]
    message = choice.get("message", {}) or {}
    reasoning = message.get("reasoning") or ""
    content = message.get("content") or ""

    if reasoning:
        (log_dir / "reasoning.txt").write_text(reasoning, encoding="utf-8")
    (log_dir / "content.md").write_text(content, encoding="utf-8")

    tool_calls = message.get("tool_calls")
    if tool_calls:
        sys.stderr.write(
            "ox: WARNING: model emitted tool_calls despite no tools being offered; "
            "logged but ignored\n"
        )

    usage = body.get("usage", {}) or {}
    sys.stderr.write(
        f"ox: finish={choice.get('finish_reason')} "
        f"prompt_tokens={usage.get('prompt_tokens')} "
        f"completion_tokens={usage.get('completion_tokens')} "
        f"reasoning_chars={len(reasoning)}\n"
    )

    print(content)


if __name__ == "__main__":
    main()
