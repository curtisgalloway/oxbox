<!--
SPDX-FileCopyrightText: 2026 Curtis Galloway
SPDX-License-Identifier: Apache-2.0
-->

# oxbox

A small harness for pointing an **untrusted** LLM at your code without giving it
your machine.

There is a steady supply of "cloaked" models on OpenRouter — anonymous,
free, suspiciously capable. Free is the tell: you are paying in data, and you
don't know who the counterparty is. This repo exists so you can *try* one
anyway, on real code, without extending it any trust it hasn't earned.

The default target is `stealth/ox-alpha`, but nothing here is specific to it.
Point `--model` at whatever you're suspicious of this week.

## The premise

The model is treated as capable, opaque, and possibly wrong. Nothing in the
design depends on it being benign. It gets **no tools, no shell, no filesystem,
and no network path back into your machine.** It emits text. A human (or a
supervising agent) reads that text before any of it executes.

## The five layers

| Layer | Mechanism |
|---|---|
| **No hands** | `ox` sends a chat completion with **no `tools` array**. The model cannot run, read, or write anything. If it emits `tool_calls` regardless, `ox` logs and warns. |
| **Explicit context** | It sees only files passed to `--files`. A credential scanner refuses to send anything matching common key patterns. |
| **Patch quarantine** | `oxapply` applies diffs **only** into `sandbox/work`, and rejects absolute paths and `..` traversal outright. |
| **Execution jail** | `oxbox` runs code under a macOS seatbelt profile with **no network** and **no writes outside the sandbox**, with the parent environment cleared (`env -i`) so no inherited secret crosses in. `fdguard.py` refuses to start if stdout/stderr point at a file outside the sandbox. |
| **Audit trail** | Every call writes `logs/<timestamp>/` with the exact request, raw response, extracted content, and metadata. The API key is never logged. |

The jail is not taken on faith. `jailtest.py` runs 14 probes from *inside* it —
TCP, UDP, DNS, `~/.ssh`, `~/.aws`, `~/.claude`, Keychains, shell history,
`.env`, `stat()` as a metadata oracle, environment inheritance, and escape
writes to both the repo and your home directory:

```
$ ./oxbox -- python3 jailtest.py
[PASS] network: outbound TCP to 1.1.1.1:443  (PermissionError)
[PASS] network: DNS resolution               (gaierror)
[PASS] fs read: ~/.ssh                       (PermissionError)
[PASS] fs write: home dir (escape)           (PermissionError)
[PASS] env: parent environment not inherited (succeeded)
...
jail holds: 14/14 probes passed
```

The checks that run *before* the jail — argument validation, patch validation,
the secret scanner, the inherited-descriptor guard — can't be reached from
inside it, so they get their own suite:

```
$ ./guardtest.sh
[PASS] oxseed refuses parent traversal
[PASS] oxbox refuses --work outside sandbox/
[PASS] oxbox refuses stdout redirected outside the sandbox
[PASS] oxapply refuses traversal in rename headers
[PASS] ox refuses a key in the task argument
...
guards hold: 14/14 passed
```

Every case in it is a regression test for a defect that was actually found and
reproduced, not a hypothetical. Run both suites after any change to
`profiles/jail.sb`, `oxbox`, or the validators. A jail you haven't tested is
decoration.

## Setup

Requires macOS (the jail uses `sandbox-exec`), Python 3, and git. No
third-party Python packages — `ox` is stdlib only, deliberately.

```bash
git clone https://github.com/<you>/oxbox
cd oxbox
export OPENROUTER_API_KEY=sk-or-v1-...
```

If you use 1Password, copy `.env.example` to `.env`, point it at your item, and
prefix commands with `op run --env-file .env --`. Any method that puts
`OPENROUTER_API_KEY` in the environment works.

## Workflow

```bash
# 1. disposable copy of the files you're willing to expose
./oxseed /path/to/repo src/thing.py tests/test_thing.py

# 2. ask the model (nothing is applied)
./ox --files src/thing.py "fix the off-by-one in parse()"

# 3. READ logs/<timestamp>/content.md yourself. this is the point.

# 4. apply into the sandbox only
./oxapply --log logs/<timestamp>

# 5. run the result with no network, no escape
./oxbox -- .venv/bin/python -m pytest -q

# 6. see exactly what changed
git -C sandbox/work diff HEAD

# 7. burn it down
./oxseed --clean
```

Install dependencies **outside** the jail (it has no network), then execute
inside it.

Modes: `--mode diff` (default, returns a patch), `--mode review` (findings, no
patch), `--mode ask` (plain question). Add `--dry-run` to build and log a
request without sending it.

## What to actually watch for

The harness contains the model; it does not evaluate it. That part is yours.
Reading the diff, the things worth flagging:

- Changes beyond what was asked — unrelated edits, opportunistic "cleanup"
- Anything touching network, `subprocess`, `eval`/`exec`, or file deletion
- New dependencies, especially names one character off a real package
- Quietly weakened security: disabled cert verification, loosened permissions,
  removed validation, a hardcoded fallback credential
- Edits to build config, CI, `.gitignore`, or agent instruction files
- Code that looks right and is subtly wrong — the characteristic failure of a
  capable model, and the one a passing test suite will not catch

## Notes on `stealth/ox-alpha`

- **Malformed diffs.** It emitted a hunk with zero trailing context
  (`@@ -1,4 +1,7 @@` where a real diff has `@@ -1,7 +1,10 @@`), ignoring an
  explicit instruction to include three lines. Both `git apply` and GNU `patch`
  reject such a patch. `oxapply` falls back to `--recount -C1` and warns when it
  has to, because a patch that only applies loosely deserves a second read.
- The fix itself was correct and minimal — byte-identical to a hand-written
  reference patch once applied.
- **Reasoning traces are inconsistent.** Short calls returned
  `reasoning_chars=0` despite the model advertising mandatory reasoning; a long
  review returned 52,656 characters of it. Don't assume you'll get one.
- **Cloaked models can vanish mid-session.** Requests started failing with
  `404: No endpoints available matching your guardrail restrictions and data
  policy` — account-wide, reproduced across two different API keys. Stealth
  endpoints require prompt logging to be *enabled* at
  <https://openrouter.ai/settings/privacy>. The toggle that makes it free is
  the same one that hands over your prompts.

## The self-audit

`stealth/ox-alpha` was pointed at this harness's own source in `--mode review`
and asked to find containment defects. It produced ten findings. Four were
verified by direct experiment and **all four were real**:

| Finding | Verified escape | Status |
|---|---|---|
| Parent environment inherited into the jail | `OPENROUTER_API_KEY` and every other exported var readable by jailed code | **fixed** — `env -i` with an explicit allowlist |
| `--work` accepts any directory | `--work <repo>` wrote `PWNED.txt` to the repo root | **fixed** — refuses anything outside `sandbox/` |
| Global `file-read-metadata` | `stat()` on `~/.ssh` returned size and mtime | **fixed** — scoped to readable paths |
| Task text skips the secret scanner | a key in the prompt string was sent unscanned | **fixed** — task and `--stdin` now scanned too |
| `rename`/`copy` headers unvalidated | a rename-only patch reported "targets (0)" and passed | **fixed** — extended headers now checked |
| Symlink-creating patches unvalidated | mode `120000` patches accepted | **fixed** — refused outright |
| `oxseed` traversal unguarded | `../../../etc/hosts` copied outside the tree | **fixed** |
| TOCTOU on shared `pending.patch` | `--check` and `--apply` re-read a predictable path | **fixed** — unique temp file per run |
| Inherited descriptors bypass the jail | `oxbox -- cmd > ~/f` wrote through a handle opened before the jail | **fixed** — `fdguard.py` refuses unless opted in |
| `mach-lookup` / `ipc-posix-shm` unscoped | flagged UNCERTAIN; no escape demonstrated | **fixed** — both removed after verifying nothing needs them |

All ten are now closed. The two it correctly labeled UNCERTAIN turned out to be
removable outright: `mach-lookup` and `ipc-posix-shm` were in the profile "in
case something needs them", and nothing does — `python3` and a venv `pytest`
run both work without them.

Fixing them kept surfacing bugs the audit hadn't flagged, all of the same
shape — a check that quietly stops checking:

- `oxseed` wiped the work directory *before* validating its arguments, so a
  refused seed still destroyed the sandbox.
- Scoping `file-read-metadata` broke `jailtest.py`: with `stat()` denied, its
  own existence checks reported every sensitive path as absent and the read
  probes **skipped instead of testing**. Existence is now computed outside the
  jail and passed in.
- Tightening metadata also broke `realpath()` on the venv, because resolving a
  path needs metadata on each ancestor directory. Fixed precisely with
  seatbelt's `path-ancestors` rather than by restoring a blanket grant.
- `guardtest.sh` initially failed its own `oxbox` cases because it redirected
  output to a temp file outside the sandbox — tripping the very guard it was
  written to test.

## Known limitations

- **`--allow-external-output` genuinely re-opens a hole.** With it, jailed code
  writes attacker-chosen bytes through a descriptor your shell opened outside
  the sandbox. The flag exists because sometimes you want the output; it is not
  a formality.
- **The secret scanner is pattern-based**, so it catches recognizable key
  formats and misses bespoke ones. It reduces accidents; it is not a guarantee.
- **macOS only.** `sandbox-exec` is deprecated-but-functional; there is no
  Linux path yet.
- The model provider sees everything you send. The jail protects your machine,
  not your privacy.

Cloaked listings are evaluation deals: **prompts and completions are logged and
shared with whoever owns the model**, and `is_moderated` is false. Send nothing
you wouldn't hand to an unnamed lab.

## License

Apache-2.0. See [LICENSE](LICENSE).
