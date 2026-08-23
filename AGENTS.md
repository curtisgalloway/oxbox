<!--
SPDX-FileCopyrightText: 2026 Curtis Galloway
SPDX-License-Identifier: Apache-2.0
-->

# oxbox

A supervised harness for running an **untrusted** model against real code.

The model here is `stealth/ox-alpha` on OpenRouter — a cloaked, free, 1M-context
model. "Cloaked" means the provider is anonymized and the listing is an
evaluation deal: **prompts and completions are logged and shared with whoever
owns the model.** `is_moderated` is false. Treat every byte sent as published to
an unnamed third party.

## Threat model

The model is assumed to be capable, opaque, and possibly wrong or adversarial.
It is *not* assumed to be malicious — but nothing here depends on it being
benign.

## Containment layers

1. **No hands.** `ox` sends a plain chat completion with **no `tools` array**.
   The model cannot run a command, read an unhanded file, or write to disk. Its
   only output channel is text. If it ever emits `tool_calls` anyway, `ox` logs
   and warns.
2. **Explicit context.** It sees only files named in `--files`. A secret scanner
   refuses to send anything matching common credential patterns.
3. **Patch quarantine.** `oxapply` applies diffs **only** into `sandbox/work`,
   and refuses absolute paths or `..` traversal outright.
4. **Execution jail.** `oxbox` runs code with **no network at all** and **no
   writes outside the sandbox** — seatbelt on macOS, bubblewrap on Linux, and a
   hard refusal everywhere else. Verified by `jailtest.py` from inside and
   `guardtest.py` from outside.
5. **Audit trail.** Every call writes `logs/<timestamp>/` containing the exact
   request, the raw response, the extracted content, and metadata. The API key
   is never logged (it lives in a header, not the payload).

## Workflow

```bash
./oxseed /path/to/repo file1.py file2.py           # disposable copy + pristine commit
op run --env-file .env -- ./ox --files file1.py "task"   # ask the model
# a human/Claude reads logs/<ts>/content.md here
./oxapply --log logs/<ts>                          # sandbox only
./oxbox -- .venv/bin/python -m pytest -q           # jailed, no network
git -C sandbox/work diff HEAD                      # what actually changed
./oxseed --clean                                   # burn it down
```

Dependencies are installed **outside** the jail (it has no network), then
executed inside it.

## Observed behavior

- Reasoning traces are inconsistent: `reasoning_chars=0` on short calls despite
  advertised mandatory reasoning, but 52,656 characters on a long review. Never
  assume one will be there.
- Cloaked endpoints can disappear mid-session with
  `404: No endpoints available matching your guardrail restrictions and data
  policy` — account-wide, not key-specific. Stealth models require prompt
  logging enabled at <https://openrouter.ai/settings/privacy>.
- Emits unified diffs with **zero trailing context**, ignoring an explicit
  instruction to include three lines. Such patches are rejected by both
  `git apply` and GNU `patch`. `oxapply` falls back to `--recount -C1` and
  **warns loudly** when it has to, because a patch that only applies loosely
  deserves a closer read.

## Rules

- Never point `oxapply` at a real repository. It is sandbox-only by design;
  keep it that way.
- Never run model-produced code outside `oxbox`.
- Re-run BOTH suites after any change to `profiles/jail.sb`, `oxbox`, or the
  validators: `./oxbox -- python3 jailtest.py` (in-jail probes) and
  `python3 guardtest.py` (pre-jail refusals plus positive controls). A jail you
  have not tested since editing is decoration.
- Do not restore `(allow mach-lookup)` or `(allow ipc-posix-shm)`. Both were
  removed after verifying `python3` and a venv `pytest` run work without them.
  If some toolchain genuinely needs one, scope it to named services rather than
  reinstating the blanket form.
- Metadata rights on WORK's ancestors come from `path-ancestors`. That is what
  lets `realpath()` resolve the work dir without granting `stat()` across the
  filesystem — do not swap it for a broad `(subpath "/Users")`.
- Tests must not redirect an `oxbox` invocation to a regular file outside the
  sandbox; the descriptor guard refuses it and the case fails for the wrong
  reason. Use `os.devnull` or a pipe. This bit `guardtest` on its first run.
- Never decide inside the jail whether a sensitive path exists — `stat()` is
  denied, so the check reports "absent" for everything and the probe skips
  instead of testing. Existence is computed by `oxbox` and passed in via
  `OXBOX_EXISTING_PATHS`. This bit once already.
- The secret scanner covers `--files` bodies, the task argument, and `--stdin`.
  Anything new that reaches the payload must be scanned too — the scan lives in
  `build_context`, so route new content through it rather than around it.
- Do not send anything to this model you would not hand to an unnamed lab.

## Cross-platform rules

- **Never add a "best effort" mode.** `oxbox` supports seatbelt and bubblewrap
  and refuses everywhere else, deliberately. A harness that appears to sandbox
  but doesn't is worse than none, because it will be trusted.
- **Python 3.9 is the floor.** The system `python3` on macOS is still 3.9, so
  no 3.10+ APIs: no `Path.write_text(newline=...)`, and `shutil.rmtree(onexc=)`
  stays behind its version check.
- **Write patches and audit artifacts with explicit newlines.** Python's text
  mode translates `\n` to `\r\n` on Windows. `oxapply` writes its temp patch
  with `newline=""` and `ox` uses `write_lf`. Without that, git compares a CRLF
  patch to an LF tree and rejects every patch with an error that reads like a
  malformed diff. Cost real time to find; only reproduces on Windows.
- **Path checks must be textual, not `Path.is_absolute()`.** On Windows
  `/etc/passwd` has a root but no drive, so `is_absolute()` returns False and a
  rooted path sails through. Check for `~`, `/`, `\`, and a drive letter, and
  split traversal on both separators.
- **Escape-write verification belongs in `guardtest.py`, not `jailtest.py`.**
  The backends disagree from inside: seatbelt denies the `open()`, while
  bubblewrap materialises the work dir's parents as ephemeral tmpfs so the
  write *succeeds* into a layer the host never sees. Identical containment,
  opposite results. Only a check running outside can ask the question that
  matters — did the host change?
- **Every escape test needs proof it ran.** Assert a marker written inside the
  jail, or the whole section passes vacuously when `oxbox` fails to start.
- **Refusal tests need positive controls beside them.** A validator that
  rejects everything passes every refusal test. `guardtest.py` applies a known
  good patch for exactly this reason — the CRLF bug above was invisible until
  that control existed.
