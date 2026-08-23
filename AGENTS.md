<!--
SPDX-FileCopyrightText: 2026 Curtis Galloway
SPDX-License-Identifier: Apache-2.0
-->

# sketchy-ai-sandbox

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
4. **Execution jail.** `oxbox` runs code under a seatbelt profile with **no
   network at all** and **no writes outside the sandbox**. Verified by
   `jailtest.py` — 12 probes covering TCP, UDP, DNS, `~/.ssh`, `~/.claude`,
   shell history, `.env`, Keychains, and escape writes.
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

- Returns **no reasoning trace** despite advertising mandatory reasoning
  (`reasoning_chars=0` on every call so far). You get outputs, not thinking —
  supervision has to be output-based.
- Emits unified diffs with **zero trailing context**, ignoring an explicit
  instruction to include three lines. Such patches are rejected by both
  `git apply` and GNU `patch`. `oxapply` falls back to `--recount -C1` and
  **warns loudly** when it has to, because a patch that only applies loosely
  deserves a closer read.

## Rules

- Never point `oxapply` at a real repository. It is sandbox-only by design;
  keep it that way.
- Never run model-produced code outside `oxbox`.
- Re-run `./oxbox -- python3 jailtest.py` after any change to `profiles/jail.sb`.
- Do not send anything to this model you would not hand to an unnamed lab.
