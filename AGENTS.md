<!--
SPDX-FileCopyrightText: 2026 Curtis Galloway
SPDX-License-Identifier: Apache-2.0
-->

# oxbox

A supervised harness for running an **untrusted** model against real code.

There is no default model — the caller names one, or names a survey manifest.
What the tool is *for* is the cloaked, free listings on OpenRouter, of which
`stealth/ox-alpha` was the first (revealed as GLM 5.3 and delisted; see the
README). "Cloaked" means the provider is anonymized and the listing is an
evaluation deal: **prompts and completions are logged and shared with whoever
owns the model.** `is_moderated` is false. Treat every byte sent as published to
an unnamed third party. That is a property of the deal, not of any one listing,
so it survives the model of the week changing.

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
- Cloaked endpoints also run dry, which is a *different* failure from the
  404 above: `429 ... temporarily rate-limited upstream` with
  `"limit_source": "upstream_provider_shared_pool"`. The free listing shares
  one quota across all its users, so no key or privacy-setting change fixes
  it — only backing off. Serial requests with a 120-second retry floor
  clear it (measured: ~30 attempts across 18 batches, all cleared within
  three tries); concurrent requests trigger it reliably, so never fan out
  against the shared pool. Timed retries belong in the caller, not in `ox` —
  exiting non-zero with the provider's error text intact is what makes the
  failure class diagnosable. (`--failover` is not a retry: it is one pass
  across *different* manifest entries, which is the polite move against a
  shared pool, not a second draw on the same one.) Do not "fix" a 429 by
  touching the privacy toggle; that is the 404's remedy and it is already
  right.
- `ox` exits non-zero on an API error, but a pipeline masks it: `./ox … |
  tail` reports `tail`'s exit status, not `ox`'s. A script that must pipe
  needs `set -o pipefail`; better is not to pipe — `--output` writes the
  answer to a file (removed first, so a failed run cannot leave a stale one)
  and `--status-file` writes a JSON summary (`ok`, `error`, `finish_reason`,
  token counts, `truncated`, `log_dir`) on every exit. The same record is
  always written as `status.json` in the run's log directory.
- Emits unified diffs with **zero trailing context**, ignoring an explicit
  instruction to include three lines. Such patches are rejected by both
  `git apply` and GNU `patch`. `oxapply` falls back to `--recount -C1` and
  **warns loudly** when it has to, because a patch that only applies loosely
  deserves a closer read.

## Rules

- Never point `oxapply` at a real repository. It is sandbox-only by design;
  keep it that way.
- Never run model-produced code outside `oxbox`.
- **A key ox can send is a key the jail must not see.** `VENUES` in `ox` and the
  name list in `jailtest.py`'s `env_canary` move together — adding a venue
  without adding its key variable to that probe leaves the new credential
  outside the test that exists to catch exactly this.
- **Never widen the destination without pinning the credential.** `--base-url`
  requires `--api-key-env` on purpose: `ox` sends the key as a Bearer token to
  whatever URL it is given, so a bare base-url flag over a hardcoded key is a
  credential-exfiltration path wearing a convenience flag. Named venues bind
  URL and key variable in one table entry; keep it that way.
- **A manifest chooses provider and model, never where a credential goes.**
  `--manifest` resolves `venue` against the VENUES table; the file's
  `base_url` is cross-checked documentation and is never honored, so a
  tampered manifest cannot re-aim a key. Keep it that way — a downloaded
  file with the power to aim a Bearer token is the exact hole the venue
  table exists to close.
- **A manifest named by URL is fetched under the venue request's rules.**
  https only, no redirects, and no credential — the fetch carries no
  Authorization header and reads no key variable. The bytes ox used are
  written to `manifest.json` in every attempt's log directory: `latest.json`
  moves with each issue and the survey reads runs back by manifest, so a
  digest alone would leave the audit trail pointing at a document that no
  longer says what it said. wiretest covers all four properties; the
  ox-review scripts mirror the fetch rules for their listing and leave the
  destination to ox.
- **Failover is opt-in and belongs to `--manifest` only.** The default is
  probe mode: one request, one destination, because a survey measurement
  that silently switched targets would be corrupt data. `--failover` is one
  pass across permitted entries — no wrap-around, no waiting — and every
  attempt gets its own log directory and status entry.
- Re-run ALL THREE suites after any change to `profiles/jail.sb`, `oxbox`, `ox`,
  or the validators: `python3 guardtest.py` (pre-jail refusals plus positive
  controls), `python3 wiretest.py` (what the request actually carries, against a
  local listener), and `./oxbox -- python3 jailtest.py` (in-jail probes). A jail
  you have not tested since editing is decoration.
- **A wire test must drive `ox`, never rebuild its logic.** The first version of
  the redirect check constructed an opener with `NoRedirects` itself, so it passed
  even after `ox` stopped using it — it asserted a property of the test. Every
  assertion in `wiretest.py` has been mutation-checked: break the behavior in
  `ox` and confirm the test goes red before trusting it.
- **A review fan-out stops at the queue.** `.claude/skills/ox-review` lets
  several subagents work one review, and every one of them sends through
  `oxreview.py`'s lock, so exactly one request is on the wire at a time. That
  is not caution, it is the measurement above: concurrent calls against a
  shared free pool are refused immediately while a serial queue with a
  120-second floor clears. Subagents are for reading and verifying findings;
  they buy nothing at the venue. Do not add a "just this once" bypass, and do
  not let a batch call `ox` directly.
- **Ask before publishing someone's code.** The exposure gate in that skill is
  not a formality: everything `ox` sends is logged and shared with whoever owns
  the model, so a private repository is *published* by a review and nothing
  unpublishes it. The verdict comes from a real unauthenticated fetch rather
  than the shape of the hostname, because `github.example.com` is not
  `github.com` and only a request can tell. Keep `unknown` on the same side of
  the line as `not-public` — a probe that could not reach the host has not
  cleared anything.
- **A finding nobody checked is a rumor.** The skill's subagents verify each
  finding against the real source before reporting it, in both directions: the
  model invents defects in code that does not exist, and it describes real bugs
  with the wrong mechanism. Refuted findings stay in the report — how often the
  reviewer is wrong is half of what a survey is measuring.
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
- **Run the jail suite as an ordinary user.** At uid 0 the `/etc/shadow` probe
  cannot tell a leaking jail from an account that bypasses file permissions, so
  `jailtest` skips it and says why rather than answering vacuously — the same
  rule as the existence checks above. Every other read probe stays meaningful at
  any uid: the real home is never bound into the jail, so absence blocks those,
  not permissions. Measured on Debian 13 — 14/14 as a normal user with the probe
  running and passing, 9/9 with 1 skipped as root.
- **Seed and run as the same user.** `bwrap` puts the run in a user namespace,
  and a work dir owned by a uid that namespace does not map appears as `nobody`
  (65534) — so not even root inside can write it, and `fs write: inside work
  dir` fails for a reason that has nothing to do with containment. Seeding the
  sandbox as yourself and then running `sudo ./oxbox` is exactly how to produce
  that confusing result; don't mix the two.
- The secret scanner covers `--files` bodies, the task argument, and `--stdin`.
  Anything new that reaches the payload must be scanned too — the scan lives in
  `build_context`, so route new content through it rather than around it.
- Do not send anything to this model you would not hand to an unnamed lab.

## Packaging rules

- **State anchors at the working directory; only code anchors at the script.**
  `sandbox/`, `logs/`, and the `.env` sensitive-path probe are
  working-directory relative, because installed tools live in `/usr/bin` or a
  Homebrew Cellar where script-relative state is unwritable or worse. Two
  assets are script-relative, and both use the same two-location pattern:
  the seatbelt profile (`profiles/jail.sb` beside the script, or
  `../share/oxbox/jail.sb` in an installed prefix — `find_profile` in
  `oxbox`) and the ox-review skill (`.claude/skills/ox-review` beside the
  script, or `../share/oxbox/ox-review` — `find_skill`, carried by all four
  tools). Keep new state cwd-anchored and new code assets on that pattern.
- **`find_skill`/`print_skill` is duplicated four times on purpose, like
  `VERSION`.** Each tool is a standalone script, so sharing the block would
  mean shipping a module and a `sys.path` to find it on — which is a bigger
  change to the packaging story than the block is worth. What makes four
  copies safe is the check: wiretest runs `--skill` on all four and asserts
  identical stdout, a zero exit, and a provenance line naming the tool you
  actually ran. Edit one copy, edit all four, and let that case prove it.
- **A packaged asset needs a smoke-test line, or it will be forgotten.**
  `ox --skill` reads a file the package has to ship, and the failure mode is
  silent until someone installs a package and asks for it. The release
  workflow runs `--skill` against the installed ox and greps for the
  rewritten script path, which fails both when the file is missing and when
  the path rewriting stops working. The Homebrew formula lives in
  `curtisgalloway/homebrew-tap` and needs the same `share/oxbox/ox-review`
  layout; a tap that installs only the four executables leaves `--skill`
  refusing on brew installs.
- **Four channels, one layout.** The release ships a `.deb` (Linux, a `/usr`
  prefix, `packaging/nfpm.yaml`), a macOS tarball (a relocatable `bin/` beside
  `share/`, `packaging/macos-tarball.sh`) and a Windows MSI (per-user under
  `%LOCALAPPDATA%\Programs\oxbox`, `packaging/windows/`); the Homebrew
  formula installs that same prefix into the Cellar. All four are the same
  shape because `find_profile` and `find_skill` know exactly one rule —
  `../share/oxbox` from the script — so a change to that resolution breaks
  four packages at once, and a new asset has to be added in four places. Each
  is smoke-tested by the job that builds it, installed for real; the macOS
  tarball is unpacked into a scratch prefix rather than copied over
  `/usr/local`, because running from wherever you put it is what that
  artifact promises.
- **Windows ships each tool twice, and one of the four is a refusal.** `bin\`
  in the MSI holds the extensionless script and a `.cmd` shim beside it,
  because Windows cannot execute a shebang; the shim is what the PATH entry
  makes typeable. Write those shims with labels and never with parenthesised
  blocks — `%errorlevel%` inside a block expands when the block is parsed
  rather than when it runs — and treat the exit code as load-bearing, because
  `oxbox` exits 78 on native Windows by design and a shim that swallowed that
  would turn a refusal into an apparent success. The smoke test asserts the
  78. `jail.sb` is not packaged there: there is no seatbelt to find.
- **A job's actions resolve before any step `if` runs.** Gating a step on a
  missing secret does not stop the job from being set up, and setup can fail
  on its own: the winget job died in "Set up job" on v0.4.0 because
  `winget-releaser` calls `cargo-bins/cargo-binstall@main` internally and this
  repo's Actions policy requires a full-length SHA on every action, transitive
  ones included. The release itself was fine — published, tap re-pinned — and
  the run was still red. A job that must not run yet has to be gated at the
  **job** level, and on a `vars.` value, since the `secrets` context is not
  available in a job `if`.
- **The MSI is signed, or it silently is not.** Every signing step is gated on
  `vars.AZURE_SIGNING_ACCOUNT`, so an unconfigured repo (or a fork) ships an
  unsigned MSI rather than failing — which means "not set up" and "working"
  look identical unless something inspects the finished artifact. That is what
  the verify step is for, and why it asserts an RFC 3161 timestamp as well as
  a valid signature: the certificates live 72 hours, so an untimestamped
  signature is valid on release day and dead three days later on every copy
  already downloaded. The signing account is shared across projects; the
  onboarding runbook is `~/src/iac/mac-common/code-signing/README.md`.
- **All three tools must agree on where the sandbox is.** `oxseed` creates
  it, `oxapply` writes into it, `oxbox` jails into it; they all derive it
  from the working directory. Changing the anchor in one without the others
  quietly splits the sandbox in two.
- **The test suites assert against the checkout layout** (`guardtest`
  chdirs to the repo root for exactly this reason) and are not packaged.
  Verifying the jail on a new machine is a git-clone operation; the release
  workflow's smoke test runs jailtest against the installed tools so a
  package that breaks the jail cannot ship.
- **The tag must match the tools.** Every tool carries `VERSION`; wiretest
  asserts the four agree, and the release workflow refuses a tag that
  disagrees with `ox --version`. Bump all four together.

## Cross-platform rules

- **Never add a "best effort" mode.** `oxbox` supports seatbelt and bubblewrap
  and refuses everywhere else, deliberately. A harness that appears to sandbox
  but doesn't is worse than none, because it will be trusted.
- **WSL2 is the Windows story and it is tested**, not a hand-wave: Ubuntu 24.04
  under WSL runs the bubblewrap backend unchanged, from the ext4 home and from
  `/mnt/c` alike. Unprivileged bwrap works because the WSL2 kernel lacks the
  AppArmor userns patch that an Ubuntu 24.04 *host* carries. Do not soften the
  native-Windows refusal on the strength of WSL working — they are different
  execution environments and `sys.platform` tells them apart.
- **Python 3.9 is the floor.** The system `python3` on macOS is still 3.9, so
  no 3.10+ APIs: no `Path.write_text(newline=...)`, and `shutil.rmtree(onexc=)`
  stays behind its version check.
- **Write patches and audit artifacts with explicit newlines.** Python's text
  mode translates `\n` to `\r\n` on Windows. `oxapply` writes its temp patch
  with `newline=""` and `ox` uses `write_lf`. Without that, git compares a CRLF
  patch to an LF tree and rejects every patch with an error that reads like a
  malformed diff. Cost real time to find; only reproduces on Windows.
- **End a `pwsh` CI step that asserts a non-zero exit with an explicit
  `exit 0`.** GitHub's `pwsh` shell appends `exit $LASTEXITCODE` to every
  script it runs. These tools exit non-zero on purpose — `oxbox` answers 78 on
  native Windows — so a step that asserts that refusal leaves 78 in
  `$LASTEXITCODE`, and the step then fails *after every assertion has passed*,
  with no error text at all, because nothing errored. `Process completed with
  exit code 1` and an empty log is the whole symptom. It cost the Windows
  release job three round trips and read like an MSI problem the entire time;
  two plausible theories about PowerShell error handling were wrong before
  breadcrumbs found it. Print progress markers in a CI step whose failure mode
  is silence — they are what turned this from guesswork into one line.
- **A document printed to stdout needs the same care as one written to a file.**
  `--skill` prints SKILL.md, and Windows' text-mode `sys.stdout` re-encodes it
  in the locale codepage — cp1252 renders the runbook's em dashes as `0x97` —
  and translates every `\n` to `\r\n` on the way out. `ox --skill > runbook.md`
  there produced a file no UTF-8 reader could open, and it took `guardtest`
  down with a `UnicodeDecodeError` traceback instead of a red line. All four
  tools now write the document as UTF-8 bytes through `sys.stdout.buffer`, the
  stdout counterpart of `write_lf`, and `guardtest` asserts the contract on the
  bytes so the failure reports itself. Only CI and a real Windows host catch
  this; macOS and Linux are byte-identical either way.
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
