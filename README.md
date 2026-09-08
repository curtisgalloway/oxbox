<!--
SPDX-FileCopyrightText: 2026 Curtis Galloway
SPDX-License-Identifier: Apache-2.0
-->

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="oxbox-logo-dark.png">
    <img src="oxbox-logo.png" width="160"
         alt="Line drawing of an ox looking out of an open cardboard box">
  </picture>
</p>

<p align="center">
  <a href="https://github.com/curtisgalloway/oxbox/actions/workflows/ci.yml"><img
     src="https://github.com/curtisgalloway/oxbox/actions/workflows/ci.yml/badge.svg" alt="CI status"></a>
  <a href="https://github.com/curtisgalloway/oxbox/releases/latest"><img
     src="https://img.shields.io/github/v/release/curtisgalloway/oxbox"
     alt="Latest release"></a>
  <a href="LICENSE"><img
     src="https://img.shields.io/badge/license-Apache--2.0-blue"
     alt="License: Apache-2.0"></a>
</p>

# oxbox

A small harness for pointing an **untrusted** LLM at your code without giving it
your machine.

There is a steady supply of "cloaked" models on OpenRouter — anonymous,
free, suspiciously capable. Free is the tell: you are paying in data, and you
don't know who the counterparty is. This repo exists so you can *try* one
anyway, on real code, without extending it any trust it hasn't earned.

**Cheap is the same problem as free**, and most of what is worth trying is
cheap rather than free. A model at a few cents per million tokens is no more
audited than a free one: same unnamed provider, same logged prompts, same
absence of anything you could call a contract. Price changes the invoice, not
the counterparty — and a review that costs pennies is *easier* to fire off
without thinking about where the code just went, which is the whole hazard.
`--allow-paid` is how you opt into those deliberately, and an entry whose cost
a manifest does not state counts as paid rather than free, because `oxbox send` does not
spend on the strength of an absence.

**There is no default model.** The listings worth pointing this at change week
to week, so `oxbox-send` names none of its own and asks you to choose: `--model` for a
model you picked, or `--manifest` for the current issue of
[the Oxbox Survey](https://oxbox.ai), which publishes what is worth trying and
the runs behind each recommendation. Point `--venue` at wherever it lives:

```bash
oxbox send --venue zenmux   --model z-ai/glm-5.3-free   --mode review --files x.py "..."
oxbox send --venue opencode --model x-preview-f-free    --mode review --files x.py "..."
oxbox send --venue requesty --model mistral/leanstral-1-5 --mode review --files x.py "..."
```

**Each venue carries its own API key variable** — `OPENROUTER_API_KEY`,
`ZENMUX_API_KEY`, `OPENCODE_ZEN_API_KEY`, `REQUESTY_API_KEY` — and `oxbox-send` reads
only the one belonging to the venue you asked for. That pairing is the security
property: a single `--base-url` flag over one hardcoded key would mean a
mistyped host receives your OpenRouter credential. An unlisted endpoint is still
reachable via `--base-url`, but only together with `--api-key-env` naming the
variable it may have, so no credential travels somewhere by default.

The destination is recorded in each run's `meta.json` (`venue`, `endpoint`,
`key_env`) alongside the model, because an audit trail that omits where the code
went is not an audit trail.

## The premise

The model is treated as capable, opaque, and possibly wrong. Nothing in the
design depends on it being benign. It gets **no tools, no shell, no filesystem,
and no network path back into your machine.** It emits text. A human (or a
supervising agent) reads that text before any of it executes.

## The five layers

This is the point where oxbox is usually mistaken for a sandbox for coding
agents, or for a coding agent. It is neither: those tools fence a trusted
agent's actions, and oxbox gives an untrusted model no actions at all. How
that plays out against `srt`, OpenHands, Codex CLI, Docker Sandboxes,
microsandbox and Cleanroom, including the one layer where oxbox is the
narrower tool, is a page of its own: [How oxbox compares](docs/comparison.md).


`oxbox` is the one command. Each step of the workflow is a subcommand —
`oxbox sandbox`, `oxbox send`, `oxbox patch`, `oxbox jail` — handed to a
script of the same name (`oxbox-sandbox`, `oxbox-send`, `oxbox-patch`,
`oxbox-jail`) that does that one job and nothing else, so a process listing
says which piece is running. The layers below are named by the script that
enforces them.

| Layer | Mechanism |
|---|---|
| **No hands** | `oxbox-send` sends a chat completion with **no `tools` array**. The model cannot run, read, or write anything. If it emits `tool_calls` regardless, `oxbox-send` logs and warns. |
| **Explicit context** | It sees only files passed to `--files`. A credential scanner refuses to send anything matching common key patterns. |
| **Patch quarantine** | `oxbox-patch` applies diffs **only** into `sandbox/work`, and rejects absolute paths and `..` traversal outright. |
| **Execution jail** | `oxbox` runs code with **no network** and **no writes outside the sandbox** — seatbelt on macOS, bubblewrap on Linux — with the environment cleared so no inherited secret crosses in. It refuses to start if stdout/stderr point at a file outside the sandbox. |
| **Audit trail** | Every call writes `logs/<timestamp>/` with the exact request, raw response, extracted content, and metadata. The API key is never logged. The survey reads these files back; the fields it depends on are listed in its [log contract](https://github.com/curtisgalloway/oxbox-survey/blob/main/docs/log-contract.md). |

The jail is not taken on faith. `jailtest.py` probes from *inside* it — TCP,
UDP, DNS, `~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.claude`, Keychains, shell
history, `.env`, `/etc/shadow`, `stat()` as a metadata oracle, and environment
inheritance. The sensitive-path list is platform-aware and computed outside:

```
$ oxbox jail -- python3 jailtest.py
[PASS] network: outbound TCP to 1.1.1.1:443  (PermissionError)
[PASS] network: DNS resolution               (gaierror)
[PASS] fs read: ~/.ssh                       (PermissionError)
[PASS] fs metadata: stat ~/.ssh (oracle)     (PermissionError)
[PASS] env: parent environment not inherited (succeeded)
...
jail holds: 12/12 probes passed, 0 skipped
```

**That total moves, by design, and the table below shows 13 for this same
machine.** The sensitive-path list is computed outside the jail and only paths
that actually exist get probed, so the count follows the box and the directory
you run from:

- A laptop carrying `~/.aws` and `~/.gnupg` probes more than a bare CI runner,
  which reports 9/9.
- The list includes the project root's `.env` (`sensitive_paths` in `oxbox`), so
  the same machine reports 13 from a checkout that has one and 12 from a
  worktree that does not — which is the whole difference between the run above
  and the macOS row below.

A differing total is not a failure — a `FAIL` line is.

The checks that run *before* the jail — argument validation, patch validation,
the secret scanner, the inherited-descriptor guard — can't be reached from
inside it, so they get their own suite:

```
$ python3 guardtest.py
[PASS] oxbox-sandbox refuses parent traversal
[PASS] oxbox refuses --work outside sandbox/
[PASS] oxbox refuses stdout redirected outside the sandbox
[PASS] oxbox-patch refuses traversal in rename headers
[PASS] `oxbox send` refuses a key in the task argument
...
guards hold: 90/90 passed, 0 skipped   (77/77 + 7 skipped on Windows)
```

Every case in it is a regression test for a defect that was actually found and
reproduced, not a hypothetical. Run both suites after any change to
`profiles/jail.sb`, `oxbox`, or the validators. A jail you haven't tested is
decoration.

## Platforms

| | Jail | Everything else |
|---|---|---|
| **macOS** | seatbelt (`sandbox-exec`, built in) | ✅ |
| **Linux** | bubblewrap (`apt install bubblewrap`) | ✅ |
| **Windows + WSL2** | bubblewrap, inside WSL | ✅ |
| **Windows, native** | ❌ none — `oxbox` refuses | ✅ |

Every row is tested, not asserted. The tools are native executables; the
suites that test them, and the Python reference they are held to, run on
Python 3.9+ (the system `python3` on macOS is still 3.9, so nothing there
uses 3.10+ APIs).

| Tested on | Result |
|---|---|
| CI, every push — macOS, Ubuntu, Windows, 3.9 floor | guardtest 90/90 (Windows 77/77 + 7 skipped), wiretest 81/81 (Windows 80/80 + 1 skipped), jailtest 9/9 |
| macOS 26.6.2, seatbelt | jailtest 13/13 |
| Debian 13 (trixie), bubblewrap 0.12.0, Python 3.13.5 | jailtest 14/14 |
| WSL2 Ubuntu 24.04.2, bubblewrap 0.9.0, Python 3.12.3 | jailtest 10/10 |
| Windows 11 Pro 25H2 (build 26200), PowerShell 7.6.5, Python 3.13.14 | no jail — `oxbox` refuses, exit 78 |

**The CI row owns every number that does not vary by host, because it is the
only row that cannot go stale.** `guardtest` and `wiretest` are the same suite
everywhere — bar the cases a platform cannot express, which are skipped and
counted as skips, never quietly dropped — so repeating their totals per machine
bought nothing except four hand-runs every time a case is added. It stopped
being hypothetical twice on 2026-09-05.

The hand-run rows therefore carry only what CI cannot know: which jail backend
the host actually has, and `jailtest`'s count, which moves for the reasons
above — the spread from 9 to 14 is the sensitive-path list, not the jail. All
four were green at `036a99b` on 2026-09-05, on every suite the platform can run
— which on native Windows is guardtest and wiretest, there being no jail to
test. Three machines between them: macOS locally, Windows and its WSL2 distro on
one box, Debian on another.

Six guardtest cases and one wiretest case need POSIX file permissions or
symlinks to provoke the failure they check, so they skip on Windows and say why. A skip is
not a smaller suite; it is a case that would otherwise pass vacuously.

### Windows

**Natively there is no jail, and `oxbox` refuses to run rather than pretend.**
No unprivileged sandbox is reachable from a stdlib script that restricts both
the filesystem and the network: Job Objects cap CPU and memory but not file or
network access, and AppContainer needs Win32 API work plus fragile ACLs.
Windows Sandbox is a real boundary, but the wrong shape for this tool — it
reaches fewer machines than WSL does, cannot run without a writable host share,
and on a real Pro machine would not start at all from a non-interactive
session: the launcher exits 0 and silently does nothing. It and Sandboxie were
both evaluated and declined; `AGENTS.md` records the reasoning, the hardware it
was measured on, and what would reopen either.

The rest of the toolkit is fully native on Windows: `oxbox send`, `oxbox sandbox`
and `oxbox patch` need nothing the MSI does not carry. You can talk to the
model, scan for secrets, and quarantine its patches. Only *executing* its
output needs the jail.

That much ships as a signed per-user MSI on the
[latest release](https://github.com/curtisgalloway/oxbox/releases): no
elevation, and `%LOCALAPPDATA%\Programs\oxbox\bin` added to your PATH. It
carries `oxbox-jail` too, refusal and all, so `oxbox --skill` answers and the
five tools stay one set.

**With WSL2 you get the full thing**, and the Linux backend runs unchanged:

```bash
wsl --install -d Ubuntu
wsl
sudo apt install bubblewrap
python3 guardtest.py
```

Both suites pass in WSL, and — verified — it works whether the repo lives on
the WSL ext4 filesystem or on the Windows drive under `/mnt/c`. Unprivileged
bubblewrap works there because the WSL2 kernel does not carry the AppArmor
patch that restricts user namespaces on an Ubuntu 24.04 host; there is no
`kernel.apparmor_restrict_unprivileged_userns` knob to trip over.

WSL2 runs on **every** Windows edition, Home included — it needs the Virtual
Machine Platform feature, not the full Hyper-V that Windows Sandbox requires.
That is why it is the whole Windows story and not a fallback.

#### A distro worth running it in

The command above works, but it puts the jail inside the distro you use for
everything else. Two defaults there are worth changing, because they decide
where an escape from the jail lands, not whether one happens.

Use a dedicated, throwaway distro:

```powershell
wsl --install -d Ubuntu-24.04
wsl --export Ubuntu-24.04 "$env:TEMP\rootfs.tar"
wsl --import oxbox "$env:LOCALAPPDATA\WSL\oxbox" "$env:TEMP\rootfs.tar"
wsl -d oxbox
```

Inside it, cut both paths back to Windows:

```ini
# /etc/wsl.conf   —   then, from PowerShell: wsl --shutdown
[automount]
enabled = false           # no /mnt/c at all
[interop]
enabled = false           # cannot exec Windows binaries
appendWindowsPath = false
```

Then `sudo apt install bubblewrap` and keep the checkout on the distro's own
filesystem (`~/src/oxbox`), not under `/mnt/c`. Both locations work — that is
the verified result above — but on ext4 the work dir lives inside the VM's
virtual disk, so there is no Windows share for jailed code to reach through
even after an escape.

Stated exactly, because the difference matters:

- **What this buys.** A bwrap escape lands in a distro holding no `~/.ssh`, no
  credentials, and no route to the Windows filesystem — and `wsl --unregister
  oxbox` erases the whole thing. Setting these on your *main* distro would buy
  the same thing at the cost of `code .`, `explorer.exe` and your Windows PATH,
  which is why a separate distro is the version people will actually keep.
- **What it does not buy.** Kernel isolation. WSL2 runs every distro as a
  container inside one shared utility VM on one shared kernel, so a kernel
  exploit reaches your other distros. Windows itself stays behind the Hyper-V
  boundary either way — which is the same boundary Windows Sandbox is built
  from, and the reason a hardened WSL jail is layered rather than weaker: a
  bwrap escape on a native Linux host owns that host outright.

## Setup

Requires git, plus `bubblewrap` on Linux. The tools are native executables;
nothing else has to be installed first. (The `oxbox-review` agent skill's helper
scripts, and the test suites, are Python 3.9+.)

**Install from a package:**

```bash
# macOS or Linux, via Homebrew — the channel that upgrades itself
brew install curtisgalloway/tap/oxbox

# macOS without Homebrew: the universal tarball from the latest GitHub
# Release. bin/ beside share/, so it runs from wherever you unpack it.
tar xzf oxbox-<version>-macos-universal.tar.gz
sudo cp -R oxbox-<version>-macos-universal/ /usr/local/

# Debian/Ubuntu: the .deb for your architecture from the latest GitHub Release
sudo apt install ./oxbox_<version>_amd64.deb

# Any other Linux: the same prefix layout as the macOS tarball
tar xzf oxbox-<version>-linux-amd64.tar.gz
```

```powershell
# Windows: the signed per-user MSI from the latest GitHub Release.
# No elevation, and it puts oxbox on PATH.
msiexec /i oxbox-<version>.msi /qn
```

**Or run from a checkout:**

```bash
git clone https://github.com/curtisgalloway/oxbox
cd oxbox
export OPENROUTER_API_KEY=sk-or-v1-...
```

Either way, the tools operate on the **working directory**: `oxbox sandbox`
builds `./sandbox/`, `oxbox send` logs to `./logs/`, and `oxbox jail` runs in
`./sandbox/work` — so stand in the project directory you are working from (a
source checkout run from its root behaves the same, with `target/release/oxbox`
after `cargo build --release`, or `python3 python/oxbox` for the reference
scripts, in place of `oxbox`). The test suites assert against the checkout layout, so
verifying the jail on a new machine is a git-clone operation even when the
tools came from a package.

**Where sandboxes live, and how many.** Every sandbox is `<root>/NAME`. The
root is `OXBOX_SANDBOX_ROOT` if set, else `root` under `[sandbox]` in
`~/.config/oxbox/config.ini` (`XDG_CONFIG_HOME` honored; `%APPDATA%\oxbox\config.ini`
on Windows), else `./sandbox`; a relative value resolves against the working
directory. `oxbox sandbox`, `oxbox patch` and `oxbox jail` all take
`--sandbox NAME` to pick one, and the default name is `work`, so with nothing
configured the layout is `./sandbox/work` as it always was. `oxbox sandbox
--status` lists every sandbox under the root with its file count, whether it
has uncommitted changes, and the repo it was seeded from; `--destroy` removes
the named one and `--destroy --all` removes the root.

```ini
# ~/.config/oxbox/config.ini
[sandbox]
root = ~/oxbox-sandboxes

[send]
manifest = https://oxbox.ai/manifests/latest.json
allow_paid = false
```

**Only `oxbox` is on `PATH`.** A package installs the four scripts into a
`libexec` directory beside it — the Homebrew keg's and the tarball's
`libexec/bin`, the `.deb`'s `/usr/libexec/oxbox/bin`, the MSI's `libexec\bin`
— and `oxbox` finds them from its own location, so there is one way to run
everything and one `--help` to read. `oxbox helper` lists them with the path
each resolved to, and `oxbox helper send ...` runs one directly. Type a
subcommand's flag at `oxbox` by mistake (`oxbox --manifest ...`) and it
answers with the subcommand that takes it.

If you use 1Password, copy `.env.example` to `.env`, point it at your item, and
prefix commands with `op run --env-file .env --`. Any method that puts
`OPENROUTER_API_KEY` in the environment works. The oxbox-review skill's scripts
do the prefixing themselves when `OXBOX_ENV_FILE` names that file, so an
agent driving a review never holds the key in its own environment.

## Workflow

```bash
# 1. disposable copy of the files you're willing to expose
#    (--add, --remove, --list, --read and --write tend it afterwards;
#    --sandbox NAME on this, patch and jail keeps several apart)
oxbox sandbox --create /path/to/repo src/thing.py tests/test_thing.py

# 2. ask the model (nothing is applied). Name one, or take this week's
#    pick from the survey with --manifest; there is no default.
oxbox send --manifest https://oxbox.ai/manifests/latest.json \
     --files src/thing.py "fix the off-by-one in parse()"

# 3. READ logs/<timestamp>/content.md yourself. this is the point.

# 4. apply into the sandbox only
oxbox patch --log logs/<timestamp>

# 5. run the result with no network, no escape
oxbox jail -- .venv/bin/python -m pytest -q

# 6. see exactly what changed
git -C sandbox/work diff HEAD

# 7. burn it down
oxbox sandbox --destroy
```

Install dependencies **outside** the jail (it has no network), then execute
inside it.

Modes: `--mode diff` (default, returns a patch), `--mode review` (findings, no
patch), `--mode ask` (plain question). Add `--dry-run` to build and log a
request without sending it.

`--effort` is `low`, `medium`, `high` (the default), `xhigh` or `max`. Those
are the levels venues serve, and **no model serves all of them**: Gemini 3.x
Flash accepts `low`, `medium` and `high` and calls `medium` its own default,
OpenAI's reasoning models add `xhigh`, and `max` is carried by around one
model in eight — Claude Sonnet 5 and GLM 5.3 Flash among them. Asking a model
for a level it does not serve is answered by the venue, not by `oxbox send`, so the
level a model actually takes belongs in the manifest entry beside its token
cap (below) rather than in a table here that goes stale every issue.

`--provider` pins the request to particular upstream endpoints. On OpenRouter a
model id is a pool of endpoints, and price, output cap, quantization and
failure mode are properties of the endpoint: the survey measured one payload
answered in 47 seconds by one provider and never by another, and a run billed
at double the list price because it landed on an endpoint priced above it.
The flag takes OpenRouter's [`provider` object](https://openrouter.ai/docs/features/provider-routing)
as JSON and sends it verbatim:

```bash
oxbox send --model deepseek/deepseek-v4-flash \
  --provider '{"only": ["digitalocean", "streamlake"], "allow_fallbacks": false}' ...
```

`oxbox send` does not interpret the object; what its fields mean is
OpenRouter's contract. It is refused on any other venue and with `--base-url`,
because those would drop it silently and the request would go out unpinned.
Absent, today's behavior: the venue's default routing. The request records
the pin in `request.json` and `meta.json`, and `status.json` reports the
endpoint that actually answered as `route`.

## Survey manifests

The Oxbox Survey publishes a machine-readable manifest with each issue — an
ordered list of that week's recommended models. `--manifest` points `oxbox send` at the
file instead of transcribing venue and model by hand:

```bash
oxbox send --manifest oxbox-manifest-2026-09-01.json --files x.py --mode review "..."
oxbox send --manifest https://oxbox.ai/manifests/latest.json --files x.py --mode review "..."
```

A manifest is a file or an `https://` URL. The survey serves each issue's
manifest at a dated URL and the current one as `latest.json`, so the second
form is "this week's pick" with no download step. The fetch follows the same
rules as the venue request: https only, no redirects, and no credential — the
request carries no Authorization header and reads no key variable. The bytes
`oxbox send` used are written into the run's log directory as `manifest.json`, because
`latest.json` will say something else next issue and the audit trail has to
keep saying what this run used.

To make a manifest the default, name it once as `manifest` under `[send]` in
`~/.config/oxbox/config.ini` (the same file that holds the sandbox root). It
stands in for `--manifest` when nothing on the command line names a
destination — a typed `--model`, `--venue` or `--base-url` is a choice the
config file does not overrule — and the run announces on stderr where the
manifest came from. The oxbox-review skill's preflight reads the same key.
`allow_paid = true` beside it opens the cost gate once, exactly as passing
`--allow-paid` on every call would, for someone who has decided paid entries
are fine; the run says `allow_paid from <file>` when the file is what opened
it. The file only opens the gate, the default stays free-only, and a value
that is neither true nor false is an error rather than a closed gate.

`oxbox send` takes the first *permitted* entry: cost confirmed `free` unless you pass
`--allow-paid` or set it in the config file (an entry of unknown cost counts as paid), a venue this `oxbox send`
knows, and that venue's key variable actually set. Skipped entries are
announced with their reasons, and the run's status record lists every one.

### What a manifest contains

The format is defined here, because `oxbox send` is the program that reads
it; the survey publishes to it. A manifest is a JSON object with a short
header and a ranked list:

- `manifest_version` — an integer, `1` today (`1` added `provider`; a `0`
  document is still read). A document without an integer
  here is refused as "not a recommendations manifest" (the survey ships other
  manifest-shaped files, such as its corpus manifest, and this is the field
  that tells them apart); a version newer than this `oxbox send` understands is
  refused with a pointer to update.
- `issue_date` — the survey issue the file belongs to. Not read by `oxbox send`;
  it survives in the run's `manifest.json`, which keeps the bytes as served.
- `defaults` — an object applying to every entry. Two keys are read,
  `max_tokens` and `effort`; anything else is reported and ignored, and an
  `effort` outside the ladder above is reported and dropped.
- `recommendations` — a non-empty list, walked in order. Each entry carries:
  - `venue` — which gateway serves it: `openrouter`, `zenmux`, `opencode` or
    `requesty`. This is the only field that decides where a request goes, and
    it must name a venue `oxbox send` already knows; an unknown venue skips
    the entry.
  - `model` — the id to send, exactly as that venue's catalog spells it.
  - `cost` — `free`, `paid` or `unknown`. Omitted means `unknown`, and
    anything but `free` is skipped unless you pass `--allow-paid`.
  - `why` — the survey's one-line reason for the entry, in its words. Read
    and kept with the entry; `oxbox send` does not act on it.
  - `params` — optional per-entry overrides, the same two keys as `defaults`:
    a lower `max_tokens` for a model whose completion cap is below the
    default, or the `effort` level that model actually serves.
  - `provider` — optional, the OpenRouter `provider` object the survey
    measured this entry with (see `--provider` above), sent verbatim with the
    request. Only `openrouter` honors one; an entry carrying `provider` on
    any other venue is skipped with that reason rather than sent unpinned,
    and so is an entry whose `provider` is not an object. `--provider` on
    the command line beats the entry's. The survey's rule is that a pin is
    a claim backed by a measurement, so it fills `only` with the endpoints
    it actually ran, `allow_fallbacks: false`, and `max_price` at the list
    price — a reader who drops the pin keeps the price guard.
  - `rank` — informational. Position in the list is authoritative, and a
    `rank` that disagrees with it is reported.
  - `base_url` — documentation for a human reader. `oxbox send` cross-checks it
    against its own venue table and warns on disagreement, but never honors
    it (see below).
  - `pricing_usd_per_mtok` — documentation for a human reader; not read.

An entry can also be skipped because its venue's key variable is not set,
and every skip is announced with its reason and listed in the run's status
record.

Two usage models, chosen explicitly:

- **Probe mode (the default).** One request, one destination, exactly what a
  survey measurement needs. If the chosen entry fails, the run fails.
- **`--failover`.** For everyday use — you want an answer, not a data point.
  On a failure after the request is sent (429, 5xx, network error, empty
  response), `oxbox send` moves to the next permitted entry. One pass, no waiting:
  waiting out a busy pool on a timer is still the caller's job. Each attempt
  is announced on stderr and gets its own log directory, and the status
  record carries the full attempt list.

  Passing `--failover` is consent to send the payload to *any* permitted
  entry until one answers. The manifest is the blast radius; the cost gate
  and which key variables you export bound it.

The manifest chooses provider and model — **never where a credential goes**.
`venue` must name an entry in `oxbox send`'s own table; the URL and key variable come
from there, and a `base_url` in the file is documentation that `oxbox send`
cross-checks and refuses to honor. A tampered manifest cannot re-aim a key.
Precedence: explicit flags beat the entry's `params`, which beat the
manifest's `defaults`, which beat the built-ins. `params` and `defaults`
both carry `max_tokens` and `effort` — the two facts that are properties of
the model rather than of the request, and that the survey has measured and
`oxbox send` has not. `provider` is a property of the entry alone, so it has
no place in `defaults`. An `effort` `oxbox send` does not recognize is reported and ignored
rather than forwarded, because a manifest is an outside document.
Each attempt's `meta.json` records the manifest's sha256 and the entry
used, because an audit trail should say why the destination was chosen,
not just what it was.

## Driving a review from an agent

```bash
oxbox --skill       # print the runbook, with this installation's paths
```

`oxbox skill` is the same thing, and the four scripts answer `--skill` too
(`oxbox helper send --skill`), so an agent that reached for any of them first
still finds it.

`.claude/skills/oxbox-review/` is a Claude Code skill that hands the whole review
loop to an agent: it picks the current manifest, batches the files, fans the
work out across subagents, and merges what comes back. Copy the directory into
another project's `.claude/skills/` to use it there; the scripts are stdlib-only
Python 3.9+ like everything else here, and they find `oxbox-send` through `oxbox` on
`PATH` (as `oxbox send`), directly via `OX`, or in the checkout named by
`OXBOX_HOME`. `OXBOX_MANIFEST` pins the manifest — a file or the survey's
https URL; unset, and with none on disk, preflight uses the survey's current
issue — and `OXBOX_ENV_FILE` names the 1Password `.env` holding the venue
keys, so one environment serves every project.

An agent that has never seen this README finds it a different way: `--skill` is
in every tool's `--help`, and printing it substitutes the script paths of the
installation it is standing in — a checkout's `.claude/skills/oxbox-review`, or
`/usr/share/oxbox/oxbox-review` from the package — so the commands it reads are
commands it can run. The document goes to stdout and the path it came from to
stderr, so `oxbox --skill > runbook.md` yields the document alone. wiretest asserts
the five print the same bytes, the same way it asserts they declare one
VERSION.

Two things in it are worth knowing about even if you never run an agent.

**The fan-out stops before the wire.** Subagents are useful for a review because
verifying a finding means opening the file and checking the claim, and that is
where the reading time goes. They are useless for *sending*, because the free
cloaked listings share one upstream quota and refuse concurrent calls — measured
above. So every batch goes through `oxreview.py`, which holds a lock while its
request is in flight and backs off on the 120-second floor. Batches pipeline;
requests do not overlap.

```bash
python3 .claude/skills/oxbox-review/scripts/preflight.py   # oxbox send, manifest, gate
python3 .claude/skills/oxbox-review/scripts/oxreview.py \
    --manifest oxbox-manifest-2026-08-27.json \
    --label auth --out .ox-review/auth --file src/auth.py \
    --task "Review for correctness bugs and incorrect error handling."
```

**It asks before publishing your code.** The venues log prompts and share them
with whoever owns the model, so sending a private repository publishes it, and
no later deletion unpublishes it. `exposure.py` settles whether that has already
happened by making a real unauthenticated request — the same `info/refs` call
`git clone` starts with, carrying no credential of any kind — and reading the
provider's API where there is one. A hostname is not evidence: the enterprise
install at `github.example.com` looks exactly like the public one, and only the
probe can tell them apart.

```
$ python3 .claude/skills/oxbox-review/scripts/exposure.py
verdict: public
curtisgalloway/oxbox on github.com is publicly readable: anyone can already clone this code
```

Anything other than `public` — a private repo, a host the probe could not reach,
no remote at all — exits 10 and the skill stops to ask a human, with the
destination and the file list in front of them. Uncommitted and unpushed work is
reported but never blocks: reviewing code before you push it is the point.

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

## Notes on `stealth/ox-alpha` (delisted)

Kept because it is the measured record, not because you can run it: the model
this harness was built against was revealed as GLM 5.3 and delisted, and is
absent from every archived catalog from 2026-08-27 on. It was still this tool's
hardcoded default for weeks after it stopped existing, which is why there is no
hardcoded default any more.

- **Malformed diffs.** It emitted a hunk with zero trailing context
  (`@@ -1,4 +1,7 @@` where a real diff has `@@ -1,7 +1,10 @@`), ignoring an
  explicit instruction to include three lines. Both `git apply` and GNU `patch`
  reject such a patch. `oxbox-patch` falls back to `--recount -C1` and warns when it
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
- **And they run out.** A different failure, with a different fix:
  `429: stealth/ox-alpha is temporarily rate-limited upstream`, carrying
  `"limit_source": "upstream_provider_shared_pool"`. Free cloaked listings
  share one upstream quota across everybody using them, so this is neither
  your key nor your account — it is the pool being busy, and no settings
  change clears it. Unlike the 404, it is transient: back off and retry.
  Measured over ~30 attempts across an 18-batch review run: a serial queue
  with a 120-second retry floor cleared every 429 within three attempts,
  while three requests launched concurrently were all refused immediately.
  Concurrency is the trigger, not volume — run one request at a time, retry
  at two-minute spacing, and never fan out against the shared pool. (An
  earlier two-attempt sample suggested 10-minute spacing; the larger run
  corrected it.) Distinguish the two failures by the code, because the
  404's advice (go enable prompt logging) is the wrong move here and sends
  you to a settings page that is already correct.

  Worth planning around if you script `oxbox-send`: a long review can simply be
  unavailable for a while, and the model you are evaluating is exactly the
  kind least likely to have capacity when you want it. Note also that
  `oxbox-send` exits non-zero on an API error, but a pipeline hides that
  (`oxbox send … | tail` reports `tail`'s status). If you must pipe, use
  `set -o pipefail`; better, skip the pipeline: `--output review.md` writes
  the answer to a file, and `--status-file status.json` writes a run summary
  (`ok`, `error`, `finish_reason`, token counts, `truncated`, `venue_cost`,
  `route`) on every exit, so a script checks a fact instead of shell plumbing.
  `route` is the upstream provider the venue says it sent the request to,
  when it says: a model listing on OpenRouter can be served by several
  providers, the venue picks one per request, and `venue_cost` is the price
  of that route — the survey saw one model billed at double its card price on
  a different route. Null when the venue names none.

## The Rust port

The five tools exist twice in this repository: a Rust workspace under
`crates/`, which is what every package installs from 1.0.0 on — `oxbox`,
`oxbox-sandbox`, `oxbox-send`, `oxbox-patch`, `oxbox-jail`, with the shared
pieces (version, the embedded runbook, the sandbox root and name rules, the
libexec lookup) in one library crate instead of a copy per file — and the
Python scripts under `python/`, which are the reference implementation the
binaries are held to. The structure is the same because it was designed for
this: one command on `PATH`, four executables in `libexec`, each a process
of its own so a process listing says which piece is running.

The same three suites hold both implementations to one contract:
`OXBOX_UNDER_TEST=$PWD/target/debug python3 guardtest.py` and `wiretest.py`
drive the binaries instead of the scripts, and `target/debug/oxbox jail --
python3 jailtest.py` probes from inside the Rust jail. `AGENTS.md` records
where the two are allowed to differ. wiretest needs the binaries built with
`cargo build --features oxbox-send/test-overrides`, which compiles in the
same knobs the suite patches into a copy of the Python source (venue URLs
aimed at its loopback listener, the https guards relaxed); a release build
lacks the feature and ignores those variables. CI runs all of it on macOS,
Ubuntu and Windows.

**Only `oxbox-send` has dependencies.** The jail, the sandbox, the patch
quarantine and the dispatcher are standard-library only, so the
security-critical pieces stay readable in full with nothing to audit beneath
them; `Cargo.lock` is where that claim can be checked. `oxbox-send` needs a
TLS stack, and the tree it pulls in — 48 crates as of this writing, from
`cargo tree -p oxbox-send` — is: `ureq` (HTTP, redirects disabled) with
`rustls`, `rustls-webpki`, `webpki-roots`, `ring` and `rustls-pki-types`;
`serde_json` with `serde_core`, `indexmap`, `itoa`, `zmij`; `regex` (the
secret scanner) with `regex-automata`, `regex-syntax`, `aho-corasick`,
`memchr`; `sha2` with `digest`,
`block-buffer`, `crypto-common`, `hybrid-array`, `const-oid`, `typenum`,
`cpufeatures`;
`flate2` with `miniz_oxide`, `adler2`, `simd-adler32`, `crc32fast` for gzip
responses; and the small crates beneath those (`http`, `httparse`,
`ureq-proto`, `base64`, `percent-encoding`, `utf8-zero`, `bytes`, `log`,
`once_cell`, `cfg-if`, `libc`, `getrandom`, `hashbrown`, `equivalent`,
`subtle`, `untrusted`, `zeroize`).

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
| `oxbox-sandbox` traversal unguarded | `../../../etc/hosts` copied outside the tree | **fixed** |
| TOCTOU on shared `pending.patch` | `--check` and `--apply` re-read a predictable path | **fixed** — unique temp file per run |
| Inherited descriptors bypass the jail | `oxbox -- cmd > ~/f` wrote through a handle opened before the jail | **fixed** — `oxbox` refuses unless opted in |
| `mach-lookup` / `ipc-posix-shm` unscoped | flagged UNCERTAIN; no escape demonstrated | **fixed** — both removed after verifying nothing needs them |

All ten are now closed. The two it correctly labeled UNCERTAIN turned out to be
removable outright: `mach-lookup` and `ipc-posix-shm` were in the profile "in
case something needs them", and nothing does — `python3` and a venv `pytest`
run both work without them.

Fixing them kept surfacing bugs the audit hadn't flagged, all of the same
shape — a check that quietly stops checking:

- `oxbox-sandbox` wiped the work directory *before* validating its arguments, so a
  refused seed still destroyed the sandbox.
- Scoping `file-read-metadata` broke `jailtest.py`: with `stat()` denied, its
  own existence checks reported every sensitive path as absent and the read
  probes **skipped instead of testing**. Existence is now computed outside the
  jail and passed in.
- Tightening metadata also broke `realpath()` on the venv, because resolving a
  path needs metadata on each ancestor directory. Fixed precisely with
  seatbelt's `path-ancestors` rather than by restoring a blanket grant.
- `guardtest` initially failed its own `oxbox` cases because it redirected
  output to a temp file outside the sandbox — tripping the very guard it was
  written to test.

## Known limitations

- **`--allow-external-output` genuinely re-opens a hole.** With it, jailed code
  writes attacker-chosen bytes through a descriptor your shell opened outside
  the sandbox. The flag exists because sometimes you want the output; it is not
  a formality.
- **The secret scanner is pattern-based**, so it catches recognizable key
  formats and misses bespoke ones. It reduces accidents; it is not a guarantee.
- **No jail on native Windows.** `oxbox` refuses there; use WSL2, which is
  tested, runs on every edition including Home, and gives you the full Linux
  backend. See Platforms above.
- **Every backend shares the host kernel.** seatbelt and bubblewrap are policy
  and namespace sandboxes, not virtual machines: a kernel privilege escalation
  escapes both. That is accepted here — the threat model is an unreliable,
  opaque model, not an adversary carrying a kernel 0-day — but it is the
  ceiling on what the jail can promise. Under WSL2 the jail sits inside a
  Hyper-V VM, making it the one configuration where an escape does not
  immediately own the host.
- **`sandbox-exec` is deprecated-but-functional** on macOS. It still works and
  Apple still ships it, but it is not a forever guarantee.
- **The Linux backend needs unprivileged user namespaces.** Some hardened
  distros disable them (`kernel.unprivileged_userns_clone=0`, or AppArmor's
  `kernel.apparmor_restrict_unprivileged_userns`); bubblewrap will not work
  there without a setuid install.
- The model provider sees everything you send. The jail protects your machine,
  not your privacy.

Cloaked listings are evaluation deals: **prompts and completions are logged and
shared with whoever owns the model**, and `is_moderated` is false. Send nothing
you wouldn't hand to an unnamed lab.

## License

Apache-2.0. See [LICENSE](LICENSE).
