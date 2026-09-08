<!--
SPDX-FileCopyrightText: 2026 Curtis Galloway
SPDX-License-Identifier: Apache-2.0
-->

# How oxbox compares

oxbox is a supervised review and patch harness for unfamiliar models. It
combines explicit context selection, credential checks, an audit trail,
patch quarantine, and offline execution in a disposable workspace. Its
value is the integration of those steps under a small, tested contract.

It overlaps with process sandboxes and complements autonomous coding
agents. The useful distinction is what capabilities the consulted model
receives and how its output reaches execution. Other sandboxes also defend
against dangerous or compromised processes; granting an agent tools inside
a boundary does not mean trusting it outside that boundary.

Every statement here about another project was checked against that
project's repository or documentation on 2026-09-06. Software moves; the
"checked" notes say what was looked at, so a later reader can re-check the
same thing.

**Terms.** A *tool loop* is the cycle in which a model asks its harness to
run a command, read a file or fetch a page, gets the result, and asks again;
it is what makes a model an agent. *Seatbelt* is macOS's process sandbox
(`sandbox-exec`); *bubblewrap* is a Linux one built on namespaces; *Landlock*
and *seccomp* are Linux kernel mechanisms that restrict a process's files and
system calls; a *microVM* is a small virtual machine with its own kernel,
which isolates more strongly than any of those. *Egress* is outbound network
traffic. *WFP* is the Windows Filtering Platform, the kernel's packet filter.
A *venue* is oxbox's word for an API gateway such as OpenRouter that fronts
many models; *chat completions* and *Responses* are two request shapes such
gateways speak.

## The question each tool answers

Agent sandboxes restrict what a process can read, write, execute, and
reach over the network. An agent can explore and iterate within those
restrictions. That is useful for autonomous development, and the boundary
must hold even when the process behaves dangerously.

oxbox serves a narrower workflow: obtain a review or a proposed patch from
a model, then inspect and test it separately. `oxbox send` sends chat
completions without registering tools. The model receives selected context
and returns text; it cannot independently read more files or run commands.
A human or supervising agent reviews that text before applying a patch into
a disposable copy and testing it with `oxbox jail`.

The review step is a workflow requirement, not a technical proof of safety.
The commands do not prove that a reviewer inspected a patch. A malicious
answer can still persuade a supervisor to take an unsafe action, and code
accepted for testing still needs containment. A stronger execution backend
would therefore benefit oxbox too.

## Side by side

| Tool | Primary workflow | Execution boundary | Relationship to oxbox |
|---|---|---|---|
| **oxbox** | Selected context in, review or patch out; supervised application and testing | seatbelt on macOS, bubblewrap on Linux; native Windows execution refused | Packages disclosure controls, audit artifacts, quarantine, and a fixed offline jail |
| **srt** (Anthropic) | Restrict arbitrary processes, including agent tools | OS sandbox with configurable filesystem and network policy | Substantial overlap with the jail layer; broader configuration and embedding options |
| **OpenHands** | Autonomous coding with shell, editing, and browsing tools | Depends on the selected agent-server backend | Supports exploration and iteration that oxbox leaves to the supervisor |
| **Codex CLI** (OpenAI) | Interactive or autonomous coding with tools | Platform sandbox and permission policy | Can serve as a supervisor; its agent loop is a different workflow |
| **Docker Sandboxes** | Run coding agents in disposable development environments | Separate microVM kernel, network policy, credential proxy | Stronger host isolation than oxbox's native jail; supports full development loops |
| **microsandbox** | Execute untrusted workloads | microVM via libkrun | A potential execution substrate for a supervised harness |
| **Cleanroom** (Buildkite) | Run policy-controlled repository workloads | microVM, deny-by-default egress, credential gateway | Overlap in containment goals; focused on workload execution |

## Each tool, briefly

**srt** (`anthropic-experimental/sandbox-runtime`). A sandbox for arbitrary
processes, built for Claude Code and released as a "Beta Research Preview".
It does what `oxbox jail` does, and more: writes are allow-listed rather than
fixed to one directory, egress is allow-listed by domain through proxies
rather than denied outright, Unix sockets are blocked by default and can be
allowed by path, and there is a library API for embedding. On Windows,
which oxbox refuses, srt has an alpha backend: the sandboxed process runs as
a dedicated `srt-sandbox` local user under a restricted token, with a
machine-wide WFP filter blocking that account's outbound traffic except to
the proxy port range. Setting that up is a one-time elevated
`windows-install` with a UAC prompt; whether the launch path then works from
a non-interactive session is not stated in its README and was not tested
here. Checked: README as of the 2026-09-03 push, sections "How It Works",
"Network Isolation", "Windows (alpha)".

**OpenHands** (`All-Hands-AI/OpenHands`). A coding agent with a web UI and
an agent-server backend that runs locally, in Docker, or on a VM. The model
drives a tool set that includes a shell, file editing and a browser; in the
SDK's default preset the browser tools are enabled unless the agent is in
CLI mode. Any model the LiteLLM naming scheme covers can be used, OpenRouter
among them. Its sandbox is the agent's workspace for exploration and
iteration; oxbox separates consultation from patch application and testing.
Checked: README "Option 2: With a Docker Sandbox" and
`software-agent-sdk` `openhands-tools/openhands/tools/preset/default.py`
(`enable_browser: bool = True`, `enable_browser=not cli_mode`).

**Codex CLI** (`openai/codex`). OpenAI's terminal agent. Its sandbox
primitives are the same family as oxbox's jail: seatbelt on macOS, Landlock
on Linux (`codex-rs/sandboxing/src/landlock.rs`), and a restricted token on
Windows (`codex-rs/windows-sandbox-rs/src/token.rs`), with network off in
the `workspace-write` policy. The agent loop is the difference. For
third-party models, Codex speaks only OpenAI's Responses request shape: the
`WireApi` enum in `codex-rs/model-provider-info` has the single variant
`Responses`, so a vendor that serves only chat completions has to sit behind
a gateway that translates. OpenRouter is such a gateway, and issue #24286
("OpenRouter model catalog parsing fails on startup") was still open against
the current release, `rust-v0.153.4` of 2026-09-04, when checked.

**Docker Sandboxes** (`sbx`). Docker's product for running coding agents,
Claude Code and Codex among them, each in its own microVM with its own
Docker daemon, filesystem and network. Outbound traffic goes through a
host-side proxy with a network panel for allowing or blocking hosts, and
credentials can be injected by that proxy without the agent seeing them.
The `sbx` CLI is free, including for commercial work; organization-wide
governance of network, filesystem and MCP policies is a separate paid
subscription. Its separate kernel provides a stronger host boundary than
oxbox's native jail, while the model inside can still drive tools. Checked:
docs.docker.com/ai/sandboxes and its usage page.

**microsandbox** (`superradcompany/microsandbox`, formerly under
`zerocore-ai`). A microVM runtime and library on libkrun, Apache-2.0, for
running untrusted workloads on Apple Silicon and on Linux with KVM. It is
not a review harness; it is the kind of primitive a stricter `oxbox jail`
backend could be built on, if the jail ever needed a separate kernel rather
than a policy sandbox. Checked: README and license as of the 2026-09-06
push.

**Cleanroom** (`buildkite/cleanroom`). Policy-controlled microVMs for
repository workloads, with deny-by-default network policy and a host-side
gateway that brokers credentials into the guest. Of everything here it is
closest to oxbox in spirit, in that egress is denied unless named and
credentials never sit inside the sandbox, but it is a CI substrate rather
than a review tool. Checked: README as of the 2026-09-06 push.

## What oxbox packages together

These safeguards are not exclusive inventions. A plain API client can omit
tools, and existing software can provide scanning, logging, disposable
workspaces, and containment. oxbox makes them a repeatable workflow and tests
the boundaries between them:

- **No tool loop, by construction.** The request carries no `tools`,
  `functions` or `tool_choice`. wiretest asserts this on the bytes that
  reach the wire when the suite runs.
- **A key goes only to its own venue.** `oxbox send` reads the one key
  variable that belongs to the venue you asked for; `--base-url` requires
  `--api-key-env` beside it; a manifest may name a venue but never a URL a
  credential goes to. A redirect is answered, not followed with the
  Authorization header attached.
- **A pre-send secret scan.** Every file in `--files` and the task text
  itself are scanned for credential shapes before anything leaves the
  machine, and a hit refuses the run.
- **Patch quarantine.** `oxbox patch` applies only into the sandbox tree,
  refusing absolute paths, `..`, rename and copy headers that escape, and
  symlink-creating hunks.
- **No default model, and a survey to choose one.** The free and cloaked
  listings worth trying change weekly; `--manifest` takes the Oxbox
  Survey's current issue, `--allow-paid` is an explicit step, and an entry
  of unknown cost counts as paid.
- **An audit trail that says why.** Each run records venue, endpoint, key
  variable, the manifest's digest and bytes when a manifest is used, and the
  entry chosen. Cost and upstream-provider information are recorded when the
  venue returns them.
- **Containment regression tests.** jailtest runs inside the jail on
  every platform that has one; guardtest exercises every refusal from
  outside, with positive controls. The counts differ by host and the docs
  say why.

## Where oxbox is the narrower tool

- **The jail is a narrower srt.** It grants writes to one directory,
  denies all network, and offers no allow-lists. Those are the reasons to
  keep it, not claims that it does more: the jail has no dependencies
  beyond the platform's own sandbox tool (`sandbox-exec`, which macOS
  ships, or `bubblewrap`, one package on Linux), its policy is fixed rather
  than configured, and "no network" is a rule rather than a default. A
  pluggable backend, including srt itself, would not change what oxbox is,
  because the jail is one layer of five and the other four are where the
  difference lives. That is a design note, not a plan.
- **Native Windows.** srt has a backend; oxbox refuses and points at WSL2.
  AGENTS.md records why Windows Sandbox and Sandboxie were declined. What
  would make adopting srt's approach acceptable is the same list: no
  standing elevation, and a launch path that works from a non-interactive
  session. srt's one-time elevated install may satisfy the first; the
  second is unverified.
- **Isolation strength.** The microVM tools isolate with a separate kernel.
  oxbox's jail shares the host kernel, and a kernel privilege escalation
  escapes it. The README's "Known limitations" says so; the threat model is
  an unreliable, opaque model, not an adversary with a kernel exploit.

## Tradeoffs and evidence of usefulness

Explicit context selection and supervised patch handling take time. They
fit bounded reviews and small changes better than tasks that require broad
repository exploration, repeated tool use, or network-dependent tests. A
caller must supply additional context when the initial selection is not
enough, and install dependencies outside the offline jail.

The secret scanner catches recognizable credential patterns. It does not
make proprietary source safe to disclose: code can be confidential without
containing any credentials. The provider sees every byte sent, and cloaked
listings share prompts and completions with an unnamed model owner.

Cheap inference alone does not establish a useful workflow. Evaluation
should count verified findings and accepted patches alongside false
positives, rejected patches, inference cost, and supervisory time. A useful
comparison is the same supervising model working alone versus consulting
another model through oxbox on comparable tasks. Preserved requests and
responses make those results inspectable; containment tests alone do not
show that a second opinion improves the outcome.

## Keep consultation bounded

Adding a tool loop would change the consulted model's authority and require
reconsidering context disclosure and execution policy. Logging, credential
binding, and quarantine could still be useful, but the current guarantee
that the consulted model cannot independently act would be lost. Keeping
consultation separate from action preserves the workflow oxbox is designed
for.
