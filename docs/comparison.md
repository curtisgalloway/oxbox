<!--
SPDX-FileCopyrightText: 2026 Curtis Galloway
SPDX-License-Identifier: Apache-2.0
-->

# How oxbox compares

People meeting oxbox tend to assume it duplicates one of two things: a
sandbox for coding agents, such as Anthropic's `srt`, or a coding agent
itself, such as OpenHands. It is neither, and the reason is the direction of
the threat model rather than any feature. This page lays that out so a reader
can reach the conclusion from the facts, and it is candid about the one layer
where oxbox does overlap and is the narrower tool.

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

Most tools in this space answer: how do I stop a coding agent from wrecking
my machine? The agent is trusted to act; the sandbox limits what its tool
loop can reach. The model drives a shell, edits files, fetches pages, and the
fence decides which of those touch the real filesystem or the real network.

oxbox answers a different question: how do I get a review or a patch from a
model I do not trust at all? The model gets no tool loop. `oxbox send` posts
one chat-completions request with no `tools` array, so the model cannot ask
for anything to be run, read or written; it reads the files it was handed
and emits text. A human reads that text. Only then does `oxbox patch` apply
it into a disposable copy, and only then does `oxbox jail` run the result
with no network and no writes outside that copy. The jail exists to run the
model's *output* after review, not to fence the model while it works.

That difference is the whole comparison. Where another tool's sandbox is
stronger than oxbox's jail, it is stronger at fencing an agent that oxbox
never lets exist.

## Side by side

| Tool | Who is trusted | What the model can do | Isolation primitive | Network inside | Model access | Overlap with oxbox |
|---|---|---|---|---|---|---|
| **oxbox** | nobody: the model is treated as adversarial | emit text; no `tools` array is ever sent | seatbelt on macOS, bubblewrap on Linux, refusal on native Windows; the jail runs the reviewed output, not the model | none inside the jail; `oxbox send` itself reaches only the chosen venue over https | OpenRouter, ZenMux, OpenCode Zen, Requesty; one key variable per venue; any chat-completions endpoint with `--base-url` plus `--api-key-env` | — |
| **srt** (Anthropic) | the agent | whatever the wrapped process does | seatbelt; bubblewrap plus seccomp; on Windows a dedicated `srt-sandbox` local user with a WFP egress fence | denied by default; domain allow-list through host-side HTTP and SOCKS proxies | not applicable; it wraps any process | the jail layer only; srt is the broader jail |
| **OpenHands** | the agent | shell, file edits, web browsing, API calls; the browser tool set is on by default outside CLI mode | Docker container (an "agent server" backend; can also run without a sandbox or on a VM) | open | any model via LiteLLM naming, OpenRouter included | none on threat model; it protects the host from a trusted agent |
| **Codex CLI** (OpenAI) | the agent | shell and writes inside the workspace | seatbelt; Landlock on Linux; a restricted token on Windows | off in `workspace-write` | only the Responses request shape (`WireApi` has one variant); OpenRouter works through that shape, and its catalog parsing bug #24286 is open as of v0.153.4 | jail primitives similar; the agent loop is the difference |
| **Docker Sandboxes** (`sbx`, runs Claude Code, Codex, OpenCode and others) | the agent | a full development loop, including its own Docker daemon | microVM per sandbox | proxied, with per-host allow and block rules; organization-wide policies are the paid tier | whatever the agent inside supports | the strongest host isolation on this list; the model still drives tools |
| **microsandbox** | the agent, or code | run code | microVM via libkrun, Apache-2.0; Apple Silicon and Linux with KVM | configurable | not applicable | a possible stricter jail backend; no review harness |
| **Cleanroom** (Buildkite) | the agent | run CI-style repo workloads | microVM; deny-by-default egress; a host-side gateway that brokers credentials into the guest | denied by default | not applicable | closest in spirit on egress and credential handling; a different job |

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
among them. It shares nothing with oxbox's threat model: OpenHands protects
your machine from what a trusted agent does, and the sandbox is the agent's
workspace. Checked: README "Option 2: With a Docker Sandbox" and
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
subscription. It is the strongest host isolation on this list, and the
model inside still drives tools. Checked: docs.docker.com/ai/sandboxes and
its usage page.

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

## What is only in oxbox

None of the tools above has these, because none of them treats the model as
the adversary:

- **No tool loop, by construction.** The request carries no `tools`,
  `functions` or `tool_choice`. wiretest asserts this on the bytes that
  reach the wire, every run.
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
  variable, the manifest's digest and bytes, the entry chosen, what the
  venue said it charged, and which upstream provider it routed to.
- **The fence is probed, not asserted.** jailtest runs inside the jail on
  every platform that has one; guardtest exercises every refusal from
  outside, with positive controls. The counts differ by host and the docs
  say why.

## Where oxbox is the narrower tool

- **The jail is a narrower srt.** It grants writes to one directory,
  denies all network, and offers no allow-lists. Those are the reasons to
  keep it, not claims that it does more: the jail has no dependencies
  beyond the operating system's own sandbox, its policy is fixed rather
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

## A constraint worth writing down

If oxbox ever grew a tool loop, it would become a smaller OpenHands with a
weaker sandbox, and every property in "What is only in oxbox" would stop
being true. The absence of the loop is the design.
