<!--
SPDX-FileCopyrightText: 2026 Curtis Galloway
SPDX-License-Identifier: Apache-2.0
-->

# Security policy

This repo's entire product is a containment claim: that an untrusted model's
output can be generated, quarantined, and executed without reaching your
machine. A defect in that claim is the only kind of bug here that really
matters, so reports are welcome and will be treated seriously.

## Reporting

Use GitHub's **[private vulnerability reporting](https://github.com/curtisgalloway/oxbox/security/advisories/new)**
— it is enabled on this repo. Please do not open a public issue for a
containment bypass until there is a fix.

There is no bounty and no SLA. This is a personal project; expect a human, not
a process.

A report is most useful with a reproduction that runs. If you can express it as
a probe in `jailtest.py` (inside the jail, looking out) or a case in
`guardtest.py` (outside, checking a refusal), that is ideal — every case
currently in those suites is a regression test for a defect that was actually
reproduced, not a hypothetical, and a new one is how a fix gets to stay fixed.

## In scope

The layers that are supposed to hold:

- **Escaping the jail.** Any read, write, or `stat()` outside the work dir from
  code running under `oxbox`; any network egress at all — TCP, UDP, DNS.
- **Escaping the quarantine.** Any patch that makes `oxapply` write outside
  `sandbox/work`, or any argument that makes `oxseed` copy from outside the
  source tree — absolute paths, traversal, symlinks, extended diff headers.
- **Secrets reaching the provider.** Any content that lands in the request
  payload without passing the scanner. The scan lives in `build_context`; a
  path that routes around it is a bug even if the scanner would have missed the
  content anyway.
- **The key leaking.** The API key lives in a header and must never appear in
  `logs/`. Anywhere it does is a bug.
- **Guards that stop guarding.** A validator that silently starts passing
  everything, a probe that skips instead of testing, a refusal that no longer
  refuses. This class has bitten this repo more than once and is worth a report
  even without a concrete exploit.

## Not vulnerabilities

These are known, deliberate, and documented in the README. Reporting them is
not useful:

- **`--allow-external-output` re-opens a hole.** With it, jailed code writes
  attacker-chosen bytes through a descriptor your shell opened outside the
  sandbox. That is what the flag is for, which is why it is opt-in and named
  the way it is.
- **The secret scanner is pattern-based.** It catches recognizable key formats
  and misses bespoke ones. It reduces accidents; it was never a guarantee.
- **There is no jail on native Windows.** `oxbox` refuses to run rather than
  pretend, exiting 78. Use WSL2, which is tested. "Add a best-effort mode" is
  not a fix and will not be accepted — a harness that appears to sandbox but
  does not is worse than none, because it will be trusted.
- **`sandbox-exec` is deprecated on macOS.** It still works and Apple still
  ships it. If Apple removes it, that is a porting problem, not a
  vulnerability.
- **The Linux backend needs unprivileged user namespaces.** Hardened distros
  that disable them cannot run the jail without a setuid bubblewrap install.
- **The provider sees everything you send.** The jail protects your machine,
  not your privacy. Cloaked listings log prompts and share them with whoever
  owns the model. This is stated plainly and repeatedly; it is the deal.
- **The model being wrong, subtly wrong, or adversarial.** That is the premise,
  not a bug. The harness contains the model; evaluating it is the operator's
  job.

## Supported versions

`main`, and only `main`. There are no releases and no backports.
