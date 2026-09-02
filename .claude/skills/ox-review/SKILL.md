---
name: ox-review
description: >-
  Get a second-opinion code review from an outside model through oxbox's `ox`,
  fanned out across subagents that each verify the findings against the real
  source before reporting them. Use this whenever someone wants code reviewed by
  a model other than you — "have ox review this", "second opinion on my diff",
  "run the stealth model over these files", "use the survey manifest", "what
  would an outside reviewer find in this branch" — or whenever oxbox, ox, or a
  survey manifest is mentioned in a review context. It picks the current
  manifest, serializes requests so a shared free pool does not refuse them, and
  checks whether the project is a publicly readable open source repository
  before any code leaves the machine, warning and asking for confirmation when
  it is not.
---

<!--
SPDX-FileCopyrightText: 2026 Curtis Galloway
SPDX-License-Identifier: Apache-2.0
-->

# Reviewing code with ox

`ox` sends source files to a model and returns findings as text. The model gets
no tools, no shell, and no path back to the machine — its only output is prose
you read. That containment is what makes it safe to point an untrusted model at
real code.

What containment does **not** do is take the code back. The venues `ox` talks to
are evaluation deals: prompts and completions are logged and shared with whoever
owns the model, and on OpenRouter a free cloaked listing only works with prompt
logging switched *on*. Every byte sent is published to an unnamed third party,
permanently. That is why this skill checks whether the project is already public
before it sends anything, and why the check is not a formality you can wave
through on the user's behalf.

Three things do the work:

| | |
|---|---|
| `scripts/preflight.py` | Finds ox, picks the current manifest, asks ox where it would send, and runs the exposure gate. |
| `scripts/exposure.py` | Answers "can a stranger already clone this?" with a real unauthenticated probe. Called by preflight; run it alone to re-check. |
| `scripts/oxreview.py` | Runs one review batch. Serializes every batch machine-wide and backs off on a busy pool. |

`ox --skill` prints this document with the script paths of whichever
installation you are standing in, so an agent that has these tools on `PATH` can
find the runbook without being told where it lives. `oxbox`, `oxseed` and
`oxapply` answer `--skill` with the same document, and all four list it in
`--help`, so whichever one an agent reaches for first leads here.

Run everything from the project root. oxbox anchors its state at the working
directory: `logs/` and the queue live beside the code under review.

## 1. Preflight

```bash
python3 .claude/skills/ox-review/scripts/preflight.py
```

Read the whole report; it is short and every section decides something.

- **exit 0** — ox is ready and the project is publicly readable. Go to step 3.
- **exit 10** — ox is ready but the exposure gate needs a human. Go to step 2.
- **exit 1** — it cannot run. The report says why: no ox, no manifest, or no
  manifest entry this run may use (usually a key that is not exported). Fix that
  with the user; do not work around it by hand-picking a venue.

If no manifest is found, ask the user for the current one rather than falling
back to a bare `--venue`/`--model`. The manifest is the record of *why* a
destination was chosen, and `ox` writes its sha256 into every run's `meta.json`
for exactly that reason. Point `--manifest` or `OXBOX_MANIFEST` at the issue's
file, or at its https URL: the survey serves the current issue's manifest at
<https://oxbox.ai/manifests/latest.json>, and `ox` (0.5.0 or later) fetches it
itself — https only, no redirects, no credential sent — and keeps the bytes it
used as `manifest.json` in every run's log directory, so the audit trail
survives the URL moving on to the next issue.

If the venue keys live in 1Password, set `OXBOX_ENV_FILE` to the `.env` file
holding the `op://` references (or pass `--env-file`). Both scripts then run
`ox` under `op run --env-file <file> --`, so the keys exist only inside `ox`'s
own process and never in the agent's environment. Preflight names the file it
will use under `== ox ==`.

## 2. The exposure gate

The gate reports one of five verdicts. Only `public` clears it:

| verdict | meaning |
|---|---|
| `public` | An anonymous clone succeeds. The code is already readable by the world. |
| `not-public` | The remote refused an anonymous read, or there is no hosted remote. |
| `unknown` | The probe could not reach the host. Unresolved is not the same as fine. |
| `no-remote` | The code exists only on this machine. Sending it would be its first publication. |
| `not-a-repo` | No git repository, so nothing is known to be published. |

For anything but `public`, stop and ask the user with `AskUserQuestion` before a
single byte goes out. Give them the facts they need to decide, not a yes/no
shorn of context:

- the verdict and the evidence line the gate printed (`HTTP 401`, `no git
  remote`, whichever it was);
- the destination — venue and model — from the preflight report;
- what would be sent: the file list and roughly how many bytes;
- the consequence, plainly: this code is not published today, and sending it
  publishes it to whoever owns that model, with logging enabled and no way to
  retract it.

Offer real alternatives alongside proceeding: review locally instead, or send a
narrowed subset of files that carries no proprietary logic. If the user declines,
stop — do not offer a smaller version of the same request in the hope of a
different answer.

One decision covers the whole run. Do not re-prompt per batch; that trains people
to click through. But if the scope later grows to files the user did not see when
they agreed, that is a new decision and needs a new answer.

When the verdict *is* `public`, proceed without a prompt — but still say in one
line where the code is going before the first request, so the destination is
never a surprise.

Two things the gate deliberately does not treat as blockers, because they are the
normal case: uncommitted changes, and commits not yet pushed. Reviewing work
before you push it is the point. The gate reports them as context; what matters
is whether the project as a whole is published.

## 3. Choose the scope and batch it

Default to the change under discussion, not the whole repository — a reviewer
given everything reports on everything.

```bash
git diff --name-only <base>...HEAD          # a branch's changes
git diff --name-only                        # uncommitted work
```

Batch the files: at most **5 files or about 40 KB**, whichever comes first. Small
batches beat one big call for a specific reason — `ox` warns when an answer is
truncated at the token cap, and oxbox has watched a review get cut off four
findings into fifteen. A batch that fits leaves the model room to finish.

Keep secrets out of the payload. `ox` has a scanner that refuses files matching
credential patterns, and **`--force` exists to override it — never pass it.**
`oxreview.py` does not offer the flag. If the scanner trips, that is the answer:
drop the file.

Tell the user how long this will take before starting. Requests are serialized
(step 4 explains why), so wall clock is roughly the number of batches times a
single request. If that is more than a handful, say so and let them narrow the
scope.

## 4. Fan out one subagent per batch

Spawn a subagent per batch, in one message so they start together. They will
queue behind each other at the venue and that is intended: the fan-out buys
*verification* concurrency, not more requests. While one batch is on the wire,
the others are reading source and checking claims, and none of the raw review
dumps land in your context.

Never call `ox` directly from several agents, and never work around the queue.
oxbox measured what happens: free cloaked listings share one upstream quota
across everyone using them, a serial queue with a 120-second retry floor cleared
every 429 within three attempts, and three concurrent requests were all refused
immediately. Concurrency is the trigger, not volume. `oxreview.py` is where that
knowledge lives.

Give each subagent this task:

```
Review one batch of files with oxbox and verify what comes back.

1. From the project root, run:

   python3 .claude/skills/ox-review/scripts/oxreview.py \
     --manifest <MANIFEST> \
     --label <BATCH-LABEL> \
     --out .ox-review/<BATCH-LABEL> \
     --file <PATH1> --file <PATH2> \
     --task "Review these files for correctness bugs, security issues, resource
             leaks, race conditions and incorrect error handling. Context: <ONE
             OR TWO SENTENCES ON WHAT THIS CODE DOES AND WHAT CHANGED>."

   It may wait for other batches before its request goes out. That is normal —
   let it wait rather than interrupting it. Do not add --force. Do not add
   --failover unless you were told the operator agreed to the full destination
   list.

   Give the call a long timeout — 600000 ms if your tool takes one. A batch
   routinely runs 4-12 minutes on the wire and can sit far longer in the
   queue, while most agent shells cut a command off after 120 seconds. The
   command surviving that cutoff is the danger: the process keeps running and
   keeps its place in the queue, so an agent that reads the timeout as failure
   and re-runs fires a second request into the same pool and collides with its
   own first one. If you are cut off, wait for the file instead of re-running:

       until [ -f .ox-review/<BATCH-LABEL>/review.md ]; do sleep 10; done

2. If it exits non-zero, read .ox-review/<BATCH-LABEL>/run.json, report the
   `diagnosis` field, and stop. Do not retry by hand; the retry policy is
   already in the script.

3. Read .ox-review/<BATCH-LABEL>/review.md. Then verify every finding against
   the actual file before you pass it on. Open the source, check the line, and
   decide: does the failure scenario actually happen?

   This is the part that matters. The model is capable, opaque, and possibly
   wrong; its characteristic failure is output that looks right and is subtly
   wrong, in both directions — a real bug described with the wrong mechanism,
   and a confident finding about code that does not exist. A finding you did not
   check is a rumor.

4. Return only this, and nothing else — no file edits, no patches, no fixes:

   ## batch <BATCH-LABEL> — <files>
   destination: <venue>/<model> from run.json
   
   ### <file>:<line> — <one-sentence defect> [CONFIRMED | REFUTED | UNCERTAIN]
   failure scenario: <specific inputs or state leading to the wrong outcome>
   evidence: <what you read in the source that settles it>
   
   If the batch produced no findings worth keeping, say so in one line.
   If run.json reports the answer was truncated, say that too — findings past
   the cut are missing.
```

## 5. Merge and report

Collect the subagents' returns and give the user one ranked list. Group
duplicates that several batches found. Lead with CONFIRMED findings, then
UNCERTAIN; keep REFUTED ones in a short closing section rather than dropping
them silently — knowing the reviewer produced three claims that did not hold is
part of judging the reviewer, which is the other half of what oxbox is for.

State plainly which batches failed and why, and which files were therefore never
reviewed. A review with a silent hole in it is worse than a short one.

Then stop. This skill produces findings, not changes. `--mode review` returns no
patch by design, and model-produced patches belong in the sandbox flow —
`oxseed`, `oxapply`, `oxbox` — never applied to the real working tree. If the
user wants fixes, either write them yourself from the confirmed findings, or run
that flow deliberately.

## Failures worth recognizing

- **429, shared pool.** `oxreview.py` retries with the measured 120-second
  floor. If it still fails, the pool is busy — not your key, not your account,
  and no setting changes it. Wait, or narrow the scope.
- **404 about guardrails and data policy.** Different failure, opposite remedy:
  cloaked free listings need prompt logging enabled at
  <https://openrouter.ai/settings/privacy>, which is the same toggle that hands
  over your prompts. Never offer this as the fix for a 429; the setting is
  already correct there.
- **Truncated answer.** `ox` warns and `status.json` records it. Re-run that
  batch with fewer files rather than accepting a partial review as complete.

## Keeping the logs

Every run writes a directory under `logs/` holding the request, the raw
response, `status.json`, and — when the model spent its budget thinking — the
reasoning. That is the audit trail of what left the machine. It is also
evidence: the Oxbox Survey reads these directories to establish which manifest
entry actually served a piece of work, and a recommendation the survey cannot
point at a run for is a recommendation resting on a model card rather than on
measurement. Deleting a log costs more than the disk it frees.

**Keep runs for at least 14 days.** The survey's cycle is weekly, so a
seven-day horizon means one missed cycle silently destroys the input to the
next. Two cycles of slack is the floor, and volume is not the constraint —
sixty runs is a few megabytes.

The stronger reason is what lives in the failures. A batch that fails leaves
evidence that exists nowhere else: a run on 2026-08-30 came back with empty
content and 22 KB of genuine review stranded in `reasoning.txt`, cut off
mid-word, with `finish_reason` null. Nothing but that log records the failure
mode. Successful runs are replaceable by running again; the rare ones are not.

**Never delete a run the survey has not read, whatever its age.** A survey pass
leaves a watermark beside the runs it consumed:

```
logs/.oxsurvey-scraped.json
  { "scraped_through":     "2026-08-30T16-05-13Z",
    "scraped_through_iso": "2026-08-30T16:05:13", ... }
```

Any run directory whose name **sorts above** `scraped_through` has not been read
yet, and age does not override that. The comparison is a plain string
comparison, not a timestamp parse — which is why `scraped_through` is written in
the same shape `ox` names directories, `%Y-%m-%dT%H-%M-%SZ`, with dashes in the
time and no colons.

That detail carries more weight than it looks. While the two forms disagreed,
`-` (0x2D) sorted below `:` (0x3A), so every run in the same hour compared as
older than the watermark: a run 54 minutes *newer* than the last scrape read as
already-read, and the naive comparison would have swept exactly the evidence
this rule exists to protect. `scraped_through_iso` is the readable form for
humans and is not the field to compare against.

Absent and unreadable are different answers. If the file is absent, no survey
has ever read this directory and age alone governs. If it is present but will
not parse, **prune nothing** — a truncated or hand-edited watermark says the
survey's position is unknown, not that it is zero, and collapsing those two
cases deletes the evidence the rule was written to keep.

The watermark sits inside `logs/` on purpose, so anything pruning inside a
project finds it beside the runs it is about to delete instead of having to walk
upwards to discover it exists.

Nothing prunes automatically today — this is a rule for whoever prunes by hand,
and for any tool that later does it for them. `OXBOX_LOG_RETENTION_DAYS` is the
name reserved for that knob, in days, with `0` meaning keep everything; it is an
environment variable rather than a config file because `ox` has no config file
and one setting does not justify inventing one. Deletion is the only operation
in this toolset with no undo, which is why it is documented here before it is
automated.

## Installing this in another project

The scripts are self-contained (Python 3.9+, standard library only, no
third-party packages — the same floor the rest of oxbox holds to). An agent that
only has the tools on `PATH` can work straight from `ox --skill` — or
`oxbox`/`oxseed`/`oxapply --skill`, which print the same thing — whose commands
already point at the installed scripts. To make Claude Code load this
as a skill in another project, copy `.claude/skills/ox-review/` into that
project's `.claude/skills/`, or into `~/.claude/skills/` to have it everywhere,
then make sure `ox` is reachable:
installed on `PATH`, named by `OX`, or an oxbox checkout pointed at by
`OXBOX_HOME`. Two more variables make it work from any project with no
per-project setup: `OXBOX_MANIFEST`, the current manifest as a file or https
URL, and `OXBOX_ENV_FILE`, the 1Password `.env` holding the venue keys.

Add `logs/` and `.ox-review/` to that project's `.gitignore`. Both hold the
audit trail of what was sent and what came back; keep them, but keep them out of
the history. Ignored is not the same as disposable — see **Keeping the logs**
above before anything sweeps them.
