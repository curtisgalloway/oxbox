# Release train profile: oxbox

Derived from commit 5a46f9d on 2026-09-20. Executed by the `release-train`
skill; kept honest by `profile_check.py` (see `## Sources`). Lines marked
`UNVERIFIED` were inferred by the agent that wrote this file and have not been
confirmed by a maintainer or by a passing arm.

## Project

- cli: `oxbox`
- version source: **six files, and only the combination is checked.** The
  workspace `version` in `Cargo.toml` (which the `version` job cross-checks
  against the tag) *and* the `VERSION = "X.Y.Z"` constant in each of
  `python/oxbox`, `python/oxbox-send`, `python/oxbox-patch`,
  `python/oxbox-sandbox` and `python/oxbox-jail`. `wiretest.py` asserts that all
  five Python tools declare the same VERSION *and* that the built Rust binary
  prints it, so bumping Cargo.toml alone turns the `rust` job red on every
  platform while `cargo test` stays green. Measured on this release: the 1.4.0
  bump missed the Python five and CI failed 81/82 with "oxbox-send --version
  prints it". Bump all six, then run `python3 wiretest.py`.
- tag format: `v<X.Y.Z>`; subject `<X.Y.Z>: <lowercase summary>` (note: no
  leading `v` in the subject, unlike the skill's default)
- main branch: `main`; protected: yes — linear history, 0 required reviews,
  required checks `guards (ubuntu-latest)`, `guards (macos-latest)`,
  `guards (windows-latest)`, `guards (3.9 floor)`, `jail (ubuntu-latest)`,
  `jail (macos-latest)`
- release workflow: `.github/workflows/release.yml`
- apt workflow: `.github/workflows/apt.yml` — rebuilds and deploys the signed
  pool to Pages; also runs weekly on cron because the apt `Release` file
  carries a 30-day `Valid-Until` and an expired one breaks `apt update` on
  every client
- ci workflow: `.github/workflows/ci.yml`
- bump rules: conventional commits (`feat` minor, `fix` patch, others none).
  This repo's subjects are mostly bare imperative or `docs:`-prefixed, so most
  releases are classified `heuristic` — a new venue, a new distribution
  channel or a new subcommand is a minor. UNVERIFIED
- releaser identity: the repo's commits use a GitHub noreply author of the form
  `<id>+<username>@users.noreply.github.com`; the tag is made with that same
  form, read from `git log`, never from a literal in this file

## Hosts

Roles only. The machines behind them, how to reach them, and any credentials
live in `RELEASE-TRAIN.local.md` (gitignored), one section per role.

| role | needed by | what it must have |
|---|---|---|
| local | homebrew, macos-tarball, source | macOS, Rust stable, Homebrew |
| linux-builder | deb, linux-tarball, apt | Linux, Rust stable, `dpkg`/`apt`, `nfpm`, `gpg` |
| windows-bench | msi | Windows, PowerShell over ssh, `msiexec` |

`local` is the machine the train runs on. `linux-builder` is a local VM named
only in the local file; it is aarch64, so it can build and smoke the arm64
`.deb` and tarball but **not** the amd64 ones — see the arms' caveats. It runs
Ubuntu 24.04 while the workflow builds in a `debian:bookworm` container, which
is a fidelity gap the arms record. `windows-bench` is a reachable Windows 11
host, AMD64, PowerShell 7, `msiexec` present; the `msi` arm can run.

## Smoke contract

Run against the installed copy, with `HOME` pointed at a fresh temp dir and the
working directory outside the checkout.

`oxbox` is a dispatcher in front of four helper binaries that every channel
installs into a `libexec` directory beside it — the Homebrew keg's and the
tarball's `libexec/bin`, the `.deb`'s `/usr/libexec/oxbox/bin`, the MSI's
`libexec\bin`. S2 and S3 exist because that is the part packaging breaks: the
dispatcher runs fine while the helpers it dispatches to are missing.

| id | check | pass condition |
|---|---|---|
| S1 | `oxbox --help` | exit 0; lists `sandbox`, `send`, `patch`, `jail`, `helper`, `skill` |
| S2 | `oxbox skill` | exit 0; prints the oxbox-review skill, proving a packaged data file was found |
| S3 | `oxbox helper` | exit 0; lists all four helpers, each resolving to a path **inside the installed prefix** — a helper resolving to a build dir or not at all is a FAIL |
| S4 | `oxbox sandbox --create` then `--status` then `--destroy`, under `OXBOX_SANDBOX_ROOT` in the temp `HOME` | round trip exits 0 and leaves nothing behind |
| S5 | `oxbox send --dry-run --model x --mode ask 'hi'` with no API key set | exit 0; prints the built request and `dry run, nothing sent`; no panic, no network. **This is designed behavior** — the credential check is gated on `!args.dry_run`, `release.yml` asserts exit 0 for this exact command ("A dry run needs no key"), and `a_dry_run_builds_and_files_the_request_without_a_key` pins it |
| S5b | the same command **without** `--dry-run`, no API key | exits non-zero with the named credential error (`OPENROUTER_API_KEY not set …`); no panic, no network. This is what S5 was meant to check and was testing the wrong command shape for; pinned by `destination_and_credential_are_resolved_together` |
| S6 | `oxbox --version` | exit 0; prints exactly the version being released |
| S7 | `oxbox send --help` | exit 0; the `--venue` list includes `openrouter-us` (new in this release, and the reason a stale helper binary would be invisible to S1–S3) |

## Channels

### homebrew

- kind: homebrew
- artifact: bottle built from `curtisgalloway/homebrew-tap`
- workflow job: `bump-tap`
- host: local
- build: none locally; the tap is re-pinned by the `bump-tap` job from a
  `repository_dispatch` the release fires
- install like a user: `brew install --formula curtisgalloway/tap/oxbox` into a
  throwaway prefix (`HOMEBREW_CACHE`/`HOMEBREW_TEMP` redirected; never touch the
  developer's default keg — uninstall in cleanup)
- smoke: S1–S7 and S5b
- cleanup: `brew uninstall oxbox`; remove the redirected cache/temp dirs
- caveats: before the tag exists the tap still points at the previous version,
  so on a dry run this arm verifies the *previous* release's artifact and is
  reported PARTIAL rather than PASS

### deb

- kind: deb
- artifact: `oxbox_<version>_<arch>.deb`
- workflow job: `linux-build`
- host: linux-builder
- build: `cargo build --locked --release`, then install nfpm the way the
  workflow does — the pinned `NFPM_VERSION` (2.46.3) `.deb` fetched from the
  nfpm release and `apt-get install`ed — then `nfpm package -f
  packaging/nfpm.yaml -p deb`, and `packaging/tarball.sh` beside it
- install like a user: `sudo apt install ./oxbox_<version>_<arch>.deb` in the VM
- smoke: S1–S7 and S5b, plus a check that the four helpers live under
  `/usr/libexec/oxbox/bin`
- cleanup: `sudo apt remove oxbox`; delete the built artifacts
- caveats: the builder is aarch64, so only the arm64 package is built and
  smoked here; the amd64 package is inspected in CI and never installed by
  this train. The builder is Ubuntu 24.04, not the workflow's `debian:bookworm`
  container, so a dependency the container lacks would not show up here.

### apt

- kind: deb (repository)
- artifact: the signed pool under `/apt/` on the project's Pages site
- workflow job: none
- host: linux-builder
- build: `packaging/scripts/build-apt-repo.sh <debs-dir> <out-dir> <key-fpr>`
  against a throwaway signing key, into a temp dir
- install like a user: serve the built pool over a loopback HTTP server in the
  VM, add it as a deb822 source with `Signed-By` pointing at the throwaway
  key, then `apt update && apt install oxbox`
- smoke: S1–S7 and S5b, plus: `apt update` reports no `Valid-Until` warning, and
  `apt-cache policy oxbox` shows the repository as the install candidate
- cleanup: remove the source file and keyring, `apt remove oxbox`, delete the
  temp pool and the throwaway key
- caveats: the pool is built and deployed by the `build` and `deploy` jobs
  of `.github/workflows/apt.yml`, not by the release workflow, which is why
  `workflow job` is `none` above; a Pages deploy is what publishes the pool,
  not the Release itself. The arm signs with a throwaway key rather than
  `APT_SIGNING_KEY`, so it proves the pool's structure and apt's acceptance of
  it, not that the production key still works. It is also aarch64, so the amd64
  index is built but never installed from.

  **The channel is live and has been released** — `apt.yml` has run
  successfully on push, dispatch and its weekly schedule, and the published
  pool carries every release through 1.3.0. What has **never run** is
  `release.yml`'s `refresh-apt-repo` job: v1.3.0 was published about 45 minutes
  before #71 merged, so no tag has ever dispatched `apt.yml`. The next tag is
  the first. Its failure mode is quiet and ugly — the pool keeps serving the
  previous version while the Release page shows the new one, which reads as a
  release that did not happen. Verify it after every tag; see `## Publish`.
  Note also that the dispatch is `--ref main`, so `apt.yml` always assembles
  with **main's** `build-apt-repo.sh`, never the tag's.

### linux-tarball

- kind: zip (tar.gz)
- artifact: `oxbox-<version>-linux-<arch>.tar.gz`
- workflow job: `linux-build`
- host: linux-builder
- build: `packaging/tarball.sh` as `linux-build` runs it
- install like a user: `tar xzf` into a throwaway prefix, run the `oxbox` inside it
- smoke: S1–S7 and S5b, plus: the four helpers resolve to `libexec/bin` *inside the
  extracted tree*
- cleanup: delete the extracted tree and the archive
- caveats: aarch64 only, as for `deb`

### macos-tarball

- kind: zip (tar.gz)
- artifact: `oxbox-<version>-macos-universal.tar.gz`
- workflow job: `macos`
- host: local
- build: `cargo build --locked --release` then `packaging/tarball.sh`, as the
  `macos` job runs it
- install like a user: `tar xzf` into a throwaway prefix outside the checkout
- smoke: S1–S7 and S5b, plus: the archive is universal (`lipo -archs` lists both
  `x86_64` and `arm64` for `oxbox` and all four helpers)
- cleanup: delete the extracted tree and the archive
- caveats: the workflow's copy is built on a clean runner; this arm builds in
  the release worktree, so a stale `target/` could mask a missing-file bug.
  Build with a worktree-local `CARGO_TARGET_DIR`. UNVERIFIED

### msi

- kind: msi
- artifact: `oxbox-<version>-x64.msi` (`build.ps1` appends the arch; release notes use that name too)
- workflow job: `windows`
- host: windows-bench
- build: `packaging\windows\build.ps1 -Version <v> -OutDir dist -BinDir target\release`
- install like a user: **first query `RelatedProducts` on oxbox's UpgradeCode.**
  A registered older oxbox MSI shares that code, so installing MajorUpgrades it
  away and the `msiexec /x` cleanup then leaves the machine with no oxbox at
  all. If one is present, back up its prefix, its `HKCU\Software\oxbox` and the
  User PATH before installing, and restore them after — and know that the old
  product *registration* cannot be recreated without the old MSI. Then
  `msiexec /i oxbox-<version>-x64.msi /qn` into a throwaway prefix and run the
  installed `oxbox.exe`
- smoke: S1–S7 and S5b, plus: the four helpers resolve to `libexec\bin` under the
  install root
- cleanup: `msiexec /x` the package
- caveats: the workflow Azure-signs the MSI; this arm builds an unsigned one
  from the same `build.ps1` and cannot verify signing, which would surface
  only in the real `windows` job. The host is AMD64 while the local machine
  is not, so the MSI is built on the bench rather than cross-built.

### source

- kind: source
- artifact: none; the checkout itself
- workflow job: none
- host: local
- build: `cargo build --locked --release` with a worktree-local `CARGO_TARGET_DIR`
- install like a user: run `target/release/oxbox` in place, which is the path
  the README documents for keeping a checkout on the distro's own bubblewrap
- smoke: S1–S4, S6, S7 — S5 is included, but S3 is expected to resolve helpers
  to the build directory rather than an installed prefix, which is correct for
  this channel
- cleanup: remove the worktree-local target dir
- caveats: this is the only arm that does not test packaging at all; it exists
  so a build break is attributed to the code rather than to a channel

## Archaeology

- issue source: `gh issue list --state closed --limit 200 --repo curtisgalloway/oxbox`
- fix commits: `git log --grep='Fixes #' --grep='Closes #' -i -E` over subjects
  and bodies; prefer the trailers over loose `#N` matches, which pick up prose
  mentions
- test locations: Rust unit tests inline in `crates/*/src/*.rs` under
  `#[cfg(test)]`; this repo keeps them in the same file as the code, so a new
  assertion goes in the module it exercises
- how to run: `cargo test --locked --workspace`
- prove-it-bites: **the skill's default recipe does not work in this repo.**
  `git checkout <fix>^ -- <fixed files>` reverts the tests along with the code,
  because this repo keeps them inline in the file they exercise. Measured on
  `06d02d8` (the #50 provider pin): the file revert left the suite *green* at 30
  tests instead of 35, since the five that would have caught it went back in the
  box with the bug — and it would delete any new test written into that file.
  Several reverts also do not compile (reverting `oxbox-core/src/lib.rs` past
  `588a67c` restores an `include_str!` path renamed in that same commit).

  Use a **surgical revert** instead: apply the literal reverse of the fix's
  production hunk to HEAD, leave the tests in place, run the suite, then
  restore. Establish coverage by mutating fix-derived lines one at a time.
  Keep every revert inside a single scripted run that ends in
  `git checkout HEAD -- crates/` and asserts `git status --porcelain -- crates/`
  is empty — other arms build in this worktree concurrently, so a revert window
  left open across a turn is genuinely dangerous
- note: `cargo test --locked --workspace` is not the whole safety net. Two fixes
  are protected only by the Python suites — `33941ec` (the 1.0.1 Homebrew
  `real_exe_dir` bug) by `guardtest.py`, and the `openrouter-us` venue by
  `wiretest.py`, which checks the *Python reference's* venue table and not the
  Rust `VENUES` table. Retiring the Python reference would drop both guards
  silently

## Publish

- gate: ask before tag/push. The repo is public on github.com, so the user's
  business-hours schedule applies — quote `date` at the moment of asking, and
  do not assume a weekday evening is outside it
- steps: push the release branch; open a PR carrying only the archaeology
  commits; wait for the six required checks; merge (linear history, so rebase
  or squash); tag the merged head `v<X.Y.Z>` with subject `<X.Y.Z>: <summary>`;
  push the tag; watch `release.yml` and then `apt.yml`, which `release.yml`
  triggers and which is what actually publishes the pool
- **after the tag, before anything else: confirm `refresh-apt-repo` dispatched
  `apt.yml` and that the run succeeded**, then `curl` the live
  `dists/stable/main/binary-<arch>/Packages` and grep for `Version: <X.Y.Z>`.
  That job has never run; if it silently does not fire, the pool keeps serving
  the previous version while the Release page shows the new one, and the only
  symptom a user sees is that `apt upgrade` has nothing for them
- re-verify:
  - homebrew: `brew install curtisgalloway/tap/oxbox` from the public tap, S1–S3
  - apt: add the public repository per the README's deb822 block, `apt update`,
    `apt install oxbox`, S1–S3, and assert the installed version is the one just
    tagged rather than the previous one
  - deb: download `oxbox_<version>_arm64.deb` from the Release, verify its
    checksum against the sidecar, install, S1–S3
  - linux-tarball / macos-tarball: download from the Release, verify checksums,
    extract, S1–S3
  - msi: download and verify the checksum only; no host to install on

## Sources

| path | blob | feeds |
|---|---|---|
| `.github/workflows/release.yml` | 573e71d95540 | Channels, Publish |
| `.github/workflows/apt.yml` | 13decb28f727 | Channels: apt, Publish |
| `.github/workflows/ci.yml` | 1a94495f15a4 | Project: required checks |
| `packaging/nfpm.yaml` | b82f704e958e | Channels: deb |
| `packaging/tarball.sh` | a6a7e07510b4 | Channels: linux-tarball, macos-tarball |
| `packaging/scripts/build-apt-repo.sh` | 20a931acd010 | Channels: apt |
| `packaging/windows/build.ps1` | 7bc77704ba77 | Channels: msi |
| `README.md` | 8ce7e94c3f91 | Channels: install like a user |
| `Cargo.toml` | be0e4fdc6173 | Project: version source |
