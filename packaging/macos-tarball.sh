#!/bin/sh
# SPDX-FileCopyrightText: 2026 Curtis Galloway
# SPDX-License-Identifier: Apache-2.0

# Stage the macOS release tarball (built by .github/workflows/release.yml).
#
#   packaging/macos-tarball.sh <version> <outdir>
#
# The layout is a prefix -- bin/ beside share/ -- because that is the only
# thing find_profile and find_skill know how to resolve: both look one level
# up from the script for share/oxbox. Unpack it anywhere and run bin/ox in
# place, or copy the contents over /usr/local; either way the seatbelt profile
# and the ox-review skill are where the tools expect them. It mirrors what the
# Homebrew formula installs, on purpose: brew is the maintained macOS channel
# and this is the same thing for people who do not use it, so a layout bug
# here is a layout bug there.
#
# Not packaged, same as the .deb: guardtest/wiretest/jailtest. They assert
# against a source checkout's layout, so verifying the jail is a git-clone
# operation and README says so.
#
# Unlike the Linux .deb there is no dependency metadata to declare -- the
# seatbelt jail is `sandbox-exec`, which ships with macOS, and the tools are
# stdlib-only Python against the system python3.

set -eu

version="${1:?usage: macos-tarball.sh <version> <outdir>}"
outdir="${2:?usage: macos-tarball.sh <version> <outdir>}"

root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
name="oxbox-${version}-macos"
stage="${outdir}/${name}"

rm -rf "$stage"
mkdir -p "$stage/bin" "$stage/share/oxbox/ox-review/scripts" "$stage/share/doc/oxbox"

for tool in ox oxbox oxapply oxseed; do
    install -m 0755 "$root/$tool" "$stage/bin/$tool"
done

# The seatbelt profile. The .deb omits it (Linux jails with bubblewrap); on
# macOS it is the jail, and oxbox refuses to run without it.
install -m 0644 "$root/profiles/jail.sb" "$stage/share/oxbox/jail.sb"

# The ox-review skill, listed file by file rather than copied wholesale so a
# stray __pycache__ in the checkout cannot end up in a release artifact.
install -m 0644 "$root/.claude/skills/ox-review/SKILL.md" \
    "$stage/share/oxbox/ox-review/SKILL.md"
for script in preflight.py exposure.py oxreview.py; do
    install -m 0755 "$root/.claude/skills/ox-review/scripts/$script" \
        "$stage/share/oxbox/ox-review/scripts/$script"
done

install -m 0644 "$root/LICENSE" "$stage/share/doc/oxbox/LICENSE"
install -m 0644 "$root/README.md" "$stage/share/doc/oxbox/README.md"
install -m 0644 "$root/AGENTS.md" "$stage/share/doc/oxbox/AGENTS.md"

# --uid/--uname are bsdtar spellings (GNU tar wants --owner) and this builds a
# macOS artifact on macOS, so that is the tar we get. Recording root:wheel
# instead of whoever built it keeps the archive from carrying a runner account
# name, and keeps two builds of one tag byte-comparable.
tar -C "$outdir" --uid 0 --gid 0 --uname root --gname wheel \
    -czf "${outdir}/${name}.tar.gz" "$name"
rm -rf "$stage"

echo "${outdir}/${name}.tar.gz"
