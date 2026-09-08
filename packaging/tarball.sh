#!/bin/sh
# SPDX-FileCopyrightText: 2026 Curtis Galloway
# SPDX-License-Identifier: Apache-2.0

# Stage a release tarball from built binaries (run by
# .github/workflows/release.yml on macOS and inside the Linux containers).
#
#   packaging/tarball.sh <version> <outdir> <suffix> <bindir>
#
#   suffix   macos-universal | linux-amd64 | linux-arm64: the platform part of
#            the archive name, oxbox-<version>-<suffix>.tar.gz
#   bindir   where the five executables are: target/release, or a directory
#            of lipo'd universal binaries on macOS
#
# The layout is a prefix -- bin/ beside libexec/ and share/ -- because that
# is what the tools know how to resolve: oxbox looks for its helpers one
# level up in libexec/bin, and the jail and the skill printer look up from
# the executable for share/oxbox. Unpack it anywhere and run bin/oxbox in
# place, or copy the contents over /usr/local; either way the helpers, the
# seatbelt profile and the oxbox-review skill are where the tools expect them.
# It is the same layout the Homebrew formula pours, on purpose: on macOS and
# on Linux the formula installs THIS archive, so a layout bug here is a
# layout bug there and the release smoke test catches both.
#
# Not packaged, same as the .deb: guardtest/wiretest/jailtest. They assert
# against a source checkout's layout, so verifying the jail is a git-clone
# operation and README says so.
#
# The seatbelt profile ships in the Linux archive too. It is 2 KB, the
# Linux jail never reads it, and one layout for both platforms is worth more
# than the bytes.

set -eu

version="${1:?usage: tarball.sh <version> <outdir> <suffix> <bindir>}"
outdir="${2:?usage: tarball.sh <version> <outdir> <suffix> <bindir>}"
suffix="${3:?usage: tarball.sh <version> <outdir> <suffix> <bindir>}"
bindir="${4:?usage: tarball.sh <version> <outdir> <suffix> <bindir>}"

root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
name="oxbox-${version}-${suffix}"
stage="${outdir}/${name}"

rm -rf "$stage"
mkdir -p "$stage/bin" "$stage/libexec/bin" "$stage/share/oxbox/oxbox-review/scripts" \
    "$stage/share/doc/oxbox/docs"

install -m 0755 "$bindir/oxbox" "$stage/bin/oxbox"

# The helpers live off PATH. oxbox finds them at ../libexec/bin from its own
# location (helper_dirs); `oxbox <sub>` execs oxbox-<sub>, and
# `oxbox helper <sub>` runs one directly.
for tool in oxbox-sandbox oxbox-send oxbox-patch oxbox-jail; do
    install -m 0755 "$bindir/$tool" "$stage/libexec/bin/$tool"
done

install -m 0644 "$root/profiles/jail.sb" "$stage/share/oxbox/jail.sb"

# The oxbox-review skill, listed file by file rather than copied wholesale so a
# stray __pycache__ in the checkout cannot end up in a release artifact.
install -m 0644 "$root/.claude/skills/oxbox-review/SKILL.md" \
    "$stage/share/oxbox/oxbox-review/SKILL.md"
for script in preflight.py exposure.py oxreview.py; do
    install -m 0755 "$root/.claude/skills/oxbox-review/scripts/$script" \
        "$stage/share/oxbox/oxbox-review/scripts/$script"
done

install -m 0644 "$root/LICENSE" "$stage/share/doc/oxbox/LICENSE"
install -m 0644 "$root/README.md" "$stage/share/doc/oxbox/README.md"
install -m 0644 "$root/AGENTS.md" "$stage/share/doc/oxbox/AGENTS.md"
# Under docs/ beside the README, so its relative link resolves when installed.
install -m 0644 "$root/docs/comparison.md" "$stage/share/doc/oxbox/docs/comparison.md"

# Recording root:wheel instead of whoever built it keeps the archive from
# carrying a runner account name, and keeps two builds of one tag
# byte-comparable. bsdtar (macOS) and GNU tar (the Linux containers) spell
# that differently.
if tar --version 2>/dev/null | grep -q GNU; then
    tar -C "$outdir" --owner=0 --group=0 --numeric-owner \
        -czf "${outdir}/${name}.tar.gz" "$name"
else
    tar -C "$outdir" --uid 0 --gid 0 --uname root --gname wheel \
        -czf "${outdir}/${name}.tar.gz" "$name"
fi
rm -rf "$stage"

echo "${outdir}/${name}.tar.gz"
