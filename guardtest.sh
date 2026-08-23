#!/bin/bash
# SPDX-FileCopyrightText: 2026 Curtis Galloway
# SPDX-License-Identifier: Apache-2.0
#
# Exercises the containment checks that run OUTSIDE the jail, which jailtest.py
# cannot reach: argument validation, patch validation, the secret scanner, and
# the inherited-descriptor guard.
#
# Every case here corresponds to a defect found in the self-audit. They are
# regression tests, not hypotheticals.
#
# NOTE: re-seeds sandbox/work. Run ./oxseed --clean afterwards if you care.
#
# Usage: ./guardtest.sh

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TMP="$(mktemp -d -t oxbox-guardtest)"
PASS=0
FAIL=0

report() {
  if [ "$1" -eq 0 ]; then
    printf '[PASS] %s\n' "$2"
    PASS=$((PASS + 1))
  else
    printf '[FAIL] %s\n' "$2"
    FAIL=$((FAIL + 1))
  fi
}

# Output goes to /dev/null, not a temp file: a regular file outside the sandbox
# would trip oxbox's own inherited-descriptor guard and fail every oxbox case
# for the wrong reason. /dev/null is a character device, so the guard ignores it.

# Expect a command to exit non-zero (a refusal).
expect_refused() {
  local label="$1"
  shift
  if "$@" >/dev/null 2>&1; then
    report 1 "$label (command succeeded; it should have refused)"
  else
    report 0 "$label"
  fi
}

# Expect a command to exit zero (a legitimate use that must keep working).
expect_allowed() {
  local label="$1"
  shift
  if "$@" >/dev/null 2>&1; then
    report 0 "$label"
  else
    report 1 "$label (refused; it should have been allowed)"
  fi
}

mkdir -p "$TMP/src"
printf 'def f():\n    return 1\n' > "$TMP/src/mod.py"

printf '=== seed guards ===\n'
expect_refused "oxseed refuses parent traversal" \
  "$HERE/oxseed" "$TMP/src" ../../../etc/hosts
expect_refused "oxseed refuses absolute path" \
  "$HERE/oxseed" "$TMP/src" /etc/hosts
expect_allowed "oxseed accepts a normal file" \
  "$HERE/oxseed" "$TMP/src" mod.py

printf '\n=== jail argument guards ===\n'
expect_refused "oxbox refuses --work outside sandbox/" \
  "$HERE/oxbox" --work "$HERE" -- /usr/bin/true
expect_allowed "oxbox runs with the default work dir" \
  "$HERE/oxbox" -- /usr/bin/true

printf '\n=== inherited descriptor guard ===\n'
if "$HERE/oxbox" -- /usr/bin/true > "$TMP/outside.txt" 2>&1; then
  report 1 "oxbox refuses stdout redirected outside the sandbox"
else
  report 0 "oxbox refuses stdout redirected outside the sandbox"
fi
if "$HERE/oxbox" -- /usr/bin/true > "$HERE/sandbox/work/inside.txt" 2>/dev/null; then
  report 0 "oxbox allows stdout redirected inside the sandbox"
else
  report 1 "oxbox allows stdout redirected inside the sandbox"
fi
if "$HERE/oxbox" --allow-external-output -- /usr/bin/true > "$TMP/optin.txt" 2>&1; then
  report 0 "oxbox honours --allow-external-output"
else
  report 1 "oxbox honours --allow-external-output"
fi

printf '\n=== patch guards ===\n'
cat > "$TMP/rename.patch" <<'PATCH'
diff --git a/mod.py b/../../../../tmp/pwned
similarity index 100%
rename from mod.py
rename to ../../../../tmp/pwned
PATCH
expect_refused "oxapply refuses traversal in rename headers" \
  "$HERE/oxapply" --diff "$TMP/rename.patch"

cat > "$TMP/symlink.patch" <<'PATCH'
diff --git a/leak b/leak
new file mode 120000
--- /dev/null
+++ b/leak
@@ -0,0 +1 @@
+/etc/passwd
PATCH
expect_refused "oxapply refuses symlink-creating patches" \
  "$HERE/oxapply" --diff "$TMP/symlink.patch"

cat > "$TMP/absolute.patch" <<'PATCH'
--- a/etc/passwd
+++ b//etc/passwd
@@ -1 +1 @@
-x
+y
PATCH
expect_refused "oxapply refuses absolute paths" \
  "$HERE/oxapply" --diff "$TMP/absolute.patch"

printf '\n=== secret scanner ===\n'
expect_refused "ox refuses a key in the task argument" \
  "$HERE/ox" --dry-run --mode ask "my key is sk-abcdefghijklmnopqrstuvwxyz012345"
printf 'AKIAIOSFODNN7EXAMPLE\n' > "$TMP/creds.txt"
expect_refused "ox refuses a key in a --files body" \
  "$HERE/ox" --dry-run --mode ask --files "$TMP/creds.txt" "explain this"
expect_allowed "ox accepts an ordinary prompt" \
  "$HERE/ox" --dry-run --mode ask "explain what a unified diff is"

rm -rf "$TMP"
printf '\n'
if [ "$FAIL" -ne 0 ]; then
  printf 'GUARDS LEAK: %d passed, %d FAILED\n' "$PASS" "$FAIL"
  exit 1
fi
printf 'guards hold: %d/%d passed\n' "$PASS" "$PASS"
