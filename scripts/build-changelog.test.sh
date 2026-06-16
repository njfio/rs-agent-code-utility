#!/usr/bin/env bash
# Regression test for scripts/build-changelog.sh.
#
# The rollup must keep the `_Nothing yet._` placeholder under
# `## [Unreleased]` and insert the new version section *below* it.
# Earlier the awk injected the new header immediately after the
# `## [Unreleased]` line, stranding `_Nothing yet._` at the foot of the
# new section and leaving `[Unreleased]` empty.
#
# Run: bash scripts/build-changelog.test.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SCRIPT="$SCRIPT_DIR/build-changelog.sh"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# Mirror the repo layout the script expects ($0/../.. is REPO_ROOT).
mkdir -p "$tmp/scripts" "$tmp/changelog.d"
cp "$SCRIPT" "$tmp/scripts/build-changelog.sh"

cat > "$tmp/CHANGELOG.md" <<'EOF'
# Changelog

## [Unreleased]

_Nothing yet._

## [0.1.0] - 2020-01-01

### Initial

First release.
EOF

cat > "$tmp/changelog.d/10-feat-thing.md" <<'EOF'
### Feature: a thing

Did a thing.
EOF

"$tmp/scripts/build-changelog.sh" 0.2.0 >/dev/null

cl="$tmp/CHANGELOG.md"
fail() { echo "FAIL: $1"; echo "----- CHANGELOG.md -----"; cat "$cl"; exit 1; }

# 1. Exactly one placeholder remains.
n=$(grep -c '_Nothing yet._' "$cl" || true)
[[ "$n" -eq 1 ]] || fail "expected exactly one '_Nothing yet._', got $n"

# 2. Order is [Unreleased] < _Nothing yet._ < [0.2.0] (placeholder stays
#    under Unreleased, new section sits below it).
u=$(grep -n '^## \[Unreleased\]' "$cl" | head -1 | cut -d: -f1)
p=$(grep -n '_Nothing yet._'      "$cl" | head -1 | cut -d: -f1)
v=$(grep -n '^## \[0.2.0\]'       "$cl" | head -1 | cut -d: -f1)
[[ -n "$u" && -n "$p" && -n "$v" && "$u" -lt "$p" && "$p" -lt "$v" ]] \
  || fail "structure wrong: [Unreleased]@${u:-?} _Nothing yet._@${p:-?} [0.2.0]@${v:-?}"

# 3. The fragment body landed inside the new section, above the prior version.
f=$(grep -n 'Did a thing.'  "$cl" | head -1 | cut -d: -f1)
o=$(grep -n '^## \[0.1.0\]' "$cl" | head -1 | cut -d: -f1)
[[ -n "$f" && -n "$o" && "$v" -lt "$f" && "$f" -lt "$o" ]] \
  || fail "fragment not inside new section: [0.2.0]@${v:-?} frag@${f:-?} [0.1.0]@${o:-?}"

echo "PASS: build-changelog.sh preserves the [Unreleased] placeholder"
