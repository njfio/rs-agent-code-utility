#!/usr/bin/env bash
# Roll up `changelog.d/*.md` fragments into a new version section in
# `CHANGELOG.md`, then delete the consumed fragments.
#
# Usage:
#   scripts/build-changelog.sh <version>
#
# Example:
#   scripts/build-changelog.sh 0.5.5
#
# Writes:
#   - CHANGELOG.md gets a new `## [<version>] - <today>` section
#     inserted between `## [Unreleased]` and the previous version
#     header, containing the concatenated fragments (sorted by
#     filename so PR-number ordering is preserved).
#   - All `changelog.d/*.md` files except `README.md` are deleted.
#
# Dry-run: pass `--dry-run` as the second arg to print the resulting
# CHANGELOG header without modifying anything on disk.
#
# Pre-flight checks:
#   - Refuses to run if `changelog.d/` has no fragments other than
#     README.md (nothing to release).
#   - Refuses to run if the version arg doesn't match `<major>.<minor>.<patch>`.
#   - Refuses to run if the version already appears as a header in
#     `CHANGELOG.md` (idempotency / accidental-rerun guard).

set -euo pipefail

VERSION="${1:-}"
DRY_RUN=""
if [[ "${2:-}" == "--dry-run" ]]; then
    DRY_RUN=1
fi

if [[ -z "$VERSION" ]]; then
    echo "Usage: $0 <version> [--dry-run]" >&2
    echo "Example: $0 0.5.5" >&2
    exit 64
fi

if ! [[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "ERROR: version must be MAJOR.MINOR.PATCH (got: $VERSION)" >&2
    exit 64
fi

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

if [[ ! -f CHANGELOG.md ]]; then
    echo "ERROR: CHANGELOG.md not found at $REPO_ROOT" >&2
    exit 1
fi

if [[ ! -d changelog.d ]]; then
    echo "ERROR: changelog.d/ not found at $REPO_ROOT" >&2
    exit 1
fi

# Idempotency guard: don't re-release the same version.
if grep -q "^## \[$VERSION\]" CHANGELOG.md; then
    echo "ERROR: version $VERSION is already present in CHANGELOG.md" >&2
    exit 1
fi

# Find fragments (everything in changelog.d/ except README.md).
shopt -s nullglob
FRAGMENTS=()
for f in changelog.d/*.md; do
    base="$(basename "$f")"
    if [[ "$base" == "README.md" ]]; then
        continue
    fi
    FRAGMENTS+=("$f")
done
shopt -u nullglob

if [[ ${#FRAGMENTS[@]} -eq 0 ]]; then
    echo "ERROR: no fragments in changelog.d/ (only README.md)" >&2
    echo "Nothing to release." >&2
    exit 1
fi

# Sort fragments by filename — keeps PR-number ordering deterministic.
IFS=$'\n' SORTED=($(printf '%s\n' "${FRAGMENTS[@]}" | sort))
unset IFS

TODAY=$(date +%Y-%m-%d)
TMP_HEADER=$(mktemp)
trap 'rm -f "$TMP_HEADER"' EXIT

# Build the new section header + concatenated fragments.
{
    echo "## [$VERSION] - $TODAY"
    echo ""
    for f in "${SORTED[@]}"; do
        cat "$f"
        echo ""
    done
} > "$TMP_HEADER"

if [[ -n "$DRY_RUN" ]]; then
    echo "===== Dry run: would insert under [Unreleased] ====="
    cat "$TMP_HEADER"
    echo "===== Fragments that would be deleted ====="
    printf '  %s\n' "${SORTED[@]}"
    exit 0
fi

# Insert the new section right after the `## [Unreleased]` line.
# awk is more robust than sed for multi-line insertion.
TMP_OUT=$(mktemp)
awk -v inject_file="$TMP_HEADER" '
    /^## \[Unreleased\]/ {
        print
        # Print the inject content immediately after [Unreleased].
        while ((getline line < inject_file) > 0) {
            print line
        }
        close(inject_file)
        # Also print an empty separator if not already present.
        next
    }
    { print }
' CHANGELOG.md > "$TMP_OUT"
mv "$TMP_OUT" CHANGELOG.md

# Delete the consumed fragments.
for f in "${SORTED[@]}"; do
    rm -- "$f"
done

echo "Inserted $VERSION section with ${#SORTED[@]} fragment(s)."
echo "Deleted fragments:"
printf '  %s\n' "${SORTED[@]}"
echo ""
echo "Review the result:"
echo "  head -50 CHANGELOG.md"
echo "Then commit:"
echo "  git add CHANGELOG.md changelog.d/"
echo "  git commit -m 'release: v$VERSION — <theme>'"
