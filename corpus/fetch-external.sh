#!/usr/bin/env bash
# Fetch external repos for cross-codebase semantic-eval corpora.
#
# v0.5.0–v0.5.3 corpora (`semantic-eval-rts-core*.toml`) all ran
# against `crates/rts-core` — the repo that holds the ranker code.
# Self-eval is a weak falsifier: even with blind-v2's outside-in
# protocol, the developer's vocabulary still inherits from years
# of staring at the same symbols.
#
# v0.5.4 adds external-repo corpora. Each query was authored after
# reading the repo's README + running `outline_workspace` against
# it; expected symbols were verified to actually exist via
# `find_symbol`. The repos are popular, well-documented, and span
# multiple languages so the ranker is exercised across the
# 12-language extractor matrix.
#
# Pinning: each repo is checked out at a specific commit (NOT a
# moving branch tip) so the corpus reproduces stable numbers across
# runs. Bumping a pin is a deliberate maintenance step that
# requires re-validating expected_top_k.
#
# Usage:
#   ./corpus/fetch-external.sh           # fetch all pinned repos
#   ./corpus/fetch-external.sh ripgrep   # fetch one
#
# The fetched repos land in `corpus/repos/`, which is gitignored.

set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")" && pwd)/repos"
mkdir -p "$REPO_DIR"

# (name | url | commit | description) — pipe-delimited because URLs contain ':'.
REPOS=(
    "rust-log|https://github.com/rust-lang/log.git|0.4.22|Rust logging facade (~2k LOC, tiny well-known Rust)"
    "ripgrep|https://github.com/BurntSushi/ripgrep.git|14.1.1|Recursive line-search CLI (~30k LOC, medium Rust, meta-relevant)"
    "cobra|https://github.com/spf13/cobra.git|v1.8.1|Go CLI framework (~15k LOC, popular Go)"
    "requests|https://github.com/psf/requests.git|v2.32.3|Python HTTP for humans (~10k LOC, classic Python)"
)

fetch_one() {
    local name="$1" url="$2" commit="$3" desc="$4"
    local dest="$REPO_DIR/$name"

    if [[ -d "$dest/.git" ]]; then
        echo "[$name] already cloned at $dest"
        (cd "$dest" && git fetch --depth 1 origin "$commit" 2>&1 | tail -1 && git checkout "$commit" 2>&1 | tail -1)
    else
        echo "[$name] cloning $url ($commit) — $desc"
        if git clone --depth 1 --branch "$commit" "$url" "$dest" 2>/dev/null; then
            :
        else
            # `--branch` only works on tag/branch names; commit SHAs need a full clone.
            rm -rf "$dest"
            git clone "$url" "$dest" 2>&1 | tail -1
            (cd "$dest" && git checkout "$commit" 2>&1 | tail -1)
        fi
    fi
    local lines
    lines=$(find "$dest" -type f \( -name '*.rs' -o -name '*.go' -o -name '*.py' -o -name '*.js' -o -name '*.ts' -o -name '*.java' -o -name '*.cs' \) -not -path '*/\.*' -exec wc -l {} + 2>/dev/null | tail -1 | awk '{print $1}' || echo "?")
    echo "[$name] checkout complete; ~$lines code lines"
}

if [[ $# -eq 0 ]]; then
    for spec in "${REPOS[@]}"; do
        IFS='|' read -r name url commit desc <<< "$spec"
        fetch_one "$name" "$url" "$commit" "$desc"
    done
else
    for arg in "$@"; do
        found=0
        for spec in "${REPOS[@]}"; do
            IFS='|' read -r name url commit desc <<< "$spec"
            if [[ "$name" == "$arg" ]]; then
                fetch_one "$name" "$url" "$commit" "$desc"
                found=1
                break
            fi
        done
        if [[ "$found" -eq 0 ]]; then
            echo "unknown repo: $arg" >&2
            echo "available: $(printf '%s\n' "${REPOS[@]}" | awk -F'|' '{print $1}' | tr '\n' ' ')" >&2
            exit 1
        fi
    done
fi

echo ""
echo "External corpora can now be run with:"
echo "  rts-bench semantic --corpus corpus/semantic-eval-<name>.toml --workspace corpus/repos/<name> --dry-run"
