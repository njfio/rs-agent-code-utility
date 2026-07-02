#!/usr/bin/env bash
set -euo pipefail
IN=$(cat)
SID=$(jq -r '.session_id' <<<"$IN")
PROMPT=$(jq -r '.prompt // empty' <<<"$IN")
ROOT=$(git rev-parse --show-toplevel 2>/dev/null) || exit 0
command -v rts >/dev/null 2>&1 || exit 0
[ -n "$PROMPT" ] || exit 0

CFG="$ROOT/.entropy/config.toml"
K=$(python3 -c 'import sys,tomllib;print(tomllib.load(open(sys.argv[1],"rb"))["retrieval"]["k"])' "$CFG" 2>/dev/null || echo 12)
BUDGET=$(python3 -c 'import sys,tomllib;print(tomllib.load(open(sys.argv[1],"rb"))["retrieval"]["token_budget"])' "$CFG" 2>/dev/null || echo 1500)
TO=$(python3 -c 'import sys,tomllib;print(tomllib.load(open(sys.argv[1],"rb"))["retrieval"]["timeout_secs"])' "$CFG" 2>/dev/null || echo 2)

OUT=$(timeout "$TO" rts context --for "$PROMPT" --k "$K" \
        --token-budget "$BUDGET" --format hook-json 2>/dev/null) || exit 0
[ -n "$OUT" ] || exit 0

DIR="$ROOT/.entropy/session/$SID"; mkdir -p "$DIR"
# Accumulate offered symbols across all prompts in the session (dedupe by symbol_id, keep best rank).
jq -c '.offered[]' <<<"$OUT" >> "$DIR/offered.raw.jsonl"
jq -s 'group_by(.symbol_id) | map(min_by(.rank))' "$DIR/offered.raw.jsonl" > "$DIR/offered.json"

CTX=$(jq -r '.rendered' <<<"$OUT")
jq -n --arg ctx "$CTX" \
  '{hookSpecificOutput:{hookEventName:"UserPromptSubmit", additionalContext:$ctx}}'
