#!/usr/bin/env bash
set -euo pipefail
IN=$(cat)
SID=$(jq -r '.session_id' <<<"$IN")
TRANSCRIPT=$(jq -r '.transcript_path // empty' <<<"$IN")
ROOT=$(git rev-parse --show-toplevel 2>/dev/null) || exit 0
DIR="$ROOT/.entropy/session/$SID"
[ -f "$DIR/start.json" ] || exit 0

BASE=$(jq -r '.base_rev' "$DIR/start.json")
STARTED=$(jq -r '.started_at' "$DIR/start.json")
BRANCH=$(jq -r '.branch' "$DIR/start.json")

# --- diff stats: committed since base + staged/unstaged + untracked, exempt globs excluded ---
CFG="$ROOT/.entropy/config.toml"
EXCLUDES=()
while IFS= read -r g; do [ -n "$g" ] && EXCLUDES+=(":(exclude)$g"); done < <(
  python3 -c 'import sys,tomllib;print("\n".join(tomllib.load(open(sys.argv[1],"rb"))["gate"]["exempt"]))' "$CFG" 2>/dev/null)

read -r ADD DEL FILES < <(
  { git diff --numstat "$BASE"...HEAD -- . "${EXCLUDES[@]}" 2>/dev/null
    git diff --numstat HEAD -- . "${EXCLUDES[@]}" 2>/dev/null
    git ls-files -o --exclude-standard -- . "${EXCLUDES[@]}" 2>/dev/null \
      | while IFS= read -r f; do
          [ -f "$f" ] && printf '%d\t0\t%s\n' "$(wc -l < "$f")" "$f"
        done
  } | awk -F'\t' '$1!="-"{a+=$1; d+=$2; f[$3]=1} END{printf "%d %d %d\n", a+0, d+0, length(f)}')

# --- token stats from transcript (verify field names against your CC version, §10) ---
TOK_OUT=0; CTX_PEAK=0; TURNS=0
if [ -n "$TRANSCRIPT" ] && [ -f "$TRANSCRIPT" ]; then
  TOK_OUT=$(jq -s '[.[]|select(.type=="assistant")|.message.usage.output_tokens // 0]|add // 0' "$TRANSCRIPT")
  CTX_PEAK=$(jq -s '[.[]|select(.type=="assistant")|((.message.usage.input_tokens//0)+(.message.usage.cache_read_input_tokens//0)+(.message.usage.cache_creation_input_tokens//0))]|max // 0' "$TRANSCRIPT")
  TURNS=$(jq -s '[.[]|select(.type=="user")]|length' "$TRANSCRIPT")
fi

EV="$ROOT/.entropy/events/$(date -u +%Y-%m).jsonl"
mkdir -p "$(dirname "$EV")"
jq -cn \
  --arg t task --arg sid "$SID" --arg repo "$(basename "$ROOT")" --arg branch "$BRANCH" \
  --arg started_at "$STARTED" --arg ended_at "$(date -u +%FT%TZ)" \
  --arg base_rev "$BASE" --arg head_rev "$(git rev-parse HEAD 2>/dev/null || echo none)" \
  --argjson lines_added "$ADD" --argjson lines_removed "$DEL" --argjson files_touched "$FILES" \
  --argjson tokens_out "$TOK_OUT" --argjson context_peak "$CTX_PEAK" --argjson turns "$TURNS" \
  '{t:$t, session_id:$sid, repo:$repo, branch:$branch, started_at:$started_at,
    ended_at:$ended_at, base_rev:$base_rev, head_rev:$head_rev,
    lines_added:$lines_added, lines_removed:$lines_removed, files_touched:$files_touched,
    tokens_out:$tokens_out, context_peak:$context_peak, turns:$turns}' >> "$EV"

# --- offered vs used: word-boundary match of offered symbol names in ADDED lines ---
if [ -f "$DIR/offered.json" ]; then
  ADDED_LINES=$(
    { git diff -U0 "$BASE"...HEAD -- . "${EXCLUDES[@]}" 2>/dev/null
      git diff -U0 HEAD -- . "${EXCLUDES[@]}" 2>/dev/null; } \
    | grep '^\+' | grep -v '^+++' || true)
  UNTRACKED=$(git ls-files -o --exclude-standard -- . "${EXCLUDES[@]}" 2>/dev/null \
    | while IFS= read -r f; do [ -f "$f" ] && cat "$f"; done)
  ADDED_LINES="$ADDED_LINES"$'\n'"$UNTRACKED"
  jq -c '.[]' "$DIR/offered.json" | while IFS= read -r sym; do
    NAME=$(jq -r '.name' <<<"$sym")
    USED=0
    if [ -n "$NAME" ] && grep -Fqw -- "$NAME" <<<"$ADDED_LINES"; then USED=1; fi
    jq -cn --arg t retrieval --arg sid "$SID" --argjson sym "$sym" --argjson used "$USED" \
      '{t:$t, session_id:$sid, symbol_id:$sym.symbol_id, name:$sym.name,
        path:$sym.path, rank:$sym.rank, score:$sym.score,
        used:$used, match_kind:"word"}' >> "$EV"
  done
fi
exit 0
