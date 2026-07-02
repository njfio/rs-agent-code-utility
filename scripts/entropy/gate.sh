#!/usr/bin/env bash
# entropy gate v0 — net-lines budget at push/PR time.
# Usage: gate.sh [gate|require-negative]
set -euo pipefail

MODE="${1:-gate}"
ROOT="$(git rev-parse --show-toplevel)"
CFG="$ROOT/.entropy/config.toml"

toml() {  # toml <dotted.key> <default>
  python3 - "$CFG" "$1" "${2:-}" <<'PY'
import sys, tomllib
try:
    node = tomllib.load(open(sys.argv[1], "rb"))
    for k in sys.argv[2].split("."):
        node = node[k]
    print("\n".join(map(str, node)) if isinstance(node, list) else node)
except Exception:
    print(sys.argv[3])
PY
}

WARN=$(toml gate.warn_net_lines 200)
BLOCK=$(toml gate.block_net_lines 400)
BASE=$(toml gate.default_base origin/main)

UPSTREAM=$(git rev-parse --abbrev-ref --symbolic-full-name '@{u}' 2>/dev/null || true)
RANGE="${UPSTREAM:-$BASE}...HEAD"

EXCLUDES=()
while IFS= read -r g; do
  [ -n "$g" ] && EXCLUDES+=(":(exclude)$g")
done < <(toml gate.exempt "")

read -r ADD DEL < <(git diff --numstat "$RANGE" -- . "${EXCLUDES[@]}" 2>/dev/null \
  | awk '$1 != "-" { a += $1; d += $2 } END { printf "%d %d\n", a+0, d+0 }')
NET=$(( ADD - DEL ))

BRANCH=$(git rev-parse --abbrev-ref HEAD)
SID="${ENTROPY_SESSION_ID:-}"

log_event() {  # log_event <action> [reason]
  local dir="$ROOT/.entropy/events"
  mkdir -p "$dir"
  jq -cn \
    --arg t gate --arg ts "$(date -u +%FT%TZ)" \
    --arg repo "$(basename "$ROOT")" --arg branch "$BRANCH" \
    --argjson net "$NET" --argjson add "$ADD" --argjson del "$DEL" \
    --argjson warn "$WARN" --argjson block "$BLOCK" \
    --arg action "$1" --arg reason "${2:-}" --arg sid "$SID" \
    '{t:$t, ts:$ts, repo:$repo, branch:$branch, net:$net, added:$add,
      removed:$del, warn:$warn, block:$block, action:$action,
      override_reason:$reason, session_id:$sid}' \
    >> "$dir/$(date -u +%Y-%m).jsonl"
}

if [ "$MODE" = "require-negative" ]; then
  if [ "$NET" -ge 0 ]; then
    log_event "block" "consolidation must be net-negative"
    echo "entropy: consolidation PR must be net-negative (net=$NET)." >&2
    exit 1
  fi
  log_event "pass"
  echo "entropy: net=$NET ✓ (net-negative required and satisfied)"
  exit 0
fi

if [ -n "${ENTROPY_OVERRIDE:-}" ]; then
  log_event "override" "$ENTROPY_OVERRIDE"
  echo "entropy: OVERRIDE (net=$NET, block=$BLOCK): $ENTROPY_OVERRIDE" >&2
  exit 0
fi

if [ "$NET" -gt "$BLOCK" ]; then
  log_event "block"
  cat >&2 <<EOM
entropy: BLOCKED — net +$NET lines exceeds budget ($BLOCK).
  Shrink the diff, split the change, or push with:
    ENTROPY_OVERRIDE="reason" git push
  Overrides are logged, not judged.
EOM
  exit 1
elif [ "$NET" -gt "$WARN" ]; then
  log_event "warn"
  echo "entropy: warning — net +$NET lines (warn=$WARN, block=$BLOCK)." >&2
else
  log_event "pass"
fi
exit 0
