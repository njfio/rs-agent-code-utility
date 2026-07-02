#!/usr/bin/env bash
set -euo pipefail
IN=$(cat)
SID=$(jq -r '.session_id' <<<"$IN")
ROOT=$(git rev-parse --show-toplevel 2>/dev/null) || exit 0
DIR="$ROOT/.entropy/session/$SID"
mkdir -p "$DIR"
jq -n \
  --arg started_at "$(date -u +%FT%TZ)" \
  --arg base_rev "$(git rev-parse HEAD 2>/dev/null || echo none)" \
  --arg branch "$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo none)" \
  '{started_at:$started_at, base_rev:$base_rev, branch:$branch}' > "$DIR/start.json"
exit 0
