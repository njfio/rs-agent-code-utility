#!/usr/bin/env bash
# version: 0.8.0
# rts-verify.sh — Claude Code PostToolUse hook (verify-v0 P2.U2, this repo).
#
# Fires AFTER a Write/Edit/MultiEdit tool runs (so the file is on disk),
# runs `rts verify <file>`, and — when the file references symbols/imports
# that don't exist in the index — feeds those hallucinated references back
# into the model's next-turn context via hookSpecificOutput.additionalContext
# so the agent can correct them.
#
# Annotate-only: NEVER blocks an edit (PostToolUse can't anyway — the tool
# already ran). The blocking edit gate is a later phase.
#
# Contract (see https://code.claude.com/docs/en/hooks):
#   - Stdin: PostToolUse JSON payload from Claude Code.
#   - Stdout (on findings): JSON envelope with hookEventName=PostToolUse
#     + additionalContext. Visible to the model on next turn. PostToolUse
#     CANNOT set permissionDecision (it's after the fact).
#   - Stdout (silent): empty. Nothing enters the agent's context.
#   - Exit 0 ALWAYS. We never block — soft enforcement. Errors during
#     hook execution degrade to silent.
#
# Environment knobs (mirror rts-nudge.sh):
#   RTS_HOOK_DISABLED=1            — opt out; hook is silent for the session.
#   RTS_BIN                        — path to the `rts` binary (else $PATH).
#   RTS_NUDGE_FORCE_DAEMON_UP=1    — test-only: skip the probe, assume up.
#   RTS_NUDGE_FORCE_DAEMON_DOWN=1  — test-only: skip the probe, assume down.
#   XDG_RUNTIME_DIR                — daemon-health probe cache location.

set +e  # NEVER let an error bubble up — soft enforcement.

# ---------- 1. Fast early bails ----------

# Opt-out: any non-empty, non-"0" value disables the hook.
if [[ -n "${RTS_HOOK_DISABLED:-}" && "${RTS_HOOK_DISABLED}" != "0" ]]; then
    exit 0
fi

# Read the entire payload. Bail silently on read failure.
payload="$(cat 2>/dev/null)"
if [[ -z "$payload" ]]; then
    exit 0
fi

# ---------- 2. Parse with jq (ONE shell-out, all fields batched) ----------

# Single jq invocation extracts tool_name + the edited file path. PostToolUse
# carries the path under tool_input.file_path (Write/Edit/MultiEdit all use
# file_path).
read_jq=$(printf '%s' "$payload" | jq -r '
    [
      (.tool_name             // ""),
      (.tool_input.file_path  // "")
    ] | @tsv
' 2>/dev/null)

if [[ -z "$read_jq" ]]; then
    exit 0
fi

IFS=$'\t' read -r tool_name file_path <<<"$read_jq"

# Only file-mutating tools get verified. Everything else is silent.
case "$tool_name" in
    Write|Edit|MultiEdit) ;;
    *) exit 0 ;;
esac

# Need a real, existing file path to verify.
if [[ -z "$file_path" || ! -f "$file_path" ]]; then
    exit 0
fi

# ---------- 3. Daemon-health probe (cached) ----------
#
# Only verify if rts is actually available. A down daemon → silent (the
# `rts verify` call would just error with exit 3). Reuses rts-nudge's
# probe approach + force-knobs so the two hooks share behavior.
if [[ -n "${RTS_NUDGE_FORCE_DAEMON_DOWN:-}" ]]; then
    exit 0
fi
if [[ -z "${RTS_NUDGE_FORCE_DAEMON_UP:-}" ]]; then
    runtime_dir="${XDG_RUNTIME_DIR:-/tmp}"
    probe_file="${runtime_dir}/rts-up.${PPID:-$$}"
    if [[ -e "$probe_file" ]]; then
        :  # Cached "up".
    else
        if pgrep -x rts-daemon >/dev/null 2>&1; then
            mkdir -p "$runtime_dir" 2>/dev/null
            : >"$probe_file" 2>/dev/null
        else
            exit 0  # rts not running — silent.
        fi
    fi
fi

# ---------- 4. Locate the `rts` binary ----------
#
# $RTS_BIN wins (tests / non-PATH installs); else fall back to $PATH.
rts_bin="${RTS_BIN:-}"
if [[ -z "$rts_bin" ]]; then
    rts_bin="$(command -v rts 2>/dev/null)"
fi
if [[ -z "$rts_bin" || ! -x "$rts_bin" ]]; then
    exit 0  # No rts binary — silent.
fi

# ---------- 5. Run `rts verify <file>` ----------
#
# --no-color so the captured output is escape-free when re-emitted into
# JSON. RTS_NO_AUTOSPAWN is intentionally NOT set: if the daemon is up
# (probe passed) the call connects; if a race took it down, the call
# exits 3 → we stay silent below.
verify_out="$("$rts_bin" --no-color verify "$file_path" 2>/dev/null)"
verify_code=$?

# Exit-code contract from `rts verify`:
#   0 → clean / unsupported language / nothing to check → silent.
#   1 → ≥1 hallucinated reference → emit nudge.
#   3 → daemon error / unreachable → silent.
# Only act on exit 1 WITH output.
if [[ "$verify_code" -ne 1 || -z "$verify_out" ]]; then
    exit 0
fi

# ---------- 6. Emit the nudge ----------
#
# Bash-native JSON string escape (no jq fork on the output path). The
# verify output is workspace-controlled symbol names + our nudge line —
# ASCII-safe in practice; the escape covers \, ", and newlines. A broken
# envelope (exotic chars) degrades to a logged hook-output error, never
# silent corruption.
context="rts verify found references in ${file_path} that don't resolve against the index (possible hallucinations):
${verify_out}
Verify these symbols/imports actually exist before relying on them — use mcp__rts__find_symbol / mcp__rts__verify_symbol to confirm, or fix the names."

escape_for_json() {
    local s="$1"
    s="${s//\\/\\\\}"   # \  → \\
    s="${s//\"/\\\"}"   # "  → \"
    s="${s//$'\n'/\\n}" # newline → \n
    printf '"%s"' "$s"
}

escaped=$(escape_for_json "$context")

printf '{"hookSpecificOutput":{"hookEventName":"PostToolUse","additionalContext":%s}}\n' "$escaped"
exit 0
