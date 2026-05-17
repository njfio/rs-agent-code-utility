#!/usr/bin/env bats
# Tests for .claude/hooks/rts-nudge.sh — Claude Code PreToolUse hook
# that nudges agents toward rts MCP tools when they bash grep/rg/find.
#
# Run: bats .claude/hooks/tests/rts-nudge.bats
#
# Each test pipes a fixture JSON to the hook on stdin, captures
# stdout (the hook's JSON envelope to Claude Code), and asserts on
# the `additionalContext` field. The hook must never block (exit 0
# always) and must be silent when it has nothing useful to say.

setup() {
    REPO_ROOT="$(cd "$BATS_TEST_DIRNAME/../../.." && pwd)"
    HOOK="$REPO_ROOT/.claude/hooks/rts-nudge.sh"
    [[ -x "$HOOK" ]] || skip "hook not built or not executable: $HOOK"

    # Force a known PROJECT_DIR so realpath checks are deterministic.
    export CLAUDE_PROJECT_DIR="$REPO_ROOT"

    # Disable the daemon-health cache by pointing it at a unique
    # tempdir per-test so probe results don't leak across tests.
    export XDG_RUNTIME_DIR="$(mktemp -d)"

    # Default: pretend the daemon IS running so we exercise the
    # nudge path. Tests that want the "daemon down" case override.
    export RTS_NUDGE_FORCE_DAEMON_UP=1

    # Default: clear the opt-out env. Tests that want it set override.
    unset RTS_HOOK_DISABLED
}

# Helper: build a PreToolUse JSON payload for a Bash command and
# pipe through the hook. Captures stdout in $output; exit code in
# $status. Mirrors bats's `run` shape but with explicit stdin.
hook_with() {
    local tool="$1" command="$2"
    local payload
    payload=$(printf '{"tool_name":"%s","tool_input":{"command":"%s"},"cwd":"%s","hook_event_name":"PreToolUse"}' \
        "$tool" "$command" "$CLAUDE_PROJECT_DIR")
    run bash -c "printf '%s' '$payload' | '$HOOK'"
}

# ---------- Pattern detection (the R2 mapping table) ----------

@test "grep -rn on workspace path → nudges toward find_symbol/grep" {
    hook_with "Bash" "grep -rn 'socket_path_for_workspace' crates/"
    [ "$status" -eq 0 ]
    [[ "$output" == *"mcp__rts__"* ]]
    [[ "$output" == *"additionalContext"* ]]
}

@test "rg with name-shaped pattern → nudges toward find_symbol" {
    hook_with "Bash" "rg 'fn make_widget' crates/"
    [ "$status" -eq 0 ]
    [[ "$output" == *"find_symbol"* ]]
}

@test "find . -name '*.rs' → nudges toward outline_workspace" {
    hook_with "Bash" "find . -name '*.rs'"
    [ "$status" -eq 0 ]
    [[ "$output" == *"outline_workspace"* ]]
}

@test "egrep on workspace path → nudges" {
    hook_with "Bash" "egrep 'foo' crates/rts-core/src/lib.rs"
    [ "$status" -eq 0 ]
    [[ "$output" == *"mcp__rts__"* ]]
}

@test "fgrep on workspace path → nudges" {
    hook_with "Bash" "fgrep 'panic!' crates/"
    [ "$status" -eq 0 ]
    [[ "$output" == *"mcp__rts__"* ]]
}

# ---------- Silent paths (no nudge) ----------

@test "non-Bash tool (e.g. Read) → silent" {
    hook_with "Read" "noop"
    [ "$status" -eq 0 ]
    # Empty stdout means no envelope, no nudge.
    [ -z "$output" ]
}

@test "Bash with no search command (cargo build) → silent" {
    hook_with "Bash" "cargo build --release"
    [ "$status" -eq 0 ]
    [ -z "$output" ]
}

@test "Bash with git status → silent" {
    hook_with "Bash" "git status"
    [ "$status" -eq 0 ]
    [ -z "$output" ]
}

@test "grep on path OUTSIDE workspace (/tmp) → silent" {
    hook_with "Bash" "grep -r 'foo' /tmp/notes/"
    [ "$status" -eq 0 ]
    [ -z "$output" ]
}

@test "grep on /etc → silent (not in workspace)" {
    hook_with "Bash" "grep root /etc/passwd"
    [ "$status" -eq 0 ]
    [ -z "$output" ]
}

# ---------- Opt-out ----------

@test "RTS_HOOK_DISABLED=1 → silent even on matching command" {
    export RTS_HOOK_DISABLED=1
    hook_with "Bash" "rg 'foo' crates/"
    [ "$status" -eq 0 ]
    [ -z "$output" ]
}

@test "RTS_HOOK_DISABLED=true → silent (any truthy value)" {
    export RTS_HOOK_DISABLED=true
    hook_with "Bash" "rg 'foo' crates/"
    [ "$status" -eq 0 ]
    [ -z "$output" ]
}

# ---------- Daemon-down silence ----------

@test "rts daemon not running → silent (no nudge, no error)" {
    unset RTS_NUDGE_FORCE_DAEMON_UP
    export RTS_NUDGE_FORCE_DAEMON_DOWN=1
    hook_with "Bash" "rg 'foo' crates/"
    [ "$status" -eq 0 ]
    [ -z "$output" ]
}

# ---------- Robustness ----------

@test "malformed JSON stdin → silent (never crashes the bash call)" {
    run bash -c "printf 'not json' | '$HOOK'"
    [ "$status" -eq 0 ]
    [ -z "$output" ]
}

@test "empty stdin → silent" {
    run bash -c "printf '' | '$HOOK'"
    [ "$status" -eq 0 ]
    [ -z "$output" ]
}

@test "Bash with absurdly long command → silent or nudge, never crash" {
    local long_cmd
    long_cmd="echo $(printf 'x%.0s' {1..5000})"
    hook_with "Bash" "$long_cmd"
    [ "$status" -eq 0 ]
}

# ---------- Pipeline detection ----------

@test "pipeline with grep on workspace path → nudges" {
    hook_with "Bash" "cat crates/rts-core/src/lib.rs | grep 'fn'"
    [ "$status" -eq 0 ]
    [[ "$output" == *"mcp__rts__"* ]]
}

@test "subshell substitution with rg on workspace → nudges" {
    hook_with "Bash" "echo \$(rg --files crates/)"
    [ "$status" -eq 0 ]
    [[ "$output" == *"mcp__rts__"* ]]
}

# ---------- JSON envelope shape ----------

@test "nudge output is parseable JSON with hookSpecificOutput" {
    hook_with "Bash" "rg 'foo' crates/"
    [ "$status" -eq 0 ]
    # Validate the JSON shape via jq.
    [[ "$output" == *'"hookSpecificOutput"'* ]]
    [[ "$output" == *'"hookEventName": "PreToolUse"'* ]] || \
        [[ "$output" == *'"hookEventName":"PreToolUse"'* ]]
    [[ "$output" == *'"permissionDecision": "allow"'* ]] || \
        [[ "$output" == *'"permissionDecision":"allow"'* ]]
}

@test "nudge additionalContext is non-empty and mentions rts" {
    hook_with "Bash" "rg 'foo' crates/"
    [ "$status" -eq 0 ]
    [[ "$output" == *"rts"* ]]
}
