#!/usr/bin/env bash
# Pure-bash test runner for .claude/hooks/rts-verify.sh — the PostToolUse
# hook that runs `rts verify <file>` after Write/Edit/MultiEdit and feeds
# hallucinated references back to the agent. No bats, no external test
# framework. Runs anywhere bash + jq exist.
#
# The real `rts verify` needs a daemon + index, which we don't spin up in
# a hook unit test. Instead we stub the `rts` binary via $RTS_BIN: a tiny
# script whose exit code + stdout are driven by env vars, so each case can
# exercise the hook's branch logic deterministically. The daemon-health
# probe is bypassed with the same RTS_NUDGE_FORCE_DAEMON_UP/DOWN knobs the
# nudge hook uses.
#
# Output: one line per test (PASS/FAIL); non-zero exit if any test fails.

set -uo pipefail  # NOT -e: we want all tests to run.

REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
HOOK="$REPO_ROOT/.claude/hooks/rts-verify.sh"
if [[ ! -x "$HOOK" ]]; then
    echo "ERROR: $HOOK is not executable" >&2
    exit 1
fi

# Scratch dir for the stub `rts` binary + the file paths we "verify".
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# A stub `rts` that mimics `rts verify`'s exit-code + output contract.
# Driven by env: STUB_EXIT (default 0) and STUB_OUT (stdout to emit).
STUB_RTS="$WORK/rts"
cat >"$STUB_RTS" <<'STUB'
#!/usr/bin/env bash
# Stub `rts` for hook tests. Only handles `--no-color verify <file>`.
printf '%s' "${STUB_OUT:-}"
exit "${STUB_EXIT:-0}"
STUB
chmod +x "$STUB_RTS"

# A real file on disk for the hook's `-f` check.
TARGET_FILE="$WORK/edited.rs"
: >"$TARGET_FILE"

PASS_COUNT=0
FAIL_COUNT=0
FAILED_TESTS=()

# Run one test.
#   $1 name
#   $2 tool_name
#   $3 file_path (use "$TARGET_FILE" for an existing file, or a bogus path)
#   $4 expected: "nudge" | "silent"
#   $5 (optional) substring that MUST appear in nudge output
# Honors env: STUB_EXIT, STUB_OUT, RTS_HOOK_DISABLED,
# RTS_NUDGE_FORCE_DAEMON_UP / RTS_NUDGE_FORCE_DAEMON_DOWN.
run_test() {
    local name="$1" tool="$2" fpath="$3" expect="$4" must_have="${5:-}"
    local payload
    payload=$(jq -nc \
        --arg t "$tool" \
        --arg f "$fpath" \
        '{tool_name:$t, tool_input:{file_path:$f}, hook_event_name:"PostToolUse"}')
    local out
    out=$(printf '%s' "$payload" | RTS_BIN="$STUB_RTS" "$HOOK" 2>&1)
    local status=$?

    local fail_reason=""
    if [[ $status -ne 0 ]]; then
        fail_reason="exit $status (expected 0; hook must NEVER block)"
    elif [[ "$expect" == "nudge" ]]; then
        if [[ -z "$out" ]]; then
            fail_reason="expected nudge, got empty stdout"
        elif [[ -n "$must_have" && "$out" != *"$must_have"* ]]; then
            fail_reason="expected substring '$must_have' missing from: $out"
        fi
    elif [[ "$expect" == "silent" ]]; then
        if [[ -n "$out" ]]; then
            fail_reason="expected silent, got stdout: $out"
        fi
    fi

    if [[ -z "$fail_reason" ]]; then
        printf 'PASS  %s\n' "$name"
        PASS_COUNT=$((PASS_COUNT + 1))
    else
        printf 'FAIL  %s  — %s\n' "$name" "$fail_reason"
        FAIL_COUNT=$((FAIL_COUNT + 1))
        FAILED_TESTS+=("$name")
    fi
}

reset_env() {
    unset RTS_HOOK_DISABLED RTS_NUDGE_FORCE_DAEMON_DOWN STUB_EXIT STUB_OUT
    export RTS_NUDGE_FORCE_DAEMON_UP=1
}

# ============================================================
# Test cases
# ============================================================

# 1. Write referencing an invented symbol → hook emits a nudge naming it.
reset_env
export STUB_EXIT=1
export STUB_OUT="$TARGET_FILE:1  totally_invented_symbol  (did you mean: real_thing?)"
run_test "write_invented_symbol_nudges"   "Write" "$TARGET_FILE" "nudge"  "totally_invented_symbol"

# The nudge must carry the PostToolUse envelope + the "verify these" line.
reset_env
export STUB_EXIT=1
export STUB_OUT="$TARGET_FILE:1  bogus_sym"
run_test "nudge_envelope_hookSpecificOutput"  "Write" "$TARGET_FILE" "nudge"  "hookSpecificOutput"
reset_env
export STUB_EXIT=1
export STUB_OUT="$TARGET_FILE:1  bogus_sym"
run_test "nudge_envelope_hookEventName_post"  "Write" "$TARGET_FILE" "nudge"  '"hookEventName":"PostToolUse"'
reset_env
export STUB_EXIT=1
export STUB_OUT="$TARGET_FILE:1  bogus_sym"
run_test "nudge_has_verify_instruction"       "Edit"  "$TARGET_FILE" "nudge"  "Verify these symbols"

# 2. Write referencing only real symbols (verify exit 0, no output) → silent.
reset_env
export STUB_EXIT=0
export STUB_OUT=""
run_test "write_clean_file_silent"        "Write" "$TARGET_FILE" "silent"

# Exit 1 but EMPTY output (shouldn't happen, but be defensive) → silent.
reset_env
export STUB_EXIT=1
export STUB_OUT=""
run_test "exit1_no_output_silent"         "Write" "$TARGET_FILE" "silent"

# 3. RTS_HOOK_DISABLED=1 → silent.
reset_env
export STUB_EXIT=1
export STUB_OUT="$TARGET_FILE:1  bogus_sym"
export RTS_HOOK_DISABLED=1
run_test "hook_disabled_silent"           "Write" "$TARGET_FILE" "silent"

reset_env
export STUB_EXIT=1
export STUB_OUT="$TARGET_FILE:1  bogus_sym"
export RTS_HOOK_DISABLED=true
run_test "hook_disabled_true_silent"      "Write" "$TARGET_FILE" "silent"

# 4. Daemon down (forced) → silent (never even runs verify).
reset_env
unset RTS_NUDGE_FORCE_DAEMON_UP
export RTS_NUDGE_FORCE_DAEMON_DOWN=1
export STUB_EXIT=1
export STUB_OUT="$TARGET_FILE:1  bogus_sym"
run_test "daemon_down_silent"             "Write" "$TARGET_FILE" "silent"

# verify exit 3 (daemon error mid-run) → silent.
reset_env
export STUB_EXIT=3
export STUB_OUT=""
run_test "verify_daemon_error_silent"     "Write" "$TARGET_FILE" "silent"

# 5. Non-mutating tool (Read) → silent.
reset_env
export STUB_EXIT=1
export STUB_OUT="$TARGET_FILE:1  bogus_sym"
run_test "read_tool_silent"               "Read"  "$TARGET_FILE" "silent"

reset_env
export STUB_EXIT=1
export STUB_OUT="$TARGET_FILE:1  bogus_sym"
run_test "bash_tool_silent"               "Bash"  "$TARGET_FILE" "silent"

# MultiEdit IS a verified tool.
reset_env
export STUB_EXIT=1
export STUB_OUT="$TARGET_FILE:1  multi_bogus"
run_test "multiedit_invented_symbol_nudges" "MultiEdit" "$TARGET_FILE" "nudge" "multi_bogus"

# 6. Nonexistent / empty file path → silent.
reset_env
export STUB_EXIT=1
export STUB_OUT="x:1  bogus"
run_test "missing_file_path_silent"       "Write" "$WORK/does-not-exist.rs" "silent"
reset_env
export STUB_EXIT=1
export STUB_OUT="x:1  bogus"
run_test "empty_file_path_silent"         "Write" "" "silent"

# 7. Robustness: malformed / empty stdin → silent.
reset_env
out=$(printf 'not json' | RTS_BIN="$STUB_RTS" "$HOOK" 2>&1)
if [[ -z "$out" && $? -eq 0 ]]; then
    printf 'PASS  %s\n' "malformed_json_silent"
    PASS_COUNT=$((PASS_COUNT + 1))
else
    printf 'FAIL  %s  — got: %s\n' "malformed_json_silent" "$out"
    FAIL_COUNT=$((FAIL_COUNT + 1))
    FAILED_TESTS+=("malformed_json_silent")
fi

out=$(printf '' | RTS_BIN="$STUB_RTS" "$HOOK" 2>&1)
if [[ -z "$out" && $? -eq 0 ]]; then
    printf 'PASS  %s\n' "empty_stdin_silent"
    PASS_COUNT=$((PASS_COUNT + 1))
else
    printf 'FAIL  %s  — got: %s\n' "empty_stdin_silent" "$out"
    FAIL_COUNT=$((FAIL_COUNT + 1))
    FAILED_TESTS+=("empty_stdin_silent")
fi

# ============================================================
# Summary
# ============================================================
echo "---"
TOTAL=$((PASS_COUNT + FAIL_COUNT))
if [[ $FAIL_COUNT -eq 0 ]]; then
    printf '%d/%d tests passed.\n' "$PASS_COUNT" "$TOTAL"
    exit 0
else
    printf '%d/%d tests passed; %d FAILED:\n' "$PASS_COUNT" "$TOTAL" "$FAIL_COUNT"
    for t in "${FAILED_TESTS[@]}"; do
        printf '  - %s\n' "$t"
    done
    exit 1
fi
