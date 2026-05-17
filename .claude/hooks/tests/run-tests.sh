#!/usr/bin/env bash
# Pure-bash test runner for .claude/hooks/rts-nudge.sh — no bats, no
# external test framework. Runs anywhere bash + jq exist.
#
# Each test fires a synthetic PreToolUse payload through the hook
# and asserts on stdout / exit code. Returns non-zero exit if any
# test fails. Output is one line per test:
#   PASS  test_name
#   FAIL  test_name  (with stdout + reason)

set -uo pipefail  # NOT -e: we want all tests to run.

REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
HOOK="$REPO_ROOT/.claude/hooks/rts-nudge.sh"
if [[ ! -x "$HOOK" ]]; then
    echo "ERROR: $HOOK is not executable" >&2
    exit 1
fi

PASS_COUNT=0
FAIL_COUNT=0
FAILED_TESTS=()

# Run one test. Args:
#   $1  name (short)
#   $2  tool_name
#   $3  command
#   $4  expected_kind: "nudge" | "silent"
#   $5  (optional) substring that MUST appear in nudge output
#   $6  (optional) substring that MUST NOT appear in nudge output
# Env knobs honored: RTS_HOOK_DISABLED, RTS_NUDGE_FORCE_DAEMON_DOWN,
# CLAUDE_PROJECT_DIR (default REPO_ROOT), payload cwd.
run_test() {
    local name="$1" tool="$2" cmd="$3" expect="$4" must_have="${5:-}" must_not="${6:-}"
    # Build payload with jq so embedded quotes in `cmd` are
    # correctly JSON-escaped. The hook itself doesn't fork jq on
    # the hot path; this is test-side only.
    local payload
    payload=$(jq -nc \
        --arg t "$tool" \
        --arg c "$cmd" \
        --arg w "${CLAUDE_PROJECT_DIR:-$REPO_ROOT}" \
        '{tool_name:$t, tool_input:{command:$c}, cwd:$w, hook_event_name:"PreToolUse"}')
    local out
    out=$(printf '%s' "$payload" | "$HOOK" 2>&1)
    local status=$?

    local fail_reason=""
    if [[ $status -ne 0 ]]; then
        fail_reason="exit $status (expected 0; hook must NEVER block)"
    elif [[ "$expect" == "nudge" ]]; then
        if [[ -z "$out" ]]; then
            fail_reason="expected nudge, got empty stdout"
        elif [[ -n "$must_have" && "$out" != *"$must_have"* ]]; then
            fail_reason="expected substring '$must_have' missing from: $out"
        elif [[ -n "$must_not" && "$out" == *"$must_not"* ]]; then
            fail_reason="unexpected substring '$must_not' in: $out"
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

# Helper: clear env state between tests.
reset_env() {
    unset RTS_HOOK_DISABLED RTS_NUDGE_FORCE_DAEMON_DOWN
    export RTS_NUDGE_FORCE_DAEMON_UP=1
    export CLAUDE_PROJECT_DIR="$REPO_ROOT"
}

# ============================================================
# Test cases
# ============================================================

reset_env
run_test "grep_workspace_path_nudges"           "Bash" "grep -rn socket_path_for_workspace crates/"  "nudge"  "mcp__rts__"
run_test "rg_fn_pattern_nudges_find_symbol"     "Bash" 'rg "fn make_widget" crates/'                  "nudge"  "find_symbol"
run_test "find_dot_name_rs_nudges_outline"      "Bash" "find . -name *.rs"                            "nudge"  "outline_workspace"
run_test "egrep_workspace_nudges"               "Bash" "egrep foo crates/rts-core/src/lib.rs"         "nudge"  "mcp__rts__"
run_test "fgrep_workspace_nudges"               "Bash" "fgrep panic crates/"                          "nudge"  "mcp__rts__"
run_test "pipeline_cat_grep_nudges"             "Bash" "cat crates/rts-core/src/lib.rs | grep fn"     "nudge"  "mcp__rts__"

# Silent paths
reset_env
run_test "read_tool_silent"                     "Read" "noop"                                         "silent"
run_test "bash_cargo_build_silent"              "Bash" "cargo build --release"                        "silent"
run_test "bash_git_status_silent"               "Bash" "git status"                                   "silent"
run_test "grep_tmp_silent"                      "Bash" "grep -r foo /tmp/notes/"                      "silent"
run_test "grep_etc_silent"                      "Bash" "grep root /etc/passwd"                        "silent"

# Prose-command exemptions (added after a real false-positive: a
# `git commit -m "...heredoc with fn NAME and | grep..."` tripped
# the hook because the message body contained both a grep-shaped
# substring and a literal `|`. These commands take user prose and
# can't be meaningfully nudged.
run_test "git_commit_silent_even_with_grep_in_msg"  "Bash" 'git commit -m "blah fn NAME | grep foo"' "silent"
run_test "git_tag_silent"                            "Bash" 'git tag -a v0.5.8 -m "find: foo"'        "silent"
run_test "gh_pr_create_silent"                       "Bash" 'gh pr create --title "fix grep bug"'    "silent"
run_test "gh_issue_create_silent"                    "Bash" 'gh issue create --title "rg falls over"' "silent"

# Opt-out
reset_env
export RTS_HOOK_DISABLED=1
run_test "rts_hook_disabled_1_silent"           "Bash" "rg foo crates/"                               "silent"

reset_env
export RTS_HOOK_DISABLED=true
run_test "rts_hook_disabled_true_silent"        "Bash" "rg foo crates/"                               "silent"

# Daemon down
reset_env
unset RTS_NUDGE_FORCE_DAEMON_UP
export RTS_NUDGE_FORCE_DAEMON_DOWN=1
run_test "daemon_down_silent"                   "Bash" "rg foo crates/"                               "silent"

# Robustness
reset_env
malformed_payload="not json"
out=$(printf '%s' "$malformed_payload" | "$HOOK" 2>&1)
if [[ -z "$out" && $? -eq 0 ]]; then
    printf 'PASS  %s\n' "malformed_json_silent"
    PASS_COUNT=$((PASS_COUNT + 1))
else
    printf 'FAIL  %s  — got: %s\n' "malformed_json_silent" "$out"
    FAIL_COUNT=$((FAIL_COUNT + 1))
    FAILED_TESTS+=("malformed_json_silent")
fi

out=$(printf '' | "$HOOK" 2>&1)
if [[ -z "$out" && $? -eq 0 ]]; then
    printf 'PASS  %s\n' "empty_stdin_silent"
    PASS_COUNT=$((PASS_COUNT + 1))
else
    printf 'FAIL  %s  — got: %s\n' "empty_stdin_silent" "$out"
    FAIL_COUNT=$((FAIL_COUNT + 1))
    FAILED_TESTS+=("empty_stdin_silent")
fi

# JSON envelope shape
reset_env
run_test "nudge_envelope_has_hookSpecificOutput" "Bash" "rg foo crates/" "nudge" "hookSpecificOutput"
run_test "nudge_envelope_has_permissionAllow"    "Bash" "rg foo crates/" "nudge" '"permissionDecision":"allow"'
run_test "nudge_mentions_rts"                    "Bash" "rg foo crates/" "nudge" "rts"

# ============================================================
# Latency budget (separate; marked slow)
# ============================================================
echo "---"
echo "Latency budget check (100 warm runs, p95 budget: 50ms)..."
reset_env
payload='{"tool_name":"Bash","tool_input":{"command":"grep -rn foo crates/"},"cwd":"'"$REPO_ROOT"'","hook_event_name":"PreToolUse"}'
# Warm up
for i in 1 2 3; do printf '%s' "$payload" | "$HOOK" >/dev/null; done
latency_result=$(python3 <<EOF
import subprocess, time
payload = '''$payload'''
samples = []
for _ in range(100):
    t0 = time.perf_counter()
    subprocess.run(['$HOOK'], input=payload, capture_output=True, text=True)
    t1 = time.perf_counter()
    samples.append((t1 - t0) * 1000)
samples.sort()
n = len(samples)
p50 = samples[n//2]
p95 = samples[int(n*0.95)]
p99 = samples[int(n*0.99)]
budget_ok = p95 < 50
print(f"p50={p50:.1f}ms p95={p95:.1f}ms p99={p99:.1f}ms budget_ok={budget_ok}")
EOF
)
echo "  $latency_result"
if [[ "$latency_result" == *"budget_ok=True"* ]]; then
    printf 'PASS  %s\n' "latency_p95_under_50ms"
    PASS_COUNT=$((PASS_COUNT + 1))
else
    printf 'FAIL  %s  — see latency line above\n' "latency_p95_under_50ms"
    FAIL_COUNT=$((FAIL_COUNT + 1))
    FAILED_TESTS+=("latency_p95_under_50ms")
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
