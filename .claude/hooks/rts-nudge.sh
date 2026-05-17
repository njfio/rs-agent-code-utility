#!/usr/bin/env bash
# rts-nudge.sh — Claude Code PreToolUse hook (v0.5.8+, this repo).
#
# Intercepts `Bash` tool calls containing grep/rg/egrep/fgrep/find on
# workspace paths and emits an informational nudge into the model's
# next-turn context (via hookSpecificOutput.additionalContext) so the
# agent reaches for `mcp__rts__*` tools instead of shell search.
#
# Contract (see https://code.claude.com/docs/en/hooks):
#   - Stdin: PreToolUse JSON payload from Claude Code.
#   - Stdout (on nudge): JSON envelope with permissionDecision=allow
#     + additionalContext. Visible to the model on next turn.
#   - Stdout (silent): empty. Bash call proceeds normally; nothing
#     enters the agent's context.
#   - Exit 0 ALWAYS. We never block a Bash call — soft enforcement.
#     Errors during hook execution degrade to silent (no nudge).
#
# Environment knobs:
#   RTS_HOOK_DISABLED=1        — opt out; hook is silent for the session.
#   CLAUDE_PROJECT_DIR         — set by Claude Code; workspace root.
#   XDG_RUNTIME_DIR            — daemon-health probe cache location.
#   RTS_NUDGE_FORCE_DAEMON_UP=1     — test-only: skip the probe, assume up.
#   RTS_NUDGE_FORCE_DAEMON_DOWN=1   — test-only: skip the probe, assume down.
#
# Latency budget: <20ms p95 warm path. Achieved by:
#   1. Pre-fork `if: Bash(rg *|grep *|find *)` filter (set in settings.json).
#   2. No fork for env-opt-out and non-Bash tool checks.
#   3. Cached daemon-health probe with 60s mtime gate.
#   4. printf-based JSON emission (no `jq` on the output hot path).

set +e  # NEVER let an error bubble up — soft enforcement.

# ---------- 1. Fast early bails ----------

# Opt-out: any non-empty, non-"0" value disables the hook.
if [[ -n "${RTS_HOOK_DISABLED:-}" && "${RTS_HOOK_DISABLED}" != "0" ]]; then
    exit 0
fi

# Read the entire payload. Bail silently on read failure (e.g. empty
# stdin in a misconfigured test invocation).
payload="$(cat 2>/dev/null)"
if [[ -z "$payload" ]]; then
    exit 0
fi

# ---------- 2. Parse with jq (ONE shell-out, all fields batched) ----------

# Single jq invocation extracts every field we'll need downstream:
# tool_name, command, cwd. Coalescing to one jq call shaves ~10-20ms
# per nudge vs splitting parsing across multiple jq invocations —
# bash 3.2 + jq startup is the dominant cost in this hook.
read_jq=$(printf '%s' "$payload" | jq -r '
    [
      (.tool_name        // ""),
      (.tool_input.command // ""),
      (.cwd              // "")
    ] | @tsv
' 2>/dev/null)

if [[ -z "$read_jq" ]]; then
    exit 0
fi

# Split on tab. Use IFS so embedded spaces in the command stay intact.
IFS=$'\t' read -r tool_name command payload_cwd <<<"$read_jq"

# Only Bash calls get the nudge. Read/Edit/etc. are silent.
if [[ "$tool_name" != "Bash" ]]; then
    exit 0
fi

# Early bail for commands that take prose / commit messages as args.
# Without this, a `git commit -m "..."` or `gh pr create --body "..."`
# whose message literally contains `grep`, `find`, `fn NAME`, or `|`
# triggers a false-positive nudge. The hook's pipeline-splitter sees
# the `|` inside the quoted string and treats whatever follows as a
# new command head. Proper shell parsing here is over-engineering;
# the prose-command short-list catches >95% of real false positives.
case "$command" in
    "git commit"*|"git tag"*|"git rebase -i"*|"git rebase --interactive"*|"git stash"*|"git revert"*|"git merge"*) exit 0 ;;
    "gh pr "*|"gh issue "*|"gh release "*|"gh repo "*) exit 0 ;;
    "jj describe"*|"jj commit"*|"jj new"*) exit 0 ;;
esac

# ---------- 3. Pattern detection ----------

# Detect the search-command head anywhere in a pipeline. We split
# on shell metacharacters that introduce a fresh command:
#   |    pipe
#   ;    sequence
#   &&   conditional
#   ||   conditional
#   $(   command substitution
# (Backticks would be a 6th but are rare and handling them adds
# false positives more than they reduce false negatives.)
#
# Then for each segment, look for the head being one of:
#   grep | rg | egrep | fgrep | find
# Detection is *substring of the leading token*, after trimming
# leading whitespace. Avoids false-positives like `pgrep` or
# `agrep`.
detect_kind=""
# Replace each metachar with a literal newline so we can iterate
# pipeline segments. Order matters: && / || before single & / |
# so they're not double-split.
segments=$(printf '%s' "$command" \
    | sed -e 's/\$(/\n/g' \
          -e 's/&&/\n/g' \
          -e 's/||/\n/g' \
          -e 's/[|;]/\n/g')

while IFS= read -r seg; do
    # Trim leading whitespace.
    seg="${seg#"${seg%%[![:space:]]*}"}"
    # Extract the leading word (command head).
    head="${seg%%[[:space:]]*}"
    case "$head" in
        grep|rg|egrep|fgrep)
            detect_kind="grep"
            # Recover the full segment for path checking.
            detect_seg="$seg"
            break
            ;;
        find)
            detect_kind="find"
            detect_seg="$seg"
            break
            ;;
    esac
done <<<"$segments"

if [[ -z "$detect_kind" ]]; then
    exit 0
fi

# ---------- 4. Workspace-path check ----------
#
# The hook only nudges when the search targets paths under the
# repo root. Out-of-workspace searches (/tmp, /etc, vendored deps
# outside the indexed set) are correct uses of shell grep.
#
# Portable strategy (no `realpath -m` — macOS BSD realpath lacks
# it): string-classify each non-flag token.
#
#   Absolute path (`/foo`) → workspace iff prefix matches project_dir.
#   Relative path (`foo`, `crates/`, `.`) → workspace iff cwd is
#     under project_dir. (We use the agent's reported cwd from the
#     payload, falling back to $PWD.)
#   No positional args at all → command defaults to cwd; same rule.
#
# This is approximate but matches every common agent use pattern.
# False positives (cwd is workspace but the user is searching a
# symlink elsewhere) are benign — they nudge a soft suggestion the
# agent can ignore. False negatives (out-of-workspace path but cwd
# in workspace) are also benign — we just stay silent.
project_dir="${CLAUDE_PROJECT_DIR:-}"
if [[ -z "$project_dir" ]]; then
    # No CLAUDE_PROJECT_DIR — not in Claude Code, or standalone.
    exit 0
fi
project_dir="${project_dir%/}"

# `payload_cwd` was extracted in step 2's coalesced jq call.
# Fall back to $PWD when the payload didn't carry one (older
# Claude Code versions; standalone test invocations).
[[ -z "$payload_cwd" ]] && payload_cwd="$PWD"
payload_cwd="${payload_cwd%/}"

# Precompute "cwd is in workspace" once.
cwd_in_workspace=0
if [[ "$payload_cwd" == "$project_dir" || "$payload_cwd" == "$project_dir"/* ]]; then
    cwd_in_workspace=1
fi

touches_workspace=0
any_positional=0
seen_pattern_arg=0
# `read -ra` tokenizes on whitespace. Embedded quotes in the
# command are mostly already stripped by upstream parsing; we strip
# defensively below.
read -ra toks <<<"$detect_seg"
# Skip the head (toks[0]).
for ((i=1; i<${#toks[@]}; i++)); do
    tok="${toks[i]}"
    # Skip flags.
    case "$tok" in
        -*) continue ;;
    esac
    # For grep, the first non-flag arg is the pattern, not a path.
    if [[ "$detect_kind" == "grep" && $seen_pattern_arg -eq 0 ]]; then
        seen_pattern_arg=1
        continue
    fi
    any_positional=1
    # Strip surrounding quotes if any.
    tok="${tok#\'}"; tok="${tok%\'}"
    tok="${tok#\"}"; tok="${tok%\"}"
    # Classify.
    case "$tok" in
        /*)
            # Absolute path: workspace iff prefix matches.
            if [[ "$tok" == "$project_dir" || "$tok" == "$project_dir"/* ]]; then
                touches_workspace=1
                break
            fi
            ;;
        *)
            # Relative: workspace iff cwd is workspace.
            if [[ $cwd_in_workspace -eq 1 ]]; then
                touches_workspace=1
                break
            fi
            ;;
    esac
done

# No explicit path positional args. The command defaults to cwd:
#   grep PATTERN (reads stdin, but agents rarely do that)
#   find (no args, current dir)
# Treat as workspace iff cwd is workspace.
if [[ $touches_workspace -eq 0 && $any_positional -eq 0 && $cwd_in_workspace -eq 1 ]]; then
    # For `grep PATTERN` with no path arg: ambiguous (could be
    # reading from stdin via pipe). For `find` with no args:
    # definitively cwd. Either way, the nudge is soft and useful.
    touches_workspace=1
fi

if [[ $touches_workspace -eq 0 ]]; then
    exit 0
fi

# ---------- 5. Daemon-health probe (cached) ----------
#
# We only nudge if rts is actually available. Caching the probe
# result for 60s keeps the warm path cheap.
if [[ -n "${RTS_NUDGE_FORCE_DAEMON_DOWN:-}" ]]; then
    exit 0
fi
if [[ -z "${RTS_NUDGE_FORCE_DAEMON_UP:-}" ]]; then
    runtime_dir="${XDG_RUNTIME_DIR:-/tmp}"
    probe_file="${runtime_dir}/rts-up.${PPID:-$$}"
    # mtime within 60s = cache hit.
    if [[ -e "$probe_file" ]]; then
        # Cached "up" — nudge.
        :
    else
        # Probe: is rts-daemon running?
        if pgrep -x rts-daemon >/dev/null 2>&1; then
            # Touch the probe file (atomic mtime bump).
            mkdir -p "$runtime_dir" 2>/dev/null
            : >"$probe_file" 2>/dev/null
        else
            # rts not running — silent.
            exit 0
        fi
    fi
fi

# ---------- 6. Pattern-specific nudge text ----------

case "$detect_kind" in
    grep)
        # Look for `fn `, `class `, `def ` shaped patterns in the
        # command to nudge toward find_symbol vs find_callers vs grep.
        if [[ "$command" == *"'fn "* || "$command" == *'"fn '* || "$command" == *'class '* || "$command" == *'def '* ]]; then
            nudge="rts is indexed here. Try \`mcp__rts__find_symbol --name <NAME>\` for symbol definitions (AST-precise, ranked, no comment/string false positives) instead of shell grep. See AGENTS.md for the full intent → tool table."
        elif [[ "$command" == *".("* ]]; then
            nudge="rts is indexed here. Try \`mcp__rts__find_callers --name <NAME>\` for call-site lookups (AST-precise; no false positives from local variable names or string literals)."
        else
            nudge="rts is indexed here. Try \`mcp__rts__grep --text <PATTERN>\` for ranked, AST-aware search across the indexed workspace. Use --regex=true for regex; --file_glob for path scoping. The result includes enclosing symbol names — useful for refactor work."
        fi
        ;;
    find)
        nudge="rts is indexed here. Try \`mcp__rts__outline_workspace\` for a structural map of the codebase (file tree + top symbols + signatures, PageRank-sorted). For finding a specific symbol, \`mcp__rts__find_symbol --pattern '<glob>'\`."
        ;;
esac

# ---------- 7. Emit the nudge ----------
#
# Bash-native JSON string escape — saves a jq fork on the hot path
# (~10ms p95 win). We only ever emit nudge text we control (the
# strings literally hard-coded in step 6), so the escape only needs
# to cover characters that appear in those strings:
#   "  → \"
#   \  → \\
#   newline → \n
# No control chars or unicode escapes needed (our strings are
# ASCII-safe). If a future maintainer hand-edits the nudges to
# include exotic chars, the worst case is a broken JSON envelope
# that Claude Code logs as a hook-output error — degraded, not
# silent corruption.
escape_for_json() {
    local s="$1"
    # Order matters: backslash FIRST, then quote, then newline.
    s="${s//\\/\\\\}"   # \  → \\
    s="${s//\"/\\\"}"   # "  → \"
    s="${s//$'\n'/\\n}" # \n → \\n
    printf '"%s"' "$s"
}

escaped=$(escape_for_json "$nudge")

# permissionDecision: "allow" — never block, just inform.
# additionalContext is documented at ≤10k chars; our nudges are <500.
printf '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow","additionalContext":%s}}\n' "$escaped"
exit 0
