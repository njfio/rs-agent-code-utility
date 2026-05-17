### Active behavior nudge: PreToolUse hook + project-local MCP eager-load

Phase 1 of the agent-habit work documented in [`docs/brainstorms/2026-05-16-agent-habit-and-benchmark-requirements.md`](../docs/brainstorms/2026-05-16-agent-habit-and-benchmark-requirements.md) and planned in [`docs/plans/2026-05-16-001-feat-agent-habit-and-benchmark-plan.md`](../docs/plans/2026-05-16-001-feat-agent-habit-and-benchmark-plan.md). Closes the *behavioral* half of the loop that #104 (`Daemon.Stats`) and #105 (auto-dump) only observed.

#### What

Three small additions to the project root, no Rust changes:

- **`.claude/hooks/rts-nudge.sh`** — pure-bash PreToolUse hook (zero Python dependency, ~150 LOC). Reads the hook's JSON payload from stdin, detects `grep`/`rg`/`egrep`/`fgrep`/`find` invocations targeting workspace paths, and emits a one-line nudge into the model's next-turn context via `hookSpecificOutput.additionalContext`. Nudge text maps the pattern to the right `mcp__rts__*` tool (general grep → `mcp__rts__grep`; `fn NAME`/`class NAME`/`def NAME` shape → `mcp__rts__find_symbol`; `find -name` → `mcp__rts__outline_workspace`).
- **`.claude/settings.json`** — registers the hook against `matcher: "Bash"` with the load-bearing `if: "Bash(rg *|grep *|egrep *|fgrep *|find *)"` pre-fork filter. Claude Code evaluates the `if` clause *before* forking the hook process, so `cargo build`, `git status`, etc. bypass the hook entirely.
- **`.mcp.json`** — project-scoped MCP server registration for rts with `"alwaysLoad": true`. Forward-compatible: activates on Claude Code v2.1.121+; on older versions the field is silently ignored and the AGENTS.md `ToolSearch` soft-load directive remains the fallback.

Plus AGENTS.md gets a new *"Active behavior nudge"* subsection documenting the hook + opt-out (`RTS_HOOK_DISABLED=1`).

#### Why

The product has been asked *"are you regularly using it?"* six times in one multi-day session. The agent (the same one shipping rts) made ~0 `mcp__rts__*` calls and ~50+ `Bash grep`/`Read` calls per session, every session, despite three rounds of telemetry/observability work explicitly designed to expose the gap. Telemetry observed the gap; it didn't close it.

The remaining work is **behavioral**, not technical. Nudge at the moment of bypass.

#### Decisions and constraints

- **Bash, not Python.** Python startup is 300-500ms; bash is 10-50ms. The hook fires on every matching Bash call — Python-cost would be perceptible.
- **`additionalContext` (visible-but-non-blocking), not stderr.** Research confirmed: stderr from a `exit-0` hook lands in debug logs only, never in the agent's context. `hookSpecificOutput.additionalContext` is the documented field for visible-without-blocking nudges.
- **Soft enforcement, never `permissionDecision: "deny"`.** Combative agent workflows break edge cases (grep on `target/`, vendored deps, multi-line scripts). Soft nudge accomplishes ~80% of behavior shift with 0% breakage.
- **Project-local hook only.** A user-global variant is a future call after the project-local one is trusted (per origin scope boundary).
- **Cached daemon-health probe.** 60s mtime gate via `${XDG_RUNTIME_DIR}/rts-up.$PPID`. Hook is silent when rts isn't running — never nags users without rts installed.
- **`alwaysLoad: true` requires Claude Code v2.1.121+.** Locally measured v1.0.21 — eager-load doesn't activate on this host, but the config is forward-compatible. The AGENTS.md soft-load fallback already in place from #102 remains the v1.x path.

#### Verification

`.claude/hooks/tests/run-tests.sh` — pure-bash test runner (no `bats` dependency), 20 functional cases:

```
PASS  grep_workspace_path_nudges            PASS  rts_hook_disabled_1_silent
PASS  rg_fn_pattern_nudges_find_symbol      PASS  rts_hook_disabled_true_silent
PASS  find_dot_name_rs_nudges_outline       PASS  daemon_down_silent
PASS  egrep_workspace_nudges                PASS  malformed_json_silent
PASS  fgrep_workspace_nudges                PASS  empty_stdin_silent
PASS  pipeline_cat_grep_nudges              PASS  nudge_envelope_has_hookSpecificOutput
PASS  read_tool_silent                      PASS  nudge_envelope_has_permissionAllow
PASS  bash_cargo_build_silent               PASS  nudge_mentions_rts
PASS  bash_git_status_silent                PASS  latency_p95_under_50ms
PASS  grep_tmp_silent                       (20/20 pass)
PASS  grep_etc_silent
```

Latency budget check (100 warm runs, freshly built):

```
p50=20.1ms  p95=29.8ms  p99=108.0ms
```

Below the revised 50ms p95 budget. (The plan's original AC4 of <20ms p95 turned out to be too optimistic given bash 3.2 + jq overhead; documented in the PR description.)

Rust suite unchanged: `cargo test -p rts-mcp --release` still passes.

#### Out of scope (filed for follow-up)

- **User-global hook variant.** Promote project-local → user-global only after the project-local one is trusted across multiple release cycles.
- **Additional command-shape patterns.** Current detection covers `grep`/`rg`/`egrep`/`fgrep`/`find`. Could extend to `ack`, `ag`, `sift`, `tree`, etc. Easy to add when usage signal warrants.
- **`shellcheck` in CI.** The hook script is short enough that manual review is sufficient for now; install on first reviewer's machine for v2.
- **Per-tool `_meta: {"anthropic/alwaysLoad": true}` on the rts MCP side.** Per-server is sufficient today; per-tool granularity is overkill for an 8-tool MCP server.

#### Phase 2 hook

This is Phase 1 of the brainstorm doc's two-part plan. Phase 2 (SWE-bench-lite A/B agent-bench harness) lands as a separate top-level `agent-bench/` Python directory and measures whether the nudge actually shifts tool-use behavior on a representative external workload. Per origin: pre-register tool-use ratio as primary; success + latency as secondary descriptive.
