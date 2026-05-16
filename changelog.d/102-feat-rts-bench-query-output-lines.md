### `rts-bench query --output lines` + `AGENTS.md` "use rts, not grep" cheatsheet

Honest dogfooding answer to "are you regularly using it?" — **no**, the agent reached for `grep -rn` and `Read` 50+ times during the v0.5.5 release work and called `mcp__rts__*` exactly zero times until forced. The product was strictly better; the cost-to-use was strictly worse.

Two reasons the agent bypassed the MCP path:

1. **JSON output doesn't compose with bash idioms** the way `path:line:content` does. `rg foo | awk -F: '{print $1}' | sort -u` is one keystroke pattern. The JSON equivalent requires `jq`, knowledge of the wire shape, and more cognitive load.

2. **The deferred-tool surface** means each `mcp__rts__*` tool needs a `ToolSearch` round-trip before its schema is callable. Bash is always loaded; rts is not.

This PR closes (1) and documents the fix for (2).

#### `--output lines` mode

New global flag on `rts-bench query <sub>`:

```sh
# find_symbol: path:line:qualified_name (kind) [rank=…]
rts-bench query --output lines find-symbol --pattern 'parse_*' | sort

# find_callers: path:line:enclosing_qualified_name (kind)
rts-bench query --output lines find-callers --name socket_path_for_workspace

# grep: path:line:[enclosing_qualified_name] line_text  (v0.5.5+ daemons)
rts-bench query --output lines grep --text 'panic!(' | awk -F: '{print $1}' | sort -u

# impact_of: [depth=N] path:line:qualified_name (kind) [rank=…]
rts-bench query --output lines impact-of --name SymbolUnderRefactor

# outline_workspace: pass-through of the daemon's outline_text field
rts-bench query --output lines outline --glob 'src/**' --token-budget 1024
```

Empty results emit **nothing** and exit `0`, exactly like `rg` — `wc -l` returns 0, `| head` is a no-op. `read_symbol`, `read_symbol_at`, and `read_range` (file-body returns, not match lists) fall back to JSON automatically since lines-shape doesn't apply.

Wire-shape coupling: the renderer reads `qualified_name`, `range.start_line`, `kind`, optional `rank_score`, and the v0.5.5+ optional `enclosing_qualified_name`. Older daemons that don't populate the v0.5.5 fields produce slightly thinner output — by design, so the same `rts-bench` binary works against a mixed daemon-version fleet.

#### `AGENTS.md` cheatsheet

New section `## Tooling: use the `rts` index, not `grep` / `rg``. It enumerates:

- Which tool to use for which query intent (table form, six rows).
- The two CLI shapes (`mcp__rts__*` vs `rts-bench query …`).
- A one-line `ToolSearch` invocation to pre-load all eight `mcp__rts__*` tools at session start — turns the deferred surface into a one-time first-message cost.
- The narrow band where shell `rg` is still the right tool (out-of-workspace files, binary content, multi-line regex, daemon-not-running).

The intent is to retrain reflexes: next time an agent (or human) opens this repo, the AGENTS.md is read at session start and the rts surface is the default, not the alternative.

#### Verification

New regression test `query_cli.rs::query_output_lines_renders_rg_shaped_text`:

- Seeds a 2-file workspace (`hub.rs` with three fns + cross-calls, `notes.rs` with a comment).
- Runs `--output lines` against `find-symbol`, `find-callers`, `grep`.
- Asserts each line splits into `path:line:rest` shape; asserts the line-number field parses as `u32`.
- Asserts a no-match grep emits empty stdout and exits 0.
- Asserts pipe-composability by extracting unique paths from grep output via `BTreeSet`.

Full suite: `cargo test --workspace --release` — 0 failures across all ~300 tests.

#### Out of scope (filed for follow-up)

- **Auto-`ToolSearch` at Claude Code session start.** The AGENTS.md tells the agent to call `ToolSearch` once at session start, but that's a soft directive. Native eager-load would require a Claude Code config knob.
- **Soft enforcement hook.** A `PreToolUse` hook that nudges *"consider `mcp__rts__grep`"* when the agent calls `Bash grep`/`rg` against the workspace would close the discovery loop without forcing the issue.
