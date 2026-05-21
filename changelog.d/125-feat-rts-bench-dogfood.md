### `rts-bench dogfood` — measure rts vs Bash tool-selection from session transcripts

Round-12 honorable-mention companion to PR #121 (the tool-description audit). During the 2026-05-19/20/21 maintainer session that shipped 15 PRs to rts, the orchestrating agent used `Bash(grep)` 30+ times against rts's own source code instead of `mcp__rts__grep` — even with rts mounted. PR #121 rewrote every tool description to win the selection moment, but there was no way to MEASURE the improvement. This adds the harness.

#### What

New `rts-bench dogfood <session-jsonl-path> [--report json|text] [--rts-mounted-only]` subcommand. Ingests a Claude Code session JSONL file (or stdin with `-`) and reports:

- Total tool calls and a per-tool breakdown by source (`Bash`, `Read`, `mcp__rts__*`, …)
- `Bash` calls that pattern-match workspace navigation (`grep`/`rg`/`find`/`cat`/`ls`) and could have used an `mcp__rts__*` tool instead, broken out by category
- The rts-vs-Bash ratio in code-navigation contexts: `rts_calls / (rts_calls + candidate_bash_calls)`

Classifier patterns (all token-level, documented in `crates/rts-bench/src/dogfood/classify.rs`):

| Leading token | → would_prefer | Excluded |
|---|---|---|
| `grep`/`rg`/`egrep`/`fgrep`/`ack` | `mcp__rts__grep` | `git grep` |
| `find` with `-name`/`-path`/`-regex` filter | `mcp__rts__find_symbol` | `find /tmp`, bare `find` without filters |
| `cat <file>` | `mcp__rts__read_range` | `cat /tmp/...`, redirection (`cat > x`), heredocs |
| `ls`, `ls .`, `ls <relpath>` | `mcp__rts__outline_workspace` | `ls -l`, `ls -la`, `ls ~/Downloads` |

Build invocations (`cargo`, `make`, `npm`, etc.) are excluded outright.

#### Privacy & scope

- Client-side local analysis only. Reads JSONL files already on disk under `~/.claude/projects/`. No network, no daemon counters, no remote pings (PR #115's opt-in telemetry is a different surface).
- Not wired into CI. Manual maintainer tool.
- Measures tool SELECTION, not performance.

#### Tests

`crates/rts-bench/tests/dogfood_smoke.rs` (5 integration tests, all subprocess-driven) + 19 unit tests inside `dogfood::classify` and `dogfood::parse`:

- `parses_synthetic_session` — synthetic JSONL with known mix → expected counts
- `classifies_grep_bash_as_rts_candidate` — `Bash(grep)` → `would_prefer: "mcp__rts__grep"`
- `json_report_is_valid_json` — `--report json` parses cleanly back through `serde_json` and carries `schema_version: "dogfood-v0"`
- `text_report_renders` — `--report text` includes the stable section headings
- `rts_not_mounted_session_filters_candidates` — default `--rts-mounted-only` filter behavior is observable and toggleable

No new dependencies. No `unsafe`. Pure stdlib + `serde_json` (already a workspace dep).
