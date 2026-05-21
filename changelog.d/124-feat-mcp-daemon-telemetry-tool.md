### MCP: expose `Daemon.Telemetry` as a `daemon_telemetry` tool

PR #115 shipped `Daemon.Telemetry` as a JSON-RPC method on the daemon side and PR #120 wired its collectors (latency p50/p99, cache hit rate, cold-walk timing, languages indexed, workspace size, error counts), but the rts-mcp server only routed `daemon_stats` to the MCP tool list. External MCP-speaking clients (Claude Code, Cursor, rts-bench's MCP-based code paths) could not reach the new collectors — most visibly, PR #123's real-repo CI fixture wanted to read these counters to gate regressions on latency p99 and had to mark latency fields as `Option<u64>` with `TODO(post-G)` comments to ship.

#### What

`crates/rts-mcp/src/server.rs` gains one new `#[tool]` function, `daemon_telemetry`, which forwards `Daemon.Telemetry` over the existing connection manager. No parameters (the daemon-side handler ignores `params`). Response wire shape is the same payload documented in `docs/protocol-v0.md` for `Daemon.Telemetry`: `uptime_secs`, `languages_indexed`, `method_counts`, `method_latency_p50_ms`, `method_latency_p99_ms`, `error_counts`, `cache_hit_rate`, `cold_walk_ms_p50`, `workspace_files`.

Tool count over `tools/list` goes from 9 → 10.

#### Why

The MCP routing was the single missing piece between "the daemon collects per-method latencies" (PR #120) and "an external agent can read those latencies without speaking protocol-v0 directly". Pure routing addition; the underlying handler is already covered by PR #115 and PR #120's tests.

#### Test guard

- `crates/rts-mcp/tests/daemon_telemetry_tool.rs::daemon_telemetry_round_trip` — spawns rts-mcp + auto-spawns rts-daemon against a tiny fixture workspace, warms the index with one `find_symbol` call, then fires `tools/call name=daemon_telemetry` and asserts the response carries every collector field PR #115's protocol-v0 update documents.
- `crates/rts-mcp/tests/tool_descriptions.rs::AUDITED_TOOLS` extended to include `daemon_telemetry`. The existing 4 assertions (comparative clause, trigger-phrase hint, [80, 800] char bound, JSON round-trip) automatically guard the new description against future drift.

#### Out of scope

- No changes to the daemon's `Daemon.Telemetry` handler.
- No new parameters on the tool (the daemon handler ignores them).
- No changes to the wire protocol or version capability list.
- PR #123's `TODO(post-G)` cleanup (dropping the `Option<u64>` wrapping on the latency fields in `crates/rts-bench/src/real_repos/`) is a separate sweep — this PR unblocks it but doesn't perform it.

#### Post-deploy monitoring

No additional operational monitoring required: pure routing addition; the existing `daemon_telemetry` handler is already covered by PR #115 and PR #120's tests.
