### MCP shim resilience — heartbeat, reconnect-with-backoff, structured disconnection

`rts-mcp` and `rts` no longer drop off the tool list when the daemon hiccups. A background heartbeat detects daemon death proactively, a bounded reconnect loop auto-respawns the daemon, and tool calls during the disconnect window return new structured `DAEMON_UNAVAILABLE` / `DAEMON_DOWN` JSON-RPC error codes so agents can branch on transient vs. sustained outage without parsing English text.

#### What

**New `crates/rts-mcp/src/connection.rs` module.** A `ConnectionManager` wraps the per-workspace `DaemonClient` plus two background tokio tasks:

- **Heartbeat loop.** Issues `Daemon.Ping` every `RTS_MCP_HEARTBEAT_INTERVAL_SECS` (default 10s) with a per-call timeout of `RTS_MCP_HEARTBEAT_TIMEOUT_SECS` (default 3s). A failed ping demotes state to `Reconnecting`.
- **Reconnect-with-backoff.** Schedule `1s, 2s, 4s, 8s, 16s, 30s, 30s, 30s` (configurable via `RTS_MCP_RECONNECT_MAX_ATTEMPTS` default 8 and `RTS_MCP_RECONNECT_CEILING_SECS` default 30). After the bounded attempts state transitions to `Down`, but retries continue at the ceiling forever — transient outages of arbitrary length still recover.

**Three-state machine** (`Connected | Reconnecting | Down`) wrapped in `Arc<RwLock<…>>`. Tool calls take a read lock briefly to check state — calls during a known disconnect window short-circuit at the state check and return the structured error without touching the daemon mutex, so a burst of N concurrent calls during reconnect costs O(1) on the daemon mutex, not O(N).

**Two new MCP-shim error codes** (shim-emitted; not daemon protocol-v0 codes):

- `DAEMON_UNAVAILABLE` (numeric `-32098`) — transient. `error.data.retry_after_ms` carries the wall-clock hint until the next reconnect attempt. `error.data.transient: true`.
- `DAEMON_DOWN` (numeric `-32097`) — sustained outage after bounded-attempt exhaustion. `error.data.first_failure_ms_ago` describes how long the daemon has been unreachable. `error.data.transient: false`.

**Cross-binary parity.** Both `rts-mcp` (the MCP shim) AND the `rts` human-facing CLI binary (PR #113) use the same `ConnectionManager`. The CLI disables the background heartbeat (single-shot — no point spawning a task we'll abort 50 ms later) but still benefits from the foreground reconnect-on-transport-error path. Source: `crates/rts-mcp/src/cli.rs::connect`.

**Heartbeat ↔ idle-shutdown interaction.** `Daemon.Ping` resets the daemon's `last_activity`. The daemon's idle-shutdown is already gated on `active_connections > 0` (`crates/rts-daemon/src/state.rs::is_idle`), but the heartbeat additionally refreshes activity so a future loosening of the connection-count gate still sees fresh traffic. **An MCP shim that's still attached keeps its daemon alive — this is intentional.** Documented in code comments + protocol-v0 §14.1.

#### Why this matters

Round-11 dogfood surfaced the failure mode: the rts MCP server silently disconnected mid-session, the agent received only a "their MCP server disconnected" system reminder, and `mcp__rts__*` tools dropped off the tool list with no error and no recovery path. Three diagnosable failure modes:

1. **No heartbeat.** A single transport error was terminal; the shim sat on a dead socket until the next tool call hit `Broken pipe`.
2. **No reconnect.** Disconnections compounded — the agent worked around once; the second disconnection taught the agent to default to `Bash(grep)` permanently.
3. **No structured transient-error code.** `INTERNAL_ERROR broken pipe` was indistinguishable from "this method doesn't exist" to the MCP host.

For a project whose entire pitch is "AST-precise code retrieval for AI agents," **a tool that abandons agents on first flake is a tool agents won't come back to.** This change closes the gap with shapes proven in gRPC keepalive, HTTP/2 GOAWAY, and Tower's retry stack.

#### Verification

- Full plan: [`docs/plans/2026-05-19-004-feat-mcp-server-resilience-plan.md`](../docs/plans/2026-05-19-004-feat-mcp-server-resilience-plan.md)
- New integration test `crates/rts-mcp/tests/connection_resilience.rs` covers the four plan scenarios end-to-end against real binaries:
  1. **Daemon idle-shutdown survival** — `RTS_IDLE_SHUTDOWN_SECS=2`, idle 5s, next tool call succeeds.
  2. **Daemon SIGKILL recovery** — kill daemon, observe `DAEMON_UNAVAILABLE`, subsequent calls succeed via auto-respawn.
  3. **MCP shim crash leaves daemon alive** — kill shim 1, shim 2 connects to the SAME daemon PID.
  4. **Concurrent tool calls during reconnect** — 10 concurrent calls return consistent `DAEMON_UNAVAILABLE` shapes with bounded `retry_after_ms` hints; no thundering-herd.
- Unit tests for the backoff schedule (`1s, 2s, 4s, 8s, 16s, 30s, 30s, 30s`), error-code round-trip, and `ResilienceConfig` defaults.
- Protocol-v0 §14.1 documents the new error codes and env vars.
- v1.x daemons unaffected — shim is the sole owner of resilience state; daemon wire protocol is byte-identical.

#### Out of scope (filed for follow-up)

- **`Daemon.Stats` disconnection counters** (`disconnections.total`, `disconnections.last_at_ms`, `disconnections.last_duration_ms`). Better folded into the opt-in telemetry plan than dragged into this PR — sibling-field pattern reserved for that landing.
- **MCP protocol-level reconnect** (shim → MCP host). That's the host's responsibility; out of scope per the plan.
- **Multi-daemon failover.** Single-process daemon is the only supported topology in v0.6.
