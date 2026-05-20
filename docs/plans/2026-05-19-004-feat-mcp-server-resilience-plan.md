---
title: MCP Server Resilience — auto-reconnect, structured disconnection, daemon-survive-MCP
type: feat
status: active
date: 2026-05-19
---

# MCP Server Resilience

## Overview

During Round-11 implementation, the rts MCP server **silently disconnected
mid-session**. The agent operating Claude Code received a system reminder
("their MCP server disconnected") and `mcp__rts__*` tools dropped off the
available tool list. No structured error, no auto-recovery — the rts tools
simply ceased to exist for the remainder of the session.

For a project whose entire pitch is "AST-precise code retrieval for AI
agents," **a tool that abandons agents on first flake is a tool agents
won't come back to.** Disconnections compound: the agent works around
once; the second disconnection in the same workspace teaches the agent
to default to `Bash(grep)` permanently.

This plan closes three gaps in the MCP↔daemon connection layer:

1. **MCP shim survives daemon disconnects.** Currently the shim treats a
   broken UDS connection as fatal; it must instead reconnect.
2. **Structured disconnection error.** While reconnecting, tool calls
   return `DAEMON_UNAVAILABLE` with a `retry_after_ms` field rather than
   silently disappearing from the tool list.
3. **Daemon outlives any single MCP shim.** A crashed/restarted MCP host
   does not bring down the daemon; the daemon's existence is the
   workspace's invariant, not the MCP shim's.

## Problem Statement / Motivation

Observed in Round-11 (this very session, 2026-05-19):

> *The system reminder showed `MCP servers have disconnected: rts`. The
> agent had been mid-orchestration on three parallel implementation
> PRs. The rts MCP tools dropped off the tool list. No retry. No error.
> No path to recovery without a session restart.*

Three diagnosable failure modes in current code:

1. **No heartbeat.** The MCP shim opens a UDS connection once at startup
   and assumes it stays open forever. When the daemon's idle-shutdown
   timer fires (default 60s after last activity per
   `RTS_IDLE_SHUTDOWN_SECS`) or the daemon crashes, the shim's next
   request errors out — but the shim has no recovery path, so the MCP
   host (Claude Code, Cursor, Cline) treats it as a dead server.
2. **No reconnect.** The MCP shim's UDS client has no
   reconnect-with-backoff logic. A single transport error is terminal.
3. **No structured error code for transient unavailability.** Tools
   return generic errors that look indistinguishable from "this method
   doesn't exist" to the MCP host.

The fix shape is industry-standard (Kubernetes liveness probes, gRPC
client retry, HTTP/2 GOAWAY handling) — none of it is novel. **The work
is grinding the protocol surface into the rts-mcp client.**

## Proposed Solution

### Architecture

```
┌──────────────┐         ┌─────────────────────┐         ┌─────────────┐
│ Claude Code  │ MCP     │ rts-mcp shim        │ UDS     │ rts-daemon  │
│ MCP host     │◄──────► │ (this plan's focus) │◄──────► │             │
└──────────────┘         └─────────────────────┘         └─────────────┘
                              │
                              ├── Connection manager (new)
                              │    - state: Connected | Reconnecting | Down
                              │    - heartbeat loop (Daemon.Ping every 10s)
                              │    - reconnect-with-exponential-backoff
                              │    - daemon-respawn via existing bootstrap
                              │
                              └── Tool handlers (modified)
                                   - check state before forwarding
                                   - return DAEMON_UNAVAILABLE if Reconnecting
                                   - return DAEMON_DOWN if Down (terminal)
```

### Connection state machine

```rust
// crates/rts-mcp/src/connection.rs (new)

pub enum ConnectionState {
    /// UDS connection live; last Ping succeeded within the heartbeat
    /// window. Tool calls forward through normally.
    Connected {
        socket: Arc<Mutex<UnixStream>>,
        last_pong_at: Instant,
    },
    /// Connection lost; reconnect attempt in progress. Tool calls
    /// return DAEMON_UNAVAILABLE with retry_after_ms hint based on
    /// the next backoff step.
    Reconnecting {
        attempt: u32,
        next_retry_at: Instant,
        last_error: String,
    },
    /// Reconnect attempts exhausted (MAX_RECONNECT_ATTEMPTS = 8 by
    /// default; configurable). Tool calls return DAEMON_DOWN with
    /// guidance to restart the MCP host. The connection manager
    /// continues to retry at the ceiling interval (30s) so transient
    /// outages of arbitrary length recover automatically.
    Down {
        first_failure_at: Instant,
        last_error: String,
    },
}
```

### Heartbeat loop

A background tokio task on the rts-mcp shim:

```rust
loop {
    tokio::time::sleep(HEARTBEAT_INTERVAL).await; // 10s default
    let ping_result = tokio::time::timeout(
        HEARTBEAT_TIMEOUT, // 3s
        send_request("Daemon.Ping", json!({}))
    ).await;
    match ping_result {
        Ok(Ok(_)) => state.set_connected_now(),
        Ok(Err(e)) | Err(e) => state.demote_to_reconnecting(e),
    }
}
```

### Reconnect-with-backoff

When the heartbeat detects a failure or a tool call hits a transport
error:

1. Transition to `Reconnecting { attempt: 1, next_retry_at: now + 1s }`.
2. Reconnect attempt schedule: 1s, 2s, 4s, 8s, 16s, 30s, 30s, 30s
   (exponential with 30s ceiling, MAX_RECONNECT_ATTEMPTS=8).
3. On each attempt:
   - Check if socket file exists. If not, invoke existing daemon
     bootstrap path (`crates/rts-mcp/src/bootstrap.rs`) to spawn a
     fresh daemon.
   - Open a new `UnixStream`, send a single `Daemon.Ping`.
   - On success → `Connected`. On failure → bump `attempt`, schedule
     next.
4. After MAX_RECONNECT_ATTEMPTS, transition to `Down` but continue
   retrying at ceiling interval forever (transient outages of arbitrary
   length should still recover; "Down" is just the UX state that
   surfaces guidance to the MCP host).

### Structured error codes

Add to `crates/rts-mcp/src/error.rs` (or wherever MCP-level errors live):

- `DAEMON_UNAVAILABLE = -32098` — transient; client should retry. Carry
  `retry_after_ms` payload field for backoff hint.
- `DAEMON_DOWN = -32097` — sustained outage after retry exhaustion;
  client should surface to user.

When the MCP shim returns these errors to the host:
- Most MCP hosts will retry on transport-level errors but NOT on
  application-level errors. We use application-level codes deliberately
  so the *agent* sees them and can adjust strategy (e.g., fall back to
  Bash(grep) for one tool call rather than failing the whole turn).

### Daemon-side dual: survive MCP shim crashes

The daemon already survives MCP shim disconnects (the UDS server accepts
multiple connections; the daemon's idle-shutdown is gated on
`mount_refcount` not connection count). **No daemon-side changes needed
for this plan.** Verify with a regression test: kill the MCP shim
process, confirm daemon still serves a new connection's `Daemon.Ping`.

### Configuration

New env vars (all with sensible defaults; nothing requires user setup):
- `RTS_MCP_HEARTBEAT_INTERVAL_SECS` (default: 10)
- `RTS_MCP_HEARTBEAT_TIMEOUT_SECS` (default: 3)
- `RTS_MCP_RECONNECT_MAX_ATTEMPTS` (default: 8)
- `RTS_MCP_RECONNECT_CEILING_SECS` (default: 30)

## Technical Considerations

- **No new external dependencies.** tokio's `time::sleep` +
  `time::timeout` cover everything.
- **Connection lifecycle:** the existing `socket.rs` module in
  rts-mcp opens a `UnixStream` once. The new `connection.rs` owns the
  reconnect logic and exposes a `send_request(method, params) ->
  Result<Value, McpError>` API that internally handles reconnection.
- **Race between heartbeat and tool call:** both touch the
  `ConnectionState`. Use an `Arc<RwLock<ConnectionState>>` — heartbeat
  takes write lock briefly to update state; tool calls take read lock,
  check state, and forward through if Connected.
- **In-flight requests during disconnect:** if a tool call is awaiting
  a response when the connection dies, return `DAEMON_UNAVAILABLE` to
  the host. Do NOT silently retry — agent loops that retry on their
  own would otherwise see double-execution.
- **Daemon bootstrap reuse:** the existing
  `crates/rts-mcp/src/bootstrap.rs` already handles "socket missing →
  spawn daemon." Plug it into the reconnect loop's "is the daemon even
  running" check.
- **Disconnect cause classification (optional):** could distinguish
  "daemon idle-shutdown" (expected; quiet reconnect) from "daemon
  crashed" (notable; log at warn). Not required for v1; the user-
  visible behavior is identical.

## System-Wide Impact

- **Interaction graph:** Claude Code → MCP host → rts-mcp shim →
  connection manager → UDS → daemon. The new layer sits between shim
  and UDS. Heartbeat is a parallel task that doesn't affect the
  request path.
- **Error propagation:** today, transport errors are unstructured
  and inconsistent. After this plan: any non-business-logic failure
  surfaces as `DAEMON_UNAVAILABLE` or `DAEMON_DOWN` with retry hints.
- **State lifecycle:** `ConnectionState` is process-local to the MCP
  shim. The daemon's persistent index is untouched. Reconnection is
  cheap because there's no per-connection daemon state to rebuild
  (mounts are workspace-scoped, not connection-scoped).
- **API surface parity:** the CLI binary `rts` (Plan 002, just
  shipped as PR #113) shares the same UDS transport code via
  `rts-mcp::lib`. **It gets resilience for free** if we plumb
  the connection manager through that shared module rather than
  bolting it onto the MCP-shim entrypoint only.
- **Integration test scenarios:**
  1. **Daemon idle-shutdown survival** — set
     `RTS_IDLE_SHUTDOWN_SECS=2`, idle for 5s, verify next tool call
     succeeds via auto-respawn.
  2. **Daemon SIGKILL recovery** — kill daemon mid-session, wait one
     heartbeat cycle, verify tools return `DAEMON_UNAVAILABLE`, wait
     one reconnect attempt, verify tools return successful results.
  3. **MCP shim crash leaves daemon alive** — kill MCP shim, verify
     daemon's `mount_refcount` and `active_connections` decrement
     correctly; spawn new MCP shim, verify it connects to the same
     daemon instance.
  4. **Concurrent tool call during reconnect** — fire 10 concurrent
     tool calls during a known disconnect window; verify all 10
     return `DAEMON_UNAVAILABLE` with consistent `retry_after_ms`
     hints (no thundering-herd).

## Acceptance Criteria

### Functional

- [ ] `crates/rts-mcp/src/connection.rs` exists with `ConnectionState`
      machine and reconnect-with-backoff.
- [ ] Background heartbeat task runs at `HEARTBEAT_INTERVAL` (default
      10s) and demotes state on failure.
- [ ] Reconnect schedule follows exponential backoff with 30s ceiling.
- [ ] Daemon auto-respawn via existing bootstrap path fires when
      socket is missing during a reconnect attempt.
- [ ] New error codes `DAEMON_UNAVAILABLE = -32098` and `DAEMON_DOWN =
      -32097` documented in `docs/protocol-v0.md` (or
      MCP-shim-specific docs).
- [ ] Tools return `DAEMON_UNAVAILABLE` with `retry_after_ms` field
      when in `Reconnecting`.
- [ ] Tools return `DAEMON_DOWN` when in `Down`.
- [ ] Configuration env vars (`RTS_MCP_HEARTBEAT_*`,
      `RTS_MCP_RECONNECT_*`) work.

### Cross-binary parity (per System-Wide Impact)

- [ ] The `rts` CLI binary (from Plan 002) also benefits from the
      connection manager — either by sharing the same connection
      module from `rts-mcp::lib`, or by getting an equivalent
      treatment. Decision documented in the PR.

### Quality Gates

- [ ] Integration test `crates/rts-mcp/tests/connection_resilience.rs`
      covers the four scenarios above.
- [ ] `cargo fmt --all` clean.
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` clean.
- [ ] `cargo test --workspace` passes.
- [ ] No `unsafe` blocks (workspace deny).
- [ ] `CHANGELOG`/changelog.d entry calls out the resilience
      improvement and the new error codes.

## Success Metrics

- After ship: zero recurrences of the "MCP server disconnected, no
  recovery" failure mode in maintainer sessions over a 14-day window.
- ≥1 third-party agent host reports surviving a daemon restart
  without session interruption.
- Stress test: daemon-kill-and-respawn loop running 100 cycles
  completes with 100% of in-window tool calls eventually succeeding
  (modulo the brief `DAEMON_UNAVAILABLE` window).

## Dependencies & Risks

- **No new dependencies** — pure tokio + std.
- **Risk: reconnect storm on persistent failure.** If the daemon
  binary itself is broken (e.g., bad upgrade), the MCP shim retries
  forever at the 30s ceiling. Mitigation: log at warn level on every
  attempt past MAX_RECONNECT_ATTEMPTS; the MCP host will surface
  these warnings to the user.
- **Risk: heartbeat overhead on idle daemons.** A `Daemon.Ping`
  every 10s is ~6 RPCs/min; the daemon's idle-shutdown timer is
  reset on every call, **so the heartbeat itself defeats
  idle-shutdown**. This is intentional: an MCP shim that's still
  attached should keep its daemon alive. Document the interaction.
- **Risk: agents misinterpret `DAEMON_UNAVAILABLE` as "tool doesn't
  exist" and stop trying.** Mitigation: the error message should be
  unambiguously transient ("Daemon temporarily unavailable; retry in
  Xms"). MCP hosts that show error messages to agents will pass this
  through.

## Out of Scope (Non-Goals)

- **MCP protocol-level reconnect** (shim → Claude Code host) — that's
  the MCP host's responsibility, not ours.
- **Workspace remount on reconnect** — daemon's persisted cold-mount
  (Plan 003 / PR #111) means a respawned daemon already has the
  workspace mounted; no extra remount step needed from the shim's
  side. Verify with a regression test, but no new code.
- **Multi-daemon failover** — single-process daemon is the only
  supported topology in v0.6. Multi-daemon is a v1.0+ conversation.
- **Reconnect telemetry** — `Daemon.Stats` could grow
  `disconnections: { total, last_at_ms, last_duration_ms }` but
  that's better folded into the global telemetry plan (Plan 003 —
  2026-05-19-003). Mention as a follow-up.

## Resource Requirements

- ~2-3 focused days.
- One macOS + one Linux smoke test environment for the daemon-kill
  recovery test.
- One real-MCP-host integration test (Claude Code or Cursor) to
  verify the error codes surface correctly through the protocol
  boundary.

## Sources & References

### Internal

- MCP shim transport: `crates/rts-mcp/src/socket.rs`
- Daemon bootstrap (reuse): `crates/rts-mcp/src/bootstrap.rs`
- Existing UDS server: `crates/rts-daemon/src/server.rs` (or wherever
  the accept loop lives)
- Idle-shutdown: search for `RTS_IDLE_SHUTDOWN_SECS` in
  `crates/rts-daemon/src/`
- Plan 002 (CLI, just shipped) — shares the transport surface:
  `docs/plans/2026-05-19-002-feat-human-cli-subcommand-plan.md`
- Plan 003 (telemetry) — relevant if we add disconnect counters
  later: `docs/plans/2026-05-19-003-feat-anonymous-opt-in-telemetry-plan.md`

### External / Best Practices

- gRPC keepalive + reconnect:
  <https://grpc.io/docs/guides/keepalive/>
- HTTP/2 GOAWAY + client reconnect:
  <https://datatracker.ietf.org/doc/html/rfc7540#section-6.8>
- MCP protocol error semantics:
  <https://modelcontextprotocol.io/docs/concepts/errors>
- Exponential backoff (Polly / Tower):
  <https://docs.rs/tower/latest/tower/retry/index.html>

### Dogfood evidence

- **This session's transcript** — the originating incident.
  Maintainer should grep their session logs for
  `MCP servers have disconnected` to surface other instances.
