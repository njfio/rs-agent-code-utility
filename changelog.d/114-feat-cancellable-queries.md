### Cancellable in-flight queries — `Daemon.Cancel { cancel_id }` over the JSON-RPC envelope

Long-running `Index.*` and `Workspace.Mount` requests can now be aborted from a follow-up call. Closes the agent-loop hole where a model that revised its plan mid-query had to wait out the original — the daemon kept burning CPU on a result no one would read.

#### What

**Optional `cancel_id: String` field on every JSON-RPC request envelope.** Clients attach a self-chosen id (UUID, monotonic counter, anything 1..=256 chars); v1.x daemons ignore it, v0.6+ daemons register a cancellation token under that id for the request's lifetime. `serde(default)` ⇒ existing wire shape unchanged for clients that don't set it.

**New method `Daemon.Cancel { cancel_id }`** returns `{ cancelled: bool }`. Idempotent: an unknown id (typo, already-completed request, never-registered) returns `false` with no error envelope. Successful cancels bump `Daemon.Stats.cancellations.total`; `Daemon.Stats.cancellations.in_flight` exposes the current registry size as a gauge.

**New error code `CANCELLED` (custom JSON-RPC `-32099`)** returned by handlers whose token tripped. Not a programming error — clients that issued the cancel should treat it as the expected response.

**Cancellable handlers in v0.6:** `Index.Grep`, `Index.FindSymbol`, `Index.FindCallers`, `Index.ReadSymbol`, `Index.Outline`, `Workspace.Mount`. Hot-loop integration:

- **Structural scanner** (`grep_v2/structural.rs`) — per-match `is_cancelled()` poll inside the `for qm in matches` loop. Single relaxed atomic load, ~1ns; noise next to the per-match capture-extraction cost. Scanner moved to `spawn_blocking` so the cancel handler isn't starved on the same tokio worker.
- **Multiline regex + literal scan** (`methods/index.rs::grep`) — per-file boundary check at the top of the outer loop, plus a per-match check inside the hits loop (covers the multiline path where a single file is the smallest interruptible unit).
- **Mount cold-walk drain** (`methods/workspace.rs::mount_inner`) — per-batch-tick check inside the drain wait. Cancelled mounts return `CANCELLED` without tearing down the partially-populated store; the next Mount picks up via the persisted-fingerprint path.

**New capability string `cancellable_queries`** advertised in `Daemon.Ping.capabilities`. Gate on this before sending `cancel_id` against an unknown daemon vintage.

**Registry lifecycle is RAII.** A `CancelGuard` registered in the dispatcher unregisters the token on drop — handlers that panic, error, or return normally all clean up the same way. No leak path even under unhappy shutdown.

#### Why this matters

`Index.Grep v2` shipped in v0.6 with structural queries that can fan to thousands of nodes across hundreds of files. A 2–4 second query latency is realistic on medium workspaces; without cancellation, an agent that fires a query, reads partial context, and reframes its plan keeps the daemon working on the first query while waiting on the second — head-of-line blocking on a per-connection in-flight semaphore and dead CPU work on a result that won't be read.

Cancellation also closes a smaller paper-cut: `Workspace.Mount` on a large workspace blocks the connection for the cold-walk drain timeout (5 s). An agent that wanted to abort mid-mount previously had to close the socket and re-spawn the connection.

Worst-case abort latency is the time to the next cooperative poll — per-match (~50 µs typical) for the structural scanner, per-file (~few ms) for the multiline regex, per-25-ms-batch-tick for the mount drain. Uncancelled requests pay one relaxed atomic load per poll site: well under the noise floor of the scan work itself.

#### Verification

- Full plan: [`docs/plans/2026-05-19-001-feat-cancellable-queries-plan.md`](../docs/plans/2026-05-19-001-feat-cancellable-queries-plan.md)
- Cancel-mechanism source: `crates/rts-daemon/src/cancel.rs`
- Protocol-v0 envelope addition: §3.4 + §7.1b `Daemon.Cancel` + §14 `CANCELLED`
- New integration test `crates/rts-daemon/tests/cancel_in_flight.rs` covers the three plan scenarios: slow query cancelled mid-flight returns `CANCELLED`; stale cancel after natural completion returns `{ cancelled: false }`; two concurrent queries with different ids — cancelling one leaves the other running to completion.
- Unit tests for the registry's register/remove/cancel/in_flight semantics, the `CancelGuard` RAII drop path, and the token's clone-visibility invariant.
- v1.x callers see byte-identical wire shape on every existing method when they don't set `cancel_id`.

#### Out of scope (filed for follow-up)

- **Deadline timeouts** (`Daemon.SetTimeout { method, ms }`). Cancellation is the building block; timeouts are cancellation on a timer.
- **Cooperative streaming.** Cancelling a streaming response is a v0.7 concern.
- **Cross-daemon cancellation propagation.** Single-process scope only.
- **MCP tool-surface `cancel_id` argument.** The daemon protocol accepts it; the per-tool MCP schema doesn't expose it (agents typically can't reframe from inside a tool invocation, and adding it to every tool schema clutters the agent's view). Hosts that want to wire cancellation can address the daemon directly through the same socket.
