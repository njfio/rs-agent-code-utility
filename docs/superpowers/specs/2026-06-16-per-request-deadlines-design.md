# Per-Request Deadlines / Timeouts — Design

**Status:** Approved (design phase)
**Date:** 2026-06-16
**Author:** njf + Claude
**Topic:** Auto-cancel a daemon request that exceeds a time budget

---

## Goal

Bound the latency of any daemon query: a request that runs longer than
its deadline is cancelled and returns a `DEADLINE_EXCEEDED` error,
instead of making the agent (or CLI) wait out a pathological scan. The
deadline reuses the existing cooperative-cancellation machinery — it is
"a self-firing `Daemon.Cancel` on a timer."

## Why this, not "streaming cancellation"

The deferred v0.7 item was literally *"cancelling a streaming response
(we don't ship one yet)."* Exploration established two facts that
reshape it:

1. **No streaming responses exist.** Every request returns one
   JSON-RPC envelope; the only "stream" in the tree is the `UnixStream`
   socket transport.
2. **MCP can't stream to the agent.** A tool call yields exactly one
   `CallToolResult`; the model does not consume partial results. So the
   only consumer that could use a stream is the `rts` CLI.

Given that, the valuable slice is **bounded latency via deadlines**, not
incremental delivery. `Daemon.Cancel { cancel_id }` (v0.6, #114) already
provides cooperative abort of an in-flight query; a deadline is that
same abort fired by a timer instead of a second client message.

## Background — existing machinery (reused as-is)

- `crates/rts-daemon/src/cancel.rs`: `CancelToken(Arc<AtomicBool>)`,
  `CancelRegistry`, `CancelGuard` (RAII).
- `dispatch()` (`methods/mod.rs`) creates a `CancelToken` for **every**
  request and passes it to the slow handlers (`grep`, `find_symbol`,
  `find_callers`, `read_symbol`, `outline`, `mount`) — *independent of
  `cancel_id`*. The registry/`CancelGuard` is only used for explicit
  `Daemon.Cancel`. **The token already flows to handlers
  unconditionally**, so a deadline needs no new handler plumbing.
- Handlers poll `token.is_cancelled()` at hot-loop boundaries
  (structural scanner per-match, multiline regex per-file, mount
  cold-walk per-batch).

## Design

### 1. Wire protocol (protocol-v0, additive)

The JSON-RPC envelope gains an optional `deadline_ms` field beside
`cancel_id` (§3.4). Integer, validated `1..=600_000`; absent = no
deadline. Parsed at the connection layer and passed into `dispatch()`
the same way `cancel_id` is. Out-of-range → `INVALID_PARAMS` (mirrors
`cancel_id` length validation). New daemon capability flag
`request_deadlines` in `DAEMON_CAPABILITIES`.

### 2. MCP-side default (rts-mcp)

rts-mcp stamps `deadline_ms` on every daemon request it sends, sourced
from `RTS_DEADLINE_MS` (env), **default `30000` (30s)**, unless the
request already carries an explicit value. This bounds agent latency
out-of-the-box. The agent-facing surface is unchanged: the 10 MCP tools
gain no parameter; the agent never sees `deadline_ms`.

**Mount exemption:** rts-mcp does **not** stamp the default deadline on
`Workspace.Mount` requests (a cold-walk on a huge repo can legitimately
take minutes). An explicit `deadline_ms` on a Mount request is still
honored — the daemon stays method-agnostic; the exemption is purely the
"don't stamp the default for Mount" client policy. `RTS_DEADLINE_MS=0`
disables default stamping entirely.

### 3. Enforcement in `dispatch()`

When `deadline_ms` is present:

1. Create `deadline_fired = Arc<AtomicBool>` (owned by dispatch; keeps
   `CancelToken`'s type unchanged — no edit to `cancel.rs`'s struct).
2. Spawn a timer task: `tokio::time::sleep(deadline_ms)` →
   `deadline_fired.store(true)` then `token.cancel()`.
3. Run the handler as today (it polls the token).
4. On return, `timer.abort()` (fast completion cancels the timer).
5. If the handler result is `Err(CANCELLED)` **and** `deadline_fired`
   is set, rewrite to `Err(DEADLINE_EXCEEDED)`.

This works with or without a `cancel_id`. An explicit `Daemon.Cancel`
trips the token without setting `deadline_fired`, so it still surfaces
as `CANCELLED` — the two causes stay distinguishable. Race: if both a
client cancel and the deadline fire, `deadline_fired` may be set; the
response is `DEADLINE_EXCEEDED`. Acceptable (both mean "aborted"); the
distinction is advisory.

### 4. Error code + observability

Error code `DEADLINE_EXCEEDED` **already exists** in
`error.rs::ErrorCode` (wire string `"DEADLINE_EXCEEDED"`, with a test)
— it was reserved for exactly this and is simply not emitted yet. The
work is to *emit* it (translate the handler's `CANCELLED` when the
deadline fired) and document it in the protocol-v0 §14 table. The
documented numeric is **`-32096`** — `-32099` is `CANCELLED`, and
`-32098`/`-32097` are already taken by rts-mcp's transport-layer
`DAEMON_UNAVAILABLE`/`DAEMON_DOWN` codes, so `-32096` is the next free
slot in the JSON-RPC implementation-defined range. (Like `CANCELLED`,
the daemon emits the string on the wire; the numeric is a §14
documentation/reservation convention.) Marked non-retryable-as-is.
`Daemon.Stats` gains a `deadlines` section with a `total` counter,
mirroring `cancellations.total`.

### 5. Handler cooperative-poll coverage

For a deadline to bite, the targeted handler must poll the token. Audit
each long-running handler and add a poll at a natural batch boundary
(same pattern as the structural scanner's per-1024-row check) where
missing:

- `grep` structural + multiline — **already poll.**
- mount cold-walk drain — **already polls.**
- `outline` — audit; add per-file/per-N-symbol poll if absent.
- `find_callers` / `impact_of` BFS — audit; add per-frontier-node poll.
- `find_symbol` glob scan — audit; add per-N-candidates poll.
- `read_symbol` dependency-closure / tree-shake walker — protocol doc
  notes it does **not** poll today; add a per-expansion-layer poll.

Each addition is a single `if token.is_cancelled() { return Err(...) }`
at a loop boundary; the cost is one relaxed atomic load per batch.

### 6. Testing

Reuse the `cancel_in_flight.rs` two-connection harness style:

- **Deadline trips:** a slow query (large fixture) with a tiny
  `deadline_ms` returns `DEADLINE_EXCEEDED` within a bound.
- **Under budget:** a fast query with a generous `deadline_ms`
  completes normally.
- **Cancel still distinct:** an explicit `Daemon.Cancel` on a slow
  query returns `CANCELLED`, not `DEADLINE_EXCEEDED`.
- **Validation:** `deadline_ms` of 0 / out-of-range → `INVALID_PARAMS`;
  absent → no deadline.
- **Per newly-covered handler:** a deadline interrupts it (proves the
  added poll point works).
- **Schema/capability:** protocol schema-drift tests updated;
  `request_deadlines` capability present; `Daemon.Stats.deadlines.total`
  increments on a timeout. MCP default-stamping + mount-exemption unit
  test in rts-mcp.

## Components / files (anticipated)

- `crates/rts-daemon/src/protocol.rs` — envelope `deadline_ms` parse +
  validation.
- `crates/rts-daemon/src/methods/mod.rs` — `dispatch()` timer +
  `deadline_fired` + `CANCELLED`→`DEADLINE_EXCEEDED` translation.
- `crates/rts-daemon/src/error.rs` — `DEADLINE_EXCEEDED` code.
- `crates/rts-daemon/src/methods/{index,workspace}.rs` — added poll
  points.
- `crates/rts-daemon/src/methods/daemon.rs` / `state.rs` —
  `request_deadlines` capability; `deadlines.total` counter.
- `crates/rts-mcp/src/server.rs` (+ config) — `RTS_DEADLINE_MS` default
  stamping, Mount exemption.
- `docs/protocol-v0.md` — §3.4 envelope, §7 capability, §14 error
  table, §10 cancellation section.
- Tests: `crates/rts-daemon/tests/` (deadline e2e + schema), rts-mcp
  unit test.

## Out of scope (stays deferred)

- Streaming / incremental result frames; partial results on timeout
  (this returns an error, no partial set).
- `Daemon.SetTimeout { method, ms }` stateful per-method config.
- Cross-daemon deadline propagation.
- Per-tool `timeout_ms` on the agent-facing MCP surface.

## Success criteria

- A query exceeding its deadline returns `DEADLINE_EXCEEDED` (not
  `CANCELLED`) within a bounded margin of the budget; a query under
  budget is unaffected.
- `RTS_DEADLINE_MS` (default 30000) bounds agent queries out-of-the-box;
  `Workspace.Mount` is exempt from the default but honors an explicit
  `deadline_ms`; `RTS_DEADLINE_MS=0` disables stamping.
- Explicit `Daemon.Cancel` remains distinguishable (`CANCELLED`).
- `request_deadlines` capability advertised; `Daemon.Stats.deadlines.total`
  observable; protocol-v0 schemas + docs updated; CI green.
- No measurable regression in normal (sub-budget) query latency.
