---
title: Cancellable Long-Running Queries (CancelToken in JSON-RPC frame)
type: feat
status: active
date: 2026-05-19
---

# Cancellable Long-Running Queries

## Overview

`Index.Grep v2` shipped with structural queries, multiline regex, and
within-symbol filters in PR #110. These capabilities can fan out to
thousands of tree-sitter nodes across hundreds of files — a 2-4 second
query latency is realistic on medium workspaces. The protocol has **no
cancellation token in the JSON-RPC frame**: once a request is dispatched,
the daemon runs it to completion regardless of whether the client still
cares about the answer.

For human-driven CLI usage this is annoying. For **agent loops** — where a
model fires a query, reads partial context, then reframes its plan and
fires a *different* query — it's structurally broken: the first query
keeps consuming CPU, memory, and a worker slot while the second waits.

This plan adds cancellation as a first-class protocol primitive: clients
can attach a `cancel_id` to any request and send `Daemon.Cancel { id }` to
abort it. The structural scanner checks the cancel flag at per-match
boundaries; long queries return `error.code: CANCELLED` within ~50ms of
the cancel call.

## Problem Statement / Motivation

Three concrete failure modes from agent traces:

1. **Agent plan revision** — agent issues `Index.Grep { structural_query:
   "(class_definition) @c", text: "ABC" }`, then 200ms later decides the
   structural shape was wrong and issues a follow-up. Daemon now has two
   live queries; the first burns 3 seconds returning data nobody reads.

2. **User interrupt mid-query** — user types Ctrl-C in a CLI loop or
   navigates away in an IDE. Client closes the socket. Daemon's structural
   scanner doesn't notice until the next `await` point (which may be
   end-of-query). Wasted work, wasted heat.

3. **Cardinality runaway** — within-symbol cardinality cap fires *after*
   the structural scan completes. A query with a too-loose structural
   pattern can fan out to ~50k captures before the cap rejects the whole
   thing. With cancellation, the cap can early-abort.

Every other modern RPC has cancellation (gRPC, tower, hyper, axum). We
don't. The longer we wait, the more clients will assume `Index.Grep`
"can't be cancelled" and design around that limitation.

## Proposed Solution

### Protocol shape

Add an optional `cancel_id: String` field to every `Index.*` and
`Workspace.*` request. The client picks the id (UUID, or a numeric
counter). A separate top-level method:

```json
{ "id": "abort-1", "method": "Daemon.Cancel", "params": { "cancel_id": "q-42" } }
```

returns immediately with `{ "result": { "cancelled": true | false } }`
(`false` if the id was unknown or already completed). The daemon flips a
`CancellationToken` keyed by `cancel_id`; in-flight workers see the flag
on their next check.

### Cancellation token plumbing

```rust
// crates/rts-daemon/src/cancel.rs (new)
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

#[derive(Clone, Default)]
pub struct CancelToken(Arc<AtomicBool>);

impl CancelToken {
    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::Relaxed)
    }
    pub fn cancel(&self) {
        self.0.store(true, Ordering::Relaxed);
    }
}

// Daemon-wide registry: cancel_id -> CancelToken
// crates/rts-daemon/src/methods/registry.rs
pub struct CancelRegistry {
    inner: tokio::sync::RwLock<std::collections::HashMap<String, CancelToken>>,
}
```

The request dispatcher (in `crates/rts-daemon/src/methods/`) checks for
`cancel_id` on incoming requests, registers a token, passes it down to
the method handler, and drops the registry entry on completion.

### Scanner integration points

- **Grep v2 structural scanner**
  (`crates/rts-daemon/src/methods/grep_v2/structural.rs`): check
  `token.is_cancelled()` after every match emission. Adds ~1ns per match —
  noise.
- **Grep v2 multiline regex**
  (`crates/rts-daemon/src/methods/grep_v2/multiline.rs`): the `regex` crate
  doesn't natively support cancellation, so check between file boundaries
  and between matches within a file.
- **Index.FindSymbol / Index.FindCallers**: typically sub-100ms; only check
  the token at the top of the method, not in inner loops.
- **Workspace.Mount**: long cold-walks should honor cancellation. Check at
  each batch flush in `crates/rts-daemon/src/watcher.rs:330` walker.

### Error code

Add `CANCELLED = -32099` (outside the JSON-RPC reserved range, inside our
custom codespace alongside `INVALID_STRUCTURAL_QUERY` etc.). Document in
`docs/protocol.md`.

## Technical Considerations

- **Memory:** `CancellationToken` is `Arc<AtomicBool>`. Even with 10k
  in-flight requests (we'd be on fire long before this), the registry is
  ~1MB. Drop on completion is automatic via registry remove.
- **Race:** client sends `Daemon.Cancel` after the request has already
  completed and the registry entry was dropped. We return
  `{ cancelled: false }` and don't error — idempotent.
- **Granularity:** worst-case latency to abort is the time to the next
  check. Structural scanner checks per-match → ~50µs typical. Multiline
  regex checks per-file → up to file-scan time (~few ms). Mount cold-walk
  checks per-batch → ~50ms.
- **`tokio::sync::CancellationToken`:** considered using the upstream type
  but it has more machinery than we need (parent/child trees). A bare
  `Arc<AtomicBool>` is simpler and sufficient.
- **No deadline timeouts in this plan.** That's a separate feature
  (`Daemon.SetTimeout` per-method) — additive on top of cancellation.

## System-Wide Impact

- **Interaction graph:** request arrives → dispatcher registers token →
  handler reads `cancel_id` → spawns work with token → checks token
  periodically → returns either result or `CANCELLED` → dispatcher
  unregisters token. Cancel arrives → dispatcher flips token → next check
  fires → handler returns `CANCELLED` → caller gets answer in ~50µs.
- **Error propagation:** `CANCELLED` is not a programming error; clients
  should treat it as expected. Document this prominently.
- **State lifecycle:** cancellation does **not** roll back writes. Any
  `WatchEvent::Touched` partially processed before cancel is committed.
  This is fine because writes are idempotent (mtime+content_hash
  comparisons).
- **API surface parity:** the `cancel_id` field is optional on every
  request. Clients that don't use it work unchanged. MCP tool descriptions
  (rts-mcp) should document the new field but agents won't be required to
  set it.
- **Integration test scenarios:**
  1. Issue a slow `Index.Grep` against a 10k-file fixture; concurrently
     send `Daemon.Cancel`; assert response is `CANCELLED` within 200ms of
     cancel call.
  2. Cancel a request that completed milliseconds before the cancel
     arrived; assert `{ cancelled: false }` and the original result still
     returns successfully.
  3. Two concurrent slow queries, same client; cancel only the first;
     assert the second completes normally.

## Acceptance Criteria

- [ ] JSON-RPC request envelope accepts optional `cancel_id: String`.
- [ ] `Daemon.Cancel { cancel_id }` method returns
      `{ cancelled: bool }`.
- [ ] `Index.Grep`, `Index.FindSymbol`, `Index.FindCallers`,
      `Index.ReadSymbol`, `Index.OutlineWorkspace` all honor cancellation.
- [ ] `Workspace.Mount` honors cancellation at cold-walk batch
      boundaries.
- [ ] Error code `CANCELLED = -32099` documented in `docs/protocol.md`.
- [ ] Integration test
      `crates/rts-daemon/tests/cancel_in_flight.rs` covers the three
      scenarios above.
- [ ] `Daemon.Stats` exposes `cancellations: { total, in_flight }`
      counters.
- [ ] MCP tool descriptions in `crates/rts-mcp/src/` mention the
      `cancel_id` parameter (for agents that want to wire it up).
- [ ] No measurable latency regression (`cargo bench` baseline ±3%) on
      uncancelled queries.

## Success Metrics

- After cancellation lands, p99 daemon CPU during agent-burst traffic
  drops measurably (currently dominated by dead-work from abandoned
  queries).
- ≥1 MCP host wires up cancellation within 30 days of ship.

## Dependencies & Risks

- **No new external dependencies.** `std::sync::atomic` only.
- **Risk:** clients send cancels for ids they never registered (typo,
  off-by-one). We return `{ cancelled: false }` — harmless.
- **Risk:** structural scanner check is in a hot loop; even 1ns per match
  could matter at scale. Mitigation: `AtomicBool::load(Relaxed)` is one
  cache-hit load; benchmark first.
- **Risk:** the regex crate's DFA can't be interrupted mid-match. Worst
  case is one file's scan completes before the cancel takes effect.
  Acceptable given file-level granularity.

## Out of Scope (Non-Goals)

- **Deadline timeouts** — `Daemon.SetTimeout { method, ms }` is a separate
  conversation. Cancellation is the building block; timeouts are
  cancellation on a timer.
- **Cooperative streaming** — cancelling a streaming response (we don't
  ship one yet) is a v0.7 concern.
- **Cancellation propagation across daemons** — single-process scope only.

## Sources & References

- **Protocol surface:** `docs/protocol.md`
- **Existing dispatcher pattern:**
  `crates/rts-daemon/src/methods/mod.rs`
- **Grep v2 structural scanner:**
  `crates/rts-daemon/src/methods/grep_v2/structural.rs`
- **Walker batch flush:** `crates/rts-daemon/src/watcher.rs:330`
- **JSON-RPC custom error codes:** `crates/rts-daemon/src/error.rs`
- **Related: `tokio_util::sync::CancellationToken`** —
  <https://docs.rs/tokio-util/latest/tokio_util/sync/struct.CancellationToken.html>
  (considered but heavier than needed)
- **Related: tower-rs cancellation patterns** —
  <https://docs.rs/tower/latest/tower/timeout/index.html>
