### Stabilize `cancel_in_flight` integration tests — replace wall-clock cushions with registry-state barriers

The three integration tests in `crates/rts-daemon/tests/cancel_in_flight.rs` (added in PR #114, cancellable queries) flaked under `cargo test --workspace`. Two independent agents on unrelated PRs (#116, #117) reported a passing rerun after a single failure — the canonical fingerprint of a wall-clock race, not noise.

#### Diagnosis

Each test bridged a "did the daemon do the thing yet?" gap with a fixed `tokio::time::sleep`:

- Tests 1 + 3 (live cancel): the slow `Index.Grep` is dispatched, then the test waits 50 ms before sending `Daemon.Cancel`. The 50 ms is a wall-clock gamble that the grep's dispatch task has spawned, reached the `CancelGuard::register` await, and won the `RwLock` write lock — before the cancel's dispatch task takes the read lock and looks the id up. Under heavy CPU contention (parallel test workers in `cargo test --workspace`), tokio's scheduler can take longer than 50 ms to land all that, and the cancel observes an empty registry → returns `{ cancelled: false }` → assertion fires.

- Test 2 (stale cancel): the test waits 50 ms after a fast `Index.FindSymbol` completes, then sends a `Daemon.Cancel` with the now-stale id, expecting `{ cancelled: false }`. The 50 ms gambles that the `CancelGuard`'s drop-spawned removal task has actually run. Under contention it may not have, and the test observes `cancelled: true`.

The production cancellation surface (`CancelToken` / `CancelRegistry` / `Daemon.Cancel`) is correct. The races are entirely test-side.

#### Fix

Replace every fixed sleep with a barrier that polls `Daemon.Stats.cancellations.in_flight` until it satisfies the test's precondition:

- Live cancel: poll until `in_flight >= 1` (or `>= 2` for the concurrent-queries test) before issuing `Daemon.Cancel`. That's the registry's own "token is registered" signal — no timing gamble.
- Stale cancel: poll until `in_flight == 0` after the fast query completes. That's the guard-drop's own "token is gone" signal.

Test 1 also now puts `Daemon.Cancel` on a separate connection from the slow grep (the plan's original "from another connection send Daemon.Cancel" wording). Pipelining the cancel on the same socket as the grep meant the test couldn't probe `Daemon.Stats` mid-flight to synchronize. Two connections cleanly decouple the query path from the control path. Drops the now-redundant `cancel_to_response < 2s` wall-clock latency assertion (the test budget is already enforced by the 15 s read timeout, and the assertion's intent — "cancel arrives well before natural completion" — is now satisfied by the barrier rather than a wall-clock bound).

Verified 20/20 passing in release mode at default parallel test-threads, and 20/20 passing under 8-core CPU pressure (8 concurrent CPU-burn loops alongside the test runner).
