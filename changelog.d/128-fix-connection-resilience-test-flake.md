### Stabilize `connection_resilience` integration tests — bound response reads by caller deadline, not a hardcoded 8 s wall

The four integration tests in `crates/rts-mcp/tests/connection_resilience.rs` (added in PR #117, MCP resilience) flaked under `cargo test --release -p rts-mcp` parallel mode. PR #124 caught the flake; clean-`origin/main` reruns reproduced four `timeout reading MCP response` errors with no observable production-side fault.

#### Diagnosis

The test helper `read_one_response` capped each MCP response read at a hardcoded `Duration::from_secs(8)`. The outer poll loops (`poll_find_symbol_success`, the scenario-2 SIGKILL recovery wait, the scenario-4 herd drain) already encoded the real per-scenario tolerance (10 s for first call, 30 s for SIGKILL recovery + cold respawn). Pre-fix, the inner 8 s cap short-circuited any outer deadline > 8 s, so the resilience layer's intended recovery windows were untestable.

Under parallel-test load (4 scenarios × 4 daemons × concurrent cold-mount across them) the first `tools/call` legitimately took more than 8 s. The shim's `ConnectionManager::call` awaits `Workspace.Mount` (lazy, fires on first tool call), which awaits the daemon's cold walk + first writer-batch flush. With four daemons booting in parallel and contending for redb open + tree-sitter parser pool + filesystem walk, the natural latency on the first response spiked above 8 s. The outer 10 s and 30 s deadlines would have absorbed this — except they never got the chance, because the inner 8 s capped first.

The production resilience surface (`ConnectionManager`, heartbeat, reconnect-with-backoff, `DAEMON_UNAVAILABLE` envelope) is correct. The race is entirely test-side.

#### Fix

Replace the hardcoded `Duration::from_secs(8)` with a `deadline: Instant` parameter threaded from the caller. Each call site passes the scenario's natural tolerance (30 s everywhere — well above the worst-case cold-mount under parallel load and well above the reconnect ceiling). The outer `poll_find_symbol_success` loop's `deadline` becomes the single point of truth for "how long are we willing to wait for this symbol to appear via find_symbol", consistent with the `wait_for_in_flight(timeout, label)` barrier pattern introduced in PR #119.

Verified 20/20 passing in release mode at default parallel test-threads, 20/20 in debug mode, and 20/20 under 20-core CPU pressure (20 concurrent `yes > /dev/null` loops alongside the test runner on a 10-core machine).
