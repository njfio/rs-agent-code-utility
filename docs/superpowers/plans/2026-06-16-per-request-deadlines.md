# Per-Request Deadlines / Timeouts Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A daemon request that exceeds a time budget is auto-cancelled and returns `DEADLINE_EXCEEDED`, with rts-mcp stamping a default 30s budget on agent queries (Mount exempt).

**Architecture:** A deadline is "a self-firing `Daemon.Cancel` on a timer." `dispatch()` already creates a `CancelToken` for every request and hands it to the slow handlers; we add an optional `deadline_ms` envelope field, spawn a timer that trips that token, and translate the handler's `CANCELLED` into `DEADLINE_EXCEEDED` when the timer fired. rts-mcp's `DaemonClient::call()` stamps a default `deadline_ms` from `RTS_DEADLINE_MS`.

**Tech Stack:** Rust, tokio (timers/tasks), serde_json, the existing `crate::cancel` machinery.

**Working branch:** `feat/request-deadlines` (already created; spec committed there).

**Reference spec:** `docs/superpowers/specs/2026-06-16-per-request-deadlines-design.md`

---

## File map

- Modify: `crates/rts-daemon/src/protocol.rs` — `Request.deadline_ms` field.
- Modify: `crates/rts-daemon/src/socket.rs` — thread `deadline_ms` into `methods::dispatch`.
- Modify: `crates/rts-daemon/src/methods/mod.rs` — `dispatch()` deadline timer + validation + `CANCELLED`→`DEADLINE_EXCEEDED` translation; `AbortOnDrop` guard.
- Modify: `crates/rts-daemon/src/state.rs` — `deadlines_total: AtomicU64`.
- Modify: `crates/rts-daemon/src/methods/daemon.rs` — `request_deadlines` capability; `deadlines.total` in `Daemon.Stats`.
- Modify: `crates/rts-daemon/src/methods/index.rs` — add cooperative poll points where missing (read_symbol dependency closure; audit outline / find_callers / find_symbol).
- Modify: `crates/rts-mcp/src/daemon_client.rs` — `default_deadline_ms` field + stamp in `call()` (Mount exempt).
- Create: `crates/rts-daemon/tests/deadline.rs` — e2e deadline tests.
- Modify: `crates/rts-daemon/tests/protocol_schemas.rs` — capability + error-code coverage.
- Modify: `docs/protocol-v0.md` — §3.4 envelope, §7 capability, §10 cancellation, §14 error table.
- Create: `changelog.d/xxx-feat-request-deadlines.md`.

Note: `ErrorCode::DeadlineExceeded` (wire `"DEADLINE_EXCEEDED"`) **already exists** in `error.rs` — no new code is needed there.

---

## Task 1: `deadline_ms` envelope field + plumbing

**Files:** Modify `crates/rts-daemon/src/protocol.rs`, `crates/rts-daemon/src/socket.rs`, `crates/rts-daemon/src/methods/mod.rs`

- [ ] **Step 1: Add a failing parse test**

In `crates/rts-daemon/src/protocol.rs` `mod tests`, add:
```rust
    #[test]
    fn parse_request_with_deadline_ms() {
        let req = parse_request_line(
            br#"{"id":"1","method":"Index.Grep","params":{},"deadline_ms":5000}"#,
        )
        .unwrap();
        assert_eq!(req.deadline_ms, Some(5000));
    }

    #[test]
    fn parse_request_without_deadline_ms_defaults_none() {
        let req = parse_request_line(br#"{"id":"1","method":"Daemon.Ping","params":{}}"#).unwrap();
        assert_eq!(req.deadline_ms, None);
    }
```

- [ ] **Step 2: Run it to verify it fails to compile**

Run: `cargo test -p rts-daemon --lib protocol::tests::parse_request_with_deadline_ms`
Expected: compile error — no field `deadline_ms` on `Request`.

- [ ] **Step 3: Add the field**

In `crates/rts-daemon/src/protocol.rs`, in `struct Request` (after the `cancel_id` field):
```rust
    #[serde(default)]
    pub cancel_id: Option<String>,
    /// Optional per-request deadline in milliseconds (protocol-v0 §3.4,
    /// capability `request_deadlines`). When set and the request runs
    /// longer, the daemon trips the request's `CancelToken` and returns
    /// `DEADLINE_EXCEEDED`. Range-validated in `methods::dispatch`.
    /// Absent (`None`) = no deadline; existing clients are unaffected.
    #[serde(default)]
    pub deadline_ms: Option<u64>,
```

- [ ] **Step 4: Run the parse tests to verify they pass**

Run: `cargo test -p rts-daemon --lib protocol::tests`
Expected: PASS (including the two new tests).

- [ ] **Step 5: Thread `deadline_ms` through `socket.rs`**

In `crates/rts-daemon/src/socket.rs`, the private `dispatch(req, state)` wrapper currently ends with:
```rust
    methods::dispatch(&req.method, req.params, state, req.cancel_id).await
```
Change to:
```rust
    methods::dispatch(&req.method, req.params, state, req.cancel_id, req.deadline_ms).await
```

- [ ] **Step 6: Extend `methods::dispatch` signature (plumbing only)**

In `crates/rts-daemon/src/methods/mod.rs`, change the `dispatch` signature:
```rust
pub async fn dispatch(
    method: &str,
    params: serde_json::Value,
    state: &Arc<DaemonState>,
    cancel_id: Option<String>,
    deadline_ms: Option<u64>,
) -> Result<serde_json::Value, ProtocolError> {
```
Add `let _ = deadline_ms;` immediately after the signature for now (consumed in Task 2) to avoid an unused-variable warning. Update `prewarm_mount`'s internal call if it routes through `dispatch` (it does not — it calls `mount_inner` directly — so no change there).

- [ ] **Step 7: Build to verify plumbing compiles**

Run: `cargo build -p rts-daemon 2>&1 | tail -3`
Expected: builds clean (the `let _ = deadline_ms;` keeps it warning-free).

- [ ] **Step 8: Commit**

```bash
git add crates/rts-daemon/src/protocol.rs crates/rts-daemon/src/socket.rs crates/rts-daemon/src/methods/mod.rs
git commit -m "feat(daemon): add deadline_ms envelope field + dispatch plumbing

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 2: Deadline enforcement in `dispatch()`

**Files:** Modify `crates/rts-daemon/src/methods/mod.rs`, `crates/rts-daemon/src/state.rs`; Create `crates/rts-daemon/tests/deadline.rs`

- [ ] **Step 1: Add `deadlines_total` to `DaemonState`**

In `crates/rts-daemon/src/state.rs`, beside `pub cancellations_total: AtomicU64,` in `struct DaemonState`:
```rust
    pub cancellations_total: AtomicU64,
    /// Cumulative count of requests aborted by a per-request deadline
    /// (`deadline_ms` elapsed → token tripped → `DEADLINE_EXCEEDED`).
    /// Surfaced via `Daemon.Stats.deadlines.total`. Distinct from
    /// `cancellations_total` (explicit `Daemon.Cancel`).
    pub deadlines_total: AtomicU64,
```
And in `DaemonState::new()` beside `cancellations_total: AtomicU64::new(0),`:
```rust
            cancellations_total: AtomicU64::new(0),
            deadlines_total: AtomicU64::new(0),
```

- [ ] **Step 2: Add the `AbortOnDrop` timer guard + deadline logic to `dispatch`**

In `crates/rts-daemon/src/methods/mod.rs`, add near the top (after imports):
```rust
/// Aborts its wrapped task on drop. Used to cancel the deadline timer
/// the instant the handler returns, so a fast request leaves no timer
/// running. Drop runs on every dispatch exit (normal, error, panic).
struct AbortOnDrop(tokio::task::JoinHandle<()>);
impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Maximum accepted `deadline_ms` (10 minutes). Mirrors the envelope's
/// documented range in protocol-v0 §3.4.
const MAX_DEADLINE_MS: u64 = 600_000;
```

Replace the `let _ = deadline_ms;` placeholder from Task 1 with the timer setup, placed right after the `token`/`_cancel_guard` block and before `let started = ...`:
```rust
    use std::sync::atomic::AtomicBool;
    // Per-request deadline: validate, then arm a timer that trips this
    // request's CancelToken when the budget elapses. The handler's
    // existing cooperative poll catches it; we translate its CANCELLED
    // into DEADLINE_EXCEEDED below. Works regardless of `cancel_id`.
    let deadline_fired = Arc::new(AtomicBool::new(false));
    let _deadline_timer = match deadline_ms {
        Some(ms) => {
            if ms == 0 || ms > MAX_DEADLINE_MS {
                return Err(ProtocolError::new(
                    ErrorCode::InvalidParams,
                    format!("`deadline_ms` must be 1..={MAX_DEADLINE_MS}"),
                ));
            }
            let token = token.clone();
            let fired = deadline_fired.clone();
            Some(AbortOnDrop(tokio::spawn(async move {
                tokio::time::sleep(std::time::Duration::from_millis(ms)).await;
                fired.store(true, Relaxed);
                token.cancel();
            })))
        }
        None => None,
    };
```

- [ ] **Step 3: Translate `CANCELLED`→`DEADLINE_EXCEEDED` after the handler runs**

In `crates/rts-daemon/src/methods/mod.rs`, the handler `match` assigns `let result = match method { ... };`. Immediately after that match (before the telemetry latency recording), insert:
```rust
    // A deadline that fired surfaces as the handler's CANCELLED; rewrite
    // it so clients can tell a timeout from an explicit Daemon.Cancel.
    let result = match result {
        Err(e)
            if e.code == ErrorCode::Cancelled
                && deadline_fired.load(Relaxed) =>
        {
            state.deadlines_total.fetch_add(1, Relaxed);
            Err(ProtocolError::new(
                ErrorCode::DeadlineExceeded,
                format!(
                    "request exceeded deadline of {} ms",
                    deadline_ms.unwrap_or_default()
                ),
            ))
        }
        other => other,
    };
```
(`ErrorCode` is already imported in this file via `crate::error::{ErrorCode, ProtocolError}`.)

- [ ] **Step 4: Write the e2e deadline test**

Create `crates/rts-daemon/tests/deadline.rs`. Reuse the harness style in `crates/rts-daemon/tests/cancel_in_flight.rs` (a `TestDaemon`/socket round-trip helper + a deliberately slow `Index.Grep` over a large generated fixture). Mirror that file's setup helpers; the new assertions:
```rust
//! End-to-end tests for per-request deadlines (`deadline_ms` envelope
//! field → DEADLINE_EXCEEDED). Companion to `cancel_in_flight.rs`.

// ... reuse cancel_in_flight.rs's daemon spawn + big-fixture +
// round_trip helpers (copy or factor into a shared test module) ...

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn slow_query_hits_deadline_returns_deadline_exceeded() {
    // Big fixture so a structural grep runs longer than the budget.
    // deadline_ms = 1: the timer trips the token before the scan ends.
    // Assert the error envelope code is DEADLINE_EXCEEDED (not CANCELLED).
    // (Poll Daemon.Stats.deadlines.total to confirm the counter bumps.)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fast_query_under_budget_completes_normally() {
    // A trivial Index.FindSymbol with deadline_ms = 60000 returns a
    // normal result envelope, not an error.
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn explicit_cancel_still_returns_cancelled_not_deadline() {
    // Slow query with a cancel_id and NO deadline_ms; fire Daemon.Cancel
    // (two-connection pattern from cancel_in_flight.rs). Assert the code
    // is CANCELLED, proving the two causes stay distinct.
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn out_of_range_deadline_is_invalid_params() {
    // deadline_ms = 0 and deadline_ms = 600001 each return INVALID_PARAMS.
}
```
Implement each body against the copied helpers. For the slow-query timing, reuse the exact fixture size `cancel_in_flight.rs` uses for its slow grep (the 5000-fn `big.rs` pattern from `cli_grep.rs`); if the 1 ms budget proves flaky on a fast machine, raise the fixture size rather than the budget so the test stays deterministic.

- [ ] **Step 5: Run the deadline tests**

Run: `cargo test -p rts-daemon --test deadline`
Expected: all four pass.

- [ ] **Step 6: Run the existing cancel tests to confirm no regression**

Run: `cargo test -p rts-daemon --test cancel_in_flight`
Expected: PASS (explicit cancellation unaffected).

- [ ] **Step 7: Commit**

```bash
git add crates/rts-daemon/src/methods/mod.rs crates/rts-daemon/src/state.rs crates/rts-daemon/tests/deadline.rs
git commit -m "feat(daemon): enforce per-request deadline_ms via timer-tripped CancelToken

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 3: Capability + `Daemon.Stats.deadlines.total`

**Files:** Modify `crates/rts-daemon/src/methods/daemon.rs`

- [ ] **Step 1: Add the capability**

In `crates/rts-daemon/src/methods/daemon.rs`, in the `DAEMON_CAPABILITIES` array, after `"cancellable_queries",` add:
```rust
    "cancellable_queries",
    // v0.7+ — per-request deadlines. Any request may carry an optional
    // top-level `deadline_ms`; when the budget elapses the daemon trips
    // the request's CancelToken and returns DEADLINE_EXCEEDED (distinct
    // from CANCELLED). rts-mcp stamps a default (RTS_DEADLINE_MS, 30s)
    // on agent queries; Mount is exempt from that default. Pure additive
    // — clients that omit `deadline_ms` are unaffected. See
    // `docs/protocol-v0.md` §3.4/§14 and `crate::cancel`.
    "request_deadlines",
```

- [ ] **Step 2: Add `deadlines` to the `Daemon.Stats` snapshot**

In `crates/rts-daemon/src/methods/daemon.rs` `stats()`, the snapshot builds a `"cancellations"` object (`{ "total": ..., "in_flight": ... }`). Immediately after that key, add:
```rust
        "deadlines": {
            "total": state.deadlines_total.load(Relaxed),
        },
```
(`Relaxed` is already in scope in `stats()`.)

- [ ] **Step 3: Add a stats/capability assertion test**

In `crates/rts-daemon/tests/deadline.rs`, add:
```rust
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn capability_and_stats_advertise_deadlines() {
    // Daemon.Ping result.capabilities contains "request_deadlines".
    // Daemon.Stats result has a deadlines.total integer (>= 0).
}
```

- [ ] **Step 4: Run the test**

Run: `cargo test -p rts-daemon --test deadline capability_and_stats_advertise_deadlines`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/rts-daemon/src/methods/daemon.rs crates/rts-daemon/tests/deadline.rs
git commit -m "feat(daemon): advertise request_deadlines capability + Daemon.Stats.deadlines.total

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 4: Handler cooperative-poll coverage

**Files:** Modify `crates/rts-daemon/src/methods/index.rs`

For a deadline (or cancel) to bite, the targeted handler must poll the token at its main loop. `grep` (structural + multiline) and mount cold-walk already do. This task audits the remaining long handlers and adds a poll where missing. The poll idiom (matches the structural scanner):
```rust
if token.is_cancelled() {
    return Err(ProtocolError::new(
        ErrorCode::Cancelled,
        "request cancelled",
    ));
}
```

- [ ] **Step 1: Add a failing test for the known gap (read_symbol dependency closure)**

In `crates/rts-daemon/tests/deadline.rs`:
```rust
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn deadline_interrupts_read_symbol_dependency_closure() {
    // Index.ReadSymbol with include_dependencies=true on a symbol with a
    // large transitive type closure + deadline_ms = 1 → DEADLINE_EXCEEDED.
    // Pre-fix: the tree-shake walker doesn't poll, so it runs to
    // completion and returns a normal result (test fails).
}
```

- [ ] **Step 2: Run it to confirm the gap**

Run: `cargo test -p rts-daemon --test deadline deadline_interrupts_read_symbol_dependency_closure`
Expected: FAIL (returns a result, not DEADLINE_EXCEEDED) — confirms the walker doesn't poll.

- [ ] **Step 3: Add the poll to the dependency-closure walker**

In `crates/rts-daemon/src/methods/index.rs`, find the `read_symbol` dependency-closure / tree-shake expansion loop (the `token: CancelToken` param is already threaded into `read_symbol`). At the head of the per-expansion-layer loop, add the poll idiom above. Use the existing `ErrorCode`/`ProtocolError` imports in the file.

- [ ] **Step 4: Run the test to verify it passes**

Run: `cargo test -p rts-daemon --test deadline deadline_interrupts_read_symbol_dependency_closure`
Expected: PASS.

- [ ] **Step 5: Audit and cover the other long handlers**

Inspect each of these in `crates/rts-daemon/src/methods/index.rs` and confirm a `token.is_cancelled()` poll exists at the main per-item loop; if absent, add the poll idiom at the loop head:
- `outline` — per-file (or per-N-symbol) loop.
- `find_callers` and the `impact_of` BFS — per-frontier-node loop.
- `find_symbol` — per-candidate glob/scan loop.

For each one you add a poll to, append a sibling test to `deadline.rs` modeled on Step 1 (`deadline_interrupts_<handler>`), proving a tight `deadline_ms` interrupts it. If a handler already polls, note it in the commit body and add no test (covered by Task 2's structural-grep e2e).

- [ ] **Step 6: Run the full deadline suite + clippy**

Run: `cargo test -p rts-daemon --test deadline && cargo clippy -p rts-daemon --all-targets 2>&1 | tail -3`
Expected: tests pass; no new clippy errors.

- [ ] **Step 7: Commit**

```bash
git add crates/rts-daemon/src/methods/index.rs crates/rts-daemon/tests/deadline.rs
git commit -m "feat(daemon): poll CancelToken in read_symbol closure + audited Index handlers

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 5: rts-mcp default stamping (`RTS_DEADLINE_MS`, Mount exempt)

**Files:** Modify `crates/rts-mcp/src/daemon_client.rs`

- [ ] **Step 1: Add a failing unit test for stamping**

In `crates/rts-mcp/src/daemon_client.rs`, add a `#[cfg(test)] mod tests` (or extend it) with a pure helper test. First introduce a small pure function `fn stamped_deadline(default_ms: Option<u64>, method: &str) -> Option<u64>` that encodes the policy, then test it:
```rust
    #[test]
    fn stamps_default_on_queries_exempts_mount() {
        assert_eq!(stamped_deadline(Some(30_000), "Index.Grep"), Some(30_000));
        assert_eq!(stamped_deadline(Some(30_000), "Index.FindSymbol"), Some(30_000));
        // Mount cold-walk can legitimately exceed any default → exempt.
        assert_eq!(stamped_deadline(Some(30_000), "Workspace.Mount"), None);
        // No configured default → never stamp.
        assert_eq!(stamped_deadline(None, "Index.Grep"), None);
    }
```

- [ ] **Step 2: Run it to verify it fails**

Run: `cargo test -p rts-mcp --lib daemon_client::tests::stamps_default_on_queries_exempts_mount`
Expected: compile error — `stamped_deadline` not defined.

- [ ] **Step 3: Implement the policy helper**

In `crates/rts-mcp/src/daemon_client.rs`:
```rust
/// The deadline rts-mcp stamps on a daemon request: the configured
/// default for every method EXCEPT `Workspace.Mount` (a cold-walk on a
/// big repo can legitimately run for minutes). `None` default = never
/// stamp. An explicit per-request deadline is not modeled here — the
/// CLI/other clients set `deadline_ms` directly on the wire.
fn stamped_deadline(default_ms: Option<u64>, method: &str) -> Option<u64> {
    match default_ms {
        Some(ms) if method != "Workspace.Mount" => Some(ms),
        _ => None,
    }
}
```

- [ ] **Step 4: Run the helper test to verify it passes**

Run: `cargo test -p rts-mcp --lib daemon_client::tests::stamps_default_on_queries_exempts_mount`
Expected: PASS.

- [ ] **Step 5: Wire the default into `DaemonClient` and `call()`**

In `crates/rts-mcp/src/daemon_client.rs`:

Add a field to `struct DaemonClient`:
```rust
    workspace: PathBuf,
    /// Default deadline (ms) stamped on non-Mount requests. Sourced from
    /// `RTS_DEADLINE_MS` at construction: unset → Some(30_000); "0" →
    /// None (disabled); else the parsed value. See `stamped_deadline`.
    default_deadline_ms: Option<u64>,
```

In `DaemonClient::new()`, compute it and set the field:
```rust
    pub fn new(stream: UnixStream, daemon_bin: PathBuf, workspace: PathBuf) -> Self {
        let (rd, wr) = stream.into_split();
        Self {
            writer: wr,
            reader: BufReader::new(rd),
            next_id: AtomicU64::new(1),
            daemon_bin,
            workspace,
            default_deadline_ms: default_deadline_from_env(),
        }
    }
```
And add the env reader:
```rust
/// Read `RTS_DEADLINE_MS`: unset → Some(30_000) (30s default); "0" →
/// None (disabled); a valid u64 → Some(v); anything unparseable →
/// Some(30_000) (fail safe to the default rather than panicking).
fn default_deadline_from_env() -> Option<u64> {
    const DEFAULT_DEADLINE_MS: u64 = 30_000;
    match std::env::var("RTS_DEADLINE_MS") {
        Err(_) => Some(DEFAULT_DEADLINE_MS),
        Ok(s) => match s.trim().parse::<u64>() {
            Ok(0) => None,
            Ok(v) => Some(v),
            Err(_) => Some(DEFAULT_DEADLINE_MS),
        },
    }
}
```
(`reconnect()` builds a new stream but mutates `self.writer`/`self.reader` in place — it does NOT call `new()`, so `default_deadline_ms` persists across reconnects unchanged. No edit needed there.)

In `call()`, stamp the request object:
```rust
        let id = self.alloc_id();
        let mut req = json!({ "id": id, "method": method, "params": params });
        if let Some(ms) = stamped_deadline(self.default_deadline_ms, method) {
            req["deadline_ms"] = json!(ms);
        }
```

- [ ] **Step 6: Add an env-reader test**

In the same test module:
```rust
    #[test]
    fn env_reader_handles_unset_zero_and_value() {
        // Note: std::env is process-global; assert the parse logic via a
        // helper that takes the raw Option<&str> instead of touching env.
        fn parse(raw: Option<&str>) -> Option<u64> {
            match raw {
                None => Some(30_000),
                Some(s) => match s.trim().parse::<u64>() {
                    Ok(0) => None,
                    Ok(v) => Some(v),
                    Err(_) => Some(30_000),
                },
            }
        }
        assert_eq!(parse(None), Some(30_000));
        assert_eq!(parse(Some("0")), None);
        assert_eq!(parse(Some("5000")), Some(5_000));
        assert_eq!(parse(Some("garbage")), Some(30_000));
    }
```
(Refactor `default_deadline_from_env` to delegate to this pure `parse` over `std::env::var(...).ok().as_deref()` so the logic is tested without mutating process env.)

- [ ] **Step 7: Run the rts-mcp tests + build**

Run: `cargo test -p rts-mcp --lib daemon_client && cargo build -p rts-mcp 2>&1 | tail -3`
Expected: tests pass; builds clean.

- [ ] **Step 8: Commit**

```bash
git add crates/rts-mcp/src/daemon_client.rs
git commit -m "feat(mcp): stamp default RTS_DEADLINE_MS (30s) on daemon queries; Mount exempt

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 6: Protocol docs, schema test, changelog

**Files:** Modify `docs/protocol-v0.md`, `crates/rts-daemon/tests/protocol_schemas.rs`; Create `changelog.d/xxx-feat-request-deadlines.md`

- [ ] **Step 1: Update `docs/protocol-v0.md`**

- §3.4 (request envelope): document the optional `deadline_ms` field beside `cancel_id` — integer milliseconds, range `1..=600000`, absent = no deadline, out-of-range → `INVALID_PARAMS`.
- §7 capabilities: add `request_deadlines` with a one-line description mirroring the code comment from Task 3 Step 1.
- §10 (Cancellation): add a short "Deadlines" subsection — a deadline is a timer-fired internal cancel; on expiry the handler's cooperative poll trips and the daemon returns `DEADLINE_EXCEEDED`; rts-mcp stamps `RTS_DEADLINE_MS` (default 30s) on queries, Mount exempt.
- §14 (error table): add a `DEADLINE_EXCEEDED` row — "per-request deadline (`deadline_ms`) elapsed; v0.7+, capability `request_deadlines`; custom numeric `-32096` (next free after `-32099` CANCELLED and rts-mcp's `-32098`/`-32097`). Not a programming error — client narrows the query or raises the budget." Retryable column: "Yes (with a larger `deadline_ms` or narrower query)".

- [ ] **Step 2: Update the protocol schema-drift test**

In `crates/rts-daemon/tests/protocol_schemas.rs`, the test asserts the daemon's advertised capability set and/or error catalog match the documented list. Add `"request_deadlines"` to the expected capability set there (search the file for `"cancellable_queries"` and add the new entry alongside). If the file enumerates wire error codes, ensure `DEADLINE_EXCEEDED` is included (it already exists in `ErrorCode`).

- [ ] **Step 3: Run the schema test**

Run: `cargo test -p rts-daemon --test protocol_schemas`
Expected: PASS.

- [ ] **Step 4: Add the changelog fragment**

Create `changelog.d/xxx-feat-request-deadlines.md`:
```markdown
### Feature: per-request deadlines (`deadline_ms`) — bounded query latency

Any daemon request may now carry an optional top-level `deadline_ms`
(1..=600000). When the budget elapses the daemon trips the request's
cooperative `CancelToken` and returns the new `DEADLINE_EXCEEDED` error
(distinct from `CANCELLED`, so a timeout is tellable from an explicit
`Daemon.Cancel`). rts-mcp stamps a default from `RTS_DEADLINE_MS`
(default `30000`; `0` disables) on agent queries so latency is bounded
out-of-the-box; `Workspace.Mount` is exempt from the default (cold-walk
on a large repo can legitimately take minutes) but honors an explicit
`deadline_ms`. New capability `request_deadlines`; `Daemon.Stats` gains
`deadlines.total`. Additive — clients that omit `deadline_ms` are
unaffected.
```
(Rename `xxx-` to the PR number after the PR is opened.)

- [ ] **Step 5: Full workspace gate**

Run:
```bash
cargo fmt --all --check
cargo test --workspace 2>&1 | tail -20
cargo clippy --workspace --all-targets 2>&1 | tail -5
```
Expected: fmt clean; all tests pass; no new clippy errors.

- [ ] **Step 6: Commit**

```bash
git add docs/protocol-v0.md crates/rts-daemon/tests/protocol_schemas.rs changelog.d/xxx-feat-request-deadlines.md
git commit -m "docs(protocol): document request_deadlines + DEADLINE_EXCEEDED; changelog fragment

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Self-review notes (coverage vs spec)

- Spec §1 wire `deadline_ms` + validation + capability → Task 1 (field/plumbing), Task 2 (range validation in dispatch), Task 3 (capability), Task 6 (docs/schema).
- Spec §2 MCP default + Mount exemption → Task 5 (`RTS_DEADLINE_MS` 30s default, `stamped_deadline` Mount exemption, `0` disables).
- Spec §3 dispatch timer + `deadline_fired` + CANCELLED→DEADLINE_EXCEEDED + works-without-cancel_id → Task 2.
- Spec §4 `DEADLINE_EXCEEDED` (already in `ErrorCode`) + `-32096` doc numeric + `deadlines.total` → Task 2 (emit + counter), Task 3 (stats), Task 6 (§14 numeric).
- Spec §5 handler poll coverage → Task 4 (read_symbol closure fix + audit of outline/find_callers/impact_of/find_symbol).
- Spec §6 testing → Tasks 2–5 tests + Task 6 schema-drift; mount-exemption + env-default covered by Task 5 unit tests.
- Type/name consistency: `deadline_ms` (envelope + signatures), `deadline_fired`, `deadlines_total`, `request_deadlines`, `stamped_deadline`, `default_deadline_from_env`, `AbortOnDrop`, `MAX_DEADLINE_MS`, `ErrorCode::DeadlineExceeded` — used identically across tasks.
