//! Method dispatcher and namespace stubs for the daemon-side of
//! `docs/protocol-v0.md` §7.

use std::sync::Arc;

use crate::cancel::{CancelGuard, CancelToken};
use crate::error::{ErrorCode, ProtocolError};
use crate::state::DaemonState;

mod daemon;
pub(crate) mod grep_v2;
mod index;
mod session;
mod workspace;

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

/// v0.4 prewarm: mount eagerly during daemon startup so the initial
/// walk overlaps with the MCP handshake. Called from `main.rs` when
/// the daemon is spawned with `--workspace <path>`.
///
/// Internally calls the same `Workspace.Mount` handler the RPC uses,
/// so the resulting state is identical to a normal Mount. The first
/// real `Workspace.Mount` RPC for the same path enters Mount's
/// idempotent branch (path equality → return current status) without
/// re-doing the walk.
///
/// Errors are returned for the caller to log; they're non-fatal for
/// the daemon (the socket should still bind so the explicit Mount
/// RPC can surface the error to the client).
pub async fn prewarm_mount(
    workspace_path: &std::path::Path,
    state: &Arc<DaemonState>,
) -> Result<(), ProtocolError> {
    // Call mount_inner (bypass the prewarm-wait at the top of
    // mount()) — otherwise the background prewarm task would wait
    // for its own completion, deadlocking.
    workspace::mount_inner(workspace_path.to_path_buf(), state, CancelToken::new())
        .await
        .map(|_| ())
}

/// Route a wire-level `method` string to the appropriate handler.
///
/// Bumps `state.call_counters` per method **before** the handler
/// fires, so even errored calls count — they still represent agent
/// intent and the `Daemon.Stats` surface should show them. The bump
/// is one relaxed atomic increment per RPC; negligible overhead next
/// to the rest of dispatch.
///
/// `cancel_id` is the optional client-supplied identifier from the
/// JSON-RPC envelope (`docs/protocol-v0.md` §3.4). When set, a fresh
/// [`CancelToken`] is registered under that id for the duration of
/// the call and handed to the matching long-running handlers
/// (`Index.Grep`, `Index.FindSymbol`, `Index.FindCallers`,
/// `Index.ImpactOf`, `Index.ReadSymbol`, `Index.Outline`,
/// `Workspace.Mount`). The token
/// is removed automatically via the RAII guard once the handler
/// returns (or panics).
pub async fn dispatch(
    method: &str,
    params: serde_json::Value,
    state: &Arc<DaemonState>,
    cancel_id: Option<String>,
    deadline_ms: Option<u64>,
) -> Result<serde_json::Value, ProtocolError> {
    use std::sync::atomic::Ordering::Relaxed;
    let counters = &state.call_counters;

    // Register a cancellation token for cancellable handlers when the
    // client supplied a `cancel_id`. We do this *outside* the method
    // match so the guard lives across the await — handlers that don't
    // honor cancellation simply ignore the token clone.
    let token = CancelToken::new();
    let _cancel_guard = match (cancel_id, is_cancellable_method(method)) {
        (Some(id), true) => {
            Some(CancelGuard::register(state.cancel_registry.clone(), id, token.clone()).await)
        }
        _ => None,
    };

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

    // v0.6+ telemetry collector: time every dispatch so the
    // `method_latency_p50_ms` / `method_latency_p99_ms` collectors
    // have data. We record into the per-method histogram on both
    // success and error paths — an erroring handler still represents
    // dispatch work the daemon paid for.
    let started = std::time::Instant::now();
    let result = match method {
        "Daemon.Ping" => {
            counters.daemon_ping.fetch_add(1, Relaxed);
            daemon::ping(params, state).await
        }
        "Daemon.Stats" => {
            counters.daemon_stats.fetch_add(1, Relaxed);
            daemon::stats(params, state).await
        }
        "Daemon.Telemetry" => {
            // No call counter, by design: `Daemon.Telemetry` is the
            // collector-snapshot RPC; counting its own calls would
            // introduce a feedback loop where every `rts telemetry
            // preview` skews the very statistics it's previewing.
            daemon::telemetry(params, state).await
        }
        "Daemon.Cancel" => {
            counters.daemon_cancel.fetch_add(1, Relaxed);
            daemon::cancel(params, state).await
        }
        "Workspace.Mount" => {
            counters.workspace_mount.fetch_add(1, Relaxed);
            workspace::mount(params, state, token).await
        }
        "Workspace.Status" => {
            counters.workspace_status.fetch_add(1, Relaxed);
            workspace::status(params, state).await
        }
        "Workspace.Unmount" => {
            counters.workspace_unmount.fetch_add(1, Relaxed);
            workspace::unmount(params, state).await
        }
        "Session.Open" => {
            counters.session_open.fetch_add(1, Relaxed);
            session::open(params, state).await
        }
        "Session.Close" => {
            counters.session_close.fetch_add(1, Relaxed);
            session::close(params, state).await
        }

        "Index.FindSymbol" => {
            counters.index_find_symbol.fetch_add(1, Relaxed);
            index::find_symbol(params, state, token).await
        }
        "Index.FindCallers" => {
            counters.index_find_callers.fetch_add(1, Relaxed);
            index::find_callers(params, state, token).await
        }
        "Index.VerifySymbol" => {
            counters.index_verify_symbol.fetch_add(1, Relaxed);
            index::verify_symbol(params, state, token).await
        }
        "Index.VerifySignature" => {
            counters.index_verify_signature.fetch_add(1, Relaxed);
            index::verify_signature(params, state, token).await
        }
        "Index.VerifyImport" => {
            counters.index_verify_import.fetch_add(1, Relaxed);
            index::verify_import(params, state, token).await
        }
        "Index.VerifyClaims" => {
            counters.index_verify_claims.fetch_add(1, Relaxed);
            index::verify_claims(params, state, token).await
        }
        "Index.ImpactOf" => {
            counters.index_impact_of.fetch_add(1, Relaxed);
            index::impact_of(params, state, token).await
        }
        "Index.VerifyImpact" => {
            counters.index_verify_impact.fetch_add(1, Relaxed);
            index::verify_impact(params, state, token).await
        }
        "Index.ReadRange" => {
            counters.index_read_range.fetch_add(1, Relaxed);
            index::read_range(params, state).await
        }
        "Index.ReadSymbol" => {
            counters.index_read_symbol.fetch_add(1, Relaxed);
            index::read_symbol(params, state, token).await
        }
        "Index.ReadSymbolAt" => {
            counters.index_read_symbol_at.fetch_add(1, Relaxed);
            index::read_symbol_at(params, state).await
        }
        "Index.Outline" => {
            counters.index_outline.fetch_add(1, Relaxed);
            index::outline(params, state, token).await
        }
        "Index.Grep" => {
            counters.index_grep.fetch_add(1, Relaxed);
            index::grep(params, state, token).await
        }

        other => {
            counters.unknown_method.fetch_add(1, Relaxed);
            Err(ProtocolError::new(
                ErrorCode::InvalidParams,
                format!("unknown method: {other}"),
            ))
        }
    };

    // A deadline that fired surfaces as the handler's CANCELLED; rewrite
    // it so clients can tell a timeout from an explicit Daemon.Cancel.
    let result = match result {
        Err(e) if e.code == ErrorCode::Cancelled && deadline_fired.load(Relaxed) => {
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

    let elapsed_micros = started.elapsed().as_micros().min(u128::from(u64::MAX)) as u64;
    state.method_latency.record(method, elapsed_micros);

    // v0.6+ telemetry collector: error-count bookkeeping. We record
    // the **closed-enum wire string** (`ErrorCode::as_wire_str`),
    // never the human-readable message; the dispatcher cannot leak
    // user-controlled strings into the `error_counts` map. The
    // `unknown_method` arm above produces `INVALID_PARAMS` for
    // unknown method names (so the attacker-controlled `other`
    // string never reaches the error map).
    if let Err(e) = &result {
        state.record_error(e.code.as_wire_str());
    }

    result
}

/// Which methods honor cooperative cancellation. The dispatcher only
/// pays the registry overhead for these; everything else ignores
/// `cancel_id` (and the agent's cancel would no-op against them
/// anyway — they all return in single-digit milliseconds).
fn is_cancellable_method(method: &str) -> bool {
    matches!(
        method,
        "Index.Grep"
            | "Index.FindSymbol"
            | "Index.FindCallers"
            | "Index.VerifySymbol"
            | "Index.VerifySignature"
            | "Index.VerifyImport"
            | "Index.VerifyClaims"
            | "Index.ImpactOf"
            | "Index.VerifyImpact"
            | "Index.ReadSymbol"
            | "Index.Outline"
            | "Workspace.Mount"
    )
}
