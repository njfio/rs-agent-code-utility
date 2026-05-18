//! Method dispatcher and namespace stubs for the daemon-side of
//! `docs/protocol-v0.md` §7.

use std::sync::Arc;

use crate::error::{ErrorCode, ProtocolError};
use crate::state::DaemonState;

mod daemon;
pub(crate) mod grep_v2;
mod index;
mod session;
mod workspace;

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
    workspace::mount_inner(workspace_path.to_path_buf(), state)
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
pub async fn dispatch(
    method: &str,
    params: serde_json::Value,
    state: &Arc<DaemonState>,
) -> Result<serde_json::Value, ProtocolError> {
    use std::sync::atomic::Ordering::Relaxed;
    let counters = &state.call_counters;
    match method {
        "Daemon.Ping" => {
            counters.daemon_ping.fetch_add(1, Relaxed);
            daemon::ping(params, state).await
        }
        "Daemon.Stats" => {
            counters.daemon_stats.fetch_add(1, Relaxed);
            daemon::stats(params, state).await
        }
        "Workspace.Mount" => {
            counters.workspace_mount.fetch_add(1, Relaxed);
            workspace::mount(params, state).await
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
            index::find_symbol(params, state).await
        }
        "Index.FindCallers" => {
            counters.index_find_callers.fetch_add(1, Relaxed);
            index::find_callers(params, state).await
        }
        "Index.ImpactOf" => {
            counters.index_impact_of.fetch_add(1, Relaxed);
            index::impact_of(params, state).await
        }
        "Index.ReadRange" => {
            counters.index_read_range.fetch_add(1, Relaxed);
            index::read_range(params, state).await
        }
        "Index.ReadSymbol" => {
            counters.index_read_symbol.fetch_add(1, Relaxed);
            index::read_symbol(params, state).await
        }
        "Index.ReadSymbolAt" => {
            counters.index_read_symbol_at.fetch_add(1, Relaxed);
            index::read_symbol_at(params, state).await
        }
        "Index.Outline" => {
            counters.index_outline.fetch_add(1, Relaxed);
            index::outline(params, state).await
        }
        "Index.Grep" => {
            counters.index_grep.fetch_add(1, Relaxed);
            index::grep(params, state).await
        }

        other => {
            counters.unknown_method.fetch_add(1, Relaxed);
            Err(ProtocolError::new(
                ErrorCode::InvalidParams,
                format!("unknown method: {other}"),
            ))
        }
    }
}
