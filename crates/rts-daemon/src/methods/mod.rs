//! Method dispatcher and namespace stubs for the daemon-side of
//! `docs/protocol-v0.md` §7.

use std::sync::Arc;

use crate::error::{ErrorCode, ProtocolError};
use crate::state::DaemonState;

mod daemon;
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
pub async fn dispatch(
    method: &str,
    params: serde_json::Value,
    state: &Arc<DaemonState>,
) -> Result<serde_json::Value, ProtocolError> {
    match method {
        "Daemon.Ping" => daemon::ping(params, state).await,
        "Workspace.Mount" => workspace::mount(params, state).await,
        "Workspace.Status" => workspace::status(params, state).await,
        "Workspace.Unmount" => workspace::unmount(params, state).await,
        "Session.Open" => session::open(params, state).await,
        "Session.Close" => session::close(params, state).await,

        "Index.FindSymbol" => index::find_symbol(params, state).await,
        "Index.FindCallers" => index::find_callers(params, state).await,
        "Index.ImpactOf" => index::impact_of(params, state).await,
        "Index.ReadRange" => index::read_range(params, state).await,
        "Index.ReadSymbol" => index::read_symbol(params, state).await,
        "Index.ReadSymbolAt" => index::read_symbol_at(params, state).await,
        "Index.Outline" => index::outline(params, state).await,

        other => Err(ProtocolError::new(
            ErrorCode::InvalidParams,
            format!("unknown method: {other}"),
        )),
    }
}
