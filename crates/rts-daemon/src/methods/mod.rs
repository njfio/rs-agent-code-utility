//! Method dispatcher and namespace stubs for the daemon-side of
//! `docs/protocol-v0.md` §7.

use std::sync::Arc;

use crate::error::{ErrorCode, ProtocolError};
use crate::state::DaemonState;

mod daemon;
mod session;
mod workspace;

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

        // Index.* methods exist in the protocol but the daemon doesn't index
        // anything yet (P6 baseline: lifecycle + mount only). Return a clear
        // not-ready error so clients learn capability gaps via Daemon.Ping.
        "Index.Outline"
        | "Index.FindSymbol"
        | "Index.ReadSymbol"
        | "Index.ReadRange" => Err(ProtocolError::new(
            ErrorCode::IndexNotReady,
            format!("{method} not yet implemented in this daemon build"),
        )),

        other => Err(ProtocolError::new(
            ErrorCode::InvalidParams,
            format!("unknown method: {other}"),
        )),
    }
}
