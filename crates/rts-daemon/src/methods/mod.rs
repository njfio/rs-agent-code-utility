//! Method dispatcher and namespace stubs for the daemon-side of
//! `docs/protocol-v0.md` §7.

use std::sync::Arc;

use crate::error::{ErrorCode, ProtocolError};
use crate::state::DaemonState;

mod daemon;
// `pub(crate)` so the closure walker (`crate::closure`) can call
// `index::render_signature_for_path` for per-dep signature rendering.
pub(crate) mod index;
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

        "Index.FindSymbol" => index::find_symbol(params, state).await,
        "Index.ReadRange" => index::read_range(params, state).await,
        "Index.ReadSymbol" => index::read_symbol(params, state).await,
        "Index.Outline" => index::outline(params, state).await,

        other => Err(ProtocolError::new(
            ErrorCode::InvalidParams,
            format!("unknown method: {other}"),
        )),
    }
}
