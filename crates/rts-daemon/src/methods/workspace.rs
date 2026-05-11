//! `Workspace.*` methods: Mount, Status, Unmount.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use serde::Deserialize;

use crate::error::{ErrorCode, ProtocolError};
use crate::state::DaemonState;
use crate::workspace::{self, MountedWorkspace};

#[derive(Debug, Deserialize)]
struct MountParams {
    root: String,
    #[serde(default)]
    enable_telemetry: bool,
}

fn parse_params<T: for<'de> Deserialize<'de>>(value: serde_json::Value) -> Result<T, ProtocolError> {
    serde_json::from_value(value).map_err(|e| {
        ProtocolError::new(
            ErrorCode::InvalidParams,
            format!("params failed validation: {e}"),
        )
    })
}

/// `Workspace.Mount` — protocol-v0 §7.2.
pub async fn mount(
    params: serde_json::Value,
    state: &Arc<DaemonState>,
) -> Result<serde_json::Value, ProtocolError> {
    let p: MountParams = parse_params(params)?;
    let _ = p.enable_telemetry; // accepted but inert in this build
    let user_path = PathBuf::from(p.root);

    let mut current = state
        .workspace
        .lock()
        .map_err(|e| ProtocolError::new(ErrorCode::InternalError, format!("state poisoned: {e}")))?;

    // Idempotent within a connection: a second Mount for the same canonical
    // path returns current status.
    if let Some(existing) = current.as_ref() {
        match workspace::canonicalize(&user_path) {
            Ok(canonical) if canonical.path == existing.canonical.path => {
                workspace::verify_unchanged(existing)?;
                return Ok(status_payload(existing, state));
            }
            Ok(_other) => {
                return Err(ProtocolError::new(
                    ErrorCode::WorkspaceVanished,
                    "daemon is pinned to a different workspace; mount a fresh daemon for another path",
                ));
            }
            Err(e) => return Err(e),
        }
    }

    let mounted = workspace::mount(&user_path)?;
    let payload = status_payload(&mounted, state);
    *current = Some(mounted);
    state.mount_refcount.fetch_add(1, Ordering::Relaxed);
    state.touch();
    Ok(payload)
}

/// `Workspace.Status` — protocol-v0 §7.4.
pub async fn status(
    _params: serde_json::Value,
    state: &Arc<DaemonState>,
) -> Result<serde_json::Value, ProtocolError> {
    let current = state
        .workspace
        .lock()
        .map_err(|e| ProtocolError::new(ErrorCode::InternalError, format!("state poisoned: {e}")))?;
    if let Some(mounted) = current.as_ref() {
        Ok(status_payload(mounted, state))
    } else {
        Ok(serde_json::json!({
            "state":            "no_workspace",
            "progress":         { "files_done": 0, "files_total": 0, "phase": "no_mount" },
            "index_generation": state.index_generation.load(Ordering::Relaxed),
            "parse_failed_files": 0,
            "watcher_status":   "ok",
            "uptime_ms":        state.uptime().as_millis() as u64,
            "memory_rss_bytes": 0
        }))
    }
}

/// `Workspace.Unmount` — protocol-v0 §7.3.
pub async fn unmount(
    _params: serde_json::Value,
    state: &Arc<DaemonState>,
) -> Result<serde_json::Value, ProtocolError> {
    // The refcount decrements regardless of whether this connection is the
    // one that originally mounted (per-connection mount tracking is a v1.1
    // refinement; v0 keeps it simple).
    let prev = state.mount_refcount.fetch_sub(1, Ordering::Relaxed);
    if prev == 0 {
        // Underflow guard: never let refcount wrap below 0.
        state.mount_refcount.store(0, Ordering::Relaxed);
    }
    state.touch();
    Ok(serde_json::json!({ "drained": true }))
}

/// Compose the v0 `Workspace.Status` shape (also used as `Mount` response).
fn status_payload(mounted: &MountedWorkspace, state: &Arc<DaemonState>) -> serde_json::Value {
    // Languages the daemon's index would cover. Mirrors `rust_tree_sitter::Language::all()`
    // but listed inline so this can ship without indexing wired up yet.
    let languages = [
        "rust", "javascript", "typescript", "python", "c", "cpp",
        "go", "java", "php", "ruby", "swift",
    ];
    serde_json::json!({
        "workspace_id":     mounted.fingerprint.id_str(),
        "state":            "ready",
        "progress":         { "files_done": 0, "files_total": 0, "phase": "ready" },
        "index_generation": state.index_generation.load(Ordering::Relaxed),
        "languages":        languages,
        // The fields below show up in Status but not Mount in the spec; emit
        // them both places so a client can use either response interchangeably.
        "parse_failed_files": 0,
        "watcher_status":     "ok",
        "uptime_ms":          state.uptime().as_millis() as u64,
        "memory_rss_bytes":   0
    })
}
