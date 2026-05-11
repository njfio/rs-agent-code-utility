//! `Workspace.*` methods: Mount, Status, Unmount.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use serde::Deserialize;

use crate::error::{ErrorCode, ProtocolError};
use crate::state::DaemonState;
use crate::store::Store;
use crate::watcher::Watcher;
use crate::workspace::{self, MountedWorkspace, state_dir_for};
use crate::writer;

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
                let store_snapshot = state
                    .store
                    .lock()
                    .ok()
                    .and_then(|g| g.clone());
                return Ok(status_payload(existing, state, store_snapshot.as_deref()));
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

    // Open redb at `${XDG_STATE_HOME}/rts/<workspace_id>/db.redb`. Per
    // protocol-v0 §5.4 the state dir lives outside the workspace.
    let state_dir = state_dir_for(&mounted.fingerprint);
    if let Err(e) = std::fs::create_dir_all(&state_dir) {
        return Err(ProtocolError::new(
            ErrorCode::StorageFull,
            format!("create state dir {}: {e}", state_dir.display()),
        ));
    }
    let db_path = state_dir.join("db.redb");
    let store = std::sync::Arc::new(Store::open(&db_path).map_err(|e| {
        // SchemaVersionNewer surfaces with that specific marker; any other
        // open failure maps to StorageFull (most often is disk / perms).
        let msg = format!("{e:#}");
        let code = if msg.contains("newer than this daemon binary") {
            ErrorCode::SchemaVersionNewer
        } else {
            ErrorCode::StorageFull
        };
        ProtocolError::new(code, msg)
    })?);

    // Start the file watcher. Events go to an internal mpsc; the writer-drain
    // task (spawned below) consumes them and writes into redb.
    let (watcher, rx) = Watcher::start(&mounted.canonical.path, state.clone()).map_err(|e| {
        ProtocolError::new(
            ErrorCode::InternalError,
            format!("could not start file watcher: {e}"),
        )
    })?;

    // Spawn the writer-drain task.
    let writer_cancel = tokio_util::sync::CancellationToken::new();
    let _writer_handle = writer::spawn(
        rx,
        store.clone(),
        state.clone(),
        writer_cancel.clone(),
        mounted.canonical.path.clone(),
    );

    let payload = status_payload(&mounted, state, Some(&store));
    *current = Some(mounted);
    {
        let mut watcher_slot = state
            .watcher
            .lock()
            .map_err(|e| ProtocolError::new(ErrorCode::InternalError, format!("watcher state poisoned: {e}")))?;
        *watcher_slot = Some(watcher);
    }
    {
        let mut store_slot = state
            .store
            .lock()
            .map_err(|e| ProtocolError::new(ErrorCode::InternalError, format!("store state poisoned: {e}")))?;
        *store_slot = Some(store);
    }
    {
        let mut cancel_slot = state
            .writer_cancel
            .lock()
            .map_err(|e| ProtocolError::new(ErrorCode::InternalError, format!("writer_cancel state poisoned: {e}")))?;
        *cancel_slot = Some(writer_cancel);
    }
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
        let store_snapshot = state
            .store
            .lock()
            .ok()
            .and_then(|g| g.clone());
        Ok(status_payload(mounted, state, store_snapshot.as_deref()))
    } else {
        Ok(serde_json::json!({
            "state":            "no_workspace",
            "progress":         { "files_done": 0, "files_total": 0, "phase": "no_mount" },
            "index_generation": state.index_generation.load(Ordering::Relaxed),
            "parse_failed_files": 0,
            "watcher_status":   state.watcher_status().as_wire_str(),
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

    // When refcount falls to 0, tear down the watcher + writer task. (We
    // don't tear down the workspace mount or the store itself — the daemon
    // is workspace-pinned and a future remount on the same path should be
    // fast; the store reopens on next Mount, so dropping it is fine too.)
    if state.mount_refcount.load(Ordering::Relaxed) == 0 {
        // Signal the writer first so it drains its final batch before the
        // watcher disappears and the channel closes.
        if let Ok(mut slot) = state.writer_cancel.lock() {
            if let Some(cancel) = slot.take() {
                cancel.cancel();
            }
        }
        if let Ok(mut slot) = state.watcher.lock() {
            if slot.take().is_some() {
                state.set_watcher_status(crate::state::WatcherStatus::NoWatcher);
                tracing::info!("watcher torn down after last unmount");
            }
        }
        if let Ok(mut slot) = state.store.lock() {
            let _ = slot.take();
        }
    }

    state.touch();
    Ok(serde_json::json!({ "drained": true }))
}

/// Compose the v0 `Workspace.Status` shape (also used as `Mount` response).
fn status_payload(
    mounted: &MountedWorkspace,
    state: &Arc<DaemonState>,
    store: Option<&Store>,
) -> serde_json::Value {
    // Languages the daemon's index would cover. Mirrors `rust_tree_sitter::Language::all()`
    // but listed inline so this can ship without indexing wired up yet.
    let languages = [
        "rust", "javascript", "typescript", "python", "c", "cpp",
        "go", "java", "php", "ruby", "swift",
    ];
    let store_stats = store.map(|s| s.stats()).unwrap_or_default();
    serde_json::json!({
        "workspace_id":     mounted.fingerprint.id_str(),
        "state":            "ready",
        "progress":         {
            "files_done":  store_stats.files_indexed,
            "files_total": store_stats.files_indexed,
            "phase":       "ready"
        },
        "index_generation": state.index_generation.load(Ordering::Relaxed),
        "languages":        languages,
        // The fields below show up in Status but not Mount in the spec; emit
        // them both places so a client can use either response interchangeably.
        "parse_failed_files": store_stats.parse_failed_files,
        "watcher_status":     state.watcher_status().as_wire_str(),
        "uptime_ms":          state.uptime().as_millis() as u64,
        "memory_rss_bytes":   0
    })
}
