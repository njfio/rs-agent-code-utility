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

fn parse_params<T: for<'de> Deserialize<'de>>(
    value: serde_json::Value,
) -> Result<T, ProtocolError> {
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

    // v0.4 prewarm: if `--workspace` was passed at daemon startup,
    // a background task is currently running the initial walk. Wait
    // for it to finish before falling into the normal mount path —
    // otherwise this RPC and the prewarm would race for the redb
    // file, the notify watcher, and the writer task. After the wait,
    // either the prewarm succeeded (idempotent path below returns)
    // or it failed (we proceed with a fresh mount).
    //
    // 30 s deadline matches the per-request soft deadline (§14).
    if state
        .prewarm_in_flight
        .load(std::sync::atomic::Ordering::Acquire)
    {
        let notified = state.prewarm_done.notified();
        // Re-check after armed (Notify is edge-triggered; check
        // again in case prewarm completed between the check and the
        // notified() call to avoid lost-wakeup).
        if state
            .prewarm_in_flight
            .load(std::sync::atomic::Ordering::Acquire)
        {
            let _ = tokio::time::timeout(std::time::Duration::from_secs(30), notified).await;
        }
    }

    mount_inner(user_path, state).await
}

/// Internal entry point that skips the prewarm-wait. Called from:
///   - `mount` (the public RPC handler) — after the prewarm wait.
///   - `prewarm_mount` (the daemon's background-on-startup path) —
///     where waiting on `prewarm_done` would deadlock the task that
///     fires it.
///
/// Both callers do the same mount work; the only thing they
/// differ on is whether they need to coordinate with an
/// already-running prewarm.
pub(super) async fn mount_inner(
    user_path: PathBuf,
    state: &Arc<DaemonState>,
) -> Result<serde_json::Value, ProtocolError> {
    // Idempotent within a connection: a second Mount for the same canonical
    // path returns current status. Held in its own scope so the lock is
    // released before we await the initial walk further down (the
    // `MutexGuard` is `!Send` and would otherwise prevent this future
    // from running on the multi-threaded runtime).
    {
        let current = state.workspace.lock().map_err(|e| {
            ProtocolError::new(ErrorCode::InternalError, format!("state poisoned: {e}"))
        })?;
        if let Some(existing) = current.as_ref() {
            match workspace::canonicalize(&user_path) {
                Ok(canonical) if canonical.path == existing.canonical.path => {
                    workspace::verify_unchanged(existing)?;
                    let store_snapshot = state.store.lock().ok().and_then(|g| g.clone());
                    return Ok(status_payload(existing, state, store_snapshot.as_deref()));
                }
                Ok(_other) => {
                    return Err(ProtocolError::new(
                        ErrorCode::WorkspaceMismatch,
                        "daemon is already pinned to a different workspace on this socket. \
                         Per protocol-v0 §5.3 the socket path is per-workspace-hash; \
                         connect via the correct socket, or start a fresh daemon for the \
                         other workspace (auto-spawn handles this for new paths).",
                    ));
                }
                Err(e) => return Err(e),
            }
        }
        // No existing mount; fall through. `current` drops here.
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

    // Start the file watcher. This subscribes to the filesystem for
    // incremental events but does NOT yet run the initial walk — that's
    // deferred to `initial.spawn()` below so the writer-drain task can
    // start consuming from the channel first. See watcher.rs comment on
    // `InitialWalkHandle` for the 256-file plateau bug this restructure
    // fixes.
    let (watcher, rx, initial) =
        Watcher::start(&mounted.canonical.path, state.clone()).map_err(|e| {
            ProtocolError::new(
                ErrorCode::InternalError,
                format!("could not start file watcher: {e}"),
            )
        })?;

    // Spawn the writer-drain task before running the initial walk so
    // the channel has a consumer from event #1. The walker's
    // `blocking_send` will then propagate backpressure correctly.
    let writer_cancel = tokio_util::sync::CancellationToken::new();
    let _writer_handle = writer::spawn(
        rx,
        store.clone(),
        state.clone(),
        writer_cancel.clone(),
        mounted.canonical.path.clone(),
    );

    // Run the initial walk and AWAIT it before returning `Mount`'s
    // response. The walk is on a `spawn_blocking` task with
    // `blocking_send` (backpressure flows from writer→walker). Pre-fix
    // the walker ran synchronously inside `Watcher::start`, so all
    // observable file events landed before mount returned — multiple
    // callers (including the bench test suite's
    // `query_subcommand_exercises_all_five_tools`) depend on that
    // semantic: a single `find_symbol` immediately after `Mount`
    // returns symbols, not an empty list. Awaiting here preserves
    // that contract while keeping the structural fix (writer drains
    // throughout the walk, so the channel never overflows).
    //
    // The writer's per-batch flush still drains asynchronously, so
    // an `await` here unblocks as soon as the walk emits its final
    // event — not after every file is committed to redb. The
    // remaining time-to-fully-indexed (a few hundred ms on 100k LOC
    // per the G3 number) is what `Workspace.Status.progress` and
    // the bench's cold-probe surface.
    //
    // The double-mount check above already released its lock. Await
    // is now safe — no `!Send` guards are held.
    //
    // Wait for both the walker to finish emitting AND the writer to
    // commit at least one batch. The walker returns when its last
    // file goes into the channel; the writer drains async on its own
    // task with a 150 ms batch-flush timer. Without waiting on the
    // writer, callers that issue `find_symbol` immediately after
    // `Mount` see an empty index (the `query_subcommand_exercises_…`
    // bench test, every fresh-daemon shell flow, etc.).
    //
    // We bound the wait at 5 s — enough for any conceivable initial
    // walk to flush at least once on a real workspace — and fall
    // through on timeout so genuinely broken writers don't hang
    // `Mount` forever. The writer continues to drain in the
    // background regardless; this gate only guarantees the FIRST
    // batch is committed before `Mount` responds. Subsequent batches
    // land async per `BATCH_FLUSH_INTERVAL`, visible via
    // `Workspace.Status.progress`.
    let emitted = match initial.spawn().await {
        Ok(Ok(n)) => n,
        Ok(Err(e)) => {
            tracing::warn!(error = %e, "initial walk returned an error; mount continues");
            0
        }
        Err(e) => {
            tracing::warn!(error = %e, "initial walk task panicked; mount continues");
            0
        }
    };
    let drain_deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while emitted > 0 && std::time::Instant::now() < drain_deadline {
        let indexed = store.stats().files_indexed;
        if indexed >= emitted {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }

    let payload = status_payload(&mounted, state, Some(&store));
    {
        let mut current = state.workspace.lock().map_err(|e| {
            ProtocolError::new(ErrorCode::InternalError, format!("state poisoned: {e}"))
        })?;
        *current = Some(mounted);
    }
    {
        let mut watcher_slot = state.watcher.lock().map_err(|e| {
            ProtocolError::new(
                ErrorCode::InternalError,
                format!("watcher state poisoned: {e}"),
            )
        })?;
        *watcher_slot = Some(watcher);
    }
    {
        let mut store_slot = state.store.lock().map_err(|e| {
            ProtocolError::new(
                ErrorCode::InternalError,
                format!("store state poisoned: {e}"),
            )
        })?;
        *store_slot = Some(store);
    }
    {
        let mut cancel_slot = state.writer_cancel.lock().map_err(|e| {
            ProtocolError::new(
                ErrorCode::InternalError,
                format!("writer_cancel state poisoned: {e}"),
            )
        })?;
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
    let current = state.workspace.lock().map_err(|e| {
        ProtocolError::new(ErrorCode::InternalError, format!("state poisoned: {e}"))
    })?;
    if let Some(mounted) = current.as_ref() {
        let store_snapshot = state.store.lock().ok().and_then(|g| g.clone());
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
        "rust",
        "javascript",
        "typescript",
        "python",
        "c",
        "cpp",
        "go",
        "java",
        "php",
        "ruby",
        "swift",
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
