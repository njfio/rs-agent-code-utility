//! `Workspace.*` methods: Mount, Status, Unmount.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use serde::Deserialize;

use crate::cancel::CancelToken;
use crate::error::{ErrorCode, ProtocolError};
use crate::state::{DaemonState, MountTable, MountedRoot};
use crate::store::Store;
use crate::watcher::{WatchEvent, Watcher};
use crate::workspace::{self, state_dir_for};
use crate::writer;

#[derive(Debug, Deserialize)]
struct MountParams {
    root: String,
    #[serde(default)]
    enable_telemetry: bool,
}

/// `Workspace.Status` params. `root` (a `workspace_id` or a workspace path)
/// selects which mounted root to report; absent → the daemon's default root.
#[derive(Debug, Default, Deserialize)]
struct StatusParams {
    #[serde(default)]
    root: Option<String>,
}

/// `Workspace.Unmount` params. `root` (a `workspace_id` or a workspace path)
/// selects which mounted root to release; absent → the default root.
#[derive(Debug, Default, Deserialize)]
struct UnmountParams {
    #[serde(default)]
    root: Option<String>,
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
    cancel: CancelToken,
) -> Result<serde_json::Value, ProtocolError> {
    if cancel.is_cancelled() {
        return Err(ProtocolError::new(
            crate::error::ErrorCode::Cancelled,
            "cancelled",
        ));
    }
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

    mount_inner(user_path, state, cancel).await
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
    cancel: CancelToken,
) -> Result<serde_json::Value, ProtocolError> {
    // Serialize the whole mount critical section. The idempotency check
    // below drops the `workspace` lock before `Store::open`'s `.await`
    // (the `MutexGuard` is `!Send`), so without this guard the startup
    // prewarm task and an explicit `Workspace.Mount` RPC can both pass the
    // check and both call `Store::open` on the same redb file — redb
    // refuses the second open with "Database already open" and the daemon
    // wedges (issue #150). Holding this across check → open → set makes
    // mounts mutually exclusive: the first opens the store; any concurrent
    // mount waits here, then falls into the idempotent path below.
    //
    // Cancel-aware acquisition: `Workspace.Mount` is a documented
    // cancellable handler and a mount can queue behind a long cold mount
    // or prewarm. `CancelToken` is a bare `AtomicBool` with no async wait
    // primitive, so poll for the guard and honor `Daemon.Cancel` between
    // ticks instead of hanging for the full mount (#150 review).
    let _mount_guard = loop {
        if cancel.is_cancelled() {
            return Err(ProtocolError::new(ErrorCode::Cancelled, "cancelled"));
        }
        match state.mount_serialize.try_lock() {
            Ok(g) => break g,
            Err(_) => tokio::time::sleep(std::time::Duration::from_millis(25)).await,
        }
    };

    // Idempotent per canonical path: a second Mount for an already-mounted
    // root *joins* it (holding a second ref) and returns its status. Held in
    // its own scope so the lock is released before we await the initial walk
    // further down (the `MutexGuard` is `!Send` and would otherwise prevent
    // this future from running on the multi-threaded runtime).
    //
    // Multi-root: a mount for a *different* path is no longer
    // `WORKSPACE_MISMATCH` — it mounts as an additional root of the same
    // daemon. The first root mounted becomes the daemon's default root (the
    // one a call that names no root is served by).
    {
        let canonical = workspace::canonicalize(&user_path)?;
        let mut table = state.mounts.lock().map_err(|e| {
            ProtocolError::new(ErrorCode::InternalError, format!("state poisoned: {e}"))
        })?;
        if let Some(id) = table.id_for_path(&canonical.path) {
            let entry = table.get_mut(&id).expect("id_for_path returned a live id");
            workspace::verify_unchanged(&entry.workspace)?;
            // Count this joiner. A concurrent/idempotent mount of the same
            // workspace is a successful mount and must hold a ref; otherwise
            // the first `Workspace.Unmount` drops the store out from under
            // the other mounted clients (#150 review).
            entry.refcount += 1;
            state.mount_refcount.fetch_add(1, Ordering::Relaxed);
            let entry = table.get(&id).expect("just resolved");
            return Ok(status_payload(entry, &table, state));
        }
        // Not mounted yet; fall through. `table` drops here.
    }

    // Test-only seam (issue #150 regression). Widens the window between
    // the idempotency check and `Store::open` so the concurrency test can
    // deterministically provoke the Mount-vs-Mount / prewarm-vs-Mount
    // race. No-op unless `RTS_TEST_MOUNT_OPEN_DELAY_MS` is set; never read
    // in production. With the `mount_serialize` guard held above, only one
    // mount sits in this window at a time, so the race cannot occur —
    // which is exactly what the test asserts.
    if let Ok(ms) = std::env::var("RTS_TEST_MOUNT_OPEN_DELAY_MS") {
        if let Ok(ms) = ms.parse::<u64>() {
            tokio::time::sleep(std::time::Duration::from_millis(ms)).await;
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

    // v0.6 persisted-cold-mount decision (U5). After opening the
    // store, compare the persisted fingerprint to the current
    // (runtime + filesystem) one. The outcome determines whether
    // we skip the InitialWalkHandle (Rehydrate), wipe + re-walk
    // after an invalidation, or run the existing cold-walk path.
    //
    // The decision is recorded on `state.mount_source` for
    // surfacing via `Daemon.Stats v2`; cumulative cache-
    // effectiveness counters are bumped here too.
    use crate::fingerprint::Fingerprint;
    use crate::state::MountSource;
    state
        .rehydrate_attempts
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

    let current_fp = Fingerprint::current(&mounted.canonical.path);
    let reconciliation_in_progress = store.reconciliation_in_progress().unwrap_or(false);
    let stored_fp = store.read_fingerprint().unwrap_or(None);
    let files_count = store.files_count().unwrap_or(0);

    let mount_source: MountSource = if reconciliation_in_progress {
        // Previous daemon died mid-reconciliation. Treat redb as torn.
        let _ = store.wipe_data_tables();
        let _ = store.set_reconciliation_in_progress(false);
        MountSource::ColdWalkAfterCrash
    } else {
        match stored_fp {
            None if files_count == 0 => MountSource::ColdWalk,
            None => {
                // Files present but no stored fingerprint — older
                // daemon's redb. Wipe + cold-walk so we know the
                // shape is current; the new fingerprint stamps at
                // walk-end.
                let _ = store.wipe_data_tables();
                MountSource::ColdWalkAfterInvalidation(
                    crate::fingerprint::InvalidationReason::EmptyOrMissingFingerprint,
                )
            }
            Some(stored) => match Fingerprint::diff(&stored, &current_fp) {
                None if files_count > 0 => MountSource::Rehydrate,
                None => MountSource::ColdWalk, // stored fp matched but FILES empty (race)
                Some(reason) => {
                    let _ = store.wipe_data_tables();
                    MountSource::ColdWalkAfterInvalidation(reason)
                }
            },
        }
    };

    // Record the decision for `Daemon.Stats` (U6) and bump the
    // appropriate counter.
    // The decision itself is stored on the root's mount-table entry below
    // (`MountedRoot::mount_source`) — with N roots there is one decision per
    // root, not one per daemon. Only the cumulative counters stay on the
    // daemon.
    match &mount_source {
        MountSource::Rehydrate => {
            state
                .rehydrate_successes
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        MountSource::ColdWalkAfterInvalidation(reason) => {
            if let Ok(mut tally) = state.rehydrate_invalidations.lock() {
                *tally.entry(reason.as_label()).or_insert(0) += 1;
            }
        }
        MountSource::ColdWalkAfterCrash => {
            if let Ok(mut tally) = state.rehydrate_invalidations.lock() {
                *tally.entry("crash".to_string()).or_insert(0) += 1;
            }
        }
        MountSource::ColdWalk => {}
    }
    let skip_initial_walk = matches!(mount_source, MountSource::Rehydrate);
    tracing::info!(
        target: "rts_daemon::mount",
        mount_source = %mount_source.as_label(),
        skip_initial_walk,
        files_count,
        "persisted-cold-mount decision"
    );

    // Start the file watcher. This subscribes to the filesystem for
    // incremental events but does NOT yet run the initial walk — that's
    // deferred to `initial.spawn()` below so the writer-drain task can
    // start consuming from the channel first. See watcher.rs comment on
    // `InitialWalkHandle` for the 256-file plateau bug this restructure
    // fixes.
    // A root the daemon cannot watch is a root it cannot serve: refuse the
    // mount with the documented path-rejection code rather than an internal
    // error. Reachable for any path whose subtree the watcher cannot observe
    // (a filesystem root containing root-only directories, a bind mount, an
    // exhausted inotify budget). Since multi-root, *any* new path reaches
    // this point, so this is the code a client sees for e.g.
    // `Workspace.Mount { root: "/" }` as a non-root user.
    let (watcher, rx, initial, watch_sink) = Watcher::start(&mounted.canonical.path, state.clone())
        .map_err(|e| {
            ProtocolError::new(
                ErrorCode::InvalidWorkspacePath,
                format!(
                    "could not start file watcher for {}: {e}",
                    mounted.canonical.path.display()
                ),
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
    // Track whether the cold walk actually completed. The fingerprint
    // stamp at the end of this function MUST gate on this — Codex P1
    // review (PR #111 C4): stamping unconditionally after the 5-second
    // drain timeout would mark a slow-indexing workspace as a "valid
    // rehydratable snapshot," and a subsequent restart could take the
    // Rehydrate path with a permanently partial index.
    let mut initial_walk_ok = false;
    let emitted = if skip_initial_walk {
        // v0.6 Rehydrate path: the redb already contains a valid
        // index for this workspace (fingerprint matched, FILES
        // non-empty, no in-progress sentinel). Skip the cold walk
        // entirely — the watcher (started above) picks up any
        // changes from this point forward. First-query latency
        // collapses from `~6 s` to `<100 ms` on healthy rehydrate.
        //
        // The drop of `initial` here is intentional: the
        // InitialWalkHandle owns the channel sender end the walker
        // would have used; dropping it without spawning ensures
        // the writer never sees a `WatchEvent::ColdWalkComplete`
        // from a phantom walker.
        //
        // Rehydrate is "always trustworthy" — the on-disk state was
        // already stamped at the end of the previous mount's
        // cold walk + drain. We re-stamp at the end of this mount
        // for timestamp freshness (cheap, harmless).
        drop(initial);
        tracing::debug!(target: "rts_daemon::mount", "rehydrate: skipping initial walk");
        initial_walk_ok = true;
        0
    } else {
        // v0.6+ telemetry collector: stamp the cold-walk start time
        // so the `ColdWalkComplete` handler in `writer.rs` can
        // compute the duration and push it onto the rolling window
        // that feeds `cold_walk_ms_p50`. We use `SystemTime` (not
        // `Instant`) because pairs across the writer-task boundary
        // need a portable representation; the writer reads
        // `cold_walk_started_at_ms` via `state` after Mount returns.
        let started_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        state
            .cold_walk_started_at_ms
            .store(started_ms, std::sync::atomic::Ordering::Relaxed);
        match initial.spawn().await {
            Ok(Ok(n)) => {
                initial_walk_ok = true;
                n
            }
            Ok(Err(e)) => {
                tracing::warn!(error = %e, "initial walk returned an error; mount continues");
                0
            }
            Err(e) => {
                tracing::warn!(error = %e, "initial walk task panicked; mount continues");
                0
            }
        }
    };
    // Drain wait. Track whether we exited via "indexed >= emitted"
    // (drain_completed = true) or via the 5s timeout (false). The
    // fingerprint gate below uses this flag.
    //
    // Cooperative cancellation: poll the token between drain ticks
    // (every 25 ms). The plan calls for batch-flush-boundary checks
    // during cold walks — this is the equivalent inside the
    // post-walk drain. We surface `CANCELLED` as an early-return
    // *without* tearing down the store/watcher: the cold walk has
    // already populated whatever it managed to flush, and the
    // workspace is left unmounted (the writer + watcher slots stay
    // empty, mount_refcount stays unchanged). A follow-up Mount
    // will rediscover the partial state via the persisted-fp path
    // and pick up where this one left off.
    let drain_deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let mut drain_completed = emitted == 0; // nothing to drain → trivially done
    while emitted > 0 && std::time::Instant::now() < drain_deadline {
        if cancel.is_cancelled() {
            return Err(ProtocolError::new(
                crate::error::ErrorCode::Cancelled,
                "cancelled",
            ));
        }
        let indexed = store.stats().files_indexed;
        if indexed >= emitted {
            drain_completed = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }

    // v0.6 fingerprint stamp (Codex review PR #111 C4): write the
    // current fingerprint to META ONLY when the on-disk state is
    // trustworthy. "Trustworthy" means:
    //   - Rehydrate path: yes — state was already stamped last mount
    //   - Cold-walk path: yes IFF initial.spawn() succeeded AND the
    //     drain loop saw indexed >= emitted (vs timing out)
    //
    // Skipping the stamp when the drain timed out is what prevents
    // the "permanently partial index" failure mode. The next mount
    // will see a missing fingerprint (or a stale one) and cold-walk
    // again — correct behavior for a workspace that didn't finish
    // indexing within the 5s window.
    let trustworthy_to_stamp = initial_walk_ok && drain_completed;
    if trustworthy_to_stamp {
        if let Err(e) = store.write_fingerprint(&current_fp) {
            tracing::warn!(
                target: "rts_daemon::mount",
                error = %e,
                "failed to write fingerprint to META; next mount will cold-walk"
            );
        }
    } else {
        tracing::info!(
            target: "rts_daemon::mount",
            initial_walk_ok,
            drain_completed,
            emitted,
            indexed = store.stats().files_indexed,
            "skipping fingerprint stamp — initial walk did not complete cleanly; next mount will cold-walk"
        );
    }

    let reconcile_root = mounted.canonical.path.clone();

    // v0.6 reconciliation worker (U5 follow-up): on the persisted
    // cold-mount path (`MountSource::Rehydrate`), the cold walk is
    // skipped — but files may have changed on disk between sessions.
    // Spawn the reconciler so it scans the mount root and emits
    // `WatchEvent::Touched`/`Removed` for any drift. The writer drain
    // consumes those events through the same path as live edits.
    //
    // Fresh / cold-walk / wipe-after-invalidation mounts do NOT need
    // this — their cold walk already covers every file. Reconciliation
    // is additive on top of an already-trusted snapshot.
    if matches!(mount_source, crate::state::MountSource::Rehydrate) {
        // The writer task spawned above starts in `cold_walk_in_progress = true`
        // and suppresses its periodic flush until a `ColdWalkComplete`
        // barrier fires. On the rehydrate branch no walker is spawned
        // (so the barrier never naturally arrives), and the writer
        // would therefore hold reconciler-emitted touches in memory
        // forever — well past the per-event 150 ms timer budget. Push
        // an explicit `ColdWalkComplete` so the writer releases the
        // hold-off and begins draining as events stream in. This is
        // load-bearing for the reconciler's `Touched`/`Removed` events
        // to be observable via `Index.FindSymbol` etc.
        let barrier_sink = watch_sink.clone();
        tokio::spawn(async move {
            if barrier_sink
                .send(WatchEvent::ColdWalkComplete)
                .await
                .is_err()
            {
                tracing::warn!("rehydrate: writer channel closed before ColdWalkComplete barrier");
            }
        });

        let reconciler = crate::reconciler::Reconciler::new(
            store.clone(),
            watch_sink.clone(),
            state.reconcile_stats.clone(),
        );
        tokio::spawn(async move {
            if let Err(e) = reconciler.run(reconcile_root).await {
                tracing::warn!(error = ?e, "reconciliation failed");
            }
        });
    }
    // Keep `watch_sink` alive only for the reconciler spawn; the
    // watcher and writer hold their own references, so dropping the
    // local clone here is a no-op for steady-state operation.
    drop(watch_sink);

    // Publish the root. From here on it is addressable by its
    // `workspace_id` and (if it is the first root) it is the daemon's
    // default root. The watcher moves in with it: dropping the entry on
    // unmount is what stops the debouncer thread.
    let mount_id = {
        let mut table = state.mounts.lock().map_err(|e| {
            ProtocolError::new(ErrorCode::InternalError, format!("state poisoned: {e}"))
        })?;
        table.insert(MountedRoot {
            workspace: mounted,
            store: store.clone(),
            watcher,
            writer_cancel,
            mount_source: mount_source.clone(),
            refcount: 1,
        })
    };
    let payload = {
        let table = state.mounts.lock().map_err(|e| {
            ProtocolError::new(ErrorCode::InternalError, format!("state poisoned: {e}"))
        })?;
        match table.get(&mount_id) {
            Some(entry) => status_payload(entry, &table, state),
            None => {
                return Err(ProtocolError::new(
                    ErrorCode::InternalError,
                    "mounted root vanished immediately after insert",
                ));
            }
        }
    };

    state.mount_refcount.fetch_add(1, Ordering::Relaxed);
    state.touch();
    Ok(payload)
}

/// `Workspace.Status` — protocol-v0 §7.4.
///
/// Reports one root (the `root` param — a `workspace_id` or a path — else the
/// daemon's default root) plus the full `mounted_roots` list, so a client can
/// see every root this daemon serves and poll any one of them.
pub async fn status(
    params: serde_json::Value,
    state: &Arc<DaemonState>,
) -> Result<serde_json::Value, ProtocolError> {
    let p: StatusParams = parse_params(params)?;
    let table = state.mounts.lock().map_err(|e| {
        ProtocolError::new(ErrorCode::InternalError, format!("state poisoned: {e}"))
    })?;
    match table.resolve(p.root.as_deref()) {
        Some(id) => match table.get(&id) {
            Some(entry) => Ok(status_payload(entry, &table, state)),
            None => Err(ProtocolError::new(
                ErrorCode::InternalError,
                "mount table lost a root between resolve and read",
            )),
        },
        None if table.is_empty() => Ok(serde_json::json!({
            "state":            "no_workspace",
            "progress":         { "files_done": 0, "files_total": 0, "phase": "no_mount" },
            "index_generation": state.index_generation.load(Ordering::Relaxed),
            "parse_failed_files": 0,
            "watcher_status":   state.watcher_status().as_wire_str(),
            "uptime_ms":        state.uptime().as_millis() as u64,
            "memory_rss_bytes": 0,
            "mounted_roots":    Vec::<serde_json::Value>::new(),
        })),
        None => {
            let requested = p.root.unwrap_or_default();
            let mounted: Vec<serde_json::Value> = table
                .describe()
                .into_iter()
                .map(|(id, path)| serde_json::json!({ "workspace_id": id, "path": path }))
                .collect();
            Err(ProtocolError::new(
                ErrorCode::WorkspaceMismatch,
                format!("no mounted root matching `{requested}`"),
            )
            .with_data(serde_json::json!({
                "requested": requested,
                "mounted_roots": mounted,
            })))
        }
    }
}

/// `Workspace.Unmount` — protocol-v0 §7.3.
///
/// Releases the caller's ref on **one** root. With several roots mounted the
/// `root` param (a `workspace_id` or a workspace path) says which; absent, the
/// daemon's default root is released. When a root's refcount reaches zero its
/// watcher, writer task, index handle, and mount-table entry are dropped — the
/// daemon keeps serving its other roots, and exits only once nothing is
/// mounted and the idle window elapses.
///
/// An unmount that names no mounted root is a no-op (`unmounted: null`) rather
/// than an error, preserving the pre-multi-root behaviour where a duplicate
/// unmount is harmless; the aggregate refcount is still decremented (with the
/// same underflow guard as before).
pub async fn unmount(
    params: serde_json::Value,
    state: &Arc<DaemonState>,
) -> Result<serde_json::Value, ProtocolError> {
    let p: UnmountParams = parse_params(params)?;

    // Resolve → decrement → tear down at zero, all under one lock so a
    // concurrent mount of the same root cannot slip between the check and the
    // teardown.
    let (unmounted_id, unmounted_path, torn_down) = {
        let mut table = state.mounts.lock().map_err(|e| {
            ProtocolError::new(ErrorCode::InternalError, format!("state poisoned: {e}"))
        })?;
        match table.resolve(p.root.as_deref()) {
            Some(id) => {
                let release = match table.get_mut(&id) {
                    Some(entry) => {
                        entry.refcount = entry.refcount.saturating_sub(1);
                        entry.refcount == 0
                    }
                    None => false,
                };
                if release {
                    let entry = table.remove(&id).expect("resolved id was mounted");
                    let path = entry.root().to_string_lossy().into_owned();
                    // Signal the writer first so it drains its final batch
                    // before the watcher disappears and the channel closes.
                    entry.writer_cancel.cancel();
                    (Some(id), Some(path), Some(entry))
                } else {
                    let path = table
                        .get(&id)
                        .map(|entry| entry.root().to_string_lossy().into_owned());
                    (Some(id), path, None)
                }
            }
            None => (None, None, None),
        }
    };
    // Drop the entry outside the lock: this is what stops the debouncer
    // thread and releases the root's index handle.
    drop(torn_down);

    // The refcount decrements regardless of whether this connection is the
    // one that originally mounted (per-connection mount tracking is a v1.1
    // refinement; v0 keeps it simple).
    let prev = state.mount_refcount.fetch_sub(1, Ordering::Relaxed);
    if prev == 0 {
        // Underflow guard: never let refcount wrap below 0.
        state.mount_refcount.store(0, Ordering::Relaxed);
    }

    // The watcher status is process-wide: it only means "no watcher running"
    // once the last root is gone.
    let remaining = {
        let table = state.mounts.lock().map_err(|e| {
            ProtocolError::new(ErrorCode::InternalError, format!("state poisoned: {e}"))
        })?;
        (table.len(), table.describe())
    };
    if remaining.0 == 0 {
        state.set_watcher_status(crate::state::WatcherStatus::NoWatcher);
        tracing::info!("watcher torn down after last unmount");
    } else if unmounted_id.is_some() {
        tracing::info!(workspace_id = ?unmounted_id, "root released; other roots still mounted");
    }

    state.touch();
    Ok(serde_json::json!({
        "drained": true,
        "unmounted": unmounted_id,
        "workspace_root": unmounted_path,
        "mounted_roots": remaining.1
            .into_iter()
            .map(|(id, path)| serde_json::json!({ "workspace_id": id, "path": path }))
            .collect::<Vec<_>>(),
    }))
}

/// Compose the v0 `Workspace.Status` shape (also used as `Mount` response).
///
/// `mounted_roots` lists every root this daemon currently serves, in mount
/// order; `workspace_id` / `progress` / `languages` describe `root` (the one
/// the caller asked about, or the default root).
fn status_payload(
    root: &MountedRoot,
    table: &MountTable,
    state: &Arc<DaemonState>,
) -> serde_json::Value {
    let mounted = &root.workspace;
    let store = root.store.as_ref();
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
    let store_stats = store.stats();
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
        "memory_rss_bytes":   0,
        // Multi-root: every root this daemon serves, in mount order. The
        // first entry is the default root. `workspace_id` above names the
        // root this payload describes.
        "mounted_roots": table
            .describe()
            .into_iter()
            .map(|(id, path)| serde_json::json!({ "workspace_id": id, "path": path }))
            .collect::<Vec<_>>(),
    })
}
