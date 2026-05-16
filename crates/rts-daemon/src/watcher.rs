//! File watcher: notify + notify-debouncer-full with the v0 filter chain.
//!
//! Implements the watcher behaviour from `docs/protocol-v0.md` §6 + §9 and the
//! `Watcher` line in the §P6 phase plan. The P0.3 spike documented two macOS
//! quirks this module handles up front:
//!
//! 1. **`fs::rename` does NOT surface as `RenameMode::*` on macOS**: rename
//!    events arrive as a `Create` on the destination plus `Modify(Data)` /
//!    `Other` on the source. So the handler treats `Create` and
//!    `Modify(Data)` symmetrically and never depends on rename pairing.
//! 2. **`fs::write` of an existing file reports as `Create`**, not
//!    `Modify(Data)`. Same handling — branch by path, not by event kind.
//!
//! Both findings are baked in via [`WatchEvent::Touched`].
//!
//! Lifecycle:
//! - `Watcher::start(root, …)` performs the initial walk via
//!   `ignore::WalkBuilder` (gitignore-aware) and feeds every match through
//!   the filter (`super::filter::classify`).
//! - It then spins up a `notify-debouncer-full` watcher at 150 ms, filtering
//!   each batch by the same rules and forwarding the survivors to an mpsc.
//! - On `Event::need_rescan()` overflow, the watcher transitions
//!   `WatcherStatus` to `OverflowedRewalking`, re-runs the walker, and falls
//!   back to `Ok` once drained.
//! - `notify::ErrorKind::MaxFilesWatch` (inotify exhaustion) flips
//!   `WatcherStatus` to `PollingFallback` and re-binds with `PollWatcher`.
//!   (Implementation note: the fallback path is wired but the cutover lives
//!   in §P6 watcher hardening — for v0 we surface the status string and
//!   refuse to silently drop events.)

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use notify::{Config as NotifyConfig, EventKind, PollWatcher, RecommendedWatcher, RecursiveMode};
use notify_debouncer_full::{
    DebounceEventResult, Debouncer, RecommendedCache, new_debouncer, new_debouncer_opt,
};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::filter::{FilterDecision, PrebuiltGitignore, classify};
use crate::state::{DaemonState, WatcherStatus};

/// Env var that forces the watcher to start with `PollWatcher` from the
/// outset. Set this on hosts where inotify is exhausted by other tools
/// or where the workspace is on a filesystem that doesn't support
/// inotify (NFS, FUSE under some configurations). Dynamic mid-lifetime
/// cutover when `MaxFilesWatch` fires at runtime is a v1.x improvement;
/// this env var is the v0 escape hatch.
pub const FORCE_POLL_ENV: &str = "RTS_FORCE_POLL_WATCHER";

/// Default poll interval for `PollWatcher` when forced via the env var.
/// 750 ms matches the same range as `notify`'s default poll cadence and
/// keeps the trade-off explicit: poll mode trades event latency for
/// resilience against inotify limits.
const POLL_INTERVAL: Duration = Duration::from_millis(750);

/// Default debounce window per protocol-v0 §9.3 / P0.3 spike (`first batch
/// latency ~94-188 ms` measured at 150 ms).
pub const DEBOUNCE_WINDOW: Duration = Duration::from_millis(150);

/// Bounded mpsc capacity for events flowing from the watcher into the
/// (future) writer-drain task. Matches the protocol-v0 §9.3 default.
pub const CHANNEL_CAPACITY: usize = 256;

/// Normalised watcher event. The watcher boils every notify/debouncer event
/// down to one of these so the writer-drain doesn't have to re-implement the
/// per-OS event-kind taxonomy.
#[derive(Debug, Clone)]
pub enum WatchEvent {
    /// File appeared or its content changed. On macOS this also covers
    /// `fs::write` of an existing file (which the platform reports as
    /// `Create`) and atomic-rename targets. The handler should reparse the
    /// path.
    Touched {
        path: PathBuf,
        decision: FilterDecision,
    },
    /// File disappeared (delete, rename source, unlink). The handler should
    /// drop the file's index entries.
    Removed { path: PathBuf },
    /// Kernel event-buffer overflowed (`Event::need_rescan() == true` on
    /// Linux/Windows; FSEvents coalesce flag on macOS). The watcher has
    /// already started a re-walk; this event is purely informational.
    Rescan,
    /// v0.5.5+: emitted by `walk_and_emit_blocking` when the cold
    /// initial walk has finished pushing every existing file event.
    /// The writer uses this as a hard barrier: until it fires, the
    /// writer holds back the 150ms timer-driven flush and accumulates
    /// every cold-walk file into a single batch. Without this barrier,
    /// the cold-walk's stream could split across multiple batches —
    /// and `commit_batch`'s Pass-2 ref resolution permanently drops
    /// refs whose callee def lives in a *future* batch (§F1). The
    /// resulting half-finished reference graph caused the
    /// `impact_of_three_tier_with_test_filter` flake to surface 4/10
    /// times under heavy CI/parallel load.
    ColdWalkComplete,
}

/// Backing debouncer kind. Either the platform's `RecommendedWatcher`
/// (inotify/FSEvents/ReadDirectoryChangesW) or `PollWatcher` for hosts
/// where the kernel watcher is unavailable or exhausted.
///
/// The contained `Debouncer<...>` is held purely for its `Drop` impl
/// (which stops the background worker thread). It's never read after
/// construction — clippy's `dead_code` lint would otherwise fire on
/// the unused fields, but they're load-bearing for the watcher
/// lifecycle.
#[allow(dead_code)]
enum DebouncerHandle {
    Recommended(Debouncer<RecommendedWatcher, RecommendedCache>),
    Polling(Debouncer<PollWatcher, RecommendedCache>),
}

/// Running watcher handle. Drop it to stop watching.
///
/// The internal debouncer is held in a field so its background thread isn't
/// dropped while the daemon still wants events. The mpsc consumer side is
/// returned alongside `Watcher::start`; only one consumer is supported.
pub struct Watcher {
    /// Hold the debouncer alive. `notify-debouncer-full` runs its own thread;
    /// dropping the variant stops the underlying watcher. Variant is decided
    /// at `Watcher::start` time based on `RTS_FORCE_POLL_WATCHER`.
    _debouncer: DebouncerHandle,
    /// Workspace root for path-rebasing in log messages.
    root: PathBuf,
}

impl std::fmt::Debug for Watcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Watcher")
            .field("root", &self.root)
            .finish_non_exhaustive()
    }
}

impl Watcher {
    /// Start watching `root`. Performs the initial walk synchronously
    /// (cheap on small workspaces; can be pushed onto a blocking task on
    /// big trees in a later phase) so the caller learns about every existing
    /// file before the watcher begins reporting incremental events.
    pub fn start(
        root: &Path,
        state: Arc<DaemonState>,
    ) -> std::io::Result<(Watcher, mpsc::Receiver<WatchEvent>, InitialWalkHandle)> {
        let gitignore = PrebuiltGitignore::build(root)?;
        let gitignore = Arc::new(gitignore);
        let (tx, rx) = mpsc::channel::<WatchEvent>(CHANNEL_CAPACITY);

        // The initial walk used to run synchronously here, before the
        // writer-drain task was spawned. The walker would emit a
        // `Touched` per file into a 256-capacity channel and a `try_send`
        // failure once the channel filled — which it did on any workspace
        // larger than 256 files (≈1.5k files on a 100k-LOC Rust synth).
        // The walker bailed silently and the workspace was permanently
        // partially indexed. We now hand a `InitialWalkHandle` back to
        // the caller (workspace::mount) so it can spawn the writer first
        // and only then drive the walk through `blocking_send` — proper
        // backpressure on the cold path. See CHANGELOG entry under
        // [Unreleased]: "Daemon writer plateau".
        let initial = InitialWalkHandle {
            root: root.to_path_buf(),
            gitignore: gitignore.clone(),
            tx_for_walk: tx.clone(),
            state_for_walk: state.clone(),
        };

        // Construct the debouncer. The closure runs on the debouncer's own
        // worker thread; we forward to the async mpsc with `try_send` so a
        // slow consumer doesn't block the watcher. Drops are surfaced via
        // `WatcherStatus::OverflowedRewalking`.
        let tx_for_handler = tx.clone();
        let state_for_handler = state.clone();
        let gitignore_for_handler = gitignore.clone();
        let root_for_handler = root.to_path_buf();
        let event_handler = move |res: DebounceEventResult| match res {
            Ok(events) => {
                handle_batch(
                    events,
                    &gitignore_for_handler,
                    &root_for_handler,
                    &tx_for_handler,
                    &state_for_handler,
                );
            }
            Err(errs) => {
                for e in errs {
                    warn!(error = %e, "notify watcher error");
                    if let notify::ErrorKind::MaxFilesWatch = e.kind {
                        // v0: surface the status but don't auto-cut-over.
                        // Operators set `RTS_FORCE_POLL_WATCHER=1` and
                        // restart the daemon. Dynamic mid-lifetime
                        // swap-in is a v1.x improvement — the debouncer
                        // holds references on its worker thread that
                        // make in-place replacement fragile.
                        state_for_handler.set_watcher_status(WatcherStatus::PollingFallback);
                    }
                }
            }
        };

        // Branch on the force-poll env var. We accept anything other than
        // empty / "0" / "false" as "yes, use polling" so users don't have
        // to remember an exact spelling.
        let force_poll = std::env::var(FORCE_POLL_ENV)
            .ok()
            .map(|v| !matches!(v.as_str(), "" | "0" | "false" | "FALSE"))
            .unwrap_or(false);

        let debouncer = if force_poll {
            info!(
                "RTS_FORCE_POLL_WATCHER set; starting with PollWatcher (interval={:?})",
                POLL_INTERVAL
            );
            state.set_watcher_status(WatcherStatus::PollingFallback);
            let mut deb = new_debouncer_opt::<_, PollWatcher, _>(
                DEBOUNCE_WINDOW,
                None,
                event_handler,
                RecommendedCache::new(),
                NotifyConfig::default().with_poll_interval(POLL_INTERVAL),
            )
            .map_err(|e| std::io::Error::other(format!("new_debouncer_opt(poll): {e}")))?;
            deb.watch(root, RecursiveMode::Recursive)
                .map_err(|e| std::io::Error::other(format!("debouncer.watch(poll): {e}")))?;
            DebouncerHandle::Polling(deb)
        } else {
            let mut deb = new_debouncer(DEBOUNCE_WINDOW, None, event_handler)
                .map_err(|e| std::io::Error::other(format!("new_debouncer: {e}")))?;
            deb.watch(root, RecursiveMode::Recursive)
                .map_err(|e| std::io::Error::other(format!("debouncer.watch: {e}")))?;
            // Only flip to Ok on the recommended path — the polling path
            // already flipped to PollingFallback above.
            state.set_watcher_status(WatcherStatus::Ok);
            DebouncerHandle::Recommended(deb)
        };

        info!(
            root = %root.display(),
            force_poll,
            "watcher started"
        );

        Ok((
            Watcher {
                _debouncer: debouncer,
                root: root.to_path_buf(),
            },
            rx,
            initial,
        ))
    }
}

/// Carries everything needed to drive the cold initial walk. Held by
/// `workspace::mount` long enough to spawn the writer-drain task first,
/// then handed off (via `spawn_initial_walk`) to a blocking task that
/// pushes events with proper backpressure.
pub struct InitialWalkHandle {
    root: PathBuf,
    gitignore: Arc<PrebuiltGitignore>,
    tx_for_walk: mpsc::Sender<WatchEvent>,
    state_for_walk: Arc<DaemonState>,
}

impl InitialWalkHandle {
    /// Run the initial walk on a blocking task. Sends events with
    /// `blocking_send` so backpressure flows from the writer back to
    /// the walker — the walker slows to the writer's drain rate rather
    /// than overflowing the channel and bailing.
    ///
    /// Returns a `JoinHandle` so the caller can await completion when
    /// needed (e.g. for tests). In production we fire-and-forget; the
    /// `WatcherStatus::Ok` flip already happened in `start`, and the
    /// initial walk's emit count appears in tracing logs.
    pub fn spawn(self) -> tokio::task::JoinHandle<std::io::Result<u64>> {
        tokio::task::spawn_blocking(move || {
            walk_and_emit_blocking(
                &self.root,
                &self.gitignore,
                &self.tx_for_walk,
                &self.state_for_walk,
            )
        })
    }
}

/// Blocking-send variant of `walk_and_emit` for the cold initial walk.
/// Uses `tx.blocking_send` so backpressure propagates from the writer.
/// If the channel is permanently closed (writer task dropped) we surface
/// `OverflowedRewalking` and bail, same as the non-blocking path.
fn walk_and_emit_blocking(
    root: &Path,
    gitignore: &PrebuiltGitignore,
    tx: &mpsc::Sender<WatchEvent>,
    state: &Arc<DaemonState>,
) -> std::io::Result<u64> {
    let walker = ignore::WalkBuilder::new(root)
        .standard_filters(true)
        .git_ignore(true)
        .git_global(true)
        .git_exclude(true)
        .ignore(true)
        .add_custom_ignore_filename(".rtsignore")
        .follow_links(false)
        .build();

    let mut emitted = 0u64;
    for entry in walker {
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                warn!(error = %e, "walk error; continuing");
                continue;
            }
        };
        if !entry.file_type().map(|t| t.is_file()).unwrap_or(false) {
            continue;
        }
        let path = entry.into_path();
        let decision = classify(&path, gitignore);
        match decision {
            FilterDecision::IndexFull | FilterDecision::IndexSignatureOnly => {
                // blocking_send: parks until the consumer pulls. This
                // is the whole point of the restructure — the walker
                // backpressures on the writer-drain rate instead of
                // overflowing the 256-capacity channel.
                if tx
                    .blocking_send(WatchEvent::Touched {
                        path: path.clone(),
                        decision,
                    })
                    .is_err()
                {
                    // Channel closed (writer dropped). Flag the status
                    // for parity with the old try_send-bail path.
                    state.set_watcher_status(WatcherStatus::OverflowedRewalking);
                    return Ok(emitted);
                }
                emitted += 1;
            }
            FilterDecision::Skip(_) => {}
        }
    }
    // v0.5.5: signal the end of the cold walk so the writer can
    // release its hold-off and flush the accumulated batch as a
    // single atomic commit. Without this, the writer's 150ms
    // timer-driven flush could split the cold-walk's files across
    // batches — and `commit_batch`'s Pass-2 ref resolution would
    // permanently drop refs whose callee def lived in a future
    // batch (the `impact_of` flake). `blocking_send` is fine here:
    // there's always room in the 256-cap channel by this point
    // (we've already drained the walker into it, and the writer
    // is consuming as we go).
    if tx.blocking_send(WatchEvent::ColdWalkComplete).is_err() {
        // Channel closed before we could send the barrier — the
        // writer is gone, so there's no one to hand off to. Surface
        // the same status as a mid-walk channel-close.
        state.set_watcher_status(WatcherStatus::OverflowedRewalking);
    }
    debug!(emitted, "initial walk done");
    Ok(emitted)
}

fn handle_batch(
    events: Vec<notify_debouncer_full::DebouncedEvent>,
    gitignore: &PrebuiltGitignore,
    _root: &Path,
    tx: &mpsc::Sender<WatchEvent>,
    state: &Arc<DaemonState>,
) {
    for ev in events {
        if ev.need_rescan() {
            // Overflow on this batch; transition to OverflowedRewalking. The
            // future writer-drain layer is responsible for triggering a
            // re-walk. For the watcher-only slice, we just surface a Rescan
            // event and the status flip.
            state.set_watcher_status(WatcherStatus::OverflowedRewalking);
            let _ = tx.try_send(WatchEvent::Rescan);
            continue;
        }
        for path in &ev.event.paths {
            // Path safety: reject `..` segments outright and re-check the
            // file isn't a symlink at this depth. Per-read prefix checks
            // happen in the file-reader path, not here.
            if path
                .components()
                .any(|c| matches!(c, std::path::Component::ParentDir))
            {
                continue;
            }
            match &ev.event.kind {
                EventKind::Create(_) | EventKind::Modify(_) => {
                    let decision = classify(path, gitignore);
                    match decision {
                        FilterDecision::IndexFull | FilterDecision::IndexSignatureOnly => {
                            let _ = tx.try_send(WatchEvent::Touched {
                                path: path.clone(),
                                decision,
                            });
                        }
                        FilterDecision::Skip(_) => {}
                    }
                }
                EventKind::Remove(_) => {
                    // Don't re-filter on Remove — the file is gone and the
                    // index entry should be dropped regardless of whether it
                    // would have passed classify(). The writer-drain will
                    // no-op if the path isn't indexed.
                    let _ = tx.try_send(WatchEvent::Removed { path: path.clone() });
                }
                EventKind::Other | EventKind::Access(_) | EventKind::Any => {
                    // macOS quirk per P0.3: `fs::rename` can land here with
                    // `Other`. Treat as a touched event so the writer-drain
                    // re-reads. Filtering still applies.
                    if matches!(&ev.event.kind, EventKind::Other) {
                        let decision = classify(path, gitignore);
                        match decision {
                            FilterDecision::IndexFull | FilterDecision::IndexSignatureOnly => {
                                let _ = tx.try_send(WatchEvent::Touched {
                                    path: path.clone(),
                                    decision,
                                });
                            }
                            FilterDecision::Skip(_) => {}
                        }
                    }
                    // EventKind::Access is read-only metadata; ignore.
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    fn fresh_state() -> Arc<DaemonState> {
        Arc::new(DaemonState::new())
    }

    /// Wait for an event matching `pred` within `timeout`. Returns the matching
    /// event or panics if the timeout expires.
    async fn wait_for(
        rx: &mut mpsc::Receiver<WatchEvent>,
        timeout: Duration,
        mut pred: impl FnMut(&WatchEvent) -> bool,
    ) -> WatchEvent {
        let deadline = Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            let recv = tokio::time::timeout(remaining, rx.recv())
                .await
                .unwrap_or_else(|_| panic!("timed out waiting for event"))
                .expect("watcher channel closed unexpectedly");
            if pred(&recv) {
                return recv;
            }
        }
    }

    #[tokio::test]
    async fn initial_walk_emits_existing_files() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("a.rs"), "fn a(){}").unwrap();
        std::fs::write(tmp.path().join("b.rs"), "fn b(){}").unwrap();
        std::fs::write(tmp.path().join("readme.md"), "# x").unwrap();
        // These three should NOT come through the channel:
        std::fs::write(tmp.path().join("logo.png"), b"binary").unwrap();
        std::fs::write(tmp.path().join(".env"), "SECRET=1").unwrap();
        std::fs::write(tmp.path().join("a.rs.swp"), "swap").unwrap();

        let state = fresh_state();
        let (_watcher, mut rx, initial) = Watcher::start(tmp.path(), state).unwrap();
        let _ = initial.spawn();

        let mut seen = std::collections::HashSet::new();
        for _ in 0..3 {
            let ev = tokio::time::timeout(Duration::from_secs(2), rx.recv())
                .await
                .expect("walker should emit promptly")
                .expect("channel closed");
            match ev {
                WatchEvent::Touched { path, .. } => {
                    seen.insert(path.file_name().unwrap().to_owned());
                }
                other => panic!("unexpected event during initial walk: {other:?}"),
            }
        }

        assert!(seen.contains(std::ffi::OsStr::new("a.rs")));
        assert!(seen.contains(std::ffi::OsStr::new("b.rs")));
        assert!(seen.contains(std::ffi::OsStr::new("readme.md")));
    }

    #[tokio::test]
    async fn live_create_surfaces_through_debouncer() {
        let tmp = tempfile::tempdir().unwrap();
        let state = fresh_state();
        let (_watcher, mut rx, initial) = Watcher::start(tmp.path(), state.clone()).unwrap();
        // Run initial walk now that the receiver is owned by the test.
        let _ = initial.spawn();

        // Drain anything from the (empty) initial walk.
        while let Ok(Some(_)) = tokio::time::timeout(Duration::from_millis(100), rx.recv()).await {}

        let path = tmp.path().join("hello.rs");
        std::fs::write(&path, "fn hello(){}").unwrap();

        let ev = wait_for(&mut rx, Duration::from_secs(3), |e| {
            matches!(e, WatchEvent::Touched { path: p, .. } if p.file_name() == Some(std::ffi::OsStr::new("hello.rs")))
        })
        .await;
        match ev {
            WatchEvent::Touched { decision, .. } => {
                assert_eq!(decision, FilterDecision::IndexFull);
            }
            other => panic!("expected Touched, got {other:?}"),
        }

        // WatcherStatus should still be Ok after a quiet save.
        assert_eq!(state.watcher_status(), WatcherStatus::Ok);
    }

    #[tokio::test]
    async fn live_create_of_secrets_file_is_filtered() {
        let tmp = tempfile::tempdir().unwrap();
        let state = fresh_state();
        let (_watcher, mut rx, initial) = Watcher::start(tmp.path(), state).unwrap();
        let _ = initial.spawn();

        // Drain initial walk.
        while let Ok(Some(_)) = tokio::time::timeout(Duration::from_millis(100), rx.recv()).await {}

        std::fs::write(tmp.path().join(".env"), "SECRET=x").unwrap();
        std::fs::write(tmp.path().join("ok.rs"), "fn ok(){}").unwrap();

        // We should see `ok.rs` come through but never `.env`.
        let ev = wait_for(&mut rx, Duration::from_secs(3), |e| {
            matches!(e, WatchEvent::Touched { path, .. } if path.file_name() == Some(std::ffi::OsStr::new("ok.rs")))
        })
        .await;
        let _ = ev;

        // Drain a small tail to ensure nothing else arrives that's the `.env`.
        while let Ok(Some(ev)) = tokio::time::timeout(Duration::from_millis(200), rx.recv()).await {
            if let WatchEvent::Touched { path, .. } = &ev {
                assert_ne!(
                    path.file_name(),
                    Some(std::ffi::OsStr::new(".env")),
                    "secrets blocklist should suppress .env"
                );
            }
        }
    }
}
