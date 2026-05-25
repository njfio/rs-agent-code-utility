//! Post-cold-mount reconciliation worker.
//!
//! Runs once shortly after a persisted cold-mount (`MountSource::Rehydrate`)
//! completes. Walks the mount root using the same ignore-respecting walker
//! as the cold-walk path, compares each indexed file's on-disk metadata
//! against the persisted `FileMeta`, and emits `WatchEvent::Touched` /
//! `WatchEvent::Removed` for any drift. The writer drain consumes the
//! events through the same path as live edits and rescans.
//!
//! Without this pass the daemon would serve stale rows for every file
//! that changed while the previous daemon was dead (branch switches,
//! external editor saves, package upgrades). The hot rehydrate path is
//! preserved — reconciliation runs *after* `Mount` returns so the first
//! query is not gated on a full walk.
//!
//! **AC16 preservation.** This worker never touches `UNRESOLVED_REFS`
//! directly. Cross-file edges into a drift-detected file flow through
//! the writer's normal `Touched`/`Removed` arms, which recompute only
//! the affected file's outgoing refs. Edges *from* other files into
//! this file survive intact.

use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tokio::sync::mpsc;

use crate::filter::{FilterDecision, PrebuiltGitignore, classify};
use crate::store::Store;
use crate::watcher::WatchEvent;

/// Default per-second event emission cap. Bounds the impact of a
/// mass-drift scenario (e.g. branch switch with thousands of touched
/// files) on the foreground writer; the writer's batch budget would
/// otherwise pile up.
pub const DEFAULT_RATE_LIMIT_PER_SEC: u32 = 64;

/// Per-worker stats surfaced via `Daemon.Stats.reconciliation`.
///
/// `last_run_ns` is the Unix-epoch nanoseconds when the most recent
/// reconciliation pass finished; `0` until the first run completes.
/// Counters are cumulative across the daemon process lifetime (one
/// pass per persisted cold-mount in practice).
#[derive(Debug, Default, Clone, serde::Serialize)]
pub struct ReconcileStats {
    pub last_run_ns: u64,
    pub files_scanned: u64,
    pub files_changed: u64,
    pub files_removed: u64,
    pub throttled: u64,
}

/// One reconciliation pass. Owns nothing past `run`.
pub struct Reconciler {
    store: Arc<Store>,
    sink: mpsc::Sender<WatchEvent>,
    stats: Arc<RwLock<ReconcileStats>>,
    rate_limit_per_sec: u32,
}

impl Reconciler {
    /// Construct a reconciler at the default rate limit.
    pub fn new(
        store: Arc<Store>,
        sink: mpsc::Sender<WatchEvent>,
        stats: Arc<RwLock<ReconcileStats>>,
    ) -> Self {
        Self {
            store,
            sink,
            stats,
            rate_limit_per_sec: DEFAULT_RATE_LIMIT_PER_SEC,
        }
    }

    /// Walk `root`, compare against the persisted store, emit drift
    /// events. Returns a snapshot of the resulting stats.
    pub async fn run(self, root: PathBuf) -> anyhow::Result<ReconcileStats> {
        let started = Instant::now();
        let gitignore = PrebuiltGitignore::build(&root)
            .map_err(|e| anyhow::anyhow!("rebuild gitignore for reconcile: {e}"))?;

        // Snapshot the persisted file set up front. We can't keep a
        // redb txn open across the walk + async sends, but a single
        // pass over `list_files_with_defs` gives us everything we need
        // (path + fid) to detect orphans below.
        let indexed = self
            .store
            .list_files_with_defs()
            .map_err(|e| anyhow::anyhow!("reconcile: list_files_with_defs: {e:#}"))?;
        let indexed_paths: std::collections::HashSet<String> =
            indexed.iter().map(|f| f.path.clone()).collect();

        let mut visited: std::collections::HashSet<String> =
            std::collections::HashSet::with_capacity(indexed_paths.len());
        let mut files_scanned: u64 = 0;
        let mut files_changed: u64 = 0;
        let mut files_removed: u64 = 0;
        let mut throttled: u64 = 0;

        // Token-bucket pacing: refill `rate_limit_per_sec` tokens once
        // per second, starting full. A drift event that exhausts the
        // bucket sleeps until the next refill. Bench/test runs that
        // never exceed the cap pay zero latency cost.
        let mut bucket_tokens: u32 = self.rate_limit_per_sec.max(1);
        let mut bucket_window_started: Instant = Instant::now();

        let walker = ignore::WalkBuilder::new(&root)
            .standard_filters(true)
            .git_ignore(true)
            .git_global(true)
            .git_exclude(true)
            .ignore(true)
            .add_custom_ignore_filename(".rtsignore")
            .follow_links(false)
            .build();

        for entry in walker {
            let entry = match entry {
                Ok(e) => e,
                Err(err) => {
                    tracing::warn!(error = %err, "reconcile walk error; continuing");
                    continue;
                }
            };
            if !entry.file_type().map(|t| t.is_file()).unwrap_or(false) {
                continue;
            }
            let abs_path = entry.into_path();
            let decision = classify(&abs_path, &gitignore);
            match decision {
                FilterDecision::IndexFull | FilterDecision::IndexSignatureOnly => {}
                FilterDecision::Skip(_) => continue,
            }
            files_scanned = files_scanned.saturating_add(1);

            let rel_path = match abs_path.strip_prefix(&root) {
                Ok(p) => p.to_path_buf(),
                Err(_) => continue,
            };
            let rel_key = rel_path.to_string_lossy().into_owned();
            visited.insert(rel_key.clone());

            // File on disk but never indexed yet — emit `Touched` so
            // the writer picks it up. This covers the new-file-while-
            // daemon-was-dead case, which the cold-walk path would
            // have handled naturally.
            let Some((_, meta)) = self.store.get_file_meta(&rel_key).ok().flatten() else {
                if Self::should_throttle(
                    &mut bucket_tokens,
                    &mut bucket_window_started,
                    self.rate_limit_per_sec,
                )
                .await
                {
                    throttled = throttled.saturating_add(1);
                }
                if self
                    .sink
                    .send(WatchEvent::Touched {
                        path: abs_path.clone(),
                        decision,
                    })
                    .await
                    .is_err()
                {
                    tracing::warn!("reconcile sink closed; aborting walk");
                    break;
                }
                files_changed = files_changed.saturating_add(1);
                continue;
            };

            if !file_drifted(&abs_path, &meta) {
                continue;
            }

            if Self::should_throttle(
                &mut bucket_tokens,
                &mut bucket_window_started,
                self.rate_limit_per_sec,
            )
            .await
            {
                throttled = throttled.saturating_add(1);
            }

            if self
                .sink
                .send(WatchEvent::Touched {
                    path: abs_path.clone(),
                    decision,
                })
                .await
                .is_err()
            {
                tracing::warn!("reconcile sink closed; aborting walk");
                break;
            }
            files_changed = files_changed.saturating_add(1);
        }

        // Orphan detection: anything indexed but not seen during the
        // walk is gone (or now gitignored/secret-blocked); emit
        // `Removed` so the writer drops its rows.
        for rel_key in indexed_paths.iter() {
            if visited.contains(rel_key) {
                continue;
            }
            let abs = root.join(rel_key);
            if Self::should_throttle(
                &mut bucket_tokens,
                &mut bucket_window_started,
                self.rate_limit_per_sec,
            )
            .await
            {
                throttled = throttled.saturating_add(1);
            }
            if self
                .sink
                .send(WatchEvent::Removed { path: abs })
                .await
                .is_err()
            {
                tracing::warn!("reconcile sink closed; aborting orphan sweep");
                break;
            }
            files_removed = files_removed.saturating_add(1);
        }

        let last_run_ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);

        let snapshot = ReconcileStats {
            last_run_ns,
            files_scanned,
            files_changed,
            files_removed,
            throttled,
        };
        if let Ok(mut guard) = self.stats.write() {
            *guard = snapshot.clone();
        }
        tracing::info!(
            target: "rts_daemon::reconciler",
            files_scanned,
            files_changed,
            files_removed,
            throttled,
            elapsed_ms = started.elapsed().as_millis() as u64,
            "reconciliation pass complete"
        );
        Ok(snapshot)
    }

    /// Token-bucket gate. Returns `true` when the caller had to wait
    /// for a refill (i.e. the emission was throttled).
    async fn should_throttle(
        bucket_tokens: &mut u32,
        bucket_window_started: &mut Instant,
        rate_limit_per_sec: u32,
    ) -> bool {
        let cap = rate_limit_per_sec.max(1);
        if *bucket_tokens > 0 {
            *bucket_tokens -= 1;
            return false;
        }
        let elapsed = bucket_window_started.elapsed();
        let throttled = if elapsed < Duration::from_secs(1) {
            let remaining = Duration::from_secs(1) - elapsed;
            tokio::time::sleep(remaining).await;
            true
        } else {
            false
        };
        *bucket_window_started = Instant::now();
        *bucket_tokens = cap - 1;
        throttled
    }
}

fn file_drifted(abs_path: &Path, meta: &crate::store::schema::FileMeta) -> bool {
    let Ok(meta_io) = std::fs::metadata(abs_path) else {
        // Can't stat — treat as drift; the writer will resolve the
        // race (real removal will surface during its own read attempt).
        return true;
    };
    let mtime_ns = meta_io
        .modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_nanos() as i64)
        .unwrap_or(0);
    if mtime_ns != meta.mtime_ns {
        // Mtime mismatch is the cheap signal; confirm with a hash so
        // touch-only modifications (mtime bumped, bytes unchanged)
        // don't trigger a needless reparse.
        let Ok(content) = std::fs::read(abs_path) else {
            return true;
        };
        let hash: [u8; 32] = blake3::hash(&content).into();
        return hash != meta.content_hash;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn throttle_passes_through_under_cap() {
        let mut tokens: u32 = 4;
        let mut window = Instant::now();
        // First three calls drain the bucket; none should report throttle.
        for _ in 0..3 {
            let was = Reconciler::should_throttle(&mut tokens, &mut window, 4).await;
            assert!(!was);
        }
        assert_eq!(tokens, 1);
    }

    #[tokio::test]
    async fn throttle_sleeps_when_bucket_drained() {
        let mut tokens: u32 = 1;
        let mut window = Instant::now();
        // First call consumes the last token (no throttle).
        let was = Reconciler::should_throttle(&mut tokens, &mut window, 1).await;
        assert!(!was);
        // Next call has no tokens and must wait for a refill.
        let started = Instant::now();
        let was = Reconciler::should_throttle(&mut tokens, &mut window, 1).await;
        assert!(was, "second call should report throttled");
        assert!(
            started.elapsed() >= Duration::from_millis(500),
            "throttled call should sleep close to 1s; got {:?}",
            started.elapsed()
        );
    }
}
