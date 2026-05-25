---
title: Reconciliation Worker for Persisted Cold-Mount
type: feat
status: active
date: 2026-05-18
origin: docs/plans/2026-05-18-003-feat-persisted-cold-mount-plan.md (Unit U5)
---

# Reconciliation Worker for Persisted Cold-Mount

After a persisted cold-mount (the index loads from redb without re-walking),
files may have changed on disk between sessions — branch switches, `git
checkout`, external editor saves, package upgrades. Without a reconciliation
pass, the daemon serves stale `FILES` rows until the file is re-touched, which
silently breaks search and call-edge queries.

This work ships the periodic reconciliation worker that PR #111 documented as
the closing-of-the-loop unit U5 but did not implement.

## Acceptance Criteria

- [ ] After a persisted cold-mount, a background task scans the mount root,
      compares each indexed file's `mtime_ns` against the on-disk value, and
      falls through to `content_hash` on tie.
- [ ] Files whose on-disk `(mtime_ns, content_hash)` differ from the persisted
      `FileMeta` are queued for re-index via the existing writer path
      (`rescan_and_reconcile` at `crates/rts-daemon/src/writer.rs:375-440`).
- [ ] Files that have been deleted on disk emit `WatchEvent::Removed` so the
      writer drops their rows.
- [ ] **AC16 (preserved from #111):** `UNRESOLVED_REFS` rows must survive
      reconciliation — a stale `FileMeta` does not invalidate cross-file call
      edges; only the affected file's outgoing edges are recomputed.
- [ ] Reconciliation is bounded: emits at most N events/sec (default 64) so a
      mass branch-switch doesn't stall the foreground.
- [ ] `Daemon.Stats` exposes `reconciliation: { last_run_ns, files_scanned,
      files_changed, files_removed, throttled }` so clients can observe.
- [ ] No schema bump. The worker uses the existing `FileMeta` shape
      (`crates/rts-daemon/src/store/schema.rs:13-156`) — no new size field, no
      SCHEMA_VERSION change.

## Context

PR #111 (persisted cold-mount) shipped the durability half: the daemon's
post-walk index now survives restarts and reloads from redb in milliseconds
when the workspace fingerprint matches. But the design intentionally deferred
**post-load reconciliation** to a follow-up — the assumption was "files don't
change while the daemon is dead." That assumption fails the first time a user
restarts mid-`git checkout`.

The unit U5 of `docs/plans/2026-05-18-003-feat-persisted-cold-mount-plan.md`
specifies the worker shape; this plan lifts it into its own deliverable.

## MVP

### `crates/rts-daemon/src/reconciler.rs` (new)

```rust
//! Post-cold-mount reconciliation worker.
//!
//! Runs once shortly after a persisted cold-mount completes. Walks the
//! mount root, compares on-disk metadata to persisted FileMeta, and
//! emits WatchEvent::Touched/Removed for any drift. Throttled to avoid
//! stalling the foreground on mass branch-switches.

use std::sync::Arc;
use std::time::Duration;

use crate::store::Store;
use crate::watcher::{WatchEvent, WatchSink};

pub struct Reconciler {
    store: Arc<Store>,
    sink: WatchSink,
    rate_limit_per_sec: u32,
}

impl Reconciler {
    pub async fn run(self, root: std::path::PathBuf) -> anyhow::Result<ReconcileStats> {
        // 1. Walk root using same ignore-respecting walker as InitialWalk.
        // 2. For each visited file:
        //    - Read FileMeta from FILES table.
        //    - Compare mtime_ns; if different, compare content_hash.
        //    - On drift: sink.send(WatchEvent::Touched(path)).
        // 3. For each FileMeta whose path was NOT visited:
        //    - sink.send(WatchEvent::Removed(path)).
        // 4. Rate-limit emission to rate_limit_per_sec.
        todo!()
    }
}

#[derive(Debug, Default, Clone, serde::Serialize)]
pub struct ReconcileStats {
    pub last_run_ns: u64,
    pub files_scanned: u64,
    pub files_changed: u64,
    pub files_removed: u64,
    pub throttled: u64,
}
```

### Wiring (`crates/rts-daemon/src/methods/workspace.rs`)

In the `MountSource::Persisted` branch (around line 200), spawn the
reconciler **after** the `InitialWalkHandle::ColdWalkComplete` event would
have fired in a fresh mount:

```rust
if let MountSource::Persisted { .. } = source {
    let reconciler = Reconciler::new(store.clone(), watch_sink.clone());
    tokio::spawn(async move {
        if let Err(e) = reconciler.run(root.clone()).await {
            tracing::warn!(error = ?e, "reconciliation failed");
        }
    });
}
```

### `Daemon.Stats` integration

Extend `DaemonStats` in `crates/rts-daemon/src/methods/stats.rs` with a
`reconciliation: ReconcileStats` field. Initialize to default;
`Reconciler::run` writes via shared `Arc<RwLock<ReconcileStats>>`.

### Test

`crates/rts-daemon/tests/reconciliation_round_trip.rs`:

1. Mount a workspace, let it index, shutdown.
2. Modify a file's mtime + bytes on disk.
3. Delete another indexed file.
4. Restart daemon (triggers persisted cold-mount).
5. Wait for `Daemon.Stats.reconciliation.files_changed >= 1` and
   `files_removed >= 1`.
6. Assert `Index.FindSymbol` returns updated content.
7. Assert `Index.FindCallers` on an unchanged file still returns
   pre-restart edges (AC16: UNRESOLVED_REFS survives).

## Sources

- **Origin (parent plan):**
  [docs/plans/2026-05-18-003-feat-persisted-cold-mount-plan.md](./2026-05-18-003-feat-persisted-cold-mount-plan.md)
  Unit U5 — full design specified here; lifting wholesale.
- **Writer reuse path:**
  `crates/rts-daemon/src/writer.rs:375-440` (`rescan_and_reconcile`)
- **WatchEvent enum:** `crates/rts-daemon/src/watcher.rs:71-99`
- **FileMeta shape:** `crates/rts-daemon/src/store/schema.rs:13-156`
- **PR #111:** persisted cold-mount (this plan's predecessor)
