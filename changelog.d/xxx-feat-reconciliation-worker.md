### Reconciliation worker — catch on-disk drift after persisted cold-mount

The persisted cold-mount path (#111) deferred reconciliation: when the
daemon rehydrates from redb on restart, it trusts the on-disk index
verbatim. That's correct when the workspace hasn't moved between
sessions, but stale the moment anything edited a file while the daemon
was dead — branch switch, external editor save, package upgrade.

This PR ships the reconciliation worker that closes the loop.

#### What

**New `crates/rts-daemon/src/reconciler.rs` module.** Runs once,
spawned from `Workspace.Mount` on the `MountSource::Rehydrate`
branch. Fresh / cold-walk / wipe-after-invalidation mounts skip the
worker — their cold walk already covers every file.

The worker walks the mount root with the same ignore-respecting
`ignore::WalkBuilder` used by the cold-walk path, then for each
visited file:

- Reads the persisted `FileMeta` via `Store::get_file_meta`.
- Compares on-disk `mtime_ns` against the stored value.
- On mismatch, confirms with a blake3 hash of the file bytes
  (a touch-only modification that didn't change content shouldn't
  trigger a reparse).
- On drift, emits `WatchEvent::Touched` into the existing watcher
  channel; the writer drain reparses and commits through the same
  path as a live edit.

After the walk, anything indexed but not visited (gone from disk, or
now `.gitignore`'d, or secret-blocked) gets a `WatchEvent::Removed`
so the writer drops the row.

**Rate limiting.** A simple token bucket caps emission at 64
events/sec by default (`DEFAULT_RATE_LIMIT_PER_SEC`). A mass-drift
scenario — e.g. branch switch with thousands of touched files —
won't stall the foreground writer.

**`Daemon.Stats.reconciliation` field.** New nested object under the
existing v2 response (only emitted when a workspace is mounted):

```jsonc
"reconciliation": {
  "last_run_ns":   1748462100123456789,
  "files_scanned": 1247,
  "files_changed": 3,
  "files_removed": 1,
  "throttled":     0
}
```

Backed by a shared `Arc<RwLock<ReconcileStats>>` on `DaemonState`
following the same pattern as `rehydrate_invalidations`.

**AC16 preserved.** The worker never touches `UNRESOLVED_REFS`
directly. Cross-file edges into a drift-detected file flow through
the writer's normal `Touched`/`Removed` arms, which recompute only
the affected file's outgoing refs. Edges *from* other files into
this file survive intact.

#### Why this matters

Without reconciliation, this sequence silently broke search:

1. Daemon mounts `~/repo`, indexes 1.2k files, goes idle.
2. User does `git checkout other-branch` — 80 files differ.
3. Daemon respawns on next query, rehydrates from redb.
4. `find_symbol` returns rows for the *old* branch's code until the
   user re-touches each file.

With reconciliation:

1-2. Same as above.
3. Daemon respawns, takes the Rehydrate path, then spawns the
   worker. Within seconds, drift is detected and the writer
   reparses each changed file.
4. `find_symbol` returns the current branch's code.

#### Verification

- Plan: [`docs/plans/2026-05-18-004-feat-reconciliation-worker-plan.md`](../docs/plans/2026-05-18-004-feat-reconciliation-worker-plan.md)
- New integration test
  `crates/rts-daemon/tests/reconciliation_round_trip.rs`:
  - Session 1: mount → index three files (`drifted.rs`, `orphan.rs`,
    `stable.rs`) → assert cross-file caller edge from `stable.rs`
    into `drifted.rs::stable_callee_hub` is resolved → kill daemon.
  - Between sessions: edit `drifted.rs` body (new symbol
    `drift_target_v2`), delete `orphan.rs`, leave `stable.rs`
    untouched.
  - Session 2: respawn daemon → assert `mount_source: "rehydrate"`,
    poll `Daemon.Stats.reconciliation` for `files_changed >= 1
    && files_removed >= 1`, assert `Index.FindSymbol` surfaces the
    new symbol, assert `Index.FindCallers` still resolves
    `stable_callee_hub` callers (AC16).
- 768 workspace tests pass, including the existing
  `persisted_cold_mount_round_trip` suite.

#### Capability

New capability advertised in `Daemon.Ping`: `reconciliation_worker`.
Clients that need to gate on the new `Daemon.Stats.reconciliation`
field check this capability.
