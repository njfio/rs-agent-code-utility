### Persisted cold-mount — trust the existing on-disk redb across daemon restarts

The daemon already writes a per-workspace redb file to disk at
`${XDG_STATE_HOME}/rts/<workspace_id>/db.redb` (Linux) /
`~/Library/Caches/rts/<workspace_id>/db.redb` (macOS). But every
mount fired `InitialWalkHandle::spawn` unconditionally, so the
~6-second cold-walk tax got paid every time the daemon went idle
and respawned. The fix is small, surgical, and correctness-preserving:
teach the mount handler to *trust* the existing redb when a composite
fingerprint matches, and skip the cold walk entirely.

#### What

**META-table fingerprint.** Five new keys persist alongside the
existing `SCHEMA_VERSION`:

- `daemon_binary_version` — `env!("CARGO_PKG_VERSION")`
- `grammar_versions` — sorted `"tree-sitter-rust=0.23,tree-sitter-ts=0.23,…"` baked into the binary at compile time by a new `crates/rts-daemon/build.rs`
- `gitignore_content_hash` — blake3 over the *effective* gitignore stack (workspace `.gitignore`, ancestors, `.git/info/exclude`, `.rtsignore`, global, hardcoded fallbacks) — length-prefixed segments so two distinct stacks can never collide
- `fingerprint_combined` — blake3 of all parts truncated to 16 bytes (32 hex), the fast-path comparison key
- `reconciliation_in_progress` — single-byte sentinel set before any mid-mount reconciliation work; observed on next mount as "previous daemon died, redb is torn, wipe-and-walk"

**Mount-time decision.** `Workspace.Mount` now branches on the
fingerprint:

| Stored vs current     | FILES   | Action                                                  | `mount_source`                            |
|-----------------------|---------|---------------------------------------------------------|-------------------------------------------|
| identical             | non-empty | **skip InitialWalkHandle::spawn**; trust existing redb  | `rehydrate`                                |
| missing/mismatched    | any     | `wipe_data_tables()` (preserves META), then cold walk   | `cold_walk_after_invalidation:<reason>`    |
| in-progress sentinel  | any     | wipe + cold walk; previous daemon died mid-reconcile    | `cold_walk_after_crash`                    |
| first-ever            | empty   | cold walk, no wipe                                       | `cold_walk`                                |

Reasons are diagnostic-quality: `schema:3→4`, `binary:0.5.5→0.6.0`,
`grammar:tree-sitter-rust:0.23→0.24` (names the offending crate),
`gitignore`, `empty_or_missing_fingerprint`.

**`wipe_data_tables()` preserves META.** Drops every data table
(FILES, PATH_TO_FID, DEFS, REFS, UNRESOLVED_REFS, …) inside one redb
write txn with `Durability::Immediate`, then re-creates them empty.
META carries the load-bearing schema_version + fingerprint state
that survives a data-only wipe.

**`Daemon.Stats v2` extension.** Four new fields under the existing
`daemon_stats_v2` capability (added in #109):

```jsonc
{
  // … existing v2 fields (pinned_workspace_path, workspace_id,
  // index_generation, cold_walk_completed_at_ms) …
  "mount_source": "rehydrate",
  "rehydrate_attempts_total": 5,
  "rehydrate_successes_total": 4,
  "rehydrate_invalidations_by_reason": {
    "gitignore": 1
  }
}
```

`mount_source` is set once per `Workspace.Mount` and surfaces the
decision label directly. Cumulative counters tally cache-effectiveness
across this daemon process's lifetime.

#### What's **not** in this PR (deferred to v0.6.1)

- **Full reconciliation worker.** The plan describes an mtime/size
  delta scan against the FILES table to catch files that changed
  between sessions on the Rehydrate path. v1 ships the fingerprint
  gate + skip-cold-walk; the steady-state watcher catches changes
  from mount-time forward, but mid-shutdown edits to existing files
  with unchanged paths are deferred. A follow-up PR adds the
  reconciliation worker.

  v1 latency win is real (sub-second second-mount on a workspace
  with thousands of files); v1 staleness window is "between daemon
  shutdown and next mount, mid-file edits aren't surfaced until the
  watcher sees a touch event." Most users won't notice.

#### Why this matters

```
$ time rts-bench query find-symbol --name commit_batch
# First session  → ~6s   (cold walk; same as v0.5.x)
# Second session → <1s   (rehydrate; index already on disk + trusted)
```

Cold-walk re-runs are now *gated* on something actually changing —
schema version, daemon binary, a grammar, the gitignore stack. The
diagnostic label tells you exactly *what* changed. `rts-bench doctor`'s
workspace_index section (when running against a v0.6+ daemon) can
surface `mount_source: rehydrate` directly.

#### Verification

- Full plan: [`docs/plans/2026-05-18-003-feat-persisted-cold-mount-plan.md`](../docs/plans/2026-05-18-003-feat-persisted-cold-mount-plan.md)
- Origin brainstorm: [`docs/brainstorms/2026-05-18-persisted-cold-mount-requirements.md`](../docs/brainstorms/2026-05-18-persisted-cold-mount-requirements.md)
- New integration test
  `crates/rts-daemon/tests/persisted_cold_mount_round_trip.rs`:
  spawns daemon → mounts → indexes a symbol → kills daemon →
  spawns NEW daemon against same state_dir → mounts → calls
  `Index.FindSymbol` immediately (no polling) → asserts matches
  return. Then asserts `Daemon.Stats.mount_source == "rehydrate"`
  and the cache counters bumped exactly once.
- 222 daemon unit tests pass; 27 new tests across the U1-U6 modules
  (fingerprint diff, gitignore hash, META round-trip, wipe_data_tables,
  rehydrate end-to-end).
- All previously-green integration suites (grep, find_symbol,
  daemon_stats, grep_v2_capabilities, persisted_cold_mount,
  grep_within_symbol, grep_multiline) stay green.

#### Sequencing

This PR sequences after **#109 (doctor + Daemon.Stats v2)** and
**#110 (Index.Grep v2)** — all three share the `daemon_stats_v2`
capability + `CallCounters` struct. Branch is based on
`feat/index-grep-v2`. Merge order: 109 → 110 → 003.

#### Out of scope (filed for follow-up)

- Reconciliation worker (mtime/size delta scan) — v0.6.1 follow-up
- `--reset-snapshot` CLI flag for explicit cache invalidation (planned
  in U5 doc but not shipped)
- State_dir garbage collection for moved/deleted workspaces
- Cross-machine snapshot sharing (workspace_id is per-machine by design)
