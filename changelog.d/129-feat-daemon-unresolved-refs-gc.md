### Daemon: GC orphaned `UNRESOLVED_REFS` for removed files + bounded telemetry

PR #126 exposed `Daemon.Telemetry.unresolved_refs_count` so external observers can watch the parked-reference table grow. Without a GC pass that count was unbounded for files removed on disk — every parked row whose source file got deleted lived in the table forever, drifting the observable metric away from the actual call-graph health. This PR closes that loop.

#### What

`crates/rts-daemon/src/store/mod.rs` gains `Store::gc_unresolved_refs_for_removed_files(removed_files: &[PathBuf]) -> Result<u64, redb::Error>` — walks each removed-file path through the `FID_UNRESOLVED` reverse index, drops `UNRESOLVED_REFS[name]` rows whose `RefSite.fid` matches, returns the count actually deleted. The writer's `flush()` invokes the helper before each `commit_batch` that carries removals; `commit_batch`'s existing `drop_file_entries` then finds the rows already gone (no-op for the GC portion). `crates/rts-daemon/src/state.rs` adds two `AtomicU64` counters (`unresolved_refs_gc_runs_total`, `unresolved_refs_gc_dropped_total`) that the writer bumps on each removal-bearing flush; `Daemon.Telemetry` surfaces both as new top-level u64 fields, gated behind capability `daemon_telemetry_unresolved_refs_gc`. `schemas/v0/methods/Daemon.Telemetry.resp.schema.json` adds both fields as required; `docs/protocol-v0.md` §7.11b documents them with the bounded-growth contract.

#### Strategy

File-removal-driven (Strategy A in the PR brief). The `FID_UNRESOLVED` reverse index already provides O(distinct_callee_names_for_this_fid) lookup, so the GC is amortized into the existing file-removal flush — no background timer, no policy knobs, no schema change. TTL-driven GC (Strategy B) was rejected: it would require a new `created_at_ms` column for a hypothesis (genuinely-unresolvable refs accumulate at meaningful rates) that hasn't been measured. A is one schema change away from B if evidence ever lands.

#### Why

`unresolved_refs_count` becomes a regression signal once GC is wired in: a sudden jump without `unresolved_refs_gc_dropped_total` advancing means an extractor regression (PR #118's PHP `method_declaration` gap is exactly the class of bug that would have moved this needle). Pre-PR-128 the same jump was indistinguishable from "user deleted some files" — both look the same on the wire.

#### Test guard

- `crates/rts-daemon/src/store/mod.rs::gc_unresolved_refs_drops_rows_for_named_file` — unit test against a temp store: 1 parked row, GC pass, 0 left + dropped=1.
- `crates/rts-daemon/src/store/mod.rs::gc_unresolved_refs_preserves_other_files` — control: two files sharing a callee name; remove only one; assert the other's row survives (`FID_UNRESOLVED`-keyed lookup must not over-collect by name).
- `crates/rts-daemon/src/store/mod.rs::gc_unresolved_refs_empty_input_returns_zero` — empty-slice short-circuit (no write txn started).
- `crates/rts-daemon/tests/unresolved_refs_gc.rs::gc_drops_refs_for_removed_file` — end-to-end against the daemon binary: spawn, mount, observe phantom ref parked, delete the source file, assert count drops AND both GC counters advance.
- `crates/rts-daemon/tests/unresolved_refs_gc.rs::gc_runs_counter_bumps_on_each_removal` — two independent file removals advance `unresolved_refs_gc_runs_total` by 2.
- `crates/rts-daemon/tests/unresolved_refs_gc.rs::gc_preserves_refs_from_still_present_files` — control over the live wire: shared callee name, remove only one of two files, surviving file's ref must still be parked.
- The existing `response_matches_schema_for_each_method` schema-drift gate validates the live `Daemon.Telemetry` response against the updated JSON Schema; new fields without the schema bump or vice versa fail CI.

#### Out of scope

- No background polling timer. File-removal events are the only trigger.
- No TTL-based GC. Schema unchanged.
- No new RPC. GC is internal; observe via `Daemon.Telemetry`.
- No changes to the resolver's Pass-3 binding. Resolution and GC stay independent.

#### Post-deploy monitoring

Monitor `unresolved_refs_count` trend over time. Healthy signal: count stays bounded and `unresolved_refs_gc_dropped_total` advances as files are removed. Failure signal: count climbs monotonically without `unresolved_refs_gc_dropped_total` advancing — indicates either GC isn't firing (look at `unresolved_refs_gc_runs_total` first) or an extractor regression (an extractor change that newly drops symbol defs would park refs that match no later commit).
