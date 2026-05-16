### `rts-daemon` writer — defer unresolved refs, close the §F1 silent-drop bug

v0.5.5 #100 fixed the cold-walk path of a real correctness bug — `Store::commit_batch`'s Pass-2 ref resolution (`crates/rts-daemon/src/store/mod.rs:402`) **permanently dropping** any ref whose callee name wasn't yet in `NAME_TO_SID`. The cold-walk hold-off batched the entire initial walk into one commit, so intra-batch resolution covered every workspace symbol.

But the same §F1 filter still fired on **live edits**: save `caller.rs` (with a ref to `target`) first, save `target.rs` 200 ms later, and the writer commits caller.rs in batch N before target.rs lands in batch N+1. Batch N's Pass 2 sees no `target` in `NAME_TO_SID` and silently drops the ref. Batch N+1's commit interns the name but never goes back to look for orphaned refs. The ref is gone forever.

This PR fixes the live-edit path. **Schema version bumps 2 → 3.**

#### How

Two new tables (`SCHEMA_VERSION=3`):

- **`UNRESOLVED_REFS: &str → RefSite`** — multimap keyed by callee name. Pass 2 writes here when `NAME_TO_SID.get(name)` returns `None`, instead of dropping. The value shape is the same `RefSite` blob the resolved REFS table uses, so Pass 3's materialization is a straight insert without re-encoding.
- **`FID_UNRESOLVED: u32 → &str`** — inverse index from fid → set of callee names this file has pending unresolved refs to. Used by `drop_file_entries` to clean up a removed file's pending entries without scanning the full `UNRESOLVED_REFS` table.

Three changes to `commit_batch`:

1. **Pass 1 tracks newly-interned names.** When a def's name first gets a `NAME_TO_SID` entry (vs being a re-write of an existing name), the name lands in a `HashSet<String>` for Pass 3 to drain.
2. **Pass 2 defers, doesn't drop.** When `name_to_sid.get(r.name)` returns `None`, the ref is written to `UNRESOLVED_REFS[name]` + the (fid, name) edge to `FID_UNRESOLVED`. When it returns `Some(sid)`, the existing resolved-path insert into REFS / FID_REFS / SID_REFS_OUT fires.
3. **Pass 3 re-resolves.** For each name newly interned in this batch, drain `UNRESOLVED_REFS[name]`: read every pending `RefSite`, insert each into REFS / FID_REFS / SID_REFS_OUT (using the freshly minted sid), then `remove_all` from `UNRESOLVED_REFS[name]` and the matching `FID_UNRESOLVED` edges.

Plus `drop_file_entries` now also walks `FID_UNRESOLVED[fid]` and filter-rewrites `UNRESOLVED_REFS[name]` to drop this file's pending entries. Mirrors the existing per-file ref invalidation for the resolved REFS table.

#### Schema migration

Bumping `SCHEMA_VERSION` from 2 to 3 hits the existing rebuild path: on first open of a v2 store, the daemon wipes the redb file and re-walks the workspace. The re-walk goes through the new v0.5.6 deferred-ref logic, so any refs the §F1 filter previously dropped come back automatically. **No migration code needed.**

#### What about the cold-walk hold-off from #100?

Still in place. It's now slightly redundant: with deferred refs, splitting the cold walk across batches no longer drops cross-batch refs. But the hold-off remains the cheapest path — one big commit vs many small commits that need Pass 3 re-resolution — so we keep it. The deferred-ref machinery is the safety net for the long tail (workspaces past `BATCH_SIZE_BUDGET`, live edits, watcher-event coalescing past the 150 ms window).

#### Out of scope (filed for v0.5.7 follow-up)

- **Per-name UNRESOLVED_REFS cap.** Refs to stdlib names (`Vec`, `String`, `println`, …) will *never* resolve because they're never workspace-defined. They accumulate one entry per (fid, callsite) forever. Bound this with a per-name cap (suggest 1024) using a sibling `UNRESOLVED_REFS_COUNT` table or by polling `multimap.get(name).count()` before insert. ~30 bytes × N files × ~50 stdlib names = a few MB on disk for a typical workspace — annoying but not catastrophic, so deferred.
- **Drain UNRESOLVED_REFS on bulk re-resolve.** If a workspace re-mounts with many previously-external names now defined (e.g. a vendored stdlib added), Pass 3 only triggers on names *this batch* defines. A standalone "re-resolve all pending refs against current NAME_TO_SID" pass at mount time would clean up the long tail. Not blocking — names defined in any commit get re-resolved correctly; this is just hygiene for stale UNRESOLVED entries left over from before a workspace structure change.

#### Verification

Three new unit tests in `crates/rts-daemon/src/store/mod.rs::tests`:

1. **`cross_batch_refs_resolve_via_unresolved_refs_table`** — the direct regression. Commit batch 1 with `caller.rs` referring to undefined `target`; assert `UNRESOLVED_REFS["target"]` has 1 entry (pre-v0.5.6 it would have been silently dropped). Commit batch 2 with `target.rs` defining `target`; assert `find_callers(target)` returns the cross-batch caller. Assert `UNRESOLVED_REFS["target"]` is empty (Pass 3 drained it).

2. **`unresolved_refs_cleared_on_file_removal`** — the cleanup path. Commit `caller.rs` with unresolved ref to `target`; remove `caller.rs`; assert `UNRESOLVED_REFS["target"]` empty. Later define `target`; assert zero zombie callers materialize.

3. **`refs_external_symbol_filtered_at_commit`** — updated semantics. Pre-v0.5.6 the test asserted "no entry anywhere"; post-v0.5.6 it asserts "no `NAME_TO_SID` entry AND one `UNRESOLVED_REFS` entry". Catches accidental reversion to the drop-on-miss behavior.

Plus the existing `schema_mismatch_triggers_rebuild` test was updated to assert `stored == SCHEMA_VERSION` (the binary's current constant) rather than the hardcoded literal — future bumps no longer break this test.

Full suite: `cargo test --workspace --release` — **0 failures across all ~300 tests**.

Semantic-eval invariants post-fix:
- `corpus/semantic-eval-rts-core.toml` v1: `answerable_coverage = 1.000 ≥ 0.95 ✓`
- `corpus/semantic-eval-rts-core-blind-v2.toml`: `answerable_coverage = 1.000 ≥ 0.75 ✓`

The expanded reference graph (more refs resolve correctly → more edges in the PageRank input → ranks shift slightly) didn't degrade either ranker invariant.
