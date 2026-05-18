---
title: "feat(daemon): persisted cold-mount via redb META fingerprint + mtime reconciliation"
type: feat
status: active
date: 2026-05-18
origin: docs/brainstorms/2026-05-18-persisted-cold-mount-requirements.md
---

# Persisted cold-mount — trust the existing on-disk redb across daemon restarts

## Overview

The rts daemon already writes its index to a per-workspace on-disk redb file at the canonical state path (`state_dir_for(fingerprint) → ${XDG_STATE_HOME:-~/.local/state}/rts/<workspace_id>/db.redb` on Linux; `~/Library/Caches/rts/<workspace_id>/db.redb` on macOS). The cold-walk re-runs every daemon startup not because the redb is empty, but because **`InitialWalkHandle::spawn` fires unconditionally** at `crates/rts-daemon/src/methods/workspace.rs:145-213`.

This plan does not introduce a new cache. It teaches the existing on-disk state to be trusted across daemon restarts by:

1. Extending the existing redb `META` table with a **composite fingerprint** (schema_version + daemon_binary_version + grammar_versions + gitignore_content_hash) stored as **per-part columns** plus a combined hash for fast comparison.
2. **Conditionally skipping `InitialWalkHandle::spawn`** when META's fingerprint matches the current fingerprint and FILES is non-empty.
3. Running an **mtime/size reconciliation pass** over the FILES table to re-parse only changed files since the last shutdown.
4. Adding a `mount_source` field to `Daemon.Stats v2` (extends PR 001's `daemon_stats_v2` capability) with diagnostic values like `rehydrate`, `cold_walk`, or `cold_walk_after_invalidation:grammar:rust:0.23→0.24`.
5. Adding cache-effectiveness counters (`rehydrate_attempts`, `rehydrate_successes`, `rehydrate_invalidations_by_reason{...}`) so SC1's *"sub-100 ms first-query"* claim is observable in production.

The plan reframes five brainstorm assumptions surfaced by research:

| Brainstorm wording | Reality |
|--------------------|---------|
| "Serialize the redb snapshot to `~/.cache/rts/<workspace-hash>/`" | Already persisted at `state_dir_for(...)` (XDG_STATE_HOME on Linux, Library/Caches on macOS). Don't relocate. |
| "Write the snapshot atomically at cold-walk-done + on shutdown" | redb writes continuously and ACID-ly. Only the *fingerprint* is the snapshot atom; the data is already on disk. |
| "Cache key = `blake3(canonical_workspace_path)`" | Existing `WorkspaceFingerprint` is `blake3(dev_id ‖ inode ‖ canonical_path)[:16]`. Reuse it. |
| "Single composite fingerprint" | Per-part columns + a combined hash is strictly better (diagnostic `cold_walk_after_invalidation:<reason>` requires per-part). |
| "Snapshot covers all redb tables" | Trivially true — the redb file is already on disk. The plan just learns to trust it. |

## Problem Statement / Motivation

Cold mount on 100k LOC takes ~6 s today and is paid every time the daemon goes idle (10 min `RTS_IDLE_SHUTDOWN_SECS` default). The cold-walk is the only user-perceived latency in rts — the first query of every session feels slow. The fix lives in a small region of the daemon (the post-mount initial-walk branch); the surrounding infrastructure (per-workspace state_dir, blake3 workspace fingerprint, redb META table, SCHEMA_VERSION rebuild path) is already in place and correct.

The reframed plan also closes the SpecFlow-surfaced operational gap: today, "the daemon mounted instantly" and "the daemon did a full cold walk" are indistinguishable from outside. The new `mount_source` field makes the cache effectiveness observable.

## Proposed Solution

The implementation has **four shipping surfaces**, each small and reviewable:

### 1. Per-part fingerprint in `META`

Extend the existing META table (`crates/rts-daemon/src/store/schema.rs:13-130`) with five new keys:

```rust
META::META_DAEMON_BINARY_VERSION     -> str   // e.g., "0.6.0+sha:abc1234"
META::META_GRAMMAR_VERSIONS          -> str   // JSON: {"rust":"0.23.1","python":"0.23.0",...}
META::META_GITIGNORE_CONTENT_HASH    -> str   // blake3(effective_gitignore_bytes)[:16]
META::META_FINGERPRINT_COMBINED      -> str   // blake3(all parts)[:16]
META::META_RECONCILIATION_IN_PROGRESS -> bool // sentinel for kill-during-reconciliation
```

The combined hash is the fast-path check. The per-part columns let `mount_source` carry diagnostic-quality invalidation reasons.

### 2. Conditional cold-walk skip

At `crates/rts-daemon/src/methods/workspace.rs:145-213`, where `InitialWalkHandle::spawn` is unconditionally called, add a pre-check:

```rust
let mount_source = match (
    fingerprints_match(&store, &current_fingerprint)?,
    store.files_count()? > 0,
    store.reconciliation_was_in_progress()?,
) {
    (true, true, false) => MountSource::Rehydrate,
    (false, true, _)    => MountSource::ColdWalkAfterInvalidation(reason),
    (_, _, true)        => MountSource::ColdWalkAfterCrash,  // killed mid-reconciliation
    (_, false, _)       => MountSource::ColdWalk,            // first mount or empty redb
};

match mount_source {
    MountSource::Rehydrate => {
        spawn_mtime_reconciliation(...);  // new path
        // skip InitialWalkHandle::spawn
    }
    _ => {
        store.wipe_data_tables()?;  // preserve META across wipe
        InitialWalkHandle::spawn(...);  // existing path
    }
}
state.set_mount_source(mount_source);
```

`store.wipe_data_tables()` is a new method that clears all data tables but preserves META so we can write the *new* fingerprint after cold-walk completion.

### 3. mtime/size reconciliation worker

A new `crates/rts-daemon/src/reconciliation.rs` module. On Rehydrate, before the watcher starts processing live events:

1. Set `META_RECONCILIATION_IN_PROGRESS = true` (atomic in a redb txn).
2. Walk the workspace via the existing `ignore::WalkBuilder` (matches the cold-walk semantics at `watcher.rs:299-307`).
3. For each file encountered:
   - If in FILES with matching (mtime, size): no-op
   - If in FILES with differing (mtime, size): emit a synthetic `WatchEvent::FileChanged` to the existing writer pipeline
   - If not in FILES: emit `WatchEvent::FileAdded`
4. For each file in FILES not seen during the walk: emit `WatchEvent::FileDeleted`
5. After all events drain through the writer, write the *new* fingerprint to META and clear `META_RECONCILIATION_IN_PROGRESS`.

The watcher runs in parallel from step 2 onward (matching the cold-walk-today behavior where the watcher runs alongside the initial walk).

mtime+size is the v1 invariant. **Known limitation:** patterns that preserve mtime (`git checkout`, `cp -p`, `sed -i` on some platforms, `touch -r`) can leave the rehydrate path with a stale index for affected files. A `RTS_REHYDRATE_PARANOID=1` env var enables content-hash verification (compute blake3 on (mtime, size) match; mismatch → re-parse) — added in v1 as opt-in; default-off for cost.

### 4. `Daemon.Stats v2` `mount_source` field + cache counters

Extends PR 001's `daemon_stats_v2` capability:

```jsonc
{
  // From PR 001:
  "pinned_workspace_path": str,
  "workspace_id": str,
  "index_generation": u64,
  "cold_walk_completed_at_ms": u64 | null,
  // Added by PR 003:
  "mount_source": "cold_walk" | "rehydrate" | "cold_walk_after_invalidation:<reason>" | "cold_walk_after_crash",
  "rehydrate_attempts_total": u64,
  "rehydrate_successes_total": u64,
  "rehydrate_invalidations_by_reason": { "<reason>": u64, ... }
}
```

PR 003 ships after PR 001 and PR 002 (the doctor and grep v2 plans). All three share the `daemon_stats_v2` capability.

## Technical Approach

### Module layout

```
crates/rts-daemon/build.rs                  // NEW: emit GRAMMAR_VERSIONS from Cargo.toml
crates/rts-daemon/src/fingerprint.rs        // NEW: composite fingerprint computation
crates/rts-daemon/src/reconciliation.rs     // NEW: mtime/size reconciliation worker
crates/rts-daemon/src/store/schema.rs       // extend META with 5 new keys
crates/rts-daemon/src/store/mod.rs          // wipe_data_tables(); preserve META
crates/rts-daemon/src/methods/workspace.rs  // gate InitialWalkHandle::spawn on fingerprint
crates/rts-daemon/src/methods/daemon.rs     // extend Daemon.Stats with mount_source + counters
crates/rts-daemon/src/state.rs              // CacheCounters; MountSource on DaemonState
crates/rts-daemon/src/gitignore_hash.rs     // NEW: effective-gitignore content hasher
docs/protocol-v0.md                         // §5.4 (state dir alignment), §15.1 (rehydrate path), capability v2 entry
```

### Grammar version exposure (build.rs)

Tree-sitter grammars are pinned in `crates/rts-core/Cargo.toml:18-31`. None expose a runtime version constant today. The plan adds `crates/rts-daemon/build.rs`:

```rust
fn main() {
    let core_cargo_toml = std::fs::read_to_string("../rts-core/Cargo.toml").unwrap();
    let parsed: toml::Value = toml::from_str(&core_cargo_toml).unwrap();
    // Extract every tree-sitter-* dependency version
    let mut versions: Vec<(String, String)> = vec![];
    for (name, dep) in parsed["dependencies"].as_table().unwrap() {
        if name.starts_with("tree-sitter-") {
            let v = dep.as_str().or_else(|| dep.get("version")?.as_str()).unwrap();
            versions.push((name.clone(), v.to_string()));
        }
    }
    versions.sort();
    let map_lit = serde_json::to_string(&versions).unwrap();
    println!("cargo:rustc-env=RTS_GRAMMAR_VERSIONS={}", map_lit);
}
```

Accessed at runtime via `env!("RTS_GRAMMAR_VERSIONS")`. Tied to the build; changes whenever a grammar version bump is committed. The Cargo-toml-derived version was chosen over `tree_sitter::Language::version()` (the C ABI number, coarser-grained and rarely changes — would miss most relevant grammar updates).

### gitignore content hasher

A new `gitignore_hash.rs` module assembles the effective-gitignore byte stream in this fixed order (matching the walker's precedence per `watcher.rs:299-307`):

```
workspace/.gitignore (if present)
workspace/.git/info/exclude (if present)
workspace/.rtsignore (if present)
each ancestor/.gitignore from workspace upward to /, in walked order
~/.config/git/ignore OR ${XDG_CONFIG_HOME}/git/ignore (if present)
hardcoded fallbacks compiled into the binary (target/, node_modules/, .git/, .hg/, .svn/, build/, dist/, .next/, .cache/)
```

Each segment is prefixed with a length-tagged header (`u32 len, ASCII name, content`) to avoid ambiguity. Hash: `blake3` (already a workspace dep), truncated to 16 hex.

Semantic normalization (whitespace, comment stripping) is **out of scope for v1** — byte-equal content only. Documented limitation.

### `wipe_data_tables` helper

`crates/rts-daemon/src/store/mod.rs` already has `Store::open` that wipes the file via `std::fs::remove_file` on schema mismatch (`store/mod.rs:174-189`). The plan replaces this with a finer-grained `wipe_data_tables(&mut self) -> Result<()>` that:

1. Opens a redb write txn
2. Calls `txn.delete_table(...)` for each data table (FILES, PATH_TO_FID, FID_TO_PATH, NAME_TO_SID, SID_TO_NAME, DEFS, FID_DEFS, REFS, FID_REFS, SID_REFS_OUT, SID_DOCS, UNRESOLVED_REFS, FID_UNRESOLVED)
3. Preserves META and re-creates the data tables empty
4. Commits with `Durability::Immediate`

This way the schema-mismatch / fingerprint-mismatch path keeps the META table (where the *new* fingerprint will be written after cold-walk completion).

For backward compatibility, the old `remove_file` path is retained for the SCHEMA_VERSION_NEWER case (refuse to open).

### `DaemonState` additions

```rust
// crates/rts-daemon/src/state.rs (existing struct extended)
pub struct DaemonState {
    // ... existing fields ...
    mount_source: AtomicCell<MountSource>,           // updated once per Workspace.Mount
    cache_counters: CacheCounters,                   // process-lifetime cumulative
}

pub struct CacheCounters {
    rehydrate_attempts: AtomicU64,
    rehydrate_successes: AtomicU64,
    rehydrate_invalidations: Mutex<HashMap<String, u64>>,  // by reason
}

pub enum MountSource {
    ColdWalk,
    Rehydrate,
    ColdWalkAfterInvalidation(InvalidationReason),
    ColdWalkAfterCrash,
}

pub enum InvalidationReason {
    SchemaVersion { old: u32, new: u32 },
    DaemonBinaryVersion { old: String, new: String },
    GrammarVersion { language: String, old: String, new: String },
    Gitignore,
    EmptyOrMissingFingerprint,
}

impl InvalidationReason {
    pub fn as_label(&self) -> String {
        // Renders as "cold_walk_after_invalidation:grammar:rust:0.23→0.24" etc.
    }
}
```

### Reconciliation in progress marker

The `META_RECONCILIATION_IN_PROGRESS = true` sentinel is written *before* the first synthetic `WatchEvent::*` reaches the writer; cleared *after* the last event drains AND the new fingerprint is written. If a daemon crashes mid-reconciliation, the next mount sees the sentinel and downgrades to `ColdWalkAfterCrash` (wipes data tables, runs full cold walk, but reports the diagnostic value).

### Coordination with PR 001 and PR 002

All three plans modify `crates/rts-daemon/src/methods/daemon.rs:140-151` (Daemon.Stats response) and `:18-87` (capability list). The plan sequences as:

- **PR 001 (doctor)** lands first: adds `pinned_workspace_path`, `workspace_id`, `index_generation`, `cold_walk_completed_at_ms`. Capability `daemon_stats_v2`.
- **PR 002 (grep v2)** rebases on PR 001: adds three sub-counters (`index_grep_multiline`, `index_grep_structural`, `index_grep_within_symbol`) to `CallCounters`. No new top-level Stats fields. New capabilities `index_grep_{multiline,structural,within_symbol}` and bundle `index_grep_v2`.
- **PR 003 (this plan)** rebases on PR 002: adds `mount_source`, `rehydrate_attempts_total`, `rehydrate_successes_total`, `rehydrate_invalidations_by_reason` to Daemon.Stats. Reuses `daemon_stats_v2` capability (no new capability string needed — `mount_source` joins the v2 surface).

### System-Wide Impact

- **Interaction graph.** `Workspace.Mount` opens redb (existing) → computes current fingerprint → reads META fingerprint → decides path (rehydrate vs cold-walk-after-X) → either spawns reconciliation worker or `InitialWalkHandle::spawn` → watcher starts → writer drains events. The decision happens *once* per mount.
- **Error propagation.** Fingerprint computation failures (build.rs didn't run; gitignore unreadable) → fall back to cold-walk path with `ColdWalkAfterInvalidation(...)` and log at `warn`. Never fail Mount; always degrade.
- **State lifecycle.** META gains 5 new keys (additive — old daemons see unknown keys harmlessly via redb's table-aware open). `META_RECONCILIATION_IN_PROGRESS` is the only sentinel; cleared on success, observed on crash recovery.
- **API surface parity.** `Daemon.Stats` grows fields under existing `daemon_stats_v2`. Capability list unchanged.
- **Integration test scenarios.**
  - First-ever mount on a workspace: `mount_source = "cold_walk"`.
  - Second mount, no changes: `mount_source = "rehydrate"`; total mount-to-first-query latency under 100 ms p95 on 100k LOC.
  - `SCHEMA_VERSION` bumped between sessions: `mount_source = "cold_walk_after_invalidation:schema:3→4"`.
  - Daemon binary version bumped: `mount_source = "cold_walk_after_invalidation:binary:0.6.0→0.6.1"`.
  - Grammar version bumped (single language): `mount_source = "cold_walk_after_invalidation:grammar:rust:0.23→0.24"`.
  - Workspace `.gitignore` edited: `mount_source = "cold_walk_after_invalidation:gitignore"`.
  - Daemon killed mid-cold-walk: next mount sees non-empty FILES with no fingerprint → `cold_walk_after_invalidation:empty_or_missing_fingerprint`. Wipes and re-walks.
  - Daemon killed mid-reconciliation: next mount sees `META_RECONCILIATION_IN_PROGRESS` → `cold_walk_after_crash`. Wipes and re-walks.
  - File edited between sessions (mtime changes): reconciliation re-parses that file only.
  - File created between sessions: reconciliation indexes it.
  - File deleted between sessions: reconciliation drops it.
  - File edited via `git checkout` (mtime restored): rehydrate misses it (documented limitation); `RTS_REHYDRATE_PARANOID=1` catches it via content-hash.
  - Workspace moved (`mv ~/src/foo ~/src/bar`): inode/path change → new `workspace_id` → new state_dir → first-ever mount path on the new dir.

## Implementation Units

Ordered by dependency. U1 depends on PR 001 + PR 002 being landed.

### U1 — Grammar version exposure (build.rs)

- **Goal.** `RTS_GRAMMAR_VERSIONS` env var available at runtime via `env!`, sorted-by-name JSON of `{"tree-sitter-LANG": "version"}` pairs.
- **Files.** `crates/rts-daemon/build.rs` (new); `crates/rts-daemon/src/fingerprint.rs` (new — exposes `pub fn grammar_versions() -> &'static [(String, String)]`).
- **Approach.** build.rs parses `../rts-core/Cargo.toml`, extracts all `tree-sitter-*` deps, emits sorted JSON via `cargo:rustc-env`. Runtime accessor returns parsed pairs.
- **Patterns to follow.** Common Rust `build.rs` pattern; `cargo:rerun-if-changed=../rts-core/Cargo.toml` to invalidate the build cache on grammar bumps.
- **Execution note.** Pragmatic. No tests beyond a smoke check that the env var has expected entries.
- **Test scenarios.**
  - Grammar version count matches `crates/rts-core/Cargo.toml` count (12).
  - Build is rerun when `rts-core/Cargo.toml` changes.
- **Verification.** `cargo build -p rts-daemon` succeeds; `cargo test -p rts-daemon fingerprint::grammar_versions` green.

### U2 — gitignore content hasher

- **Goal.** `pub fn effective_gitignore_hash(workspace_root: &Path) -> Result<String>` returns blake3-of-bytes(:16) for the effective gitignore content stack.
- **Files.** `crates/rts-daemon/src/gitignore_hash.rs` (new); coordinates with `crates/rts-daemon/src/filter.rs:170-245`.
- **Approach.** Read in fixed order: workspace `.gitignore`, `.git/info/exclude`, `.rtsignore`, ancestor `.gitignore`s upward, global `~/.config/git/ignore` (or `${XDG_CONFIG_HOME}/git/ignore`), then a stable byte representation of the hardcoded fallbacks. Length-prefix each segment with `(u32_len, ASCII_name)` for unambiguous concatenation. Hash with `blake3::hash`.
- **Patterns to follow.** Existing `crates/rts-daemon/src/filter.rs:170-245` (`PrebuiltGitignore::build`) — same source paths, same precedence; this code just hashes them instead of compiling them into a matcher.
- **Execution note.** Test-first: identical content in different file orderings → same hash; bytes-different content → different hash.
- **Test scenarios.**
  - No gitignore files exist: hash == blake3 of empty stack + fallbacks. Stable across runs.
  - Workspace `.gitignore` edited by one byte: hash changes.
  - Ancestor `.gitignore` added: hash changes.
  - `XDG_CONFIG_HOME` set vs unset on Linux: doesn't change hash if file content is identical.
- **Verification.** `cargo test -p rts-daemon gitignore_hash` green.

### U3 — META schema extension + composite fingerprint

- **Goal.** META table gains 5 new keys (4 fingerprint parts + 1 reconciliation sentinel). `Fingerprint::current()` and `Fingerprint::stored(&store)` produce comparable values.
- **Files.** `crates/rts-daemon/src/store/schema.rs` (new META keys); `crates/rts-daemon/src/store/mod.rs` (read/write helpers); `crates/rts-daemon/src/fingerprint.rs` (`Fingerprint` struct + `compare` + `diff` for diagnostic invalidation reason).
- **Approach.** META is a single-bucket key-value redb table; add string-keyed entries. `Fingerprint { schema_version, binary_version, grammar_versions, gitignore_hash, combined: String }`. `Fingerprint::diff(stored, current) -> InvalidationReason` returns the first-mismatching part for diagnostics.
- **Patterns to follow.** `crates/rts-daemon/src/store/mod.rs:135-227` (existing `Store::open` + META reads for `SCHEMA_VERSION`); `store/schema.rs:13-130` (existing META layout).
- **Execution note.** Test-first: every diff path yields the expected `InvalidationReason::*`.
- **Test scenarios.**
  - Identical fingerprints: `combined` matches; `diff` returns `None`.
  - Schema bump: `diff` returns `SchemaVersion { old, new }`.
  - Binary version bump: `diff` returns `DaemonBinaryVersion { old, new }`.
  - Grammar bump for one language: `diff` returns `GrammarVersion { language, old, new }`.
  - Gitignore hash changes: `diff` returns `Gitignore`.
  - Missing fingerprint (older redb): `diff` returns `EmptyOrMissingFingerprint`.
- **Verification.** `cargo test -p rts-daemon fingerprint::diff` green; META keys appear in a round-trip test.

### U4 — `wipe_data_tables` (preserve META)

- **Goal.** `Store::wipe_data_tables(&mut self) -> Result<()>` clears all data tables (FILES, PATH_TO_FID, FID_TO_PATH, NAME_TO_SID, SID_TO_NAME, DEFS, FID_DEFS, REFS, FID_REFS, SID_REFS_OUT, SID_DOCS, UNRESOLVED_REFS, FID_UNRESOLVED) while preserving META.
- **Files.** `crates/rts-daemon/src/store/mod.rs` (new method; existing `remove_file` path on SCHEMA_VERSION_NEWER stays).
- **Approach.** Single redb write txn that opens each data table and removes all entries (or `delete_table` then recreate empty). `Durability::Immediate` commit.
- **Patterns to follow.** Existing `store/mod.rs:174-189` (file-level wipe) — the model; this version is table-level.
- **Execution note.** Test-first: confirm META survives wipe; confirm data tables are empty.
- **Test scenarios.**
  - Populated store → `wipe_data_tables` → META intact, FILES count == 0.
  - Schema-newer case still uses file-level wipe (refuses to open).
- **Verification.** `cargo test -p rts-daemon store::wipe_data_tables` green.

### U5 — Mount-time decision + reconciliation worker

- **Goal.** At `Workspace.Mount`, decide `MountSource` based on fingerprint comparison and FILES count, then route to reconciliation or cold-walk.
- **Files.** `crates/rts-daemon/src/methods/workspace.rs:145-213` (the decision branch); `crates/rts-daemon/src/reconciliation.rs` (new — the reconciliation worker).
- **Approach.** Pre-mount: compute current fingerprint. Open store. Read stored fingerprint. Compare. If match + FILES non-empty + `!RECONCILIATION_IN_PROGRESS`: set `META_RECONCILIATION_IN_PROGRESS = true`, spawn reconciliation worker (parallel to watcher start), record `MountSource::Rehydrate`. Else: `wipe_data_tables()`, set `MountSource::ColdWalk*` with reason, call `InitialWalkHandle::spawn` as today.
  
  Reconciliation worker walks `ignore::WalkBuilder` (matches the cold-walk semantics at `watcher.rs:299-307`), stats each file, compares to FILES table entries, emits synthetic `WatchEvent::FileChanged/FileAdded/FileDeleted` events to the writer pipeline. On completion: writes the new fingerprint to META, clears `META_RECONCILIATION_IN_PROGRESS`.

  `RTS_REHYDRATE_PARANOID=1` env var: on (mtime, size) match, also computes blake3 of file content; if differs from a stored content hash (added to FILES table — additive column), emit `FileChanged`. Off by default.
- **Patterns to follow.** `crates/rts-daemon/src/methods/workspace.rs:115-213` (existing mount path); `crates/rts-daemon/src/watcher.rs:267-364` (existing walker); `crates/rts-daemon/src/writer.rs:151-172` (existing batch flush after walk).
- **Execution note.** Test-first for each `MountSource` variant — see test scenarios below.
- **Test scenarios.**
  - First mount on empty state_dir: `ColdWalk`.
  - Second mount, no changes: `Rehydrate`. Latency under 100 ms p95 on 100k LOC.
  - Mount after `SCHEMA_VERSION` bump: `ColdWalkAfterInvalidation(SchemaVersion{...})`.
  - Mount after grammar version bump: `ColdWalkAfterInvalidation(GrammarVersion{...})`.
  - Mount after gitignore edit: `ColdWalkAfterInvalidation(Gitignore)`.
  - Mount after binary version bump: `ColdWalkAfterInvalidation(DaemonBinaryVersion{...})`.
  - Mount after kill-during-reconciliation (META has sentinel): `ColdWalkAfterCrash`.
  - Mount after `rm -rf state_dir`: `ColdWalk` (treated as first-ever).
  - Reconciliation re-parses only changed files (assertable via reconciliation worker emit log).
  - `RTS_REHYDRATE_PARANOID=1` + file with same (mtime, size) but different content: re-parsed.
- **Verification.** `cargo test -p rts-daemon methods::workspace::mount_source` green; manual bench on 100k LOC repo confirms latency target.

### U6 — `mount_source` + cache counters in `Daemon.Stats v2`

- **Goal.** `Daemon.Stats` response includes `mount_source` (current value), `rehydrate_attempts_total`, `rehydrate_successes_total`, `rehydrate_invalidations_by_reason`.
- **Files.** `crates/rts-daemon/src/methods/daemon.rs:140-151` (extend response struct); `crates/rts-daemon/src/state.rs` (extend `DaemonState` with `mount_source: AtomicCell<MountSource>` and `cache_counters: CacheCounters`); `crates/rts-daemon/src/state.rs` (extend `CallCounters::snapshot()` to merge cache_counters).
- **Approach.** Additive fields under existing `daemon_stats_v2` capability (no new capability string). Counters increment per Mount call.
- **Patterns to follow.** PR 001's pattern of additive `daemon_stats_v2` fields; existing `CallCounters` AtomicU64 pattern.
- **Execution note.** Test-first: round-trip test exercises every `mount_source` value.
- **Test scenarios.**
  - First call to `Daemon.Stats` after daemon spawn but before any mount: `mount_source` is absent or `null` (no mount yet).
  - After first mount: `mount_source = "cold_walk"`.
  - After rehydrate: `mount_source = "rehydrate"`; counters incremented.
  - After invalidation: `mount_source = "cold_walk_after_invalidation:<reason>"`.
- **Verification.** `cargo test -p rts-daemon methods::daemon::stats_v2_mount_source` green.

### U7 — Documentation + bench fixture

- **Goal.** `docs/protocol-v0.md` §5.4 (state dir) reaffirms the path convention; new appendix entry documents the rehydrate path; capability v2 entry lists the new fields. README's *Status* section gains the latency claim. A new bench fixture under `crates/rts-bench/benches/cold_mount.rs` measures rehydrate p95.
- **Files.** `docs/protocol-v0.md`; `README.md`; `crates/rts-bench/benches/cold_mount.rs` (new); `changelog.d/<NNNN>-persisted-cold-mount.md`.
- **Approach.** Pure docs + a small bench. README gets one new sentence under *Status*: *"Daemon startup: ~6 s cold-walk on first session, <100 ms thereafter (persisted snapshot via redb META fingerprint, v0.6+)."*
- **Patterns to follow.** Appendix F per-alpha additive log entries; existing `bench-results/` JSON outputs.
- **Verification.** Bench produces a JSON output that demonstrates the p95 target; docs lint clean.

## Requirements Trace

| ID  | Requirement (from origin) | Satisfied by | Notes |
|-----|---------------------------|--------------|-------|
| R1  | Persist post-cold-walk redb to XDG cache | U5 | **Path reframed:** reuse existing `state_dir_for` (XDG_STATE_HOME, not _CACHE_), per protocol-v0 §5.4. Redb is already there. |
| R2  | On startup: open snapshot, verify fingerprint, decide path | U5 | Decision logic at mount-time, before `InitialWalkHandle::spawn` |
| R3  | Composite fingerprint over (schema, binary, grammars, gitignore) | U1, U2, U3 | **Per-part columns** in META (not single hash) — enables diagnostic invalidation reasons |
| R4  | Rehydrate path: re-parse only changed files | U5 | mtime/size reconciliation worker |
| R5  | Snapshot writes at cold-walk-done + graceful shutdown | U5 | **Reframed:** the *data* is written continuously by redb; only the *fingerprint* is the snapshot atom |
| R6  | Atomic writes; per-table checksum | U5 | **Reframed:** redb already provides ACID + page checksums. No separate atomic-write needed; the brainstorm's claim is redundant. |
| R7  | Snapshot header + checksum-verify on load | U3 | **Reframed:** the META fingerprint *is* the header; redb already validates page checksums |
| R8  | File permissions 0600 + dir 0700 | (already enforced) | Existing daemon `umask(0077)`; no new code |
| R9  | First-query latency <100 ms p95 on healthy rehydrate | U5, U7 | Bench fixture in U7 |
| R10 | `mount_source` field in `Daemon.Stats` | U6 | Joins PR 001's `daemon_stats_v2` capability |
| R11 | `--reset-snapshot` flag clears the cache | U5 | Clears state_dir before mount; existing daemon flag scaffold |

## Acceptance Criteria

### Functional

- [ ] **AC1.** First mount on a fresh workspace produces `mount_source = "cold_walk"` and a populated META fingerprint.
- [ ] **AC2.** Restart the daemon without changes: second mount produces `mount_source = "rehydrate"` and skips `InitialWalkHandle::spawn`.
- [ ] **AC3.** Bump `SCHEMA_VERSION` constant between daemon binaries: next mount produces `cold_walk_after_invalidation:schema:N→M`.
- [ ] **AC4.** Bump a single tree-sitter grammar version: next mount produces `cold_walk_after_invalidation:grammar:<lang>:<old>→<new>`.
- [ ] **AC5.** Edit workspace `.gitignore`: next mount produces `cold_walk_after_invalidation:gitignore`.
- [ ] **AC6.** Bump daemon binary version (via build): next mount produces `cold_walk_after_invalidation:binary:<old>→<new>`.
- [ ] **AC7.** Kill daemon during reconciliation (signal between sentinel-set and fingerprint-write): next mount produces `cold_walk_after_crash` and re-walks.
- [ ] **AC8.** Kill daemon during cold-walk (no fingerprint ever written): next mount produces `cold_walk_after_invalidation:empty_or_missing_fingerprint`.
- [ ] **AC9.** Edit one file (changes mtime) between mounts: reconciliation re-parses only that file; `index_generation` increments by 1.
- [ ] **AC10.** Create a new file between mounts: reconciliation indexes it.
- [ ] **AC11.** Delete a file between mounts: reconciliation drops it from FILES.
- [ ] **AC12.** `RTS_REHYDRATE_PARANOID=1` with `git checkout` (mtime restored but content changed): re-parses the affected file. Without the flag: misses it (documented limitation).
- [ ] **AC13.** `rm -rf state_dir/<workspace_id>/` between mounts: next mount produces `cold_walk` (treated as first-ever).
- [ ] **AC14.** Move the workspace (`mv ~/src/foo ~/src/bar`): the new path produces a new `workspace_id` and a fresh `cold_walk` mount. Old state_dir orphaned (GC out of scope).
- [ ] **AC15.** `Daemon.Stats` includes `mount_source`, `rehydrate_attempts_total`, `rehydrate_successes_total`, `rehydrate_invalidations_by_reason`. All under `daemon_stats_v2` capability.
- [ ] **AC16.** All redb tables (including UNRESOLVED_REFS / FID_UNRESOLVED introduced in #103) survive rehydrate. Live-edit ref correctness from #103 is preserved.

### Non-Functional

- [ ] **AC17.** Healthy rehydrate p95 latency `<100 ms` on a 100k LOC workspace where no files changed (bench fixture in U7).
- [ ] **AC18.** Cold-walk latency unchanged ±5% vs pre-PR baseline (no regression on the cold-walk path).
- [ ] **AC19.** No new crate deps beyond `toml` (build.rs only, build-dep).
- [ ] **AC20.** Reconciliation worker memory footprint scales linearly with FILES count, not workspace size; bounded buffer for per-file events.

### Quality Gates

- [ ] **AC21.** `cargo test --workspace` green; all `MountSource` variants covered.
- [ ] **AC22.** `cargo clippy --workspace --all-targets -- -D warnings` clean.
- [ ] **AC23.** `docs/protocol-v0.md` §5.4 updated; rehydrate path documented in §15 appendix; capability v2 entry lists `mount_source` + counters.
- [ ] **AC24.** `changelog.d/<NNNN>-persisted-cold-mount.md` fragment lands.
- [ ] **AC25.** README *Status* line gains the latency claim.

## Success Metrics

- **First-week:** README's Status line lands; one closed issue references the new latency in a "feels instant now" note.
- **Cache hit rate:** `rehydrate_successes / rehydrate_attempts >= 0.95` on the author's dev workspace across 100 daemon spawns over 14 days.
- **Latency:** rehydrate p95 <100 ms on 100k LOC; cold-walk latency unchanged.
- **agent-bench:** wall-clock per-task latency for tasks 2-N in a shared-workspace sequence drops measurably vs Phase 2 PR-A baseline; visible in `bench-results/` JSON.

## Dependencies & Risks

- **PR 001 (doctor) must land first.** This plan extends `daemon_stats_v2` capability with `mount_source` + cache counters. Without PR 001, the capability doesn't exist. Hard dependency.
- **PR 002 (grep v2) lands second.** Both PR 002 and PR 003 touch `CallCounters`/Daemon.Stats but in non-overlapping ways. Sequence: 001 → 002 → 003. Rebase strictly.
- **build.rs dependency.** `crates/rts-daemon/build.rs` adds a build-time `toml` parse. If `crates/rts-core/Cargo.toml` is malformed, the daemon won't build. Low risk; one-line catch-up if it ever breaks.
- **mtime+size is not content-equivalent.** Documented limitation. `RTS_REHYDRATE_PARANOID=1` is the escape valve. If support requests demand it, promote to default in a follow-up PR.
- **gitignore content hash is byte-equal only.** A whitespace-only edit of `.gitignore` invalidates the snapshot. Pragmatic compromise for v1; semantic normalization is a possible v2.
- **State_dir GC is out of scope.** Workspaces that move or are deleted leak their state_dir. Disk growth is bounded by the count of distinct workspaces the user has indexed; a future `rts-bench doctor --gc-orphaned-state` or similar can address.
- **Atomic-write inside redb.** redb's ACID semantics cover all the META writes. No separate tmpfile+rename for the fingerprint metadata. The brainstorm's R6 is redundant; the plan documents this rather than implementing redundant safety.
- **macOS path alignment.** Existing daemon uses `~/Library/Caches/rts/<id>/db.redb` (per `workspace.rs:249-266`). Plan does NOT move this; alignment with brainstorm's `~/.cache/rts/<hash>/` was wrong. Protocol-v0 §5.4 is authoritative.

## Scope Boundaries

The following are explicit non-goals for this PR:

- **No relocation of the redb file.** Reuse existing `state_dir_for`. Brainstorm R1 wording corrected.
- **No real-time mirroring** of redb edits beyond what redb already does (ACID transactions). Already rejected in brainstorm as challenger.
- **No in-tree cache** (`<workspace>/.rts-cache/`). Already rejected.
- **No multi-machine snapshot sharing.** Workspace-id is per-machine (dev/inode).
- **No state_dir garbage collection.** Disk growth is documented as a known issue.
- **No semantic gitignore normalization.** Byte-equal content only.
- **No content-hash by default.** Opt-in via `RTS_REHYDRATE_PARANOID=1`.
- **No grammar hot-reload.** Tree-sitter grammars are statically linked.
- **No `Daemon.Reset` RPC.** `--reset-snapshot` CLI flag is the only knob (per R11).

## Sources & References

- **Origin document:** [docs/brainstorms/2026-05-18-persisted-cold-mount-requirements.md](../brainstorms/2026-05-18-persisted-cold-mount-requirements.md). Carried-forward decisions (with research-driven corrections):
  1. Full redb snapshot, mtime-rehydrate — Key Decisions §1 (redb already persisted; plan adds fingerprint gate)
  2. XDG cache dir keyed by workspace hash — Key Decisions §2 (**corrected:** reuse `state_dir_for`; XDG_STATE_HOME not _CACHE_)
  3. Single composite fingerprint — Key Decisions §3 (**corrected:** per-part columns + combined hash for diagnostics)
  4. Write at cold-walk-done + graceful shutdown; checksum-verify on load — Key Decisions §4 (**corrected:** only the fingerprint is the snapshot atom; redb data writes are continuous and ACID)
- **Research consolidations:**
  - `crates/rts-daemon/src/store/mod.rs:42` — `SCHEMA_VERSION = 3` (the prior META key)
  - `crates/rts-daemon/src/store/mod.rs:135-227` — `Store::open` schema check + rebuild path
  - `crates/rts-daemon/src/store/schema.rs:13-130` — all redb tables (META has the single SCHEMA_VERSION key today)
  - `crates/rts-daemon/src/methods/workspace.rs:117-137` — state_dir mount path
  - `crates/rts-daemon/src/methods/workspace.rs:145-213` — **the decision site** (where `InitialWalkHandle::spawn` fires unconditionally today)
  - `crates/rts-daemon/src/workspace.rs:22-148` — `WorkspaceFingerprint` (blake3 over dev/inode/path)
  - `crates/rts-daemon/src/workspace.rs:239-266` — `state_dir_for` / `state_home_root`
  - `crates/rts-daemon/src/watcher.rs:88-99` — `WatchEvent::ColdWalkComplete`
  - `crates/rts-daemon/src/watcher.rs:267-364` — initial walk
  - `crates/rts-daemon/src/writer.rs:102-114` — writer cancellation flush
  - `crates/rts-daemon/src/writer.rs:151-172` — cold-walk-complete consumer
  - `crates/rts-daemon/src/filter.rs:170-245` — `PrebuiltGitignore::build` (gitignore source paths and precedence)
  - `crates/rts-core/Cargo.toml:18-31` — 12 tree-sitter grammar pins (the source for build.rs)
  - `crates/rts-daemon/Cargo.toml:40-80` — existing deps (`blake3`, `dirs = "5"`, `redb = "2"`, `tempfile = "3"`)
  - `docs/protocol-v0.md` §5.4 — canonical state path (XDG_STATE_HOME / Library/Caches)
  - `docs/protocol-v0.md` §5.2 — workspace_id_hex definition
  - `docs/protocol-v0.md` §15.1 — schema bump rebuild semantics (extended here for fingerprint)
- **Related PRs / plans:**
  - **PR 001** (`docs/plans/2026-05-18-001-feat-rts-bench-doctor-plan.md`) — `daemon_stats_v2` capability (hard dependency).
  - **PR 002** (`docs/plans/2026-05-18-002-feat-index-grep-v2-plan.md`) — `CallCounters` extensions (rebased before PR 003).
  - #103 (UNRESOLVED_REFS / FID_UNRESOLVED tables — survive rehydrate per AC16)

## Deferred to Implementation

All 10 brainstorm-deferred questions resolved here:

- **[Affects R1]** Cache path on macOS: aligned to existing `state_dir_for` (`~/Library/Caches/rts/<id>/`), NOT a new XDG_CACHE_HOME path. Protocol-v0 §5.4 is authoritative.
- **[Affects R3]** Grammar version source: tree-sitter-LANG **crate** versions via build.rs injection. NOT runtime `Language::version()` (C ABI number, too coarse).
- **[Affects R3]** gitignore content hashing: byte-equal content only; segments concatenated in walker-precedence order with length-prefix headers. Semantic normalization is v2.
- **[Affects R7]** Snapshot header: META fingerprint columns + redb's own page checksums. No separate header file or sidecar manifest.
- **[Affects R4]** Reconciliation walk strategy: top-down via existing `ignore::WalkBuilder` (matches cold-walk semantics). FILES table is iterated post-walk to find deleted entries.
- **[Affects R5]** Atomic write on non-atomic FS: redb manages this internally. The plan does NOT add a separate tmpfile+rename for fingerprint; the META writes are inside redb txns.
- **[Affects R9]** Rehydrate latency budget breakdown: redb open ~5ms, fingerprint read ~1ms, file-stat scan of 10k files ~50ms, incremental re-parse of changed files (variable). 100 ms p95 is the worst-case test budget.
- **[Affects R5]** Snapshot-on-shutdown timing: bounded to 2s. If META write doesn't complete in 2s, daemon exit proceeds anyway; next mount sees inconsistent state and falls back to `cold_walk_after_invalidation:incomplete_fingerprint`.
- **[Affects R3]** Daemon binary version: full semver string (`env!("CARGO_PKG_VERSION")`). Patch bumps invalidate; this is conservative but safe.
- **[Affects R10]** doctor's `workspace_index` section consumes `mount_source` from `Daemon.Stats v2`. Per PR 001's plan U6, this is already on the doctor surface.

## Post-Deploy Monitoring & Validation

- **What to monitor/search**
  - Logs: daemon `tracing` output at `info` for every Mount with the resolved `MountSource`. At `warn` for any fingerprint mismatch or reconciliation-in-progress on next startup.
  - Metrics/Dashboards: `Daemon.Stats.mount_source` value, `rehydrate_successes / rehydrate_attempts` ratio over time, `rehydrate_invalidations_by_reason` distribution.
- **Validation checks (queries/commands)**
  - Manual: `rts-bench doctor` shows `mount_source` in the workspace_index section.
  - Bench: `cargo bench -p rts-bench cold_mount` shows p95 <100ms on a healthy rehydrate.
  - Round-trip: integration test exercises every `MountSource` variant.
- **Expected healthy behavior**
  - `rehydrate_successes / rehydrate_attempts >= 0.95` after the first week.
  - p95 rehydrate latency <100ms on 100k LOC workspaces.
  - No regression in cold-walk latency.
- **Failure signal(s) / rollback trigger**
  - Spike in `cold_walk_after_invalidation:*` rates → check whether a recent grammar bump or schema bump is responsible (expected) vs unexpected drift (regression).
  - Spike in `cold_walk_after_crash` → daemon is being killed mid-reconciliation; investigate user-side `kill -9` patterns.
  - Any panic in `reconciliation.rs` → revert. The redb file is untouched by the rehydrate-decide branch on the cold-walk path, so revert is safe.
- **Validation window & owner**
  - 14-day window post-merge; author monitors.

---

## Plan Status

- **Detail level:** MORE (standard plan)
- **SpecFlow:** complete; 12 edge cases and 4 ambiguities resolved
- **Brainstorm corrections:** 5 (path, hash structure, snapshot atom, table preservation, atomic-write redundancy)
- **Deepen:** not requested
- **Coordination:** PR 001 → PR 002 → PR 003 sequencing required
- **Next:** `/ce:work` on the three plans in order, starting with PR 001 (doctor).
