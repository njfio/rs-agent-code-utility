---
date: 2026-05-18
topic: persisted-cold-mount
---

# Persisted cold-mount index

## Problem Frame

The daemon walks the workspace once on startup (~1 s on 10k LOC, ~6 s on 100k) and watches for changes after that. The watcher keeps the index live during a session, but the daemon idles out after 10 minutes (per README) and gets re-spawned on the next agent invocation — paying the full cold-walk cost again.

For a 100k LOC workspace, that's a ~6 s delay before the *first* query of every session can be answered. It's the only user-perceived latency in rts. The daemon already uses redb as its persistence engine; the data is shaped right, the schema is versioned (`SCHEMA_VERSION` bumped to 3 in #103). What's missing is reuse of that on-disk state across daemon restarts: today the daemon walks from zero whether the index existed five seconds ago or never.

A persisted cold-mount index reuses the post-cold-walk redb snapshot, validates that it's still relevant via a composite fingerprint, and re-parses only files whose `(mtime, size)` changed since the snapshot was written. The target effect: *"open editor, ask question"* feels instant for the first query of every session, not just the second.

## Requirements

- **R1.** The daemon persists its post-cold-walk redb state to an XDG cache directory keyed by a stable hash of the canonical workspace path: `${XDG_CACHE_HOME:-~/.cache}/rts/<blake3(canonical_workspace_path)>/snapshot.redb`. On macOS, resolves to `~/Library/Caches/rts/<hash>/snapshot.redb` (exact path resolution deferred to planning).
- **R2.** On daemon startup with a non-empty cache directory:
  1. Open the snapshot file and read its header.
  2. Verify the snapshot's stored fingerprint matches the current fingerprint (see R3).
  3. On match: enter **rehydrate path** (R4).
  4. On mismatch or read error: enter **cold-walk path** (existing behavior), logging the reason for the bypass.
- **R3.** The fingerprint is a single composite value covering everything that could invalidate cached state:
  - `SCHEMA_VERSION` (redb table layout)
  - daemon binary version (semver string or `git describe`)
  - the version of every tree-sitter grammar crate currently linked
  - hash of the workspace's effective `.gitignore` content (including parent-dir/global gitignores)
  Any drift triggers a full cold walk.
- **R4.** The **rehydrate path** behaves as follows:
  1. Open the redb snapshot in-place (no copy).
  2. Scan the workspace and compute `(mtime, size)` for each file the snapshot claims to know about.
  3. Re-parse and re-index only files whose `(mtime, size)` differs from the snapshot, plus files present on disk but absent from the snapshot.
  4. Drop snapshot entries for files no longer present on disk.
  5. Start the watcher as today.
- **R5.** Snapshot writes happen at exactly two points:
  - Immediately after the initial cold-walk completes (first write).
  - On graceful daemon shutdown (SIGTERM, idle-timeout, or explicit stop).
  Live edits between these two points are NOT flushed to the snapshot file in real time. The in-memory redb table is the source of truth between writes; if the daemon dies ungracefully (SIGKILL, panic), the snapshot at most loses session-window edits, which are re-derivable from the workspace on next startup.
- **R6.** Snapshot writes are atomic: write to `snapshot.redb.tmp` in the same directory, fsync, then `rename` to `snapshot.redb`. A reader that opens during the write window sees either the old snapshot or the new one — never a torn file.
- **R7.** The snapshot file has a small header (or sidecar manifest, choice deferred to planning) carrying:
  - magic bytes / format identifier
  - fingerprint (R3)
  - write timestamp
  - per-table checksum (blake3 of the serialized table contents)
  At load time, the daemon verifies the per-table checksum. A mismatch causes the snapshot to be discarded (cold-walk path) AND the cache directory cleared so subsequent startups don't retry the broken snapshot.
- **R8.** Snapshot file permissions are `0600` (owner-only) and the cache directory is `0700`. The daemon's existing `umask(0077)` invariant already enforces this; planning confirms.
- **R9.** First-query latency on a healthy rehydrate: target **p95 < 100 ms** on a 100k LOC workspace where no files changed between sessions. This is the user-perceived metric; if the snapshot is good but rehydrate is slow, the feature has failed its purpose.
- **R10.** `Daemon.Stats` (#104) exposes a new field, `mount_source`, with one of these values from the most recent startup:
  - `cold_walk` — no snapshot present
  - `rehydrate` — snapshot rehydrated successfully
  - `cold_walk_after_invalidation:<reason>` — snapshot present but invalidated (schema, grammar, gitignore, checksum)
  This lets agent-bench, `rts-bench doctor` (separate brainstorm), and operators see whether the snapshot is doing its job.
- **R11.** When the user explicitly wants a clean rebuild, `rts-daemon --reset-snapshot` clears the cache directory before starting. Single flag; no subcommand. Existing daemon flags remain unchanged.

## Success Criteria

- **SC1.** On a 100k LOC workspace, the *second* daemon startup of a session sequence (i.e., the one that finds a valid snapshot) reaches "first query answerable" in **p95 < 100 ms**, versus ~6 s today. Cold walk on first-ever startup of a workspace is unchanged.
- **SC2.** A deliberate `SCHEMA_VERSION` bump or grammar-version bump invalidates the snapshot transparently: the next daemon startup logs the invalidation reason, performs a full cold walk, writes a new snapshot, and subsequent startups rehydrate from the new snapshot. No user intervention needed.
- **SC3.** The README's *Status* / *Quick start* section gains a one-line claim: *"Daemon startup: ~6 s cold-walk on first session, sub-100 ms thereafter (persisted snapshot)."*
- **SC4.** In the agent-bench harness, per-task wall-clock latency for tasks that share a workspace with a previous task drops measurably (the cold-mount tax is gone for tasks 2-N). Visible in the JSON output without harness changes.

## Scope Boundaries

- **Out of scope (v1):** real-time mirroring of redb edits to the snapshot file (rejected challenger). Doubles write amplification for a marginal `kill -9` recovery benefit; the live-edit path is fast enough that a re-walk after ungraceful exit is acceptable.
- **Out of scope (v1):** in-tree cache location (`<workspace>/.rts-cache/`). Adds gitignore pressure and multi-user-on-shared-workspace foot-guns. XDG cache is canonical for this v1; a configurable cache dir is a possible v2.
- **Out of scope (v1):** snapshot sharing across machines (rsync, scp, dotfile sync). Workspace-path-keyed snapshots are machine-local by design; cross-machine sharing involves canonical-path mapping and clock-skew handling that doesn't belong in v1.
- **Out of scope (v1):** snapshot garbage collection. Old snapshots accumulate one per workspace; a `rts-bench doctor`-adjacent pruning command is a separate feature.
- **Out of scope (v1):** snapshot compression. redb is already compact for this workload; zstd-on-disk adds CPU at every read for marginal disk savings. Revisit if snapshots get large in practice.
- **Out of scope (v1):** multi-daemon coordination on the same snapshot. The existing per-workspace daemon model already enforces one daemon per workspace; if a second daemon tries to write, the second one loses (atomic rename semantics). Cross-process locking on the snapshot file is a v2 if it becomes a problem.
- **Out of scope (v1):** snapshot for multi-workspace daemons (federated index). Tracked separately under ideation idea #8 (rejected, deferred to its own round).
- **Out of scope (v1):** an MCP-callable "reset snapshot" command. The CLI flag `--reset-snapshot` is the only knob; agents don't get to clear the cache.

## Key Decisions

- **Full redb snapshot over per-file parse cache or "just the file list."** The post-cold-walk redb is the most expensive thing to rebuild (PageRank closure, call graph, enclosing-name resolution). Caching just parsed trees would still pay the graph-build cost on every startup. Caching just the file list saves ~10% of cold-walk. Snapshotting the whole redb captures the full investment.
- **XDG cache, machine-local over in-tree.** Cleaner: no repo pollution, no `.gitignore` churn, no multi-user-on-shared-workspace conflicts. Lost on `mv`/`rsync` of the workspace, which triggers a one-time cold walk — acceptable cost for the operational clarity.
- **Single composite fingerprint over per-language invalidation.** One hash, one decision: "do these bytes still apply to this state of the world?" Per-language is more efficient on a grammar bump but introduces per-table-per-language version tracking. The cost of a full re-walk after a grammar bump is bounded (one cold walk per grammar bump per workspace, paid once); the cost of getting per-language invalidation wrong is silent corruption.
- **Write at cold-walk-done + graceful shutdown; checksum-verify on load.** Two writes per daemon lifetime; no write amplification on live edits; ungraceful exit at worst loses one session's incremental updates, which are re-derivable from disk. Checksum verification turns "I trust the cache" into a per-load assertion.
- **`mount_source` telemetry.** Without it, we can't tell whether the snapshot is doing its job. The agent-bench harness and `doctor` both want to know. Costs one field in `Daemon.Stats`.

## Dependencies / Assumptions

- The daemon's redb backing store is currently a *temporary* on-disk file (or in-memory) that doesn't survive restarts. The brainstorm assumes the work is to *promote* this to a stable, hashable location — not to invent persistence from scratch. (To confirm at planning by reading `crates/rts-daemon/src/store/mod.rs`.)
- redb's file format is stable enough across patch versions to be cached on disk and read back later. Major redb version bumps are part of the daemon binary version in the fingerprint.
- All linked tree-sitter grammars expose a version string (or compile-time `version()` callable) that we can capture into the fingerprint. Most tree-sitter language crates do; verify per-grammar at planning.
- The `.gitignore` content hash is stable: parent-dir gitignores and global gitignores (e.g., `~/.config/git/ignore`) are part of the effective file list, so their content goes into the fingerprint.
- `Daemon.Stats` is the canonical surface for the new `mount_source` field; protocol-v0 evolution rules govern how it's exposed.

## Outstanding Questions

### Resolve Before Planning

*(none — all product-level decisions are made)*

### Deferred to Planning

- **[Affects R1]** **[Technical]** Exact cache path resolution on macOS: strict XDG (`$XDG_CACHE_HOME` then `~/.cache`) or platform-native (`~/Library/Caches`)? Other rust tooling on macOS is split; pick one and document it.
- **[Affects R3]** **[Needs research]** How does each linked tree-sitter grammar crate expose its version? Some have `tree_sitter_LANG::LANGUAGE_VERSION`, others have `Cargo.toml` versions only. The fingerprint needs a uniform source per grammar.
- **[Affects R3]** **[Technical]** `.gitignore` content hashing: include parent-dir ancestors? Include the global gitignore? Order-sensitive (concatenation order matters)? Whitespace-normalized? Recommend strict bytewise concatenation in walk order, no normalization.
- **[Affects R7]** **[Technical]** Snapshot header layout: in-line at the start of the redb file (custom magic + offset), or sidecar `snapshot.meta` JSON next to `snapshot.redb`? Sidecar is simpler to evolve; in-line is harder to corrupt independently.
- **[Affects R4]** **[Technical]** Rehydrate-path file-list scan: do we walk the workspace top-down (like cold walk) or iterate the snapshot's known files and stat each? The first finds new files faster; the second is incremental in the steady state. Likely both, run in parallel.
- **[Affects R5]** **[Technical]** Atomic write on filesystems where rename-over-existing isn't atomic (some FUSE, some network FS): is there a fallback? Accept that snapshot reuse on non-atomic FS is best-effort and falls back to cold walk on checksum mismatch.
- **[Affects R9]** **[Technical]** Concrete rehydrate-path latency budget breakdown: redb open (≈5 ms?), header verify (≈1 ms), stat scan of 10k files (≈50 ms?), incremental re-parse of changed files (variable). Quantify in planning so SC1 is testable.
- **[Affects R5]** **[Technical]** Snapshot-on-shutdown timing: bound how long graceful shutdown will wait for the snapshot write. If it takes >2 s, abort the write (next startup will cold-walk). Don't hang daemon shutdown on slow disk.
- **[Affects R3]** **[Product]** Daemon binary version in the fingerprint: full semver (any patch bump invalidates), or just major.minor? Patch bumps usually don't change on-disk shape, but they sometimes fix indexer bugs that re-parsed files would benefit from. Lean toward full version for safety; profile if it's actually costly.
- **[Affects R10]** **[Product]** Is `mount_source` exposed in the `rts-bench doctor` workspace-state section (brainstorm #1)? Strongly recommend yes — doctor is the natural place to see "your snapshot is fresh / stale / missing."

## Next Steps

→ All three queued brainstorms are now drafted (`rts-doctor`, `index-grep-v2`, `persisted-cold-mount`). Recommended order for `/ce:plan`: doctor first (lowest complexity, fastest to ship and gives field signal for the other two), then `index-grep-v2` (largest value-prop win, real adoption-shifter), then persisted cold-mount (deepest invariants, benefits from doctor's `mount_source` surface).
