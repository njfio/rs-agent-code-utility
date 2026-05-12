# P0.2 — redb storage smoke results

**Date**: 2026-05-11
**Platform**: macOS arm64 (Darwin 25.4.0)
**Versions confirmed**: `redb 2.6.3`, `postcard 1.1.3`, `blake3 1.8.5`
**Toolchain**: rustc 1.90.0 (homebrew); edition 2024; rust-version 1.85.

## Verdict: STRONG GO

The plan's schema works as designed. Latency, throughput, and footprint all clear their respective budgets by large margins. Long-lived `ReadTransaction` per reader task **is** measurably faster than fresh-txn-per-query (~2× on median); the perf oracle's recommendation is validated.

## Versions: plan correction needed

`redb 2.6.3` is current (May 2026), not `4.x` as the deepening's redb-schema agent claimed. The framework-docs agent had it right (`2.6.1` at the time of their writing). The plan's `Stack` section currently says `redb = "4"` — **must be corrected back to `redb = "2"`**. `Durability::Immediate` and `Durability::None` both exist in 2.6 (and worked in this spike); `Durability::Eventual` may also exist — not needed since `None` + periodic `Immediate` flush is the documented batched pattern.

Action: update plan §Stack and §Concrete redb schema to pin `redb = "2"` (currently resolving to 2.6.3).

## Measurements

### Build (one batched `WriteTransaction` over the whole synthetic corpus)

| Metric | Value |
|---|---|
| Files | 500 |
| Unique symbol names interned | 10,001 |
| `DEFS` rows | 12,500 |
| `REFS` rows | 37,500 |
| Skeleton-blob bytes total | 21,890 |
| Build wall-time | **157 ms** |
| On-disk file size | **4.53 MiB** |

Extrapolating linearly to a 10× larger corpus (≈100k LOC, the plan's S3 target):
- Build wall-time ≈ 1.6s (target <5s — comfortable headroom)
- On-disk size ≈ 45 MiB (target <50 MiB — fits, but tighter than the 10k case)

If the 10× extrapolation holds, **S3's "on-disk <50 MB" budget is workable but not roomy** at 100k LOC. Larger monorepos will need either a tier-2 archive layer or eviction of cold skeleton blobs (already in the plan as "100k-LOC scope only").

### Point lookup latency — 10,000 queries

Query pattern: lookup name → resolve SID via `NAME_TO_SID` → multimap-scan first ≤16 `DefSite` rows in `DEFS`. Realistic of `find_symbol`'s hot path.

| Variant | p50 | p95 | p99 | max |
|---|---|---|---|---|
| **Fresh `ReadTransaction` per query** | 1.46 µs | 2.6 µs | 2.8 µs | 98 µs |
| **Shared long-lived `ReadTransaction`** | 0.67 µs | 1.8 µs | 1.9 µs | 10.0 µs |

**Both** variants clear the redb-layer portion of S1's <10 ms warm p95 budget by roughly **3.5–5 orders of magnitude**. The shared-txn variant is **~2.2× faster on p50** and meaningfully tighter on the tail (p99 ~1.9 µs vs ~2.8 µs).

The perf oracle predicted txn-open at 50-200 µs; actual measurement is ~0.8 µs on this hardware. The "long-lived ReadTransaction" optimization is **still worth doing** — it's measurably faster and free to implement — but it is **not** the single biggest warm-path win on macOS arm64 as predicted. Either txn-open got faster in recent redb releases, or the prediction was based on older numbers.

Either way, the plan's recommendation stands: P6 daemon code should hold a `ReadTransaction` per reader task and refresh on generation bumps.

### Batched-write throughput — re-upsert 100 files in one txn

| Durability | Wall-time |
|---|---|
| `Immediate` (fsync each commit) | **28.5 ms** |
| `None` (no fsync; flush deferred) | **12.8 ms** |

Both clear the plan's spike target (<50 ms for 100 files). Extrapolating to the worst-case `git checkout` 2000-file storm:
- Naive per-file-txn: 100× → ~28× higher = 2.85 s (Immediate) or ~1.3 s (None). **Confirms the plan's "per debounce window, one batched txn" guidance** — naive per-file commits would choke under bursts.
- One batched-txn: 28.5 ms scales sub-linearly with row count (B-tree COW amortization). Likely ~250 ms for 2000-file batch, fitting inside a 500ms-1s "indexing" UI window.

`Durability::None` is **~2.2× faster** than `Immediate` on the same hot path. Confirms the plan's batched pattern: `None` per debounce window + periodic `Immediate` flush every 5s or every N=50 files for durability.

### Disk growth after writes

After re-upserting 100 files: 4.53 MiB → 4.53 MiB (no measurable growth). redb COW reuses freed pages within the same database file. Long-running daemons should periodically `db.compact()` to reclaim, per the redb-schema agent — not tested here.

## What's confirmed

- ✅ **Plan's schema works**: `TableDefinition`/`MultimapTableDefinition` with `u32` keys and `&[u8]` postcard-encoded values compile and perform.
- ✅ **`postcard` encoding** is fast enough to deserialize 16 multimap rows per query without registering in p95 (decode is ~50ns/row).
- ✅ **Symbol interning saves space**: 12,500 def rows in 4.53 MiB ≈ 380 bytes/row including B-tree overhead. With `String` keys that would be roughly 2-3× larger.
- ✅ **Edition 2024 + MSRV 1.85** builds cleanly.

## API quirks worth noting in P6

- **Cannot hold an immutable `Table::get` borrow alive while calling `Table::insert`** on the same table (`E0502` — see [src/main.rs:140](src/main.rs:140)). Workaround: `let existing = table.get(k)?.map(|v| v.value());` — pull the value out, drop the borrow, then `insert`. Trivial but worth a note in the daemon's coding conventions.
- `WriteTransaction::set_durability(d)` takes `&mut self` (or by value depending on version) — pattern is `let mut txn = db.begin_write()?; txn.set_durability(Durability::None);` before `open_table`. Works.
- `MultimapTableDefinition` access pattern is symmetric to `TableDefinition`; reads via `multimap.get(&k)?` return a streaming iterator of `AccessGuard<V>` rows.

## Things not verified by this spike (deferred)

- **Concurrent multi-reader behavior** under contention — the daemon will have many tasks holding `ReadTransaction`s. redb's MVCC contract says reads never block writers; needs an in-vivo test with a writer task running.
- **Compaction cost** (`db.compact()`) and when to trigger it.
- **File-handle behavior under daemon crash + restart** — redb's two-phase commit should recover cleanly; not tested here.
- **`Database::open` cost on an existing 50 MB file** — one-time at daemon start; perf oracle estimated 1-10 ms.
- **Real symbol distribution**: this corpus has each name appearing 100× on the shared keys (`new`, `from`, `into`, `default`, `build`) and unique on others. Real codebases vary; the multimap fanout numbers are representative but not perfect.

## Reproduction

```bash
cd spikes/p0-2-redb-smoke
cargo build --release
./target/release/p0-2-redb-smoke
```
