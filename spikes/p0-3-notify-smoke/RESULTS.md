# P0.3 — notify + notify-debouncer-full smoke results

**Date**: 2026-05-11
**Platform**: macOS arm64 (Darwin 25.4.0)
**Versions confirmed**: `notify 8.2.0`, `notify-debouncer-full 0.7.0`, `notify-types 2.1.0`, `file-id 0.2.3`
**Toolchain**: rustc 1.90.0 (homebrew); edition 2024; rust-version 1.85.

## Verdict: PARTIAL GO — needs macOS rename workaround documented in the plan

The 150ms debounce window, overflow signal, and basic event taxonomy all work as expected. **However, `fs::rename` on macOS does NOT surface as `EventKind::Modify(ModifyKind::Name(RenameMode::*))`** in this configuration, contradicting the framework-docs agent's framework guidance and what the plan currently assumes for rename pairing.

## Measurements

| Scenario | Ops | Wall-time (writes) | Batches delivered | First-batch latency | Counts |
|---|---|---|---|---|---|
| Storm: 500 fresh creates | 500 | 54.9 ms | 3 | 94.5 ms | 503 creates, 2 modifies |
| Modify-in-place: 200 files | 200 | — | 1 | 188.6 ms | **200 "creates"** (not Modify) |
| Atomic-rename (write tmp + rename): 200 | 200 | — | 2 | 183.9 ms | **0 RenameMode**; 400 Create + 600 Modify + 400 Other |
| Cross-dir rename: 100 | 100 | — | 1 | 188.4 ms | **0 RenameMode**; 100 Create + 200 Other |
| Editor swap decoys: 7 files | 7 | — | 1 | 180.5 ms | 7 creates |

First-batch latency floors at ~94-188 ms (consistent with the 150 ms debounce window plus a ~30-80 ms FSEvents coalesce delay).

## What's confirmed

- ✅ **Debounce coalescing**: 500 rapid creates → 3 batches (~167 ops/batch). Production daemon will see large batches under burst load.
- ✅ **`new_debouncer(timeout, tick_rate, handler)` API** signature works as the framework-docs agent described.
- ✅ **`DebouncedEvent.event.kind`** matches `EventKind::{Create, Modify(Data), Modify(Name(_)), Remove}` taxonomy.
- ✅ **`need_rescan()` is callable** on every event for overflow detection (no overflow triggered here; would need a `git checkout` of 100k+ files to verify in vivo).
- ✅ **Editor swap decoys show up** in the event stream — the pre-filter must run inside our event handler, the debouncer doesn't drop them.
- ✅ **Edition 2024, MSRV 1.85** builds cleanly on rustc 1.90 with `notify-debouncer-full 0.7.0`.

## What's surprising / contradicts prior research

### 1. macOS produces no `RenameMode` events for `fs::rename` (HIGH-impact finding)

The framework-docs research agent confidently described pattern-matching on `RenameMode::Both`/`From`/`To`/`Any`. **On macOS in this configuration, none of those variants fire** for either atomic-rename (write-tmp + rename) or cross-directory rename. The events instead come through as a `Modify(Data)` on the new path plus an `Other` event.

This appears to be a macOS FSEvents limitation: FSEvents reports file-system changes by inode and path coalesced; `notify-debouncer-full`'s file-id cache is supposed to pair them, but the pairing failed for all 300 rename operations in this run. The framework-docs agent's `match` arms on `RenameMode::*` would silently drop every rename in production.

**Plan implications:**
- The daemon's rename-detection design **cannot rely on `RenameMode::Both`** alone. It needs a secondary path-matching strategy:
  - Maintain an internal `path → blake3(content_first_64KiB)` map updated on every event.
  - On a `Create` event for a previously-unseen path, look up the content hash; if it matches a recently-`Remove`d path, treat as a rename and avoid re-parsing.
  - For atomic-rename (write-temp + rename-over), the destination's content matches the temp's pre-rename content — also detectable via hash.
- Alternatively, accept that renames don't get paired on macOS and just re-parse the file under its new name. Cost: a redundant parse per rename. Acceptable for v1.
- **Recommend in the plan**: ship the content-hash fallback path detection from day one; do not depend on `RenameMode` events on macOS.

### 2. `fs::write` of an existing file reports as `Create`, not `Modify(Data)`

In the modify-in-place scenario, 200 writes to existing files produced 200 `Create` events and zero `Modify` events. On macOS FSEvents, "atomically replaced or recreated" is the default and there is no in-place modify reported via the watcher — only a fresh inode/path entry.

**Plan implication**: the daemon's event handler should treat `Create` and `Modify(Data)` symmetrically (re-parse + upsert). Do not branch on event kind to decide whether to re-parse; branch only on the path and "have we seen this content before."

### 3. Storm-create produces 3 batches, not 1

500 creates in 54 ms wall-time still hit the debouncer over multiple 150 ms windows because the writes themselves spread the FSEvents stream over ~55 ms plus a coalesce tail. Burst coalescing is good but not perfect — the daemon should size its mpsc buffer to handle several hundred events per batch and possibly several batches per logical "save storm."

## Action items rolled forward into the plan (P5/P6)

- [ ] Document on-macOS rename behavior in `protocol-v0.md`: renames surface as Create+Modify+Other, not `RenameMode::*`.
- [ ] Add content-hash-based rename-detection as a first-class path in the daemon's watcher event handler (P6).
- [ ] Update the plan's "Watcher" subsection to remove the implication that `RenameMode::Both` rename pairing is the primary detection mechanism on macOS.
- [ ] In a future test on Linux (inotify), verify whether `RenameMode::Both`/`From`/`To` does fire — the macOS behavior may not generalize.
- [ ] Treat `Create` and `Modify(Data)` symmetrically in the daemon's event-handler dispatch.

## Things not verified by this spike (deferred)

- Linux inotify behavior (different OS; needs a Linux runner — punt to CI).
- `PollWatcher` fallback when inotify exhausts (Linux-only).
- Watcher overflow (`need_rescan() == true`) — would need a true burst, e.g., `git checkout` 50k+ files. Plan needs to verify in P6 integration test scenario #4.
- `notify-debouncer-full`'s `Cache::add_root`/`remove_root` pre-filter API — used to suppress `target/` thrash. Not exercised here.

## Reproduction

```bash
cd spikes/p0-3-notify-smoke
cargo build --release
STORM_N=500 ./target/release/p0-3-notify-smoke
```

Environment variable `STORM_N` (default 500) controls the burst size.
