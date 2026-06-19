# Spike p1-1 — `verify_edit` scoped-delta vs. shadow index

**Question (the P3 gate):** can `verify_edit` evaluate a proposed patch against
the index, without mutating the live index, within a sub-second budget — and
does it need a copy-on-write **shadow index** (Approach A), or does a **scoped
in-memory delta** (Approach B) suffice?

**Verdict: Approach B (scoped delta). No shadow index for `verify_edit` v0.**

---

## The two approaches

- **A — shadow index (COW):** copy the redb DB to a temp location, re-commit the
  patched files, query the copy. redb has no native COW snapshot, so this is a
  whole-DB file copy (~4.5 MiB / 500 files; ~45 MiB at 10× corpus) plus a
  re-commit — **~100–150 ms dominated by the file copy**, before any analysis.
- **B — scoped delta:** for each patched file, re-parse OLD + NEW content to diff
  its defs/refs, then query the **live** index for callers of any changed/removed
  symbol. The caller query is the already-merged `verify_impact` /
  `impact::compute` (single-query latency independently measured **<10 ms**). The
  only *new* per-edit cost over today's queries is the re-parse + reference
  extraction of the patched files — which this spike measures directly.

## Measurement

Per-file delta cost = `parse_content` ×2 (old+new) + `extract_references` ×1,
measured over **203 real source files** in this repo (avg 15 KiB/file), steady
state (parser caches warmed):

| | per file |
|---|---|
| mean | 9.8 ms |
| p50 | 6.8 ms |
| p95 | 25.6 ms |
| p99 | 54.7 ms |
| max | 125 ms |

Extrapolated edit latency (parse + a generous 20 ms caller-query/file = up to 2
changed symbols × <10 ms), budget = 1000 ms:

| patch size | pessimistic (p95/file, serial) | realistic (mean/file, parallel parse) |
|---|---|---|
| 1 file | 46 ms ✅ | 20 ms ✅ |
| 5 files | 228 ms ✅ | 102 ms ✅ |
| 10 files | 456 ms ✅ | 204 ms ✅ |
| 25 files | 1140 ms ⚠️ | 510 ms ✅ |
| 50 files | 2281 ms ⚠️ | 1020 ms ⚠️ |

## Conclusion

1. **Typical edits (1–10 files) fit with wide margin** — tens to low-hundreds of
   ms — under both extrapolations. This is the overwhelming majority of agent
   edits and PRs.
2. **Large patches (25+ files)** only risk the budget under the *pessimistic*
   serial-worst-case (every file at p95). Parsing is embarrassingly parallel
   (per-file, no shared state — the same `spawn_blocking` pattern `impact`
   already uses), which keeps 25-file patches at ~0.5 s.
3. **A shadow index would be *slower* here**, not faster — the whole-DB file copy
   dominates and buys nothing the delta doesn't already give. So Approach A is
   not the mitigation for large patches.
4. **The real levers for large patches** are (a) parallel parse, and (b) an
   explicit cap on files-analysed-per-call, surfaced as a clear "N files not
   analysed" signal so a partial result is never read as a clean `pass`.

## What this green-lights for P3 (`verify_edit`)

- **Input:** `{ edits: [{file, range, replacement}] }` or full post-edit file
  contents — NOT a unified diff (no diff-parsing crate in the tree; avoids the
  dep and the apply-ambiguity).
- **Engine:** scoped delta — diff each patched file's defs/refs (old vs new),
  then reuse the live index + `impact`/`verify_impact` for callers.
- **Checks (reuse map):** `broken_callers` → `impact::compute` / `refs_to_symbol`
  + F4 arity; `signature_breaks` → F4 `signature_shape` vs call sites;
  `dangling_refs` → removed defs still referenced in the live index;
  `new_symbols` → patched defs absent from `NAME_TO_SID`. **`test_coverage` is
  deferred** — rts has no test-reachability data (a separate plan).
- **Budget:** parallelise per-file parsing; cap files-analysed with a partial-
  result signal.

## Reproduce

```
cd spikes/p1-1-verify-edit-delta
cargo run --release
```

Excluded from the workspace (see root `Cargo.toml` `exclude`).
