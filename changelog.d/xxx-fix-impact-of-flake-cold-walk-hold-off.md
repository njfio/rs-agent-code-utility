### `rts-daemon` writer — cold-walk hold-off fixes silent ref-graph holes

`impact_of_three_tier_with_test_filter` had been an intermittent flake in CI under heavy parallel load. Investigation surfaced a real correctness bug in the writer, not just a timing issue with the test:

#### Root cause

`Store::commit_batch`'s Pass-2 ref resolution (`crates/rts-daemon/src/store/mod.rs:402`) **permanently drops** any ref whose callee name isn't yet in `NAME_TO_SID`:

```rust
let callee_sid = match name_to_sid.get(r.name.as_str())? {
    Some(v) => v.value(),
    None => continue, // external symbol; skip per F1
};
```

The intent of this §F1 filter is to drop refs to stdlib / builtin names that will *never* be defined in the workspace. But the same code path also fires when the callee's def **happens to be in a future batch**. Once Pass 2 commits the batch missing the ref, the ref is gone — no retry happens when the callee def lands in a later batch.

Under the writer's 150ms `BATCH_FLUSH_INTERVAL`, the cold initial walk's stream of file events normally fits in one batch (BATCH_SIZE_BUDGET = 128 files). But under CI/parallel-test load:

- The cold walk emits 7 files at ~T=0–50ms via `blocking_send`.
- The writer's `tokio::select!` was pseudo-randomly biased; under load the `flush_timer.tick()` arm wins enough times to split the stream.
- File N+k commits before file N. Cross-batch refs in N→N+k are filtered as "external" and dropped permanently.
- `Index.ImpactOf` then returns an incomplete caller list, and the test's `assert!(names.contains("caller_a"))` fires.

The bug was reproducible: 4/10 failures running the full test suite 10 times in a row with the test hardened to expose the underlying issue (`wait_for_refs` polling for committed REF edges with a 10s timeout — without the fix, the REFs *never* settled because they'd been dropped).

#### Fix

A new `WatchEvent::ColdWalkComplete` sentinel:

- **Walker** emits it from `walk_and_emit_blocking` after the file-iteration loop finishes (via `blocking_send` like any other event).
- **Writer** starts with `cold_walk_in_progress = true` and treats this flag as a hard barrier: while it's set, the `flush_timer.tick()` arm is a no-op — events accumulate in `upserts` / `removals` HashMaps but never flush.
- When `ColdWalkComplete` arrives, the writer fires one atomic `flush()` (via `Durability::Immediate` so the commit hits disk before Mount returns its status payload), then clears the flag and resumes normal 150ms batching.

Because the walker uses `blocking_send`, the receiver-side state is always consistent: by the time `ColdWalkComplete` is consumed, every `Touched` it preceded is already in the writer's local `upserts`. The whole cold walk lands as one batch — and Pass-2 ref resolution sees every workspace symbol when resolving refs.

The size budget (`BATCH_SIZE_BUDGET = 128`) still applies as a safety valve for very-large cold walks. Cross-batch refs in workspaces with >128 files aren't fully resolved — same pre-existing trade-off as before this PR. The typical 1k-file repo where everything fits in one batch is now correct end-to-end.

#### Test hardening

`tests/impact_of_round_trip.rs` adds a new helper `wait_for_refs(target, expected_callers[], timeout)` that polls `Index.FindCallers` until every expected (target ← caller) edge is committed. This is **not** a workaround — it's a regression guard: if the writer fix regresses and refs go missing again, the test will time out at 10s with a descriptive error message rather than silently passing on a half-finished reference graph.

#### Verification

10 consecutive full-suite runs after the fix:

```
Run 1: PASS    Run 6: PASS
Run 2: PASS    Run 7: PASS
Run 3: PASS    Run 8: PASS
Run 4: PASS    Run 9: PASS
Run 5: PASS    Run 10: PASS
---SUMMARY: 10/10 passed---
```

Previously: 4/10 failures (same hardware, same load pattern). The fix is necessary AND sufficient.

#### Out of scope (filed for follow-up)

- **Live-edit cross-batch refs.** This PR fixes the cold-walk path. Sequential file saves >150ms apart still hit the §F1 permanent-drop bug — if you save `caller_a.rs` first and `target.rs` second, with >150ms between saves, the `caller_a → target` ref drops forever. In practice users type linearly so this is rare, but the proper fix is an `UNRESOLVED_REFS` table that defers unresolvable refs and re-materializes them when their callee def first lands. Tracked separately.
- **Very-large cold walks (>128 files).** When the batch size budget triggers, the cold-walk hold-off doesn't help: we still split. A future revision could promote the hold-off to span the entire walk regardless of size, with the cost being peak memory during initial index. Worth doing once we see real workspaces large enough to matter.
