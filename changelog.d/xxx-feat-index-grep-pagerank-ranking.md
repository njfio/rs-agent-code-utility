### `Index.Grep` — sort matches by enclosing-def PageRank

#98 added `enclosing_qualified_name` + `enclosing_kind` + `enclosing_def_range` to every grep match. This PR closes the loop: each match now carries a `rank_score` (the PageRank of its enclosing def), and the response is sorted by `rank_score` descending. Hits in the workspace's busiest, most central code float to the top — matching `find_symbol`'s default ordering and saving agents from re-ranking client-side.

#### Wire shape

```jsonc
{
  "matches": [
    {
      "file": "crates/rts-daemon/src/methods/index.rs",
      "range": { "start_line": 1156, "end_line": 1156, "start_byte": 38420, "end_byte": 38449 },
      "line_text": "    if let Some(g) = &glob {",
      "enclosing_qualified_name": "grep",
      "enclosing_kind": "fn",
      "enclosing_def_range": { "start_byte": 36800, "end_byte": 42100, "start_line": 1098, "end_line": 1287 },
      // NEW in this PR:
      "rank_score": 0.000142
    }
    // …additional matches in non-increasing rank_score order
  ]
}
```

#### Ranking rules

- **Primary key**: `rank_score` descending. File-scope matches and cold-start (PageRank not yet computed) collapse to `0.0` and sink to the bottom — same convention as `Index.FindCallers.callers[].rank_score`.
- **Tie-breaker**: `(file, start_byte)` ascending. Stable cross-call ordering when two matches share an enclosing def (and thus the same rank).
- **NaN-safe**: `f64::total_cmp` handles any oddity in case future PageRank tweaks introduce non-finite values. `partial_cmp` would have panicked.

#### Implementation

- New field `FoundSymbol.sid` plumbed through the three `Store` constructors. Every constructor already had `sid` in scope; this just exposes it on the public struct. Lets grep (and any future `defs_in_file` → `pick_innermost_def` consumer) look up `SymbolRanks::rank_for(sid)` directly without a second `sid_for_name` lookup that would be ambiguous for overloaded names.
- Lazy-fetch PageRank via the existing `symbol_ranks_lazy(state, store, generation)` helper. Cache-warm: one mutex-lock + one Arc clone (sub-microsecond). Cache-miss: triggers a compute on the daemon's blocking pool — same path `find_symbol` and `find_callers` use, so cold-start cost is shared, not duplicated.
- TOCTOU invariant preserved: `index_generation` is read *before* the file walk starts, matching the Deepening §C contract.

#### Verification

`grep_round_trip.rs` adds Case **P**: every match must carry a finite `rank_score`, and the response must be in non-increasing `rank_score` order across the entire `matches` array. Existing 15 cases (A-O) continue to pass byte-for-byte.

Semantic-eval invariants checked post-change:
- `corpus/semantic-eval-rts-core.toml` against `crates/rts-core` — `answerable_coverage = 1.000 ≥ 0.95 ✓` (no regression vs the pre-change baseline).

Full suite: `cargo test -p rts-daemon -p rts-mcp --release` — 160+ tests pass.

#### Backward compatibility

One new field on each match object. Existing callers that don't read `rank_score` see no behavior change *except* the result ordering shifts from "file-walk order" to "rank desc, file/byte asc". That ordering shift is the whole point of the PR, but it's worth flagging: any test that asserted "first match is in file X" without a more specific filter is now order-dependent on PageRank, not file-walk order.

The `grep_round_trip.rs` existing Case A asserts `matches[0]["file"].ends_with("a.rs")` — that still holds because there's only one match for the query.

#### Out of scope (filed for follow-up)

- **`rank_score` as a query parameter (`min_rank`, `top_rank_only`)**. Once agents start filtering by rank, they'll want to express "only hits in the top decile of central code." Today's response includes the rank so client-side filtering is trivial; promoting to a server-side parameter is worth doing when usage patterns demand it.
- **File-level rank vs symbol-level rank**. The current sort uses the *enclosing def's* PageRank. For matches at file scope (no enclosing def), an alternative would be the mean rank of all defs in that file — surfaces hits in "central files" even when they're in module-level code. Worth exploring once we have a concrete query that motivates it.
