---
title: "feat(rts-daemon): index Rust doc comments and expose via find_symbol/read_symbol"
type: feat
status: active
date: 2026-05-15
---

# Doc-comment indexing for rts-daemon

## Overview

Extend the daemon to extract Rust doc comments (`///` and `//!`)
during the parse/index pass and expose them through the existing
`"doc": null` placeholder in `Index.FindSymbol` and
`Index.ReadSymbol` responses. Then update the bench's semantic
scorer to match query tokens against doc text in addition to
identifier names.

The two miss patterns in the blind-v2 corpus (PR #62) point at
queries that need *behavioral* understanding ("what cleans up after
analysis?", "where are language-specific queries defined?"). The
graph-only baseline saturates around 90% answerable coverage on
verified corpora because identifier-shaped matching can only get
so far. Doc comments are the cheapest source of behavioral signal
the codebase already authors.

This is *capability extension*, not a ranker tweak — it makes new
information available to scoring rather than recombining existing
information differently.

## Problem statement

`Index.FindSymbol` and `Index.ReadSymbol` already include a `"doc":
null` field in their wire response. The wire shape is committed to;
the storage and extraction are missing.

Meanwhile, `crates/rts-core` (the legacy code) already implements
`extract_rust_doc_comments` (line ~976 of `analyzer.rs`) and
populates `Symbol::documentation` for Rust. The function is even
called *from* the legacy extractor path — but
`writer.rs:symbol_to_def()` (line ~506) drops the field on the
floor when translating `Symbol` to `DefSite`.

So the gap is plumbing, not new extraction. But it needs a careful
storage-schema decision because adding a field to `DefSite`'s
postcard-serialized form would break existing on-disk data.

## Proposed solution

**Option B (recommended): additive sidecar table.** Add a new
multimap `SID_DOCS: sid (u32) → postcard(DocBlob { fid, text })`
keyed on the same symbol ID `DefSite` already uses. Existing
`DefSite` serialization stays unchanged; old data stays readable;
new data picks up doc text via an extra read.

Option A (extend `DefSite`) is rejected: it requires a schema
migration on every existing on-disk store. The daemon ships to
users; we don't want to gate a v0.5.x bump behind data migration
for an additive capability.

## Technical approach

### Implementation units

**U1 — Storage schema and plumbing**
- Add `SID_DOCS` `MultimapTableDefinition` to `store/schema.rs`.
  Multimap because the same symbol can be defined in multiple
  files (e.g. `pub mod foo;` re-exports), and each occurrence has
  its own doc context.
- Add `DocBlob { fid: u32, text: String }` postcard-serializable
  struct.
- Add `Store::doc_for_sid(sid: u32) -> Result<Vec<DocBlob>>`
  helper.

Files: `crates/rts-daemon/src/store/schema.rs`,
`crates/rts-daemon/src/store/mod.rs`.

Verification: redb open round-trip test; writing then reading a
known `(sid, doc)` pair returns the same text.

**U2 — Writer extraction**
- Pull `sym.documentation` from the legacy `Symbol` already
  produced by rts-core's analyzer (no new tree-sitter queries
  needed for the MVP — Rust only).
- In `writer.rs:commit_batch`, after defs are written, insert
  doc blobs into `SID_DOCS` for symbols where `documentation`
  is `Some`.

Files: `crates/rts-daemon/src/writer.rs`.

Verification: integration test that mounts a workspace with a
documented Rust fn, queries the symbol, asserts the doc text
flows through to `Store::doc_for_sid`.

**U3 — Wire-shape plumbing**
- `Index.FindSymbol`: replace the `"doc": null` placeholder with
  an actual lookup against `SID_DOCS`. Take the first match (or
  the one matching the symbol's reported `file`).
- `Index.ReadSymbol` (shape=signature path especially): same
  treatment.

Files: `crates/rts-daemon/src/methods/index.rs`.

Verification: extend `tests/find_symbol_round_trip.rs` —
documented symbol returns non-null `doc`; undocumented returns
null.

Capability: advertise `find_symbol_doc_field` (or similar) in
`Daemon.Ping` so the bench can detect whether the daemon's payload
includes real docs vs the null placeholder.

**U4 — Bench scorer integration**
- Add `Candidate::doc: Option<String>` (populated from the wire
  response).
- In `score_candidate`, after existing token matching, check each
  query token against the candidate's `doc` text (lowercased,
  substring match). Award e.g. `+4.0 * idf(tok)` — between
  sub-token and substring tiers.

Files: `crates/rts-bench/src/semantic.rs`.

Verification: re-run both rts-core corpora. Blind v2 should
recover the "what cleans up after analysis?" miss (since the
relevant `clear*`/`reset*` functions presumably have doc comments
mentioning cleanup).

### Patterns to follow

- The existing `REFS` / `FID_REFS` multimap pattern in
  `store/schema.rs` is the direct template for `SID_DOCS`.
- `Store::find_callers` (in `store/mod.rs`) shows the read pattern
  for "sid → multimap values."
- `tests/find_symbol_round_trip.rs` is the integration test
  template — copy its mount/wait/probe shape.
- The capability list in `methods/daemon.rs` is where to advertise
  `find_symbol_doc_field`.

### Out of scope (filed for follow-up)

- Languages other than Rust. C, JavaScript, Python, etc. each
  have their own doc-comment conventions. Rust first because (a)
  it's the workspace I bench against, (b) rts-core already
  extracts Rust doc comments, (c) every other language extension
  is additive once the storage + plumbing exists.
- `outline_workspace` exposing docs. The token budget there is
  already tight; including doc text would inflate responses.
- Doc-comment-derived natural-language summarization or query
  expansion. Just substring matching for the MVP.

## Acceptance criteria

- [ ] `Index.FindSymbol` response contains real doc text for
      documented Rust symbols (verified by integration test).
- [ ] `Index.FindSymbol` response contains `null` doc for
      undocumented Rust symbols (existing behavior preserved).
- [ ] `Daemon.Ping` advertises a new capability
      (`find_symbol_doc_field` or similar) for clients to detect.
- [ ] On-disk format is back-compatible: an existing v0.4.1 redb
      store opens cleanly under the new daemon; new doc data
      populates as files are re-indexed.
- [ ] `rts-bench semantic` against `corpus/semantic-eval-rts-core.toml`
      still hits 95%+ answerable coverage (no regression).
- [ ] `rts-bench semantic` against
      `corpus/semantic-eval-rts-core-blind-v2.toml` improves
      meaningfully (target: 90%+ from current 80%).

## Risks

| Risk | Mitigation |
|------|------------|
| Doc-text scoring overwhelms identifier matching when query terms appear in many comments. | IDF weighting (already present in `score_candidate`) naturally down-weights common doc terms. Test the actual numbers before tuning. |
| Storage size growth on large workspaces. | Doc blobs are small (~100-300 bytes typical) and only stored for symbols that actually have docs. Estimate: <10% growth on rts-core-sized workspaces. Capture footprint number in the bench. |
| Multi-file `pub use` re-exports duplicate doc storage. | `SID_DOCS` multimap already handles this — the read path takes the first match or filters by `fid`. |
| `Symbol::documentation` from rts-core isn't actually reliable. | Spot-check on rts-core itself: pick 10 random documented fns, verify they round-trip through the daemon's pipeline. |

## Test plan

1. **Storage round-trip** — open in-memory redb, write a `DocBlob`,
   read it back, assert text matches.
2. **Writer extraction** — mount a tempdir with `pub fn foo() {}
   /// docs\n` (correctly ordered), wait for index, query, assert
   `doc` populated.
3. **Wire shape** — `Index.FindSymbol` against a known documented
   symbol returns non-null `doc`. Against an undocumented one,
   returns `null`.
4. **Bench scoring** — extend semantic.rs tests with a query that
   should match via doc text only (not via name).
5. **Eval gate** — re-run both rts-core corpora end-to-end; assert
   the v1 coverage stays at 1.00 and blind-v2 improves.
6. **Footprint** — run `rts-bench footprint` before and after on
   rts-core; capture the storage-growth delta in the CHANGELOG.

## Sources

- Origin: this plan was filed from the v0.4.1 "what else?" menu,
  Option #2.
- Companion PRs:
  - #62 (blind-v2 corpus that exposes the limit this plan addresses)
  - #63 (CI semantic-baseline guard that will protect this work
    from regressing the existing 95%+ coverage on v1).
- Relevant existing code:
  - `crates/rts-core/src/analyzer.rs:228` — `Symbol::documentation`
  - `crates/rts-core/src/analyzer.rs:976` — `extract_rust_doc_comments`
  - `crates/rts-daemon/src/writer.rs:506` — `symbol_to_def` (where
    docs currently get dropped)
  - `crates/rts-daemon/src/methods/index.rs:628` — the `"doc": null`
    placeholder in the wire shape

## Execution note

Test-first for U1 (the storage round-trip is exactly the kind of
data-shape change that benefits from a failing test before code).
Pragmatic for U2-U4 (existing integration-test infrastructure
makes test-after acceptable, especially for the wire-shape work
where the placeholder is already there).
