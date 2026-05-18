---
title: "feat(daemon,mcp): Index.Grep v2 — multiline + structural + within-symbol"
type: feat
status: active
date: 2026-05-18
origin: docs/brainstorms/2026-05-18-index-grep-v2-requirements.md
---

# `Index.Grep` v2 — multiline regex + structural queries + within-symbol scope

## Overview

Extend the existing `Index.Grep` MCP tool with three optional, fully composable input parameters — `multiline`, `structural_query`, `within_symbol` — plus a required `language` companion for structural queries. The tool surface stays at one MCP entry; existing v1 callers see byte-identical response bytes on the unchanged code path; new capabilities are advertised additively via three new capability strings on `Daemon.Ping`.

The shape is conservative: agent-supplied raw tree-sitter S-expression queries are validated via `rts_core::query::Query::new` at request time, compiled `Query` objects are cached in an LRU keyed on `(language, query_text)`, structural queries re-parse files on demand (no parsed-tree cache exists today — the brainstorm's premise was incorrect), captures are returned per-match (not globally keyed — also a brainstorm shape correction), and every new code path has explicit resource budgets (DFA size limit on multiline regex; wall-clock + result-row truncation on structural; predicate whitelist on query `#match?`).

This plan addresses **five gaps the brainstorm missed**, surfaced by SpecFlow analysis and repository research:

1. **No parsed-tree cache exists.** Writer parses transiently and discards. The plan re-parses on demand and caches the compiled `Query`, not the tree.
2. **Captures shape was wrong** in the brainstorm (`{name: [...]}` top-level). They must be **per-match**.
3. **`CallCounters` is a closed enum** (state.rs:159), not a string map. Sub-counters are additional hard-coded `AtomicU64` fields. Coordination with the doctor plan's `Daemon.Stats v2` (PR 001) is required.
4. **Regex has no DFA size limits set today.** v2 sets explicit limits and adds a `REGEX_TOO_COMPLEX` error code.
5. **`#match?` predicate inside a tree-sitter query re-injects regex DoS.** Plan ships a predicate whitelist with a shared compile budget.

## Problem Statement / Motivation

Three known shortcomings make agents drop back to `Bash rg` mid-session — measurable in every agent-bench trajectory where rts indexed the workspace but the agent still reached for `rg`:

- **No multiline.** Patterns that need to match across `\n` (a function signature on three lines; an SQL fragment with embedded newlines; a multi-line error message) silently return zero hits in v1.
- **No structural matching.** *"Find every `impl` block containing an `unsafe fn`"* requires `rg` + manual filtering, or two MCP calls + an intersection.
- **No within-symbol scope.** *"Find every `panic!` inside `fn parse_request`"* requires a `grep` + a `find_symbol` + a byte-range intersection the agent computes by hand.

Closing all three in one shipping unit tightens the value-prop without expanding the tool surface (one tool, three new optional params). Every existing v1 caller is unaffected; every new caller gets capabilities the v1 surface couldn't express.

## Proposed Solution

Three additive optional input fields on `GrepArgs` (rts-mcp side) and `GrepParams` (rts-daemon side):

- `multiline: Option<bool>` (default `false`) — when set on the regex (`pattern`) path, configures `RegexBuilder::dot_matches_new_line(true).multi_line(true)` and treats indexed file bytes as one logical buffer per file. **No-op for the literal `text` path** (literal substring search is already byte-wise across newlines).
- `structural_query: Option<String>` — a raw tree-sitter S-expression query string, evaluated against the parsed tree of every file matching the request's `language` filter. **Requires `language`.**
- `within_symbol: Option<String>` — a qualified-name match scope; matches whose byte range lies entirely inside the def byte range of the named symbol are kept. v1 minimum: single exact qualified name. Multi-def resolution (overloaded names) is policy-gated with a cardinality cap.
- `language: Option<Vec<String>>` — language filter applicable to *all* paths (literal, regex, structural). Required when `structural_query` is set; optional otherwise. Intersects with `file_glob` (AND semantics; see Cross-cutting Concerns).

The response shape gains a per-match `captures` field, present only when `structural_query` produced a match:

```jsonc
{
  // existing v1 fields preserved byte-for-byte on the unchanged path:
  "file": "crates/rts-core/src/lib.rs",
  "range": { "start_line": 42, "end_line": 47, "start_byte": 1024, "end_byte": 1180 },
  "line_text": "    impl Foo for Bar {",
  "enclosing_qualified_name": "rts_core::Foo",
  "enclosing_kind": "impl",
  "enclosing_def_range": { ... },
  "rank_score": 1.247e-3,
  // new in v2, present only on structural matches:
  "captures": {
    "fn": [{ "start": {"line": 43, "col": 8}, "end": {"line": 45, "col": 9}, "text": "..." }],
    "name": [{ "start": {"line": 43, "col": 16}, "end": {"line": 43, "col": 24}, "text": "..." }]
  }
}
```

The daemon advertises three new capabilities on `Daemon.Ping`:
- `index_grep_multiline`
- `index_grep_structural`
- `index_grep_within_symbol`

A v2 client checks capabilities before sending v2 params. Old daemons silently ignore unknown input fields, but the calling agent should not assume the feature ran — capability negotiation is the contract.

## Technical Approach

### Module layout

```
crates/rts-daemon/src/methods/index.rs
  Existing `pub async fn grep` (line ~1069-1367) — gains v2 param handling
  `pick_innermost_def` (line 2294-2303) — unchanged, reused
  NEW: `compose_filters` helper — assembles file-set / regex / structural pipeline

crates/rts-daemon/src/methods/grep_v2/  (new submodule for new code)
├── mod.rs              // entry; param-pipeline dispatcher; merges into existing handler
├── compose.rs          // composition matrix; explicit per-cell semantics
├── multiline.rs        // RegexBuilder wiring; dfa_size_limit; REGEX_TOO_COMPLEX
├── structural.rs       // per-file parse + Query eval; captures collection
├── within_symbol.rs    // find_symbol → def byte ranges → intersection filter
├── query_cache.rs      // (language, query_text) → Arc<Query> LRU
└── predicates.rs       // predicate whitelist + shared regex compile budget

crates/rts-daemon/src/state.rs
  CallCounters (159-180) — gains 3 new AtomicU64 sub-counters (closed enum extension)

crates/rts-mcp/src/server.rs
  GrepArgs (198-236) — gains 4 new Option<...> fields with #[serde(default)]
  #[tool] grep description (605-630) — appended with v2 usage notes

docs/protocol-v0.md
  §7.8b Index.Grep — append v2 wire fields; document captures shape; document
  new capabilities; document new error codes
```

### Composition matrix (binding decisions)

The six input fields produce a 2⁶ matrix. Behavior of every meaningful cell is fixed here so the implementation isn't inventing semantics per branch:

| `text` | `pattern` | `multiline` | `structural_query` | `within_symbol` | `language` | Behavior |
|--------|-----------|-------------|--------------------|-----------------|------------|----------|
| ✓      | ✗         | any         | ✗                  | optional        | optional   | v1 literal substring scan; `multiline` is no-op; `within_symbol`/`language` filter file set post-scan |
| ✗      | ✓         | ✗           | ✗                  | optional        | optional   | v1 regex scan; `within_symbol`/`language` filter file set post-scan |
| ✗      | ✓         | ✓           | ✗                  | optional        | optional   | regex with `dot_matches_new_line + multi_line` flags; whole-file buffer; explicit `dfa_size_limit` budget; **`REGEX_TOO_COMPLEX` on cap breach** |
| ✗      | ✗         | any         | ✓                  | optional        | **required** | parsed-tree query over `language` file set; per-file re-parse; `Query` LRU-cached |
| ✓      | ✗         | any         | ✓                  | optional        | **required** | **intersection**: file must contain the literal AND the structural query must match in that file; matches are structural hits whose enclosing match-range contains the literal |
| ✗      | ✓         | any         | ✓                  | optional        | **required** | **intersection**: regex match per match-line + structural query match in same file; matches are structural hits whose line text matches the regex |
| ✓      | ✓         | —           | —                  | —               | —          | **rejected as `INVALID_PARAMS`**: `text` and `pattern` are mutually exclusive in v1 already |
| ✗      | ✗         | —           | ✗                  | —               | —          | **rejected as `INVALID_PARAMS`**: at least one of `text`/`pattern`/`structural_query` required |

`within_symbol` always acts as a final post-pass filter: a match is retained only if `(match.start_byte, match.end_byte)` lies strictly inside the def byte range of any resolved symbol. Strict containment is chosen over lenient overlap (see Key Decisions).

`language` is an OR set: if `language: ["rust","ts"]`, files with either language match. `file_glob ∩ language` is AND: a file must satisfy both. A structural query that doesn't compile against one of the requested languages produces a `partial_failures` warning array but does not fail the call as long as it compiled against at least one.

### Validation, error codes, and the predicate whitelist

New error codes (returned as protocol-v0 `INVALID_PARAMS` envelopes with structured `data`):

| `data.code` | Trigger |
|-------------|---------|
| `MULTILINE_REQUIRES_REGEX` | `multiline: true` on the literal `text` path (rejected, not silently coerced) |
| `STRUCTURAL_REQUIRES_LANGUAGE` | `structural_query` set, `language` missing |
| `STRUCTURAL_QUERY_INVALID` | `Query::new(language, query_text)` failed; `data.error_message` carries the tree-sitter error |
| `STRUCTURAL_QUERY_PREDICATE_NOT_ALLOWED` | query uses a predicate outside the whitelist |
| `WITHIN_SYMBOL_NOT_FOUND` | `within_symbol` name resolves to zero defs |
| `WITHIN_SYMBOL_TOO_MANY_DEFS` | `within_symbol` resolves to more than `WITHIN_SYMBOL_MAX_DEFS` (default: 16) defs — caller can opt in via `within_symbol_allow_overload: true` |
| `REGEX_TOO_COMPLEX` | regex compile exceeded the configured `dfa_size_limit` / `size_limit` |
| `STRUCTURAL_QUERY_TIMEOUT` | structural scan exceeded `STRUCTURAL_WALL_CLOCK_MS` (default: 5_000) |
| `STRUCTURAL_QUERY_TRUNCATED` | not an error; emitted as a top-level `truncated: true` flag with metadata (rows seen, rows returned, capture-bytes total) |

Predicate whitelist (v1):
- `#eq?`, `#not-eq?` — string equality, no regex compile
- `#match?`, `#not-match?` — regex compile against a *shared* daemon-wide regex budget; each predicate must compile under `PREDICATE_REGEX_DFA_LIMIT` (default: 256 KB, more conservative than the outer `dfa_size_limit`)
- `#any-of?` — string membership
- `#is?`, `#is-not?` — node-property test (no regex)

Predicates not on the whitelist (`#contains?` variants from custom extensions, etc.) cause `STRUCTURAL_QUERY_PREDICATE_NOT_ALLOWED`. The whitelist is documented in `docs/protocol-v0.md`.

### Resource budgets

Constants live in a new `crates/rts-daemon/src/methods/grep_v2/limits.rs`:

```rust
pub const MULTILINE_DFA_SIZE_LIMIT: usize     = 32 * 1024 * 1024;  // 32 MB
pub const MULTILINE_NFA_SIZE_LIMIT: usize     = 32 * 1024 * 1024;
pub const REGEX_DFA_SIZE_LIMIT: usize         = 10 * 1024 * 1024;  // unchanged from default for v1 (single-line) path
pub const PREDICATE_REGEX_DFA_LIMIT: usize    = 256 * 1024;        // 256 KB for #match? inside queries
pub const STRUCTURAL_WALL_CLOCK_MS: u64       = 5_000;
pub const STRUCTURAL_MAX_ROWS: usize          = 4_096;             // hard cap; mirrors existing MAX_LIMIT
pub const STRUCTURAL_MAX_CAPTURE_BYTES: usize = 8 * 1024;          // per-capture text truncation
pub const STRUCTURAL_MAX_CAPTURES_PER_MATCH: usize = 64;
pub const WITHIN_SYMBOL_MAX_DEFS: usize       = 16;
pub const QUERY_LRU_CAPACITY: usize           = 64;                // (language, query_text) entries
```

Capture text exceeding `STRUCTURAL_MAX_CAPTURE_BYTES` is truncated and the per-capture object gains `"truncated": true`. The response gains a top-level `truncated: true` + metadata when row limits or wall-clock hit.

### The Query LRU

Existing `cached_refs_query` (`crates/rts-daemon/src/language.rs:276-317`) is process-wide `OnceLock<Option<Query>>` per language — keyed on language only, suitable only for the built-in query strings. Agent-supplied queries need a different cache:

```rust
// crates/rts-daemon/src/methods/grep_v2/query_cache.rs
pub struct QueryCache {
    inner: Mutex<lru::LruCache<(Language, String), Arc<rts_core::query::Query>>>,
}
```

LRU capacity = 64 entries (covers ~10 distinct queries across 6 languages with headroom). The cache lives on `DaemonState` next to `call_counters`. Eviction is by recency; no time-based eviction in v1. Grammar version drift invalidation is **out of scope for v1** (grammars are statically linked; no hot reload exists).

### Telemetry coordination with the doctor plan (PR 001)

PR 001 (`docs/plans/2026-05-18-001-feat-rts-bench-doctor-plan.md`) adds **top-level fields** to `Daemon.Stats` (`pinned_workspace_path`, `index_generation`, `cold_walk_completed_at_ms`) and a `daemon_stats_v2` capability.

This plan adds **three new fields to `CallCounters`**:
- `index_grep_multiline: AtomicU64`
- `index_grep_structural: AtomicU64`
- `index_grep_within_symbol: AtomicU64`

These appear in `CallCounters::snapshot()` as siblings of the existing `index_grep` field (not nested) — matches the existing closed-enum pattern; avoids restructuring the snapshot JSON; safe for old `--output json` consumers.

**Bump policy:** each sub-counter increments only when its corresponding param is *set* (and `multiline` requires `pattern` to be set as well; `multiline: false` does NOT bump `index_grep_multiline`). The parent `index_grep` counter increments on every grep call. A call with all three new params therefore bumps four counters total (parent + 3 sub).

**Coordination:** PRs 001 and 002 both modify `crates/rts-daemon/src/state.rs:159-180` (`CallCounters`) and `crates/rts-daemon/src/methods/daemon.rs:18-87` (capability list). The two PRs are sequenced: PR 001 lands first (smaller, lower-risk), then PR 002 rebases on top. Both add fields; neither removes any. A new capability `index_grep_v2` *also* advertises the bundle for clients that prefer a single check.

### `content_version` propagation

Existing matches carry `content_version` via the redb read txn snapshot. Captures inherit the same version implicitly: the per-file parse for structural queries happens **inside the same `defs_in_file` read txn** as the match-line lookup. No separate version tracking needed; the invariant is encoded by transaction boundary.

### System-Wide Impact

- **Interaction graph.** `Index.Grep` request → daemon `methods::dispatch` (bumps parent counter) → `grep_v2::compose` (param validation) → file walk (existing) → per-file `(read txn, optional re-parse, regex scan, structural query, within_symbol filter)` → response assembly → bump sub-counters. No new sockets, no writes to disk, no new RPCs.
- **Error propagation.** Validation errors at request entry (`INVALID_PARAMS` envelope). Per-file errors during structural scan (parse failure on one file) are logged at `debug` and the file is skipped — the call succeeds with the files that parsed. Predicate compile errors fail the whole call with `STRUCTURAL_QUERY_PREDICATE_NOT_ALLOWED`. The existing literal/regex path's error envelopes are unchanged.
- **State lifecycle.** No persistent state introduced. The Query LRU is in-memory only; cleared on daemon restart. Sub-counters are atomic-incremented; no race.
- **API surface parity.** Three new capabilities + one bundle capability advertised on `Daemon.Ping`. JSON Schema for `Index.Grep` grows three optional input fields and one optional output field. rmcp's schema hash will change; clients that pin the hash for tool-cache invalidation will see the new schema and re-cache. R8 in the origin doc is interpreted as "response bytes on the unchanged input path are byte-identical," NOT "schema bytes are unchanged."
- **Integration test scenarios.**
  - v1 caller (no v2 params) — v2 daemon responds byte-for-byte identically.
  - v2 `multiline: true` against a Rust file with a multi-line `fn` signature; expect a single match spanning multiple lines.
  - v2 `structural_query: "(impl_item)"` + `language: ["rust"]` — expect every impl block as a match with the captured node text.
  - v2 `structural_query` + `language: ["rust","ts"]` where query is valid only for Rust — expect Rust matches; `partial_failures: [{language: "ts", error: "..."}]` in response.
  - v2 `within_symbol: "parse"` resolving to one def — expect matches inside that one byte range only.
  - v2 `within_symbol: "new"` resolving to >16 defs — expect `WITHIN_SYMBOL_TOO_MANY_DEFS` error with the count.
  - v2 `within_symbol: "new"` + `within_symbol_allow_overload: true` — expect union-of-byte-ranges filter.
  - v2 adversarial multiline regex (`(?s).*` on a 4MB file) — expect `REGEX_TOO_COMPLEX` if the DFA limit breaches, else success.
  - v2 query with `#match? @x "(.*a){50}"` predicate — expect `STRUCTURAL_QUERY_PREDICATE_NOT_ALLOWED` if it breaches the predicate regex budget.
  - v2 structural query that returns >4096 rows — expect `truncated: true` in response with metadata.
  - v2 structural query that runs longer than 5s — expect `STRUCTURAL_QUERY_TIMEOUT`.
  - v2 capture text >8KB — per-capture `truncated: true`, response succeeds.
  - v2 `text` + `structural_query` intersection — expect matches present in both filters only.

## Implementation Units

Ordered by dependency. U1 must coordinate with PR 001 (rts-doctor `Daemon.Stats v2`).

### U1 — `GrepArgs`/`GrepParams` schema extension + capability advertisement

- **Goal.** Add four optional input fields (`multiline`, `structural_query`, `within_symbol`, `language`) to both rts-mcp `GrepArgs` and rts-daemon `GrepParams`; advertise four new capabilities (`index_grep_multiline`, `index_grep_structural`, `index_grep_within_symbol`, `index_grep_v2`).
- **Files.** `crates/rts-mcp/src/server.rs:198-236` (`GrepArgs`); `crates/rts-daemon/src/methods/index.rs:116-146` (`GrepParams`); `crates/rts-daemon/src/methods/daemon.rs:18-87` (capability list); `docs/protocol-v0.md` (§7.8b append + appendix entry).
- **Approach.** Add fields with `#[serde(default)] Option<...>`; `JsonSchema` derives the schema additively. Capability list grows by four `&str` entries. Test: round-trip a v1 request (no new fields) and confirm response bytes match.
- **Patterns to follow.** Existing optional-field extension pattern on `FindSymbolArgs` (`server.rs:27`), `ReadSymbolArgs` (`server.rs:158`); `pre_filter_count` precedent for optional response fields (`docs/protocol-v0.md` §7.4).
- **Execution note.** Characterization-first: capture the v1 grep response shape in a frozen golden fixture before changing anything.
- **Test scenarios.**
  - Round-trip: v1 request returns response with no new fields, byte-equal to the frozen golden.
  - Capability list contains all four new strings.
  - JSON Schema for `Index.Grep` deserializes cleanly via `schemars`.
- **Verification.** `cargo test -p rts-mcp -p rts-daemon` green; `docs/protocol-v0.md` lints clean; capability grep returns 4 new entries.

### U2 — Composition matrix + validation + error codes

- **Goal.** All `INVALID_PARAMS` envelope cases enumerated in the composition matrix table emit the correct `data.code`. Mutually-exclusive combos rejected. Required-when-X combos enforced.
- **Files.** `crates/rts-daemon/src/methods/grep_v2/mod.rs` (new); `crates/rts-daemon/src/methods/grep_v2/compose.rs` (new); `crates/rts-daemon/src/methods/index.rs` (entry point wires through `grep_v2::validate` before reaching the existing handler).
- **Approach.** Implement `pub fn validate(params: &GrepParams) -> Result<ValidatedGrepCall, GrepError>` that returns an enum representing the matrix cell to execute. Errors carry `data.code` per the error-code table.
- **Patterns to follow.** Existing `INVALID_PARAMS` envelope shape (`crates/rts-daemon/src/methods/*.rs`); the `pre_filter_count` optional-output precedent for the eventual `truncated` flag.
- **Execution note.** Test-first: write the matrix-cell tests before implementing `validate`. The matrix is the spec; tests are derived from it.
- **Test scenarios.**
  - Each of the 8 rows in the composition matrix produces the expected pass/reject result with the documented error code.
  - `text + pattern` both set → `INVALID_PARAMS { code: "PATTERN_AND_TEXT_BOTH_SET" }` (existing v1 behavior preserved).
  - `structural_query` without `language` → `STRUCTURAL_REQUIRES_LANGUAGE`.
  - `multiline: true` with `text` set → `MULTILINE_REQUIRES_REGEX`.
- **Verification.** `cargo test -p rts-daemon grep_v2::compose` green; error-code grep returns documented strings in docs.

### U3 — Multiline regex path

- **Goal.** When `multiline: true` is set with `pattern`, regex compile uses `dot_matches_new_line(true).multi_line(true)`; explicit `dfa_size_limit`/`size_limit`; `REGEX_TOO_COMPLEX` on cap breach; whole-file buffer scan.
- **Files.** `crates/rts-daemon/src/methods/grep_v2/multiline.rs` (new); `crates/rts-daemon/src/methods/index.rs:152-231` (`GrepScanner` enum gains a `MultilineRegex` variant).
- **Approach.** New `GrepScanner::MultilineRegex(regex::bytes::Regex)` built via `RegexBuilder::new(text).dot_matches_new_line(true).multi_line(true).size_limit(MULTILINE_*).build()`. Existing line-iteration scan path replaced with whole-buffer scan for this variant; match coordinates translated back to `(start_line, end_line)` via existing line-offset cache (or built per-file on first multiline hit).
- **Patterns to follow.** `crates/rts-daemon/src/methods/index.rs:1126-1136` (regex compile site); `crates/rts-daemon/src/methods/index.rs:152-231` (scanner enum).
- **Execution note.** Test-first: adversarial regex cases (`(?s).*`, `(a*)*`) before the implementation; verify they return `REGEX_TOO_COMPLEX` not `OutOfMemory`.
- **Test scenarios.**
  - Multi-line `fn` signature spanning 3 lines: matched as one record.
  - Adversarial `(?s).*` against a 4 MB file: returns `REGEX_TOO_COMPLEX` (not OOM, not hang).
  - `multiline: false` (default): behavior matches v1 exactly.
- **Verification.** `cargo test -p rts-daemon grep_v2::multiline` green; latency on a healthy v1 case unchanged (no regression).

### U4 — `within_symbol` filter

- **Goal.** When `within_symbol` is set, post-filter matches to those whose byte range lies inside any resolved def byte range. Cardinality cap with structured error.
- **Files.** `crates/rts-daemon/src/methods/grep_v2/within_symbol.rs` (new); `crates/rts-daemon/src/methods/index.rs` (call site after match collection, before sort).
- **Approach.** Call `store.find_symbol(name)` (existing API at `crates/rts-daemon/src/store/mod.rs:995-1035`). If zero defs → `WITHIN_SYMBOL_NOT_FOUND`. If >`WITHIN_SYMBOL_MAX_DEFS` and `within_symbol_allow_overload != Some(true)` → `WITHIN_SYMBOL_TOO_MANY_DEFS`. Else: union the byte ranges per-file; filter matches by `(start_byte, end_byte) ⊆ def_range` (strict containment). Filtering is per-file (no cross-file ranges).
- **Patterns to follow.** `crates/rts-daemon/src/methods/index.rs:2294-2303` (`pick_innermost_def`); `crates/rts-daemon/src/store/mod.rs:995-1035` (`find_symbol`).
- **Execution note.** Test-first: zero-def, one-def, overloaded-name-rejected, overloaded-name-allowed scenarios before the implementation.
- **Test scenarios.**
  - Single def: only matches inside that def are returned.
  - Zero defs: `WITHIN_SYMBOL_NOT_FOUND`.
  - 17 defs, no opt-in: `WITHIN_SYMBOL_TOO_MANY_DEFS { def_count: 17 }`.
  - 17 defs with `within_symbol_allow_overload: true`: matches across union returned.
  - Match on the def's closing brace boundary: strict containment (excluded by default).
- **Verification.** `cargo test -p rts-daemon grep_v2::within_symbol` green.

### U5 — Query LRU + predicate whitelist + structural execution

- **Goal.** Run agent-supplied tree-sitter S-expression queries against per-file parsed trees with caching, predicate whitelisting, wall-clock budget, and row/byte truncation.
- **Files.** `crates/rts-daemon/src/methods/grep_v2/query_cache.rs` (new — LRU keyed on `(Language, String)`); `crates/rts-daemon/src/methods/grep_v2/predicates.rs` (new — whitelist + budget); `crates/rts-daemon/src/methods/grep_v2/structural.rs` (new — per-file parse + query execution + capture extraction); `crates/rts-daemon/src/state.rs` (add `query_cache: Mutex<QueryCache>` to `DaemonState`); `crates/rts-daemon/Cargo.toml` (add `lru = "0.12"`).
- **Approach.** On first call with a given `(language, query_text)`: `rts_core::query::Query::new(language, query_text)` to validate + compile; walk the query's predicates and reject anything not on the whitelist; insert `Arc<Query>` into the LRU. Per file in scope: re-parse via existing `ParserPool::parse_and_extract` (`writer.rs:656`), then `QueryCursor::new().matches(&query, tree.root_node(), file_bytes)`; collect captures into per-match `captures` map. Wall-clock checked between files (not mid-file).
- **Patterns to follow.** `crates/rts-core/src/query.rs:11,19,45,80,109` (`Query` wrapper); `crates/rts-daemon/src/refs.rs:54-115` (existing query execution); `crates/rts-daemon/src/language.rs:276-317` (existing OnceLock cache pattern — model for LRU).
- **Execution note.** Test-first: predicate whitelist (`#match?` allowed, `#contains?` rejected); query LRU hit/miss; cross-file timeout.
- **Test scenarios.**
  - First call: query compiles, cache miss, miss counter increments.
  - Second call with same `(language, query_text)`: cache hit.
  - Query with disallowed predicate: `STRUCTURAL_QUERY_PREDICATE_NOT_ALLOWED`.
  - Query with `#match? @x "(.*a){50}"`: `STRUCTURAL_QUERY_PREDICATE_NOT_ALLOWED` (predicate regex budget breach).
  - Query against `language: ["rust","ts"]` with TS-incompatible syntax: response includes `partial_failures: [{language:"ts", error:"..."}]` but Rust results returned.
  - 100k LOC workspace with `(_) @x`: returns `STRUCTURAL_QUERY_TIMEOUT` (not hang).
  - >4096 matching nodes: `truncated: true` + `rows_seen / rows_returned` metadata.
- **Verification.** `cargo test -p rts-daemon grep_v2::structural` green; cross-language partial failures behave as documented.

### U6 — Capture serialization + per-match `captures` field

- **Goal.** Each structural match carries its own `captures` map (per-match, not top-level). Capture text is truncated at `STRUCTURAL_MAX_CAPTURE_BYTES`. Position units are `{line, col}`.
- **Files.** `crates/rts-daemon/src/methods/grep_v2/structural.rs` (capture assembly); `crates/rts-daemon/src/methods/index.rs:1302-1323` (response shape: add per-match `captures` field, present-when-relevant).
- **Approach.** Define `pub struct CapturePayload { start: LineCol, end: LineCol, text: String, truncated: bool }`. Per `Query::matches`, iterate captures, slice byte range from file content, compute `{line,col}` via the existing line-offset cache; if `text.len() > STRUCTURAL_MAX_CAPTURE_BYTES`, truncate and set `truncated: true`. Serialize as `serde_json::Map`, attach to the existing match record only when the call had `structural_query`.
- **Patterns to follow.** Existing response-record assembly (`crates/rts-daemon/src/methods/index.rs:1302-1323`); existing byte-to-line conversion utilities in `crates/rts-core/`.
- **Execution note.** Test-first: snapshot one expected response for `(impl_item)` query against a seeded Rust file.
- **Test scenarios.**
  - Single-capture query: response has `captures.fn` with one entry.
  - Multi-capture query (`@fn @name`): response has both keys with their respective entries.
  - Capture text >8KB: `truncated: true` in the capture object.
  - Non-structural call: response has NO `captures` field (absent, not empty).
  - Capture spanning across line boundaries: `start.line` < `end.line`, computed correctly.
- **Verification.** `cargo test -p rts-daemon grep_v2::structural::captures` green; response snapshot matches a committed fixture.

### U7 — Sub-counter telemetry

- **Goal.** Three new sub-counters in `CallCounters`; correctly bumped per-call by which v2 params were set; visible in `Daemon.Stats` snapshot.
- **Files.** `crates/rts-daemon/src/state.rs:159-180` (add `index_grep_multiline`, `index_grep_structural`, `index_grep_within_symbol` `AtomicU64` fields); `crates/rts-daemon/src/state.rs:187-208` (`snapshot()` includes them); `crates/rts-daemon/src/state.rs:212-231` (`total()` includes them); `crates/rts-daemon/src/methods/index.rs` (after validation, bump the relevant counters based on which params were set).
- **Approach.** Bump policy: each sub-counter bumps when its corresponding param is *set and active* (e.g., `multiline: false` does NOT bump). Bumps happen after validation but before the heavy work, so failed structural validation still counts toward `index_grep_structural` (visibility into rejection rates). Document this in `docs/protocol-v0.md`.
- **Patterns to follow.** `crates/rts-daemon/src/state.rs:159-180` (existing `CallCounters`); `crates/rts-daemon/src/methods/mod.rs:46-124` (dispatch site is unsuitable for sub-counter bumps — they happen inside `grep`).
- **Execution note.** Coordination with PR 001: this unit must NOT touch top-level `Daemon.Stats` fields (those are owned by PR 001). Only the sub-counter fields.
- **Test scenarios.**
  - Call with only `structural_query`: `index_grep_structural` += 1, other sub-counters unchanged.
  - Call with all three new params: all three sub-counters and parent `index_grep` += 1 each.
  - Call with `multiline: false`: only parent `index_grep` += 1.
- **Verification.** `cargo test -p rts-daemon` (existing `daemon_stats_round_trip.rs` pattern) extended to cover sub-counters; `cargo test -p rts-daemon grep_v2::telemetry` green.

### U8 — Docs (`docs/protocol-v0.md` updates + tool description string + agent guidance)

- **Goal.** Documentation surface complete: protocol-v0 §7.8b updated; new capabilities + error codes documented; appendix F log entry; rmcp tool description string updated with v2 usage notes.
- **Files.** `docs/protocol-v0.md` (§7.8b Index.Grep — append v2 section; Appendix F — additive entry for v2; §9 error codes — add new codes); `crates/rts-mcp/src/server.rs:605-630` (`#[tool(description=...)]` for `grep`); `AGENTS.md` (the "use rts, not grep" cheatsheet — add a paragraph about v2 capabilities); `changelog.d/<NNNN>-index-grep-v2.md` (fragment per v0.5.5+ convention).
- **Approach.** Pure docs. Tool description gets ~3 lines on v2 usage. Protocol doc gets the wire shape, capabilities, error codes, predicate whitelist, resource budgets.
- **Patterns to follow.** Appendix F precedent (per-alpha additive log entries); `pre_filter_count` doc entry as the optional-output template.
- **Execution note.** Pragmatic.
- **Verification.** Docs lint clean; cross-references resolve; one round-trip test asserts the appendix F entry's listed capabilities all appear in the daemon's runtime capability list.

### U9 — Latency baseline + benchmark fixture

- **Goal.** A reproducible benchmark capturing v1 grep latency on a known workspace, run twice (before/after the v2 PR) to assert no regression on the unchanged code path.
- **Files.** `crates/rts-daemon/benches/grep_baseline.rs` (new — uses criterion or hand-rolled timing); `crates/rts-bench/tests/grep_latency_test.rs` (new — invoked via integration test, asserts p95 < some budget).
- **Approach.** Seeded 1000-file workspace; run `Index.Grep` 100 times against the same literal pattern; record p50/p95/p99 latency. The same script runs against pre-PR and post-PR daemon binaries; output committed under `bench-results/grep-v1-baseline.json`.
- **Patterns to follow.** Existing `crates/rts-bench/tests/` integration-test pattern (tempdir + spawn daemon).
- **Execution note.** Pragmatic.
- **Verification.** Two run-and-diff scripts return same numbers ±10% between pre-PR and post-PR builds on the unchanged path; structural and multiline paths add their own numbers (no comparison — net new).

## Requirements Trace

| ID  | Requirement (from origin) | Satisfied by | Notes |
|-----|---------------------------|--------------|-------|
| R1  | Three optional input params (`multiline`, `structural_query`, `within_symbol`), fully composable | U1, U2 | Composition matrix is the binding spec |
| R2  | `multiline: true` flips multi_line + dot_matches_new_line | U3 | No-op on literal path (composition matrix) |
| R3  | Raw tree-sitter S-expression query | U5 | Predicate whitelist is the safety wrapper |
| R4  | Required `language` param for structural; per-grammar validation | U2, U5 | Partial-failures shape documented |
| R5  | `within_symbol` qualified-name match; def-byte-range filter | U4 | Strict containment; cardinality-capped |
| R6  | All three params fully composable | U2 | Matrix-cell tests |
| R7  | Captures returned per-match in `captures: {name: [...]}` | U6 | Brainstorm top-level shape corrected to per-match |
| R8  | Backward compat byte-for-byte on unchanged path | U1, U9 | Frozen golden + baseline bench |
| R9  | Structured error envelope; distinguishable codes | U2, U4, U5 | 9 codes documented |
| R10 | Sub-counters in `Daemon.Stats` | U7 | Sibling fields, not nested |

## Acceptance Criteria

### Functional

- [ ] **AC1.** A v1 caller (no v2 params) receives a response byte-identical to the frozen v1 golden.
- [ ] **AC2.** `multiline: true` + `pattern` matches across `\n` on a fixture file; `multiline: false` (default) does not.
- [ ] **AC3.** `multiline: true` + `text` (literal) returns `INVALID_PARAMS { code: "MULTILINE_REQUIRES_REGEX" }`.
- [ ] **AC4.** `structural_query` without `language` returns `STRUCTURAL_REQUIRES_LANGUAGE`.
- [ ] **AC5.** Malformed `structural_query` (e.g., `"(unbalanced"`) returns `STRUCTURAL_QUERY_INVALID` with the tree-sitter error in `data.error_message`.
- [ ] **AC6.** `structural_query` with a disallowed predicate (`#contains?`) returns `STRUCTURAL_QUERY_PREDICATE_NOT_ALLOWED`.
- [ ] **AC7.** `structural_query` with `#match? @x "(.*a){50}"` (catastrophic predicate regex) returns `STRUCTURAL_QUERY_PREDICATE_NOT_ALLOWED` due to the predicate budget cap.
- [ ] **AC8.** `structural_query` valid against `language: ["rust"]` returns matches with per-match `captures` keyed by capture name.
- [ ] **AC9.** `structural_query` valid against Rust but invalid against TS in `language: ["rust","ts"]` returns Rust matches + `partial_failures: [{language:"ts", error: ...}]`.
- [ ] **AC10.** `within_symbol: "name"` resolving to zero defs returns `WITHIN_SYMBOL_NOT_FOUND`.
- [ ] **AC11.** `within_symbol: "new"` resolving to >16 defs (default) returns `WITHIN_SYMBOL_TOO_MANY_DEFS { def_count }` unless `within_symbol_allow_overload: true`.
- [ ] **AC12.** `within_symbol: "parse"` resolving to one def keeps only matches whose byte range is strictly inside the def byte range.
- [ ] **AC13.** Adversarial multiline regex (`(?s).*` on a 4 MB file) returns `REGEX_TOO_COMPLEX`, never OOM.
- [ ] **AC14.** Structural query returning >4096 matches sets `truncated: true` with `{rows_seen, rows_returned}` metadata.
- [ ] **AC15.** Structural query running >5s returns `STRUCTURAL_QUERY_TIMEOUT`.
- [ ] **AC16.** A capture whose text exceeds 8 KB has `truncated: true` in the capture object; the response still succeeds.
- [ ] **AC17.** Repeated calls with the same `(language, query_text)` show LRU hits in a sub-counter or debug log (low priority — informational).
- [ ] **AC18.** `Daemon.Ping` advertises `index_grep_multiline`, `index_grep_structural`, `index_grep_within_symbol`, and the bundle `index_grep_v2`.
- [ ] **AC19.** `Daemon.Stats` includes three new sub-counter fields, correctly bumped by call shape.
- [ ] **AC20.** Composition: `structural_query + text` returns only matches where both filters apply (intersection).
- [ ] **AC21.** Composition: `structural_query + within_symbol` returns only structural matches whose match-range is inside the named symbol's def range.
- [ ] **AC22.** `content_version` is consistent across the match line and its captures (same redb txn snapshot).

### Non-Functional

- [ ] **AC23.** v1 grep latency p95 on the seeded 1000-file benchmark is unchanged ±10% versus pre-PR baseline (no regression on unchanged path).
- [ ] **AC24.** Query LRU caps at 64 entries; eviction is recency-ordered.
- [ ] **AC25.** New crate deps limited to `lru = "0.12"` on rts-daemon. No new deps on rts-mcp or rts-core.

### Quality Gates

- [ ] **AC26.** `cargo test --workspace` green; coverage of all 22 functional ACs.
- [ ] **AC27.** `cargo clippy --workspace --all-targets -- -D warnings` clean.
- [ ] **AC28.** `docs/protocol-v0.md` updated with the v2 wire fields, capabilities, error codes, predicate whitelist, resource budgets.
- [ ] **AC29.** A `changelog.d/<NNNN>-index-grep-v2.md` fragment lands.
- [ ] **AC30.** AGENTS.md's "use rts, not grep" cheatsheet gains a paragraph about v2 capabilities.

## Success Metrics

- **First-week:** AGENTS.md cheatsheet updated; one example using structural query in a real PR description.
- **agent-bench Phase 2 PR-B:** The v2 capabilities show up in trajectories — sub-counter visibility in `Daemon.Stats` confirms agents actually call the new modes. Target: at least 5% of `Index.Grep` calls use at least one v2 param within 30 days of merging.
- **Tool-use ratio:** Measurable reduction in `Bash rg` calls per task on the agent-bench corpus, attributable to the multi-line / structural / scoped capabilities. Wilson-CI 95% over n≥30 tasks.
- **Latency stability:** p95 of v1-shape grep on the seeded benchmark unchanged within ±10% pre/post merge.

## Dependencies & Risks

- **PR 001 (rts-doctor) must land first or merge atomically.** Both modify `CallCounters` and the capability list in `methods/daemon.rs`. The plan sequences PR 001 → PR 002.
- **`lru` crate addition.** A new dep on rts-daemon. Minimal, well-maintained (~10k downloads/day on crates.io). Plan validates the dep tree post-merge.
- **Tree-sitter 0.26 pin.** Predicate set documented for 0.26. A future tree-sitter upgrade may require predicate whitelist re-validation. Documented in `docs/protocol-v0.md` as a known maintenance item.
- **regex version skew.** Workspace has `regex = "1"` (daemon) and `"1.10"` (core). v2 features (`dfa_size_limit`, `multi_line`) require `1.5+`; both are satisfied. Plan recommends pinning workspace-wide to `1.10` in a separate small PR (out of this scope).
- **Brainstorm shape correction risks contention.** R7's top-level `{name: [...]}` shape would have produced collisions; this plan corrects to per-match. If any external consumer prototyped against the brainstorm shape, they'll need to update. No external consumers exist today.
- **Predicate whitelist may be too restrictive.** v1 whitelist deliberately covers the common cases (`#eq?`, `#match?`, etc.). If observed agent usage demands more, expand in a follow-up PR; do NOT widen pre-emptively (DoS surface).
- **Per-file re-parse cost on large workspaces.** A 100k LOC workspace with a structural query that runs against every file may approach the 5s wall-clock budget. The truncation + timeout responses are the safety valve. A future PR can add a per-call parsed-tree cache if observed usage demands it.

## Scope Boundaries

The following are explicit non-goals for this PR:

- **No named-pattern catalog** (e.g., `fn_with_attr`, `impl_containing`). Raw S-expression queries only. A v2.1 catalog can be informed by observed agent queries.
- **No structural query as a denormalized graph.** v1 runs the query per-file and unions results; no cross-file structural matching.
- **No rewriting / refactoring based on captures.** v2 is read-only; transforms live in a future `Index.RenamePreview`-shaped tool (ideation idea #6).
- **No structural queries on `Index.FindCallers`, `Index.ImpactOf`, etc.** v2 is `Index.Grep`-only.
- **No persisted-result cache.** Query LRU is in-memory; cleared on daemon restart.
- **No hot grammar reload / grammar-version invalidation.** Grammars are statically linked at daemon build time. A grammar bump requires a daemon binary rebuild.
- **No streaming response.** Structural results are buffered, truncated at the row cap, and returned as a single response. A future v2.x can add streaming if needed.
- **No `--output lines` parity for the new fields in `rts-bench query grep`.** The CLI exposes the v1 line shape only; new fields are JSON-only via the MCP path.

## Sources & References

- **Origin document:** [docs/brainstorms/2026-05-18-index-grep-v2-requirements.md](../brainstorms/2026-05-18-index-grep-v2-requirements.md). Carried-forward decisions:
  1. Single tool, additive params — Key Decisions §1
  2. Raw S-expression queries — Key Decisions §2
  3. Fully composable; captures returned — Key Decisions §3 (per-match shape corrected by this plan)
  4. Required `language` for structural queries — Key Decisions §4
  5. Sub-counters for v2 capabilities — Key Decisions §5
- **Research consolidations:**
  - `crates/rts-mcp/src/server.rs:198-236` — `GrepArgs` (extension surface)
  - `crates/rts-mcp/src/server.rs:605-630` — `#[tool]` grep description
  - `crates/rts-daemon/src/methods/index.rs:116-146` — `GrepParams`
  - `crates/rts-daemon/src/methods/index.rs:152-231` — `GrepScanner` enum (extends to MultilineRegex)
  - `crates/rts-daemon/src/methods/index.rs:1069-1367` — current grep handler
  - `crates/rts-daemon/src/methods/index.rs:1302-1323` — response record (extends with `captures`)
  - `crates/rts-daemon/src/methods/index.rs:2294-2303` — `pick_innermost_def`
  - `crates/rts-daemon/src/store/mod.rs:995-1035` — `find_symbol` (within_symbol's resolution path)
  - `crates/rts-daemon/src/store/schema.rs:159-168` — `DefSite { start, end, ... }`
  - `crates/rts-daemon/src/language.rs:67-317` — per-language queries + OnceLock cache pattern
  - `crates/rts-daemon/src/refs.rs:54-115` — existing tree-sitter Query execution
  - `crates/rts-core/src/query.rs:11-109` — `Query` wrapper
  - `crates/rts-daemon/src/state.rs:159-180` — `CallCounters` (closed enum extension)
  - `crates/rts-daemon/src/methods/daemon.rs:18-87` — capability list
  - `docs/protocol-v0.md` §7.4 (`pre_filter_count`) — optional-output precedent
  - `docs/protocol-v0.md` §7.8b — current `Index.Grep` spec
  - `docs/protocol-v0.md` §3.6 — `content_version` propagation rule
- **Related PRs / plans:**
  - **PR 001** (`docs/plans/2026-05-18-001-feat-rts-bench-doctor-plan.md`) — Daemon.Stats v2 + capability; must land first or merge atomically.
  - #104 (Daemon.Stats RPC + counters)
  - #107 (agent-bench harness — measures whether v2 capabilities shift agent tool-use ratio)

## Deferred to Implementation

All 9 brainstorm-deferred questions resolved here:

- **[Affects R2]** Multi-line resource budget: `dfa_size_limit = 32 MB`, `size_limit = 32 MB`, no wall-clock timeout (covered by overall daemon request timeout). `(?s)` is implicit when `multiline: true` (combined with `(?m)`).
- **[Affects R5]** `within_symbol` shape: single exact qualified name in v1; opt-in `within_symbol_allow_overload: true` to union N defs; otherwise capped at `WITHIN_SYMBOL_MAX_DEFS = 16`.
- **[Affects R5]** `within_symbol` intersection: strict containment (match range ⊆ def range).
- **[Affects R3, R7]** Predicate whitelist: `#eq?`, `#not-eq?`, `#match?`, `#not-match?`, `#any-of?`, `#is?`, `#is-not?`. Documented in protocol-v0.
- **[Affects R4]** Pre-validation: `Query::new` at request time; LRU caches the compiled `Query`. Malformed query yields `STRUCTURAL_QUERY_INVALID` with the tree-sitter error message.
- **[Affects R7]** Capture position units: `{line, col}` (consistent with v1 match coordinates). Byte offsets not exposed in v1.
- **[Affects R6]** Result truncation: `STRUCTURAL_MAX_ROWS = 4096`; capture text truncation at `STRUCTURAL_MAX_CAPTURE_BYTES = 8 KB`; top-level `truncated: true` + metadata.
- **[Affects R7]** `language` filter on literal/regex path: yes (parity); intersected with `file_glob`.
- **[Affects R4]** Grammar-version invalidation: out of scope for v1 (no hot reload).

## Post-Deploy Monitoring & Validation

- **What to monitor/search**
  - Logs: daemon `tracing` output at `info` for v2 calls (counter bumps) and at `warn` for resource-cap breaches.
  - Metrics/Dashboards: `Daemon.Stats` sub-counter values across sessions; agent-bench trajectory tool-use ratio (`mcp__rts__grep` count).
- **Validation checks (queries/commands)**
  - Manual: `cargo test --workspace`
  - Round-trip: a fixture trajectory replays against the v2 daemon and produces identical v1-shape responses on the unchanged path.
  - Bench: `cargo bench -p rts-daemon grep_baseline` shows ±10% on v1 path.
- **Expected healthy behavior**
  - Sub-counters show non-zero values once an agent uses v2.
  - No regression in v1 latency.
  - Adversarial inputs return structured errors, not panics/OOM.
- **Failure signal(s) / rollback trigger**
  - Spike in `STRUCTURAL_QUERY_TIMEOUT` or `REGEX_TOO_COMPLEX` errors → tighten budgets or revert.
  - Any panic in `grep_v2::*` → revert (no schema migrations).
- **Validation window & owner**
  - 14-day window post-merge; author monitors agent-bench tool-use ratio.

---

## Plan Status

- **Detail level:** MORE (standard plan)
- **SpecFlow:** complete (composition matrix, edge cases, brainstorm shape corrections all incorporated)
- **Deepen:** not requested
- **Source decisions trace:** complete; 9 brainstorm-deferred questions resolved; 5 brainstorm assumptions corrected based on research
- **Coordination:** sequences after PR 001 (doctor)
- **Next:** `/ce:plan` on `docs/brainstorms/2026-05-18-persisted-cold-mount-requirements.md`, then `/ce:work` on the three plans in order.
