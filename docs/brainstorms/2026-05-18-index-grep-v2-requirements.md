---
date: 2026-05-18
topic: index-grep-v2
---

# `Index.Grep` v2 — multiline regex + structural queries + within-symbol scope

## Problem Frame

The current `grep` MCP tool is the only `rg`-shaped surface in rts. It's the agent's natural successor to `Bash rg`, and the *enclosing-qualified-name* it returns per match is the unique reason agents reach for it instead of `rg`.

But three known shortcomings make agents drop back to `Bash rg` mid-session:

- **No multiline.** Patterns that need to match across `\n` (a function signature on three lines; an SQL fragment with embedded newlines; a multi-line error message) silently fail in v1.
- **No structural matching.** "Find every `impl` block containing an `unsafe fn`" requires `rg` + manual filtering, or two MCP calls + an intersection. `rg` is faster than rts at that point.
- **No within-symbol scope.** "Find every `panic!` *inside* `fn parse_request`" requires a `grep` + a `find_symbol` + a byte-range intersection the agent has to compute by hand.

These leaks are measurable: every `Bash rg` invocation in an agent-bench trajectory after the workspace is indexed is a v2 candidate. Closing them tightens the value-prop without expanding the tool surface (one tool, three new params).

## Requirements

- **R1.** `Index.Grep` gains three optional input parameters, fully composable with each other and with the existing literal/regex `text`/`pattern` inputs:
  - `multiline: bool` (default `false`)
  - `structural_query: string` (a raw tree-sitter S-expression query)
  - `within_symbol: string` (a qualified-name match scope)
- **R2.** When `multiline: true`, the regex engine treats indexed file bytes as one logical buffer per file (i.e., `.` and `[^x]` match `\n`; `(?s)` flags are honored). Single-line semantics remain the default; existing callers are unaffected.
- **R3.** `structural_query` accepts a **raw tree-sitter S-expression query string**, in the same form used internally for `@reference.call` patterns today. The query MAY include named captures (`@name`); when present, captures are returned in the response.
- **R4.** `structural_query` requires a `language` parameter: either a single language identifier (`"rust"`) or a list (`["rust", "typescript"]`). All 12 indexed languages are eligible. The daemon validates the query against each named grammar at request time and returns a structured error if the query is malformed for that grammar.
- **R5.** `within_symbol` is a **qualified-name match scope**. When set, returned matches are filtered to those whose byte range lies entirely inside the def-byte-range of the named symbol(s). Exact semantics for the parameter shape (single name, glob, list, fully-qualified path) is a planning-time decision (see Deferred questions). The minimum v1 behavior: accept a single exact qualified name.
- **R6.** All three parameters compose freely:
  - `multiline + within_symbol` — multi-line regex inside one function
  - `structural_query + within_symbol` — structural match inside one function
  - `multiline + structural_query` — structural match with regex-based capture predicates (`#match? @name "regex"`)
  - all three together — bounded multi-line structural search
- **R7.** Response shape is a superset of the v1 grep response. Existing fields (`file`, `line`, `enclosing_qualified_name`, `kind`, span info) are preserved verbatim. Structural matches additionally carry a `captures` map: `{capture_name: [{start: {line, col}, end: {line, col}, text: string}]}`, one entry per named capture in the query. Non-structural (literal/regex) matches do not populate `captures`.
- **R8.** Backward compatibility: every existing call to `Index.Grep` (literal `text`, regex `pattern`, no new params) returns byte-for-byte the same response in v2 as in v1. The wire shape grows; no existing field changes meaning.
- **R9.** Errors on malformed input return a structured error envelope, not an empty result set. A malformed S-expr query, an unknown language, an unknown `within_symbol` name, and an unparseable regex are each distinguishable in the error code.
- **R10.** Per-method telemetry from `Daemon.Stats` (#104) distinguishes v2 calls: a v2 call counts under `Index.Grep` for the existing counter AND under a new `Index.Grep.structural` / `Index.Grep.scoped` / `Index.Grep.multiline` sub-counter so we can measure adoption of each new capability independently.

## Success Criteria

- **SC1.** A v1 agent-bench trajectory replayed against v2 reaches the same answer in fewer turns at least once (typical case: "find every panic in module X" goes from `grep` + `find_symbol` + `read_symbol` to one `grep` call with `within_symbol`).
- **SC2.** At least one agent-bench task per language family has at least one structural-query example in the chosen trajectory after v2 ships (proxy for "structural is actually used, not just shipped").
- **SC3.** The README's *"What it gives your agent"* table grows a one-line v2 note under `grep` describing the new params, without changing the row count.
- **SC4.** No regression in `Index.Grep` p95 latency on the unchanged path (literal/regex, no new params). The new sub-counters in `Daemon.Stats` make a regression visible.

## Scope Boundaries

- **Out of scope (v1):** named-pattern catalog (`fn_with_attr`, `impl_containing`, etc.). Raw S-expression queries only; sugar can be a v2.1 add-on informed by which raw queries agents actually run.
- **Out of scope (v1):** structural query *across* the entire workspace as a single denormalized graph. v1 runs the query per-file (over the parsed-tree cache) and unions results.
- **Out of scope (v1):** replacing `find_symbol`. Structural grep is for ad-hoc patterns; `find_symbol` remains the canonical "where is X defined" tool.
- **Out of scope (v1):** unifying grep + structural into a single `query` tool with sugar (the rejected challenger option). v2 keeps `Index.Grep` as the one entry point; the new params are additive.
- **Out of scope (v1):** structural queries on *non*-indexed languages or auto-detection across all 12 grammars. Language is a required input.
- **Out of scope (v1):** rewriting / refactoring based on captures. v2 is read-only retrieval; transforms live in a future `Index.RenamePreview`-shaped tool (ideation idea #6).
- **Out of scope (v1):** persisted-result caching across daemon restarts. Cache lives in memory for the daemon lifetime; planning may revisit if structural queries are slow.

## Key Decisions

- **One tool, additive params over three sibling tools or a unified `query` tool.** Backward compatible; preserves existing schema discoverability; agents that already reach for `grep` automatically get the new capabilities once they learn the new fields. Sibling tools would inflate the tool surface; a unified `query` tool would force every existing caller to relearn.
- **Raw S-expression queries over a named-pattern catalog.** Matches what's already used internally; maximum expressiveness; ships fast. The "named-pattern sugar later" challenger remains valid as a v2.1, gated on observed usage.
- **Fully composable params, captures returned.** The composition produces a small, predictable matrix: 2 (multiline yes/no) × 2 (structural yes/no) × 2 (within_symbol yes/no) = 8 modes, all behaving like the union of independent filters. Captures are the only structural-only field, returned only when relevant.
- **Required `language` for structural queries.** Avoids silent-fail when a query syntactically targets a grammar that isn't loaded. Makes the failure mode legible: "you asked for `impl_item` and we don't have a Java grammar with that node."
- **Per-capability sub-counters in `Daemon.Stats`.** Without these, we can't tell whether v2 is *actually* being used after it ships. The sub-counters cost ~50 LOC; the alternative is shipping v2 blind to adoption.

## Dependencies / Assumptions

- All 12 indexed languages already have parsed trees in the daemon's per-file tree-sitter cache. (Call-edge precision differs across 6 vs 6; that's orthogonal.)
- The tree-sitter query API exposed by the upstream `tree-sitter` crate supports running compiled queries against cached trees without re-parsing. Confirm at planning.
- The current `Index.Grep` response already carries enough span info to support intersection with a symbol's byte range; `within_symbol` filtering is a post-pass over existing match coordinates.
- `Daemon.Stats` (#104) is the canonical surface for adoption telemetry; protocol-v0 evolution rules govern how the new sub-counters are exposed.

## Outstanding Questions

### Resolve Before Planning

*(none — all product-level decisions are made)*

### Deferred to Planning

- **[Affects R2]** **[Technical]** Multi-line regex resource budget: max bytes scanned per file? Max DFA size? Wall-clock timeout? Default `(?s)` flag or require explicit opt-in? Pick concrete numbers in planning informed by the regex crate's `RegexBuilder::dfa_size_limit`.
- **[Affects R5]** **[Product]** Exact shape of `within_symbol`: single exact qualified name (v1 minimum), or also accept `["name1", "name2"]`, `pattern: "fn_*"`, `qualified_path: "module::Type::method"`? Recommend exact-name v1, glob/list as a separate enhancement.
- **[Affects R5]** **[Technical]** Within-symbol intersection semantics: match must be *entirely* inside the def byte range (strict), or *overlap* with it (lenient)? Strict is unambiguous; lenient is more forgiving for matches that span the closing brace.
- **[Affects R3, R7]** **[Technical]** Predicate support in S-expressions: do we accept `#match?`, `#eq?`, `#not-match?`, custom predicates? `tree-sitter` supports a defined set; document which v1 supports.
- **[Affects R4]** **[Technical]** Pre-validation of the S-expr query: validate at request time (per-grammar `Query::new`) and return a structured error before scanning, vs validate-and-scan in one pass. Pre-validation costs ~100µs per query but gives much better error messages.
- **[Affects R7]** **[Product]** Capture position units: line/column (consistent with v1 match coordinates), byte offsets (consistent with tree-sitter native), or both? Recommend line/column for parity with v1, byte offsets as an optional `--position-units bytes` flag.
- **[Affects R6]** **[Technical]** Result truncation: large structural queries can return thousands of captures. v2 needs explicit truncation rules and a `truncated: bool` flag. Pick limits (rows, total bytes, per-capture text length) in planning.
- **[Affects R7]** **[Technical]** Does the literal/regex grep path *also* accept the optional `language` filter (for parity, e.g., "grep `panic!` only in Rust files")? Lightweight to add; consistent with the structural path. Recommend yes.
- **[Affects R4]** **[Technical]** Grammar-version invalidation: if a tree-sitter grammar version bumps, the structural-query node names may change. How does the daemon surface "your query syntax is valid against an older grammar version"? Probably out of scope for v1 but worth a one-line note.

## Next Steps

→ Continue brainstorming idea #4 (Persisted cold-mount index) next, per the ideation queue. After brainstorm #3 lands, run `/ce:plan` on each of the three in turn.
