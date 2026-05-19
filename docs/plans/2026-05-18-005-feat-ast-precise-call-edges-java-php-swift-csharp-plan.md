---
title: AST-Precise Call Edges for Java, PHP, Swift, C#
type: feat
status: active
date: 2026-05-18
---

# AST-Precise Call Edges for Java, PHP, Swift, C#

## Overview

`rts` currently extracts AST-precise outgoing call edges for **6** of its 12
indexed languages: Rust, Python, Go, Ruby, JavaScript, TypeScript (see
`crates/rts-daemon/src/language.rs:70-195`). The remaining 6 languages —
**Java, PHP, Swift, C#, C, and C++** — fall back to the regex-based
`extract_identifiers` path (`crates/rts-daemon/src/outline.rs`), which
over-emits noise (variable names, type names, keywords) and misses
method-call structure.

This plan adds AST-precise `@reference.call` queries with `@name` sub-captures
for Java, PHP, Swift, and C# as the primary deliverable. C and C++ are listed
as optional follow-on targets — their call-edge semantics overlap heavily with
the regex fallback's already-acceptable noise floor (function-pointer calls
look identical to identifier references), so the work-per-value is materially
lower.

**Scope correction:** an earlier brief framed this as "Go/Java" — Go and
Ruby already have AST queries (`GO_REFS` at `language.rs:115-135`, `RUBY_REFS`
at `:137-139`). The actual missing 6 are Java/PHP/Swift/C#/C/C++.

## Problem Statement / Motivation

The "what you get over `rg`" pitch leans heavily on AST-precise call graphs.
For polyglot codebases — especially backend Java services, WordPress/Laravel
PHP, mobile Swift, and .NET C# — `rts` currently degrades to identifier-grep
behavior. A user calling `Index.FindCallers` on a Java method gets matches
for every textual occurrence including imports, comments, and string
literals, with no method-resolution discipline.

Closing this gap raises the substantive product surface from "6/12 languages
get the good behavior" to "10/12" — a 67% language coverage improvement.

## Proposed Solution

For each target language, add an `@reference.call` query string to
`language.rs` modeled after the existing `RUST_REFS`/`PY_REFS`/`GO_REFS`
constants. Each query captures call expressions with a sub-capture named
`name` that the existing extractor (`crates/rts-daemon/src/refs.rs:54-73`)
already filters on.

### Per-Language Query Sketches

**Java** (`tree-sitter-java`):
```scheme
(method_invocation
  name: (identifier) @name) @reference.call

(object_creation_expression
  type: (type_identifier) @name) @reference.call
```
Edge case: chained calls (`a.b().c()`) — the parser emits one
`method_invocation` per `.`, so we get edges to `b` and `c` separately.

**PHP** (`tree-sitter-php`):
```scheme
(function_call_expression
  function: (name) @name) @reference.call

(member_call_expression
  name: (name) @name) @reference.call

(scoped_call_expression
  name: (name) @name) @reference.call

(object_creation_expression
  (qualified_name (name) @name)) @reference.call
```
Edge case: variable-function calls `$fn()` resolve to a `_expression`
that's not a `name` — intentionally skipped (no static target).

**Swift** (`tree-sitter-swift`):
```scheme
(call_expression
  (simple_identifier) @name) @reference.call

(call_expression
  (navigation_expression
    suffix: (navigation_suffix
      (simple_identifier) @name))) @reference.call
```
Edge case: trailing closures look like calls but the function name is in
the preceding `simple_identifier` — covered. Swift 0.7 grammar (pinned
in `crates/rts-core/Cargo.toml`) is older than 0.23 peers; verify node
names against the installed grammar's `node-types.json`.

**C#** (`tree-sitter-c-sharp`):
```scheme
(invocation_expression
  function: (identifier) @name) @reference.call

(invocation_expression
  function: (member_access_expression
    name: (identifier) @name)) @reference.call

(object_creation_expression
  type: (identifier) @name) @reference.call
```
Edge case: generic-method calls `Foo<T>()` parse `function` as a
`generic_name` whose first child is the identifier — add a third pattern
if the smoke test misses these.

## Technical Considerations

- **Cached query handle:** `LanguageInfo::cached_refs_query` at
  `language.rs:304-317` lazily compiles `Query` instances and stores them
  on the `LanguageInfo` table. Adding a new language is a one-line addition
  to that table.
- **Performance:** queries are compiled once per process per language; the
  hot path is `extract_references` (`refs.rs:129-173`) which already
  filters captures named `"name"`. No new code paths.
- **Reference resolution:** the writer's resolver maps `name: String` →
  `symbol_id` via the symbol table at write time
  (`crates/rts-daemon/src/writer.rs`). No change needed — adding queries
  just produces more `name` strings to resolve.
- **Grammar versions:** `tree-sitter-java`, `tree-sitter-php`,
  `tree-sitter-c-sharp` are at 0.23.x; `tree-sitter-swift` is at 0.7.
  Verify each query against the grammar's `node-types.json` before
  shipping (`grep` the grammar repo's `tags.scm` as a reference baseline).

## System-Wide Impact

- **Interaction graph:** parse → query → `extract_references` → resolver →
  `OUTGOING_REFS` writes. Nothing fires outside this chain. The query
  cache is process-wide, not per-mount, so a new language affects every
  workspace using that language.
- **Error propagation:** if a query fails to compile (grammar version
  mismatch), `cached_refs_query` returns `Err` and `extract_references`
  falls through to the regex path for that file. No daemon failure.
- **State lifecycle:** call edges are recomputed per file on every parse.
  Adding queries does not invalidate persisted indices — files re-indexed
  after this lands gain precise edges; previously indexed files keep
  their regex-fallback edges until next touch.
- **API surface parity:** `Index.FindCallers` and `Index.FindCallees`
  both consume `OUTGOING_REFS`. No interface change.
- **Integration test scenarios:**
  1. Java fixture with chained `a.b().c()` — assert edges to `b` and `c`,
     not to `a`.
  2. PHP fixture mixing `$obj->method()` and `static::method()` — assert
     both resolve.
  3. Swift fixture with trailing closures — assert call edge present.
  4. C# fixture with generic method calls — assert edge present.

## Acceptance Criteria

- [ ] `language.rs` gains `JAVA_REFS`, `PHP_REFS`, `SWIFT_REFS`,
      `CSHARP_REFS` constants registered in the `LanguageInfo` table.
- [ ] Each language's existing fixture in
      `crates/rts-daemon/tests/fixtures/` (or new fixtures) parses
      cleanly and produces non-empty `@reference.call` captures.
- [ ] Per-language integration test in
      `crates/rts-daemon/tests/call_edges_<lang>.rs` mounts a fixture,
      waits for indexing, and asserts `Index.FindCallers` returns the
      expected method-level edges (not variable references, not
      identifier matches in strings/comments).
- [ ] Regression: existing Rust/Python/Go/Ruby/JS/TS call-edge tests
      still pass.
- [ ] Performance: no measurable cold-walk regression on a 100-file
      mixed-language workspace (compare `Daemon.Stats.cold_walk_ms`
      before/after).
- [ ] README "language coverage" table updated: 6→10 languages with
      AST-precise call edges.

## Success Metrics

- 4 languages move from "regex fallback" to "AST-precise" in the README
  coverage matrix.
- `Index.FindCallers` precision on a Java fixture (manually labeled true
  positives) improves from baseline.
- No regression in `Daemon.Stats.cold_walk_ms` ±5%.

## Dependencies & Risks

- **Risk:** Swift grammar at 0.7 may lack node names assumed in modern
  `tags.scm` examples. Mitigation: verify against installed grammar's
  `node-types.json` first; if missing, file a follow-up to upgrade the
  grammar before adding the query.
- **Risk:** PHP namespace-qualified calls (`\Foo\bar()`) may parse as
  `qualified_name` not `name`. Mitigation: include `(qualified_name
  (name) @name)` variant in the PHP query.
- **No new dependencies** — grammar crates already pinned in
  `crates/rts-core/Cargo.toml:18-31`.

## Out of Scope (Non-Goals)

- C and C++ AST queries (deferred — work-per-value lower; tracked as
  optional follow-on).
- Cross-language call edges (a Java method calling a Kotlin lib is still
  regex-fallback because Kotlin isn't an indexed language).
- Resolving overloaded methods to specific signatures (rts indexes by
  name only; overload disambiguation is a v0.7 conversation).

## Sources & References

- **Existing queries to mirror:**
  - `crates/rts-daemon/src/language.rs:70-114` (`RUST_REFS`)
  - `crates/rts-daemon/src/language.rs:97-114` (`PY_REFS`)
  - `crates/rts-daemon/src/language.rs:115-135` (`GO_REFS`)
  - `crates/rts-daemon/src/language.rs:137-139` (`RUBY_REFS`)
- **Extraction path:** `crates/rts-daemon/src/refs.rs:54-73, 129-173`
- **Query cache:** `crates/rts-daemon/src/language.rs:304-317`
- **Grammar crates:** `crates/rts-core/Cargo.toml:18-31`
- **Upstream `tags.scm` references for cross-checking patterns:**
  - tree-sitter-java: `queries/tags.scm`
  - tree-sitter-php: `queries/tags.scm`
  - tree-sitter-swift: `queries/tags.scm`
  - tree-sitter-c-sharp: `queries/tags.scm`
