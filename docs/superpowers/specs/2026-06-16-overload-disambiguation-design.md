# Overload Disambiguation (Parent Scope) — Design

**Status:** Approved (design phase)
**Date:** 2026-06-16
**Author:** njf + Claude
**Topic:** Make same-named definitions distinguishable by their parent scope

---

## Goal

Today the index conflates same-named symbols: every `new` across the
workspace shares one `qualified_name` (`"new"`) and — because the
reference graph keys on a per-*name* sid (`NAME_TO_SID`) — one identical
PageRank score. An agent calling `find_symbol("new")` gets 31
indistinguishable rows. This feature records each definition's **parent
scope** (the owning type/container) so `find_symbol` / `read_symbol`
can *show* and *filter* by it: `QueryBuilder::new` vs `Parser::new`.

## Scope (and non-goals)

**In scope:** `find_symbol`, `read_symbol`, `read_symbol_at` — making
*definitions* distinguishable.

**Explicit non-goals** (rts is tree-sitter, not a type-checker):
- **No type-based overload resolution.** Picking an overload by
  argument/receiver types at a call site (`obj.method()`) is impossible
  without type inference. Only syntactic parent scope is recorded.
- **No call-graph change.** `find_callers` stays name-level; the
  per-name sid / reference graph / PageRank conflation is untouched.
  (De-conflating the graph is a separate, larger project.)
- **No full path.** `parent` is the single nearest container, not a
  `crate::mod::Type` chain.
- **Same-container overloads stay parent-equal.** True overloading —
  two `f(int)` / `f(String)` in one Java/C++ class — share a parent, so
  `parent` does not separate them; they remain distinguishable only by
  `signature` / `range` (which `find_symbol` already returns). This
  feature targets the common cross-type case (`Foo::new` vs `Bar::new`),
  not in-class overload sets.

## What "parent" is

A definition's `parent` is the **name of its nearest enclosing container
definition** — one level. Containers: `impl` / `struct` / `class` /
`trait` / `enum` / `interface` / `object` / `namespace` / explicit
`module`/`mod` blocks.

- Method in `impl QueryBuilder` → `parent = "QueryBuilder"`.
- `impl Trait for Foo` → `parent = "Foo"` (the type, not the trait).
- Method in `class Parser` (Python/JS/Java/…) → `parent = "Parser"`.
- Top-level free function → `parent = None`.
- Nested (method in `impl Bar` inside `mod foo`) → nearest only:
  `parent = "Bar"` (the module is not included — single level).

`qualified_name` renders as `parent::name` with a **uniform `::`
separator** for all code languages (e.g. `QueryBuilder::new`, even in
Python/JS). Markdown headings keep their existing hierarchical
` > ` qualified names — untouched.

## Architecture (approach A: index-time extraction)

`parent` is computed once at extraction time and stored on the def — it
is intrinsic to the definition, costs nothing at query time (important
given the index already has slow scan paths), and avoids a brittle
query-time "is this def a container?" heuristic.

### 1. Extraction (`crates/rts-core/src/extraction.rs`)

The 12 per-language `extract_*_symbols` functions (`extract_rust_symbols`,
`extract_python_symbols`, `extract_javascript_symbols`,
`extract_go_symbols`, `extract_java_symbols`, `extract_ruby_symbols`,
`extract_c_symbols`, plus C++/TS/PHP/Swift/C# paths) already walk the
tree and emit `Symbol { name, kind, range, signature, … }`. Add a
per-language `parent_scope(node) -> Option<String>`: walk `node.parent()`
up to the nearest node whose kind is in that language's **container-node
set**, and read its name child (for Rust `impl_item`, resolve the
*type* operand of `impl Trait for Type`).

- The `Symbol` struct (rts-core) gains `parent: Option<String>`.
- Per-language container-node kinds live beside the existing per-language
  config in `crates/rts-core/src/languages/*.rs`.
- A language whose grammar makes this awkward returns `None` — graceful,
  never worse than today (markdown already returns its own hierarchy and
  is left as-is).

### 2. Storage (`crates/rts-daemon/src/store/mod.rs` + writer)

The DEFS record value and `FoundSymbol` gain `parent: Option<String>`.
This bumps the **redb schema version**; the daemon **auto-rebuilds the
index** on first run after upgrade (existing rehydrate/cold-walk path).
Per the documented pre-1.0 policy, an on-disk schema change between minor
versions is allowed (a downgrade needs a one-time state-dir wipe). No new
table — one field on the def value.

### 3. Wire surface (`crates/rts-daemon/src/methods/index.rs`)

- **`find_symbol`**: each match gains `parent` (string or null);
  `qualified_name` is rendered `parent::name` when a parent exists. New
  optional request param `parent` — exact-match filter (compose with the
  existing `file`/`kind` filters).
- **`read_symbol` / `read_symbol_at`**: output gains `parent`; accept an
  optional `parent` disambiguator (alongside `file`/`kind`); when the
  name is ambiguous, the `AMBIGUOUS_SYMBOL` error's `data` lists the
  candidate defs **with their `parent`** so the caller can pick.
- **`find_callers`**: unchanged (out of scope).
- New capability flag **`parent_scope`** in `DAEMON_CAPABILITIES` so
  clients can gate on the enriched `qualified_name` / `parent` field.

## Compatibility

- `parent` field and the `parent` filter param are **additive**.
- **One behavior change:** `qualified_name`'s *value* changes for code
  symbols that have a parent (`"new"` → `"QueryBuilder::new"`). This is
  documented and is arguably a correctness fix — the field is literally
  `qualified_name`, and markdown headings already return qualified
  values. Clients that matched on the bare name should read `name`
  instead (unchanged).
- Frozen surface (tool names + argument *shapes*) is unchanged; the new
  `parent` param is an additive flag (not part of the frozen set).
- redb schema bump → automatic reindex on upgrade.

## Testing

- **Per-language extraction** (`rts-core`): a fixture per code language
  with a method inside a container and a top-level free function →
  assert `parent` is the container name for the method and `None` for
  the free function; cover `impl Trait for Type` (Rust) and at least one
  nested case.
- **`find_symbol`**: returns `parent` and `qualified_name = "Parent::name"`;
  the `parent` filter narrows 31 `new`s to one type's; the two same-file
  `new`s in `query.rs` become distinguishable.
- **`read_symbol`**: `parent` disambiguator resolves a name that is
  ambiguous by `file`/`kind` alone; `AMBIGUOUS_SYMBOL.data` lists parents.
- **Protocol**: `parent_scope` capability advertised; schema-drift test
  updated; `find_symbol`/`read_symbol` response schemas include `parent`.
- **Reindex**: a smoke test that an index built by a prior schema is
  rebuilt and serves `parent` after the bump (or rely on the existing
  schema-version rebuild mechanism with a unit test on the version gate).

## Success criteria

- `find_symbol("new")` returns rows whose `qualified_name` distinguishes
  the owning type (`QueryBuilder::new`, `Parser::new`, …) and a `parent`
  field; `find_symbol("new", parent="Parser")` returns only Parser's.
- `read_symbol("new", parent="QueryBuilder")` resolves unambiguously;
  an ambiguous `read_symbol` lists candidates with parents.
- All 12 code languages populate `parent` for container-owned defs
  (or `None` where no container); markdown unchanged.
- `parent_scope` capability advertised; protocol schemas + docs updated;
  index auto-rebuilds on upgrade; CI green; no `find_callers`/call-graph
  behavior change.
