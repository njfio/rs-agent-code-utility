# Overload Disambiguation (Parent Scope) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Record each definition's nearest enclosing container (`impl`/`class`/`struct`/…) as `parent` so `find_symbol`/`read_symbol` can show and filter by it (`QueryBuilder::new` vs `Parser::new`).

**Architecture:** Add `parent: Option<String>` to the rts-core `Symbol`; assign it with a containment-based per-language pass over the tree-sitter tree (innermost enclosing container node → its name); persist it through DEFS (schema bump → auto-reindex); render `qualified_name` as `parent::name` (uniform `::`) and expose a `parent` field + filter in `find_symbol`/`read_symbol`. No reference-graph / `find_callers` change.

**Tech Stack:** Rust, tree-sitter (rts-core extractors), redb (rts-daemon store), serde_json wire.

**Working branch:** `feat/overload-disambiguation` (spec committed there).

**Reference spec:** `docs/superpowers/specs/2026-06-16-overload-disambiguation-design.md`

---

## File map

- Modify: `crates/rts-core/src/symbol.rs` — `Symbol.parent` field.
- Modify: `crates/rts-core/src/extraction.rs` — `Symbol { … }` sweep + call the parent pass.
- Create: `crates/rts-core/src/parent_scope.rs` — containment-based `assign_parents`.
- Modify: `crates/rts-core/src/lib.rs` — register the module.
- Modify: `crates/rts-daemon/src/store/mod.rs` — persist `parent` in the DEFS value; `FoundSymbol.parent`; bump schema version.
- Modify: `crates/rts-daemon/src/methods/index.rs` — `qualified_name` rendering, `parent` field, `parent` filter (find_symbol/read_symbol/read_symbol_at), `AMBIGUOUS_SYMBOL` data.
- Modify: `crates/rts-daemon/src/methods/daemon.rs` — `parent_scope` capability.
- Modify: `docs/protocol-v0.md`, `crates/rts-daemon/tests/protocol_schemas.rs`, `schemas/v0/*` — docs + schema.
- Create: `changelog.d/xxx-feat-parent-scope.md`.

---

## Task 1: `Symbol.parent` field (behavior-neutral foundation)

**Files:** `crates/rts-core/src/symbol.rs`, `crates/rts-core/src/extraction.rs` (+ any other `Symbol { … }` sites)

- [ ] **Step 1: Add the field**

In `crates/rts-core/src/symbol.rs`, add to `struct Symbol` after `documentation`:
```rust
    /// Symbol documentation if available
    pub documentation: Option<String>,
    /// Name of the nearest enclosing container definition (impl / class /
    /// struct / trait / enum / …), or `None` for a top-level symbol.
    /// Populated by `crate::parent_scope::assign_parents`. Used to render
    /// `qualified_name` as `parent::name` and to disambiguate overloaded
    /// names across types.
    #[serde(default)]
    pub parent: Option<String>,
```

- [ ] **Step 2: Find every construction site**

Run:
```bash
grep -rn "Symbol {" crates/rts-core/src/ | grep -v "//"
```
Expected: a list of `Symbol { … }` literals (most in `extraction.rs`, possibly a few in `languages/*.rs` / markdown). Every one needs `parent: None,` added (the pass in Task 3 fills it in).

- [ ] **Step 3: Add `parent: None,` to each literal**

For each `Symbol { … }` literal found, add `parent: None,` as the last field (after `documentation: …,`). This is mechanical and behavior-neutral.

- [ ] **Step 4: Build + test (neutral)**

Run:
```bash
cargo build -p rust_tree_sitter 2>&1 | tail -3
cargo test -p rust_tree_sitter 2>&1 | tail -5
```
Expected: clean build; all existing rts-core tests pass (no behavior change — `parent` is `None` everywhere, not yet surfaced).

- [ ] **Step 5: Commit**

```bash
git add crates/rts-core/src/symbol.rs crates/rts-core/src/extraction.rs
git commit -m "feat(core): add Symbol.parent field (unpopulated)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```
(Add any other touched files to the `git add`.)

---

## Task 2: Storage + wire plumbing (parent flows end-to-end, still None)

**Files:** `crates/rts-daemon/src/store/mod.rs`, `crates/rts-daemon/src/methods/index.rs`, `crates/rts-daemon/src/methods/daemon.rs`

Goal: thread `parent` from the stored def into the `find_symbol`/`read_symbol` wire (rendering `qualified_name = parent::name`, adding a `parent` field, a `parent` filter, and the capability) — while `parent` is still `None` for all defs, so behavior is neutral and verifiable in isolation.

- [ ] **Step 1: Persist `parent` in the DEFS value + `FoundSymbol`**

In `crates/rts-daemon/src/store/mod.rs`: locate the def-record encoding written by `commit_batch` and the `FoundSymbol` struct (search `struct FoundSymbol` and the DEFS value (de)serialization — likely a bincode/manual encode of `(name, kind, range, visibility, documentation, signature?)`). Add a `parent: Option<String>` field to `FoundSymbol` and to the on-disk def value (append it to the encode/decode so old code paths still read). Populate it from `Symbol.parent` wherever a `Symbol` is converted into a stored def.

- [ ] **Step 2: Bump the schema version**

Search for the redb schema-version constant (e.g. `SCHEMA_VERSION` / a version table). Increment it so the daemon's existing "schema newer → rebuild" path triggers a one-time reindex on upgrade. Verify the rebuild path exists (search `SchemaVersionNewer` / `mount_source` rehydrate logic).

- [ ] **Step 3: Render `qualified_name` + emit `parent` in `find_symbol`**

In `crates/rts-daemon/src/methods/index.rs`, the find_symbol match builder currently emits `"qualified_name": h.name`. Replace with a qualified rendering + a `parent` field. Add a helper near the handler:
```rust
/// Uniform `::` join for code symbols. Markdown defs carry their own
/// hierarchical name and a `None` parent, so they are unaffected.
fn render_qualified_name(name: &str, parent: Option<&str>) -> String {
    match parent {
        Some(p) if !p.is_empty() => format!("{p}::{name}"),
        _ => name.to_string(),
    }
}
```
At the find_symbol match-emit site:
```rust
                "qualified_name": render_qualified_name(&h.name, h.parent.as_deref()),
                "parent": h.parent,
```
(Match the surrounding `serde_json::json!` shape; `h.parent` is the field added in Step 1.)

- [ ] **Step 4: Same for `read_symbol` / `read_symbol_at`**

At the `read_symbol_body` emit site (`"qualified_name": chosen.name`), use `render_qualified_name(&chosen.name, chosen.parent.as_deref())` and add `"parent": chosen.parent`.

- [ ] **Step 5: Add the `parent` request filter**

In the `FindSymbolParams` and `ReadSymbol*Params` structs, add `#[serde(default)] parent: Option<String>`. In each handler, after the existing `file`/`kind` filtering, drop candidates whose `parent` != the requested parent (exact match) when the filter is set. For `read_symbol`'s ambiguity path, include `parent` in the `AMBIGUOUS_SYMBOL` error `data` candidate list (search the `AmbiguousSymbol` construction in read_symbol).

- [ ] **Step 6: Capability**

In `crates/rts-daemon/src/methods/daemon.rs` `DAEMON_CAPABILITIES`, add after the most recent entry:
```rust
    // v0.7+ — definitions carry a `parent` (nearest enclosing container:
    // impl/class/struct/…). `find_symbol`/`read_symbol` render
    // `qualified_name` as `parent::name` and accept a `parent` exact-match
    // filter, so same-named defs across types are distinguishable. Additive;
    // `find_callers`/the reference graph are unchanged. See
    // `docs/protocol-v0.md`.
    "parent_scope",
```

- [ ] **Step 7: Build + a plumbing test**

Run `cargo build --workspace 2>&1 | tail -3` (clean). Add a daemon integration test (in a new `crates/rts-daemon/tests/parent_scope.rs`) that mounts a tiny fixture and asserts `find_symbol` returns a `parent` field (currently `null`) and that `qualified_name` still equals the bare name (since no parent is assigned yet). This proves the plumbing without depending on Task 3.

Run: `cargo test -p rts-daemon --test parent_scope` → PASS.

- [ ] **Step 8: Commit**

```bash
git add crates/rts-daemon/src/store/mod.rs crates/rts-daemon/src/methods/index.rs crates/rts-daemon/src/methods/daemon.rs crates/rts-daemon/tests/parent_scope.rs
git commit -m "feat(daemon): thread parent through DEFS + find_symbol/read_symbol wire (unpopulated)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 3: Containment engine + Rust parent assignment

**Files:** Create `crates/rts-core/src/parent_scope.rs`; modify `crates/rts-core/src/lib.rs`, `crates/rts-core/src/extraction.rs`

- [ ] **Step 1: Write a failing Rust extraction test**

In `crates/rts-core/src/parent_scope.rs` (new file), add a `#[cfg(test)] mod tests` with:
```rust
    use crate::{languages::Language, parse_content};

    fn parent_of(src: &str, lang: Language, sym: &str) -> Option<String> {
        let parsed = parse_content(src, lang).unwrap();
        parsed
            .symbols
            .into_iter()
            .find(|s| s.name == sym)
            .unwrap()
            .parent
    }

    #[test]
    fn rust_method_parent_is_impl_type() {
        let src = "struct QueryBuilder; impl QueryBuilder { fn new() -> Self { Self } }\n\
                   fn free() {}";
        assert_eq!(parent_of(src, Language::Rust, "new").as_deref(), Some("QueryBuilder"));
        assert_eq!(parent_of(src, Language::Rust, "free"), None);
    }

    #[test]
    fn rust_trait_impl_parent_is_type_not_trait() {
        let src = "struct Foo; trait T { fn go(&self); } impl T for Foo { fn go(&self) {} }";
        assert_eq!(parent_of(src, Language::Rust, "go").as_deref(), Some("Foo"));
    }
```
(Confirm the public facade name — `parse_content` returns a value whose `.symbols` is `Vec<Symbol>`; check `crates/rts-core/src/lib.rs` for the exact return type and adapt the accessor.)

- [ ] **Step 2: Run it → FAIL**

Run: `cargo test -p rust_tree_sitter parent_scope::tests::rust_method_parent_is_impl_type`
Expected: FAIL (`parent` is `None` — the pass isn't wired yet).

- [ ] **Step 3: Implement the containment engine + Rust rules**

In `crates/rts-core/src/parent_scope.rs`:
```rust
//! Assign each symbol its nearest enclosing container's name (single
//! level). Container kinds + how to read a container's name are
//! per-language; the matching is by node-range containment, computed
//! once over the parsed tree.

use crate::languages::Language;
use crate::symbol::Symbol;
use crate::tree::SyntaxTree;

/// Fill `Symbol.parent` for every symbol: the name of the innermost
/// container node strictly enclosing the symbol's start position.
pub(crate) fn assign_parents(tree: &SyntaxTree, content: &str, language: Language, symbols: &mut [Symbol]) {
    // (container_start_byte, container_end_byte, name)
    let mut containers: Vec<(usize, usize, String)> = Vec::new();
    for kind in container_kinds(language) {
        for node in tree.find_nodes_by_kind(kind) {
            if let Some(name) = container_name(&node, kind, content) {
                containers.push((node.start_byte(), node.end_byte(), name));
            }
        }
    }
    if containers.is_empty() {
        return;
    }
    for sym in symbols.iter_mut() {
        let pos = byte_offset(content, sym.start_line, sym.start_column);
        // innermost = smallest enclosing range that is NOT the symbol itself
        let mut best: Option<(usize, &str)> = None; // (span, name)
        for (s, e, name) in &containers {
            if *s <= pos && pos < *e {
                let span = e - s;
                // skip the container that IS this symbol (a class is not its own parent)
                if *s == byte_offset(content, sym.start_line, sym.start_column) && name == &sym.name {
                    continue;
                }
                if best.map_or(true, |(b, _)| span < b) {
                    best = Some((span, name));
                }
            }
        }
        sym.parent = best.map(|(_, n)| n.to_string());
    }
}

fn byte_offset(content: &str, line_1based: usize, col_0based: usize) -> usize {
    let mut offset = 0usize;
    for (i, l) in content.split_inclusive('\n').enumerate() {
        if i + 1 == line_1based {
            return offset + col_0based.min(l.len());
        }
        offset += l.len();
    }
    offset
}

fn container_kinds(language: Language) -> &'static [&'static str] {
    match language {
        Language::Rust => &["impl_item", "trait_item", "mod_item"],
        // other languages filled in by later tasks; default empty.
        _ => &[],
    }
}

/// Extract a container node's name. Rust `impl_item` exposes the
/// implemented type via the `type` field (and an optional `trait` field
/// for `impl Trait for Type` — we want the type, not the trait).
fn container_name(node: &crate::tree::Node, kind: &str, _content: &str) -> Option<String> {
    match kind {
        "impl_item" => node
            .child_by_field_name("type")
            .and_then(|n| n.text().ok())
            .map(type_head),
        _ => node.child_by_field_name("name").and_then(|n| n.text().ok()).map(|s| s.to_string()),
    }
}

/// Reduce a type expression to its head identifier: `Vec<T>` → `Vec`,
/// `module::Foo` → `Foo`, `&Foo` → `Foo`.
fn type_head(t: &str) -> String {
    let t = t.trim_start_matches(['&', '*', ' ']);
    let head = t.split(['<', ' ']).next().unwrap_or(t);
    head.rsplit("::").next().unwrap_or(head).to_string()
}
```
Adapt method/field names to the real `Node` API (`start_byte`/`end_byte`/`child_by_field_name`/`text` were seen in `extraction.rs`; if `Node` lacks `start_byte`/`end_byte`, add thin accessors in `crates/rts-core/src/tree.rs` mirroring `start_position`). Register the module in `crates/rts-core/src/lib.rs` (`mod parent_scope;`).

- [ ] **Step 4: Call the pass from `extract_symbols`**

In `crates/rts-core/src/extraction.rs`, at the END of `extract_symbols` (just before `Ok(symbols)`), add:
```rust
    crate::parent_scope::assign_parents(tree, content, language, &mut symbols);
    Ok(symbols)
```

- [ ] **Step 5: Run the Rust tests → PASS**

Run: `cargo test -p rust_tree_sitter parent_scope::tests` → both Rust tests PASS.

- [ ] **Step 6: Full rts-core tests (no regression)**

Run: `cargo test -p rust_tree_sitter 2>&1 | tail -5` → all pass.

- [ ] **Step 7: Commit**

```bash
git add crates/rts-core/src/parent_scope.rs crates/rts-core/src/lib.rs crates/rts-core/src/extraction.rs crates/rts-core/src/tree.rs
git commit -m "feat(core): containment-based parent assignment + Rust container rules

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 4: Class-based languages (Python, JS/TS, Java, C#)

**Files:** `crates/rts-core/src/parent_scope.rs`

These languages put methods inside a named container with a `name` field, so they're table entries (no custom name logic).

- [ ] **Step 1: Failing tests**

Add to `parent_scope.rs` tests (one per language; confirm node kinds against the grammar with a throwaway `parse_content` + `find_nodes_by_kind` check if unsure):
```rust
    #[test]
    fn python_method_parent_is_class() {
        let src = "class Parser:\n    def parse(self):\n        pass\n\ndef free():\n    pass\n";
        assert_eq!(parent_of(src, Language::Python, "parse").as_deref(), Some("Parser"));
        assert_eq!(parent_of(src, Language::Python, "free"), None);
    }

    #[test]
    fn js_method_parent_is_class() {
        let src = "class Parser { parse() {} }\nfunction free() {}";
        assert_eq!(parent_of(src, Language::JavaScript, "parse").as_deref(), Some("Parser"));
    }

    #[test]
    fn java_method_parent_is_class() {
        let src = "class Parser { void parse() {} }";
        assert_eq!(parent_of(src, Language::Java, "parse").as_deref(), Some("Parser"));
    }

    #[test]
    fn csharp_method_parent_is_class() {
        let src = "class Parser { void Parse() {} }";
        assert_eq!(parent_of(src, Language::CSharp, "Parse").as_deref(), Some("Parser"));
    }
```

- [ ] **Step 2: Run → FAIL** (`container_kinds` returns `&[]` for these).

- [ ] **Step 3: Add the container kinds**

In `container_kinds`, replace the matching arms (verify each kind name against the tree-sitter grammar — the listed names are the standard ones):
```rust
        Language::Python => &["class_definition"],
        Language::JavaScript | Language::TypeScript => &["class_declaration", "class"],
        Language::Java => &["class_declaration", "interface_declaration", "enum_declaration", "record_declaration"],
        Language::CSharp => &["class_declaration", "interface_declaration", "struct_declaration", "record_declaration"],
```
These all expose `name` via `child_by_field_name("name")`, which the default `container_name` arm already handles.

- [ ] **Step 4: Run → PASS** (`cargo test -p rust_tree_sitter parent_scope::tests`). If a node kind is wrong, the test tells you; fix the kind string.

- [ ] **Step 5: Commit**

```bash
git add crates/rts-core/src/parent_scope.rs
git commit -m "feat(core): parent scope for Python/JS/TS/Java/C#

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 5: C/C++, PHP, Ruby, Swift

**Files:** `crates/rts-core/src/parent_scope.rs`

- [ ] **Step 1: Failing tests**

```rust
    #[test]
    fn cpp_method_parent_is_class() {
        let src = "class Parser { void parse(); };";
        assert_eq!(parent_of(src, Language::Cpp, "parse").as_deref(), Some("Parser"));
    }

    #[test]
    fn php_method_parent_is_class() {
        let src = "<?php class Parser { function parse() {} }";
        assert_eq!(parent_of(src, Language::Php, "parse").as_deref(), Some("Parser"));
    }

    #[test]
    fn ruby_method_parent_is_class() {
        let src = "class Parser\n  def parse\n  end\nend\n";
        assert_eq!(parent_of(src, Language::Ruby, "parse").as_deref(), Some("Parser"));
    }

    #[test]
    fn swift_method_parent_is_class() {
        let src = "class Parser { func parse() {} }";
        assert_eq!(parent_of(src, Language::Swift, "parse").as_deref(), Some("Parser"));
    }
```

- [ ] **Step 2: Run → FAIL.**

- [ ] **Step 3: Add the kinds (verify names against each grammar)**

```rust
        Language::C => &["struct_specifier"],
        Language::Cpp => &["class_specifier", "struct_specifier", "namespace_definition"],
        Language::Php => &["class_declaration", "interface_declaration", "trait_declaration"],
        Language::Ruby => &["class", "module"],
        Language::Swift => &["class_declaration", "protocol_declaration"],
```
Ruby's `class` node names its constant via a `name` child; if `child_by_field_name("name")` returns `None` for Ruby/Swift, add a small custom arm in `container_name` for that kind that reads the identifier/constant child. The test will tell you.

- [ ] **Step 4: Run → PASS.** Adjust kind/name handling per any failing test.

- [ ] **Step 5: Commit**

```bash
git add crates/rts-core/src/parent_scope.rs
git commit -m "feat(core): parent scope for C/C++/PHP/Ruby/Swift

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 6: Go (receiver-based, custom)

**Files:** `crates/rts-core/src/parent_scope.rs`

Go methods are not nested in a type; `func (r *Parser) Parse()` carries the owning type in the method's *receiver*. Containment won't find it, so handle Go specially.

- [ ] **Step 1: Failing test**

```rust
    #[test]
    fn go_method_parent_is_receiver_type() {
        let src = "package p\ntype Parser struct{}\nfunc (r *Parser) Parse() {}\nfunc Free() {}\n";
        assert_eq!(parent_of(src, Language::Go, "Parse").as_deref(), Some("Parser"));
        assert_eq!(parent_of(src, Language::Go, "Free"), None);
    }
```

- [ ] **Step 2: Run → FAIL.**

- [ ] **Step 3: Implement Go receiver handling**

In `assign_parents`, before the generic containment loop, add a Go branch: for each `method_declaration` node, read its `receiver` field (a `parameter_list`), extract the type identifier (strip a leading `*`), and set the matching symbol's `parent`. Pseudocode to adapt to the real Node API:
```rust
    if language == Language::Go {
        for m in tree.find_nodes_by_kind("method_declaration") {
            let recv_type = m
                .child_by_field_name("receiver")
                .and_then(|r| first_type_identifier(&r)) // walk to type_identifier, strip '*'
                .map(|s| s.trim_start_matches('*').to_string());
            if let (Some(name_node), Some(recv)) = (m.child_by_field_name("name"), recv_type) {
                if let Ok(mname) = name_node.text() {
                    if let Some(sym) = symbols.iter_mut().find(|s| {
                        s.name == mname
                            && byte_offset(content, s.start_line, s.start_column) >= m.start_byte()
                            && byte_offset(content, s.start_line, s.start_column) < m.end_byte()
                    }) {
                        sym.parent = Some(recv);
                    }
                }
            }
        }
        // Go has no other nesting containers we model → return after receivers.
        return;
    }
```
Implement `first_type_identifier` by scanning the receiver subtree for the first `type_identifier` node.

- [ ] **Step 4: Run → PASS.**

- [ ] **Step 5: Commit**

```bash
git add crates/rts-core/src/parent_scope.rs
git commit -m "feat(core): parent scope for Go (method receiver type)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 7: End-to-end integration, docs, schema, changelog

**Files:** `crates/rts-daemon/tests/parent_scope.rs`, `docs/protocol-v0.md`, `crates/rts-daemon/tests/protocol_schemas.rs`, `schemas/v0/*`, `changelog.d/`

- [ ] **Step 1: End-to-end daemon tests**

Extend `crates/rts-daemon/tests/parent_scope.rs`: mount a fixture with two same-named methods on different types (Rust: `impl A { fn make() {} }` + `impl B { fn make() {} }`, plus a free `fn make() {}`), then:
- `find_symbol("make")` returns three rows whose `qualified_name` are `A::make`, `B::make`, `make`, each with the matching `parent` (`"A"`, `"B"`, `null`).
- `find_symbol("make", parent="A")` returns only `A::make`.
- `read_symbol("make", parent="B")` resolves unambiguously to B's; `read_symbol("make")` (no disambiguator) returns `AMBIGUOUS_SYMBOL` whose `data` lists candidates including their `parent`.

Run: `cargo test -p rts-daemon --test parent_scope` → PASS.

- [ ] **Step 2: Protocol docs**

In `docs/protocol-v0.md`: document the `parent` field on `find_symbol`/`read_symbol`/`read_symbol_at` responses; the `parent` request filter; the enriched `qualified_name` (`parent::name`, uniform `::`); and the `parent_scope` capability (§7). Note markdown headings keep their hierarchical names.

- [ ] **Step 3: Response schemas + drift test**

Update `schemas/v0/Index.FindSymbol.resp.schema.json` and `Index.ReadSymbol.resp.schema.json` (and `read_symbol_at` if separate) to allow the new `parent` field (`{"type": ["string", "null"]}`). Add `"parent_scope"` to the expected capability set in `crates/rts-daemon/tests/protocol_schemas.rs` (search `"request_deadlines"` / `"cancellable_queries"` for where the set lives). Run: `cargo test -p rts-daemon --test protocol_schemas` → PASS.

- [ ] **Step 4: Changelog fragment**

Create `changelog.d/xxx-feat-parent-scope.md`:
```markdown
### Feature: overload disambiguation via parent scope

Definitions now carry a `parent` — the nearest enclosing container
(`impl`/`class`/`struct`/`trait`/…). `find_symbol`/`read_symbol` render
`qualified_name` as `parent::name` (uniform `::`), expose a `parent`
field, and accept a `parent` exact-match filter, so same-named defs
across types are finally distinguishable (`QueryBuilder::new` vs
`Parser::new`) — and an ambiguous `read_symbol` lists candidates with
their parents. All 12 code languages; markdown headings keep their
hierarchical names. New capability `parent_scope`. The reference graph
and `find_callers` are unchanged (still name-level). The on-disk index
schema bumped; the daemon rebuilds automatically on first run after
upgrade.
```
(Rename `xxx-` to the PR number after opening the PR.)

- [ ] **Step 5: Full workspace gate**

Run:
```bash
cargo fmt --all --check
cargo test --workspace 2>&1 | tail -25
cargo clippy --workspace --all-targets 2>&1 | tail -5
```
fmt must pass (standalone). All tests pass (the `rts-mcp public_api` test fails only in sandboxes lacking a nightly toolchain — it passes in CI; ignore that one specifically if it appears). Clippy advisory.

- [ ] **Step 6: Commit**

```bash
git add docs/protocol-v0.md crates/rts-daemon/tests/protocol_schemas.rs schemas/v0 crates/rts-daemon/tests/parent_scope.rs changelog.d/xxx-feat-parent-scope.md
git commit -m "feat: parent-scope e2e tests, protocol docs, schema, changelog

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Self-review notes (coverage vs spec)

- Spec "What parent is" (nearest container, single level, impl-trait-for → type, free fn → None) → Task 3 (engine + Rust), Tasks 4–6 (other langs).
- Spec §1 extraction across 12 languages → Tasks 3 (Rust), 4 (Python/JS/TS/Java/C#), 5 (C/C++/PHP/Ruby/Swift), 6 (Go). Markdown untouched (no container kinds; `parent=None`).
- Spec §2 storage + schema bump + reindex → Task 2 Steps 1–2.
- Spec §3 wire (`qualified_name` `parent::name`, `parent` field, `parent` filter, AmbiguousSymbol lists parents, `parent_scope` capability) → Task 2 Steps 3–6, Task 7 Step 1.
- Spec §"Compatibility" (additive field/filter; qualified_name value change; schema reindex) → Task 2 + Task 7 docs.
- Spec "non-goals" (no call-graph change) → respected: no `refs`/`find_callers`/sid edits anywhere in the plan.
- Spec testing → per-language unit tests (Tasks 3–6) + e2e (Task 7) + schema/capability (Task 7).
- Name consistency: `parent` (field), `assign_parents`, `container_kinds`, `container_name`, `render_qualified_name`, `parent_scope` (capability + module), `FoundSymbol.parent` — used identically across tasks.

## Risks / notes

- **Node-kind names** for some grammars may differ from the listed defaults (e.g. Ruby/Swift constant naming). Each per-language task is test-first, so a wrong kind surfaces immediately as a failing assertion — fix the string, not the structure.
- **The `Symbol {…}` sweep (Task 1)** is wide but mechanical; the neutral build+test gate catches a missed site (compile error).
- **DEFS encoding (Task 2 Step 1)** is the one spot needing the implementer to read the existing on-disk format; append-only field add + schema bump keeps it safe (full reindex on upgrade means no need to read old-format `parent`).
