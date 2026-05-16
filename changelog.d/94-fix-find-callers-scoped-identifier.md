### `find_callers` — capture `mod::fn()` calls (scoped_identifier gap)

**Surfaced by real MCP-path dogfood.** First session running rts-mcp wired into Claude Code natively (not through the `rts-bench query` CLI shim) caught this within five queries:

```
find_callers("socket_path_for_workspace") → callers: []
```

…despite a call site existing at `crates/rts-daemon/src/main.rs:151`:

```rust
socket::socket_path_for_workspace(&canonical)?
```

#### Root cause

The `RUST_REFS` tree-sitter query in `crates/rts-daemon/src/language.rs` captured `@reference.call` for:

- `(call_expression function: (identifier))` — bare-identifier calls like `extract_rust_symbols()`
- `(call_expression function: (field_expression field: (field_identifier)))` — method calls like `self.foo()`
- `(macro_invocation macro: (identifier))` — `macro!()`

It did **not** capture `(call_expression function: (scoped_identifier))` — `mod::fn()` and `Type::method()` style calls. In real Rust code, the majority of calls use path prefixes. Every one of them was invisible to `find_callers`.

This silently inflated "is this function dead?" queries (returning `[]` is the same wire shape as "no callers exist") and quietly skewed PageRank since the reference graph was missing huge swaths of edges.

#### Fix

Three new captures added to `RUST_REFS`:

1. `(call_expression function: (scoped_identifier name: (identifier)))` — `mod::fn()`, `Type::method()`, and arbitrarily-deep `mod::sub::fn()` paths.
2. `(call_expression function: (generic_function function: (identifier)))` — turbofish on a bare identifier (`make::<T>()`).
3. `(call_expression function: (generic_function function: (scoped_identifier name: (identifier))))` — turbofish on a scoped path (`Vec::<u32>::new()`).
4. `(macro_invocation macro: (scoped_identifier name: (identifier)))` — `mod::macro!()`.

The leaf `name: (identifier)` capture intentionally drops the path prefix and stores only the function name. That's what `find_callers --name X` matches against, and it's the right shape — agents asking "who calls `new`" want hits from `Foo::new()` and `Vec::new()` and bare `new()` collapsed.

#### Verification

End-to-end through the live MCP daemon after the fix:

```
find_callers("socket_path_for_workspace") →
  callers: [{
    file: "crates/rts-daemon/src/main.rs",
    range: { start_line: 151, ... },
    enclosing_qualified_name: "main",
    kind: "fn",
    rank_score: 7.4e-05
  }]
```

#### Out of scope (filed for follow-up)

- **Audit other languages' refs queries** for similar gaps. Python's `attribute` access is captured; Go's `selector_expression` is captured; JS/TS's `member_expression` is captured. Ruby `Module::method` and Java `Class.method` need verification.
- **PageRank recalculation impact**: this fix increases the reference-graph edge count significantly on Rust workspaces. Some rank scores will shift. The CI `semantic-eval-rts-core.toml` ≥0.95 invariant should still hold (the answers are the same; only ordering may tighten); flag if it doesn't.
- **`rts-mcp` daemon-reconnect logic**: separately surfaced this session. When the underlying rts-daemon dies, rts-mcp keeps writing to the dead socket and returns `Broken pipe`. Should reconnect / re-spawn instead. Filed as a separate issue.
