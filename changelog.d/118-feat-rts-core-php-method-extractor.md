### `rts-core` — index PHP `method_declaration` symbols

PR #116 added AST-precise call edges for PHP, including `member_call_expression`
(`$obj->method()`) and `scoped_call_expression` (`Klass::method()`). The
reference side worked correctly, but `extract_php_symbols` only emitted
symbols for `function_definition` and `class_declaration` — `method_declaration`
nodes inside classes, interfaces, and traits were never indexed. So
`Index.FindCallers("method_name")` returned `SYMBOL_NOT_FOUND` for any PHP
method, even when callers existed in the graph.

This adds a `method_declaration` branch to `extract_php_symbols` that walks
methods inside `class_declaration`, `interface_declaration`, and
`trait_declaration`, emitting `Symbol { kind: "method", ... }` with the bare
method name (matching the PHP_REFS query's capture and the Java/Ruby
extractor convention). Visibility modifiers (`public`/`private`/`protected`)
propagate to `Symbol.visibility`; methods without an explicit modifier
default to `public` per the PHP language rule.

`crates/rts-daemon/tests/call_edges_php.rs` now exercises all five PHP call
shapes end-to-end (bare, namespaced, `new`, member, scoped); the previously
skipped member-call and scoped-call assertions are active.

No public Symbol or protocol surface change. No new dependencies.
