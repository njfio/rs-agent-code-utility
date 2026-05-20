### AST-precise call edges for Java, PHP, Swift, and C#

`Index.FindCallers` and the closure walker now use tree-sitter queries
(not regex) on Java, PHP, Swift, and C# files. Coverage of AST-precise
call edges goes from 6 of 12 indexed languages (Rust/Python/Go/Ruby/JS/TS)
to 10 of 12. C and C++ remain on the regex fallback for now — function
pointers parse identical to identifier references, so the precision win
there is smaller.

#### What

Four new query strings in `crates/rts-daemon/src/language.rs`, registered
against the central `LanguageInfo` table and the `cached_refs_query`
cache:

- **`JAVA_REFS`** — `method_invocation.name` and
  `object_creation_expression.type`. Chained `a.b().c()` parses as nested
  `method_invocation` nodes, so the query captures `b` and `c` as
  separate call sites; the receiver `a` is a plain identifier under
  `object:` and never matches.
- **`PHP_REFS`** — `function_call_expression` (including the
  `qualified_name` variant for `\Foo\bar()`), `member_call_expression`,
  `scoped_call_expression`, and `object_creation_expression` (both bare
  `(name)` and namespaced `(qualified_name (name))` children).
  Variable-function `$fn()` is intentionally not captured — no static
  target to resolve.
- **`SWIFT_REFS`** — `call_expression` with `simple_identifier` (bare)
  and `navigation_expression` (method calls). Trailing closures still
  parse as `call_expression`, so they're covered without a separate
  pattern. Authored against the installed Swift 0.7 grammar's
  `node-types.json`; upstream `tags.scm` ships only `@definition.*`.
- **`CSHARP_REFS`** — `invocation_expression` in four shapes (bare
  identifier, member-access, generic-name, member-access-of-generic-name)
  plus `object_creation_expression` (identifier and generic-name).
  Covers `Foo()`, `obj.Foo()`, `Foo<T>()`, `obj.Foo<T>()`, `new Foo()`,
  and `new Foo<T>()`.

#### Why this matters

Pre-AST-precise edges, calling `Index.FindCallers` on a Java method
returned every textual occurrence of the name — including imports,
comments, and string literals — plus an edge per local variable that
happened to share the name. The same noise hit PHP/Swift/C#. For
polyglot backends (Java services + WordPress/Laravel PHP) and mobile +
.NET codebases, the value pitch of "AST-precise call graph" only held
on half the supported language matrix.

#### Verification

- Unit tests in `crates/rts-daemon/src/refs.rs` exercise the four new
  queries against representative fixtures (chained calls, member/static
  calls, namespaced calls, trailing closures, generic invocations) and
  assert local variables are NOT captured.
- `java_php_swift_csharp_cached_queries_construct_without_panic` in
  `crates/rts-daemon/src/language.rs` forces query compilation at unit-
  test time so a grammar bump that breaks the queries surfaces here
  rather than at first `Index.Outline` call.
- Per-language integration tests `crates/rts-daemon/tests/call_edges_*.rs`
  spawn the daemon, mount a per-language fixture, and assert
  `Index.FindCallers` returns the expected method-level edges.
- All existing Rust/Python/Go/Ruby/JS/TS call-edge tests continue to
  pass — the new queries plug into the existing cache and dispatcher
  without touching the hot path.

#### Out of scope

- C and C++ AST queries. Their fallback regex behavior already
  approximates what a tags.scm query would produce because function
  pointer calls look identical to identifier references; deferred.
- PHP `method_declaration` symbol extraction. The AST query captures
  member-call and scoped-call sites correctly, but the existing
  `extract_php_symbols` only indexes `function_definition` + class
  defs — so member/static call edges in PHP don't resolve to a target
  yet. Tracked separately.
