### Refs-query audit follow-up — Go generics, JS/TS scoped-new

#94 fixed the Rust `scoped_identifier` gap that hid `mod::fn()` calls from `find_callers`. That fix prompted an audit of the other languages' refs queries; this PR ships the analogous fixes.

#### Audit results

| Language | Status | Notes |
|---|---|---|
| Rust | ✅ fixed in #94 | scoped_identifier + generic_function added |
| Python | ✅ comprehensive | `attribute` covers both `obj.f()` and `module.f()` (Python has no `::`) |
| Go | ⚠️ generics missing | `MakeFoo[int]()` — generic_function calls invisible |
| Ruby | ⚠️ minimal coverage | bare-method-no-parens case is grammar-ambiguous; deferred |
| JavaScript | ⚠️ scoped-new missing | `new Module.Foo()` |
| TypeScript | ⚠️ scoped-new missing | same as JS |
| Java / C / C++ / PHP / Swift | ❌ no refs query | regex fallback; pre-existing v0+ limitation |

#### Go generics (Go 1.18+)

Generic functions are now common in the Go ecosystem (released March 2022). Calls like `MakeFoo[int]()` or `pkg.MakeFoo[int]()` have `function: (index_expression operand: …)` instead of plain `identifier` or `selector_expression`, so the old query missed every one.

Two new captures:

```scheme
(call_expression
  function: (index_expression
    operand: (identifier) @name)) @reference.call

(call_expression
  function: (index_expression
    operand: (selector_expression field: (field_identifier) @name))) @reference.call
```

#### JavaScript + TypeScript scoped-new

`new Module.Foo()` parses as `(new_expression constructor: (member_expression property: (property_identifier)))`. The old queries only captured bare `new Foo()` (identifier constructor) and missed every namespaced one. Added the member-expression form to both JS and TS query strings.

#### Out of scope (filed for further follow-up)

- **Ruby bare-method-no-parens**: `do_thing` (no receiver, no parens) is ambiguous between local-variable-read and method-call in Ruby's grammar without context. Needs scope-tracking to disambiguate; non-trivial.
- **JS/TS optional chaining**: `obj?.foo()` may parse to a different node shape than `obj.foo()`. Need empirical verification before adding a pattern.
- **JS/TS dynamic property access**: `obj["foo"]()` uses `subscript_expression`. Skip — agents shouldn't be searching by string-key method names.
- **Java / C / C++ / PHP / Swift refs queries**: still rely on regex fallback. Authoring real `@reference.call` queries for each is a multi-day audit deferred to v0.6.
- **Test-side coverage**: the refs queries' actual coverage isn't directly tested today — the `find_callers` round-trip test exercises a tiny synthetic workspace. A real test would index a known-shape repo and assert specific edge counts. Filed.

#### Validation

Build + test suite pass post-fix. Existing `find_callers` round-trip tests unchanged (they exercise Rust bare-identifier calls which were never broken). Empirical validation of the Go + JS/TS coverage requires real workspaces with generic / scoped-new patterns — `cobra` (Go) and `chalk` (JS) corpora are good first targets when promoting external corpora to CI invariants.
