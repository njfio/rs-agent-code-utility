# `grep_structural` fuzz corpus

Seeds for `fuzz_targets/grep_structural.rs`. Each file is a candidate
S-expression query fed verbatim to `rts_core::query::Query::new` against
the Rust grammar.

## What's covered

| File | Class | Why |
|---|---|---|
| `wellformed_function` | sanity | `(function_item) @fn` — the canonical example from `docs/protocol-v0.md` §7.8b. Must compile and parse cleanly. |
| `wellformed_impl_block` | sanity | `(impl_item) @impl` — another spec example. |
| `sexpr_nested_parens_deep` | parser stress | 32 levels of nested parens with no inner node. Exercises the S-expression parser's recursion depth. |
| `sexpr_unbalanced_open` | malformed | Long run of `(` with no matching `)`. Must reject without hanging. |
| `sexpr_unbalanced_close` | malformed | Long run of `)` with no opening match. Must reject. |
| `sexpr_long_capture_chain` | capture stress | 16 sequential `(identifier) @cN` patterns. The daemon's `STRUCTURAL_MAX_CAPTURES_PER_MATCH = 64` cap should clip executions; compile must still succeed. |
| `sexpr_malformed_predicate` | predicate filter | Uses `#contains?` — outside the v1 whitelist. Compile may succeed (tree-sitter doesn't enforce predicate whitelist; that's the daemon's job in `predicates.rs`) but the daemon should reject. |

## Consumer

`crates/rts-daemon/fuzz/fuzz_targets/grep_structural.rs`

## Promise validated

RESILIENCE.md §"Structural query bombs".
