### Fix: `tools/list` advertises the one-of rules the daemon already enforces

`find_symbol` and `grep` validate a *one-of* over their arguments — `find_symbol` takes
exactly one of `name` | `pattern`, `grep` at least one of `text` | `structural_query` — but
every field on both argument structs is `Option`, so schemars emitted an `inputSchema` with
no `required` at all. A client could send a call the advertised schema fully permitted and
have the daemon refuse it with `INVALID_PARAMS` (`NO_SEARCH_SOURCE_PROVIDED` for `grep`;
`"either \`name\` (exact) or \`pattern\` (glob) is required"` for `find_symbol`). Observed in
production: the client retried the identical shape four times, because nothing it had been
given said the shape was wrong. Six such refusals in roughly 13,000 calls.

The constraint is now declared at its source: `#[schemars(extend("oneOf" = …))]` on
`FindSymbolArgs` and `#[schemars(extend("anyOf" = …))]` on `GrepArgs`, in
`crates/rts-mcp/src/server.rs`. It rides the same derive that builds the rest of each
schema, so it cannot drift from the tool it describes, and it is the clause the protocol-v0
request schemas already carry
(`schemas/v0/methods/Index.FindSymbol.req.schema.json`,
`schemas/v0/methods/Index.Grep.req.schema.json`). `grep` is `anyOf`, not `oneOf`: supplying
both sources is legal and the daemon intersects them.

The other fourteen tools' advertised schemas were inspected against the daemon's 53
`INVALID_PARAMS` sites. None of them enforces a one-of over top-level arguments — their
constraints are single-field (length, range, enum), which schemars already emits — so none
changed. `verify_claims` discriminates each item of `claims` by a `type` tag inside a nested
object, which the `Vec<Value>` schema cannot express; that is untouched.

`crates/rts-mcp/tests/tool_input_schemas.rs` drives a real JSON-RPC session and asserts the
`inputSchema` each tool emits over `tools/list` — what a client reads, not the Rust type.
It fails on the pre-change revision for both tools.
