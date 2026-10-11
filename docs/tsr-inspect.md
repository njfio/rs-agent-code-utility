# TSR inspect records — registering rts and what the engine logs

The TSR Decision Engine uses `rts` as its **Inspect** substrate: when an agent
needs to look at code, it calls an `rts-mcp` tool instead of reading files, and
the engine logs that call as an *Inspect action*. This page says how the engine
registers `rts-mcp`, what the `tsr` profile guarantees, and what one inspect
record means. The record's shape is pinned by
[`schemas/inspect-record.schema.json`](../schemas/inspect-record.schema.json).

## Registering rts

`rts-mcp` is an MCP stdio server. The engine registers it with the `tsr`
profile, which is the read-only subset of the tool surface:

```sh
rts-mcp --tools tsr
```

Harnesses that cannot pass argv use the environment instead — the flag wins when
both are set (`crates/rts-mcp/src/main.rs:216`):

```sh
RTS_MCP_TOOLS=tsr rts-mcp
```

A minimal stdio client config:

```json
{
  "mcpServers": {
    "rts": {
      "command": "/path/to/target/release/rts-mcp",
      "args": ["--workspace", ".", "--tools", "tsr"]
    }
  }
}
```

`rts-mcp` auto-spawns `rts-daemon` on first call and re-spawns it if the socket dies;
a daemon already running for the same workspace is reused. (`RTS_NO_AUTOSPAWN` is
honoured by the human `rts` CLI only, not by `rts-mcp`.) All logs go to stderr; stdout
is reserved for JSON-RPC frames.

## What the profile guarantees

The profile is a **policy the server enforces, not a hint it hopes the client
respects**. A call to a tool outside the surface is refused before it reaches
the router, with JSON-RPC `-32602` (invalid params) and the message
``tool `<name>` is not in this server's tool surface; call tools/list to see
what is`` (`crates/rts-mcp/src/server.rs:1146-1153`).

Every tool in `tsr` is a pure read or check against the index — none writes,
edits, applies or mutates anything. `verify_edit` and `verify_impact` are
*gates*: they analyse a **proposed** edit passed as an argument and return a
verdict; they never write to disk or to the index. The twelve tools, with the
one-line description the server advertises for each
(`crates/rts-mcp/src/surface.rs:67-80`, descriptions at `:86-143`):

| Tool | What it does |
|---|---|
| `find_symbol` | Where a symbol is defined: AST-precise, ranked, with kind and signature. Use instead of grep for identifiers. |
| `find_callers` | Direct callers of a symbol, AST-precise. Use before changing or deleting it. |
| `read_symbol` | Read one symbol's body, optionally with its dependencies or its callers. Use instead of reading the whole file. |
| `read_symbol_at` | Read the symbol enclosing a file:line. Use for compiler errors and stack traces. |
| `read_range` | Read an explicit line range: diff hunks, stack frames, log excerpts. |
| `grep` | Literal, regex or structural search, each match labelled with the symbol that encloses it. |
| `verify_symbol` | Check that a symbol exists before you call or import it; a miss lists ranked candidates. |
| `verify_signature` | Check a call against the symbol's real arity and parameters before you write it. |
| `verify_import` | Check that an import path's final segment resolves to a real symbol. |
| `verify_claims` | Fact-check a batch of symbol, signature, import or location claims against the AST. |
| `verify_impact` | Declare a signature change, rename or removal and get its blast radius as pass or fail. |
| `verify_edit` | Gate a proposed multi-file patch: broken callers, signature breaks, dangling references. |

`daemon_stats` and `daemon_telemetry` are observability, not retrieval, and are
excluded; `outline_workspace` and `impact_of` are read-only too but are not in
the engine's named subset, so they are excluded as well.

## The inspect record

One Inspect action is one record:

```json
{
  "tool": "read_symbol",
  "args": { "name": "build_index" },
  "content_version": "9f2c1a7b4e0d3f58@1730000000123456789+42",
  "result_digest": "blake3:1f0a…64 hex chars…"
}
```

| Field | Meaning |
|---|---|
| `tool` | The `rts-mcp` tool that was called. One of the twelve read-only tools above. |
| `args` | The arguments the tool was called with, verbatim. An object (possibly empty); never null, array or scalar. |
| `content_version` | The version the result was read against (see below). Null when the response carried no version and none could be attributed to the result. |
| `result_digest` | `blake3:` + the lowercase hex of `blake3(canonical_json(response))`. |

`result_digest` is defined over the **canonical JSON of the tool's response**:
object keys sorted recursively, no insignificant whitespace, arrays in order.
Two structurally equal responses digest identically regardless of key order; a
one-field change digests differently. The reference implementation is
`canonical_json` / `result_digest` in
[`crates/rts-mcp/tests/inspect_record.rs`](../crates/rts-mcp/tests/inspect_record.rs)
(`:247-282`), and the record builder is `build_record` (`:285-297`).

## Why the engine logs it

Reproducibility and audit. The digest pins the **exact response bytes** — a
later run can tell whether the same call would return the same answer, and a
mismatch is evidence the index or the code moved. `content_version` pins the
**index generation** the answer came from, so a record is only comparable to
another record taken against the same generation. Together they make an Inspect
action replayable and its staleness detectable.

## content_version coverage

A `content_version` string is `blake3(content)[:16]@mtime_ns+index_generation`
(`crates/rts-daemon/src/methods/index.rs:661-668`); a `content_version_base` is
the bare `@index_generation`. Not every tool's response carries one — the
daemon's wire contract is unchanged, so the record's `content_version` is
populated where the response has it and null otherwise:

| Tool | Version in the response? |
|---|---|
| `read_symbol`, `read_symbol_at`, `read_range` | **yes** — `content_version` |
| `verify_symbol` | **yes** — `content_version` (the matched file's version on a hit, else the index generation) |
| `verify_edit` | **yes** — `content_version_base` (index generation, not per-file) |
| `find_symbol`, `find_callers`, `grep` | no — null |
| `verify_signature`, `verify_import`, `verify_claims`, `verify_impact` | no — null |

The per-tool evidence (schema `required` arrays and daemon response-construction
sites) is in the `content-version-coverage` artifact.

For a tool that returns no version, the version is still reachable with one
extra read-only call, and the `tsr` profile contains the tools that yield it:

- **Per-file version** — call `read_range { file, start_line, end_line }` (or
  `read_symbol { name }`) on the file the result names and read its
  `content_version`.
- **Index generation** — the substring after the final `+` of any
  `content_version`; one `read_range` or `verify_symbol` call on any indexed file
  yields one, and the generation is the same for every file in one index
  generation. (`verify_edit` rejects an empty `edits` array, so it is not a
  generation lookup; its `content_version_base` carries the generation only for a
  real edit.)

## Validating

The schema is [`schemas/inspect-record.schema.json`](../schemas/inspect-record.schema.json).
The conformance test
[`crates/rts-mcp/tests/inspect_record.rs`](../crates/rts-mcp/tests/inspect_record.rs)
builds one record from each of the twelve tools against the repository's own
fixture workspace, spawns `rts-mcp --tools tsr` as a subprocess, and asserts
every record validates against the schema, that `result_digest` is stable for
the same call, and that `content_version` is populated exactly where the
response carries one.
