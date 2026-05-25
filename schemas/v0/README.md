# `schemas/v0/` — machine-readable JSON Schemas for `protocol-v0`

JSON Schema 2020-12 documents describing the `rts-daemon` JSON-RPC wire
contract. Prose source-of-truth lives in
[`docs/protocol-v0.md`](../../docs/protocol-v0.md); these files are
the machine-readable mirror so non-Rust agent harnesses (TS, Python,
Go, …) get type-safe call sites without parsing Markdown.

## Layout

```
schemas/v0/
  README.md                         this file
  envelope.schema.json              JSON-RPC envelope (id, method, params, result, error, cancel_id)
  error.schema.json                 error object (code, message, data)
  methods/
    Daemon.Ping.req.schema.json     request `params`  for Daemon.Ping
    Daemon.Ping.resp.schema.json    response `result` for Daemon.Ping
    …                               one .req / .resp pair per method
```

Each method schema validates the **inner `params` / `result` object**,
not the full envelope. To validate an entire request:

1. Validate the outer envelope against `envelope.schema.json`.
2. Look up `methods/<envelope.method>.req.schema.json`.
3. Validate `envelope.params` against that file.

…and symmetrically for responses against `.resp.schema.json` +
`envelope.result`.

## What's covered

Every method in the v0 dispatcher
(`crates/rts-daemon/src/methods/mod.rs::dispatch`):

| Namespace | Methods |
|---|---|
| `Daemon.*` | `Ping`, `Stats`, `Telemetry`, `Cancel` |
| `Workspace.*` | `Mount`, `Status`, `Unmount` |
| `Session.*` | `Open`, `Close` |
| `Index.*` | `FindSymbol`, `FindCallers`, `ImpactOf`, `ReadRange`, `ReadSymbol`, `ReadSymbolAt`, `Outline`, `Grep` |

= 17 methods × 2 schemas = **34** method-schema files, plus the
envelope, error, and this README.

## Schema versioning

The directory name (`v0/`) tracks `protocol-v0.md`'s wire-version
major. Evolution rules mirror [§Appendix E of
`protocol-v0.md`](../../docs/protocol-v0.md):

- **Additive changes** (new optional `params` field, new optional
  result field, new capability) bump the affected schema's `$id`
  query-string version (e.g. `?v=2`) but stay under `v0/`. The schema
  must keep the existing field set so clients written against the
  earlier shape stay valid. Reviewers can spot the change in the PR
  diff and decide whether it warrants a new capability string.
- **Breaking changes** (rename, remove, change semantics) require a
  new top-level directory (`schemas/v1/`) AND a `protocol`-major bump
  in `Daemon.Ping.result.protocol` ("0" → "1"). The daemon advertises
  the new version via capability strings; clients negotiate per
  §4.3.
- **Runtime feature gating** stays the responsibility of
  `Daemon.Ping.capabilities` — the schemas are the *static* type
  contract, the capability array is the *runtime* feature contract.
  Agents MUST gate on the capability string before sending a field
  that only newer daemons recognize, even when the schema permits it.

## Use from non-Rust harnesses

Examples of downstream codegen tools that consume these files:

- TypeScript: [`json-schema-to-typescript`](https://github.com/bcherny/json-schema-to-typescript)
- Python: [`datamodel-code-generator`](https://github.com/koxudaxi/datamodel-code-generator)
- Go: [`quicktype`](https://quicktype.io/), or `go-jsonschema`
- Cross-language: [`quicktype`](https://quicktype.io/)

Codegen is intentionally out of scope for this PR — schemas are the
input, generators run downstream.

## Drift defense

`crates/rts-daemon/tests/protocol_schemas.rs` enforces three
properties:

1. Every method in the daemon's dispatcher has both a `.req` and a
   `.resp` schema file. A new method that ships without schema files
   fails CI.
2. Every schema file parses as a valid JSON Schema 2020-12 document.
3. Every method's real response (against a fixture workspace)
   validates against its `.resp` schema. Catches schema-vs-code
   drift on every PR.

CI runs the schema tests on every push to `feat/**`, `main`, and
every pull request via `.github/workflows/schemas-check.yml`.

## Out of scope

- **Code generation of TS/Python/Go types** — downstream tooling; not
  baked into this repo.
- **OpenRPC / JSON-RPC OpenAPI document** — a single super-document
  combining all methods and their schemas. Useful follow-up, not
  blocking.
- **Schema-evolution linting** (detecting breaking changes between
  schema versions and gating on capability-string advertisement).
  Useful follow-up, not v1.
- **`schemars`-derive regeneration** — generating these schemas from
  Rust types via `#[derive(JsonSchema)]`. The static-file approach
  was chosen for v1 to keep the blast radius small; a schemars-based
  pipeline can land later if the round-trip test starts catching
  drift more often than once a release.
