### Machine-readable JSON Schemas for the `protocol-v0` wire contract

`schemas/v0/` exports a JSON Schema 2020-12 document for every `params` and `result` shape the daemon serves. Non-Rust agent harnesses (TS, Python, Go, …) can now validate calls against the protocol-v0 contract statically — no more hand-translating `docs/protocol-v0.md` into types and hoping the prose hasn't drifted.

#### What

`schemas/v0/` ships with:
- `envelope.schema.json` — the JSON-RPC envelope (id, method, params, result, error, cancel_id), with a `oneOf` discriminating request / success / error / notification shapes.
- `error.schema.json` — the error object, including the closed `code` enum from §14 + §14.1.
- `methods/<Method>.req.schema.json` + `methods/<Method>.resp.schema.json` for all 17 methods the daemon dispatcher routes (`Daemon.*`, `Workspace.*`, `Session.*`, `Index.*`). 34 method-schema files total.
- `README.md` documenting the directory layout and the schema-versioning convention (additive within `v0/`, breaking requires `v1/` + `protocol`-major bump).

`crates/rts-daemon/tests/protocol_schemas.rs` enforces four properties:

1. Every method in the dispatcher has both a `.req` and `.resp` schema file. A new method that ships without schema files fails CI.
2. Every schema file under `schemas/v0/` parses as a valid JSON Schema 2020-12 document.
3. (CI-only) Every method's real response (against a fixture workspace) validates against its `.resp` schema. Catches drift between schemas and runtime emit.
4. (CI-only) Error responses match `error.schema.json`. Locks in the v0 error shape.

Properties 3 and 4 are `#[ignore]`-by-default so the regular `cargo test --workspace` path stays fast; CI opts back in via `cargo test -p rts-daemon --test protocol_schemas -- --include-ignored`. A dedicated `.github/workflows/schemas-check.yml` runs the full suite on every PR.

#### Why this matters

The protocol surface was canonical-prose-only. Today, a TS or Python harness that wants to validate its requests had to either (a) hand-translate the spec and risk drift, or (b) parse the Markdown. After 13 PRs of v0.6 work the wire shape has stabilised enough to lock in via schema files and golden-file regression tests.

Locking the contract via schemas means:
- **Future protocol changes are visible in PR diffs** — a schema change is a visible review surface; a prose-only change is not.
- **Non-Rust agent harnesses get type-safe call sites for free** — `json-schema-to-typescript`, `datamodel-code-generator`, `quicktype`, etc. all consume these files directly.
- **Schema-evolution rules become enforceable** — additive within `v0/`, breaking requires a new directory + `protocol`-major bump per `protocol-v0.md` §Appendix E.

#### Approach decision

**Option B (static files + drift test) was chosen over Option A (`schemars`-derive on Rust types).** Rationale: smaller blast radius across the daemon and MCP crates today; the round-trip test catches the same drift class a derive macro would prevent at compile time. A `schemars`-based regeneration pipeline can land as a follow-up if/when the round-trip test starts firing more often than once a release.

#### Out of scope (follow-ups)

- Code generation of TS/Python/Go types from these schemas (downstream tooling).
- An OpenRPC / JSON-RPC OpenAPI super-document combining all methods and their schemas.
- Schema-evolution linting (detecting breaking changes between schema versions, gating on capability advertisement).
- `schemars`-derive regeneration of these files from the Rust types.

#### Wire shape impact

None. The schemas DESCRIBE the existing shape; no daemon code changed.
