# Lane 03 — rts: the Inspect substrate

**Workspace:** a clone of `njfio/rs-agent-code-utility` (rts) on branch `lane/tsr-inspect`.
**Owns:** a `tsr` tool-surface profile in `crates/rts-mcp`, a schema under `schemas/`, a doc page.
**Reads first:** rts's own `AGENTS.md` and `CONTRIBUTING.md`; `crates/rts-mcp/src/surface.rs` (the
existing `core` and `verify` profiles); the engine's need, below.
**Scope:** small. This is a PR, not a platform. If the swarm finds that `--tools core` already
satisfies every point, the deliverable is the test, the schema and the doc that say so.

## What the engine needs from rts

The TSR Decision Engine (`njfio/tsr-engine`, `docs/PRD.md` §B4) uses rts as its Inspect substrate.
Every rts call an agent makes crosses the engine's hook boundary and is logged as an `Inspect`
action. For that the engine needs three things from rts:

1. A named, read-only tool-surface profile the engine's policy can allowlist by name.
2. A snapshot pin: every response in that profile carries `content_version` (or the equivalent) so
   an Inspect can be tied to the repository state it read.
3. A stable record shape — `{tool, args, content_version, result_digest}` — the hook can emit for any
   tool in the profile, with a schema it can validate against.

## Goal (the text handed to `ds-swarm run`)

In this repository (rts, AST-precise code retrieval for AI agents), add what the TSR Decision Engine
needs to log Inspect actions against rts. Read AGENTS.md and crates/rts-mcp/src/surface.rs first;
the profile mechanism (`--tools` / `RTS_MCP_TOOLS`, profiles `core` and `verify`) already exists.
Deliver: (1) a `tsr` profile for rts-mcp: the read-only subset — find_symbol, find_symbols,
find_callers, read_symbol, read_symbol_at, read_range, grep, and the verify_* tools — with one-line
descriptions, and a test asserting that no tool in the profile writes, edits or applies anything;
(2) confirm that every response from a tool in the profile carries `content_version`; where one does
not, add it in the least invasive way or document precisely where the version is available instead;
(3) `schemas/inspect-record.schema.json`: an "inspect record" `{tool, args, content_version,
result_digest}` with `result_digest` defined as blake3 of the canonical JSON response, and a
conformance test that builds one record from each tool in the profile against the repository's own
fixtures; (4) `docs/tsr-inspect.md`: one page saying how the engine registers rts (`rts-mcp --tools
tsr`) and what the record means. Do not change default behaviour, the `core` or `verify` profiles,
or any public API outside the new profile. Follow the repository's CI commands and commit
conventions.

## Definition of done (`--dod`)

The repository's own CI commands (per its AGENTS.md) pass. `rts-mcp --tools tsr` advertises exactly
the read-only subset and a test proves it contains no writing tool. schemas/inspect-record.schema.json
exists and the conformance test passes. docs/tsr-inspect.md exists. No default behaviour changed; no
other profile changed.

## Acceptance commands

```bash
cargo test -p rts-mcp
cargo run -p rts-mcp -- --tools tsr --help   # or the repository's equivalent for listing a surface
```

## Suggested run flags

```
--max-tokens 400000 --deadline-secs 5400 --max-agents 4 --reviews security,correctness
```
