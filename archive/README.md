# archive/

Modules and tests retired from the active build as part of the
**agentic-retrieval MCP pivot** (CHANGELOG: `0.2.0-alpha.1`).

These files are kept under version control so the history stays intact and
so that anyone can quickly look up the prior implementation, but they are
**not** compiled by `cargo build` and **not** maintained going forward.

The pivot's design + rationale lives in:

- `docs/brainstorms/2026-05-10-agentic-retrieval-mcp-requirements.md`
- `docs/plans/2026-05-10-001-feat-pivot-to-agentic-retrieval-mcp-server-plan.md`

## Layout

```
archive/
├── README.md     ← this file
├── src/          ← every module dropped from the slim crate
├── tests/        ← integration tests that depended on the dropped modules
└── examples/     ← all 39 demos (previously gated behind the removed `demo` feature)
```

## Why each bucket was archived

| Bucket | Files | Reason |
|---|---|---|
| AI service layer | `ai/`, `ai_analysis.rs`, `advanced_ai_analysis.rs`, `embeddings.rs`, `intent_mapping*.rs`, `reasoning_engine.rs` | Outbound LLM calls; agent-retrieval product flips the consumer direction (agents call us, not vice versa). Also removes the `candle-*` / `hf-hub` / `reqwest` deps. |
| Security analyzers | `taint_analysis.rs`, `sql_injection_detector.rs`, `command_injection_detector.rs`, `security/`, `enhanced_security.rs`, `advanced_security.rs` | Separate product surface; not required for v1 retrieval. |
| Refactoring + AST transform | `smart_refactoring.rs`, `refactoring.rs`, `ast_transformation.rs` | v2 candidate; revisit after MCP "safe edits" land. |
| Wiki + dev tooling | `wiki/`, `fuzz_testing.rs`, `integration_testing.rs`, `test_coverage.rs`, `ci_cd_integration.rs`, `performance_benchmarking.rs`, `code_evolution.rs` | Not on the retrieval path. |
| CLI + binaries | `cli/`, `bin/main.rs`, `bin/rts.rs` | The new entry points are `rts-daemon` + `rts-mcp` + `rts-bench` (separate workspace crates, P4+). |
| Infrastructure shells | `infrastructure/` | Outbound HTTP, sqlx, rate-limiter. v2 daemon will use a redb store, not sqlx. |
| Over-engineered cache | `advanced_cache.rs` | Replaced by a small `lru::LruCache` adapter in surviving code; on-disk store moves to redb in the daemon. |

## Recovering archived code

Drop a module back into the live crate by reverting the `git mv` and adding
the `pub mod <name>;` declaration back to `src/lib.rs`. Most modules also
need one or more `pub use` re-exports if you want their types in the public
API.

You will probably also have to add their crate deps back to `Cargo.toml`
(reqwest, sqlx, candle-*, etc.). The full kill list is in
`CHANGELOG.md → [0.2.0-alpha.1] → Removed`.

## Policy

- **Not maintained**: bug reports against archived code will be closed
  pointing at this README.
- **Not built by CI**: `cargo build` / `cargo test` deliberately exclude
  these directories.
- **Source of record**: prior history via `git log -- archive/src/<file>` or
  pre-pivot tags (`v0.1.x`).
