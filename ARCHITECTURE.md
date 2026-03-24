# Architecture

This document describes the current high-level architecture of `rust_tree_sitter` after the feature-gating cleanup, security-pipeline consolidation, MCP adapter recovery, and Phase 4 stretch work.

## Top-Level Shape

The repository is organized around four primary surfaces:

1. Core parsing and repository analysis in [`src`](src)
2. Security analysis through the canonical pipeline in [`src/security`](src/security)
3. Opt-in CLI binaries in [`src/cli`](src/cli)
4. MCP adapter integration in [`integration/mcp`](integration/mcp)

Supporting directories worth knowing:

- [`rules`](rules): declarative security rules (`.yaml` + `.scm`)
- [`benches`](benches): Criterion parser and security benches
- [`tests`](tests): integration and regression coverage
- [`docs`](docs): user-facing documentation and plan artifacts
- [`scripts`](scripts): lightweight CI/helper scripts

## Module Organization

Core layers in [`src/lib.rs`](src/lib.rs):

- Parsing and tree access: `parser`, `tree`, `query`, `languages`
- Repository analysis: `analyzer`, `dependency_analysis`, `semantic_graph`, `semantic_context`
- Security: `advanced_security`, `security`, `taint_analysis`, dedicated detectors
- Secondary analyzers: `performance_analysis`, `complexity_analysis`, `test_coverage`, `code_map`
- Optional feature layers: `ai` behind `net`, `intent_mapping` and `embeddings` behind `ml`, CLI behind `cli`

The important architectural direction is that higher-level user surfaces should prefer stable facades:

- `CodebaseAnalyzer` for repository analysis
- `SecurityPipeline` for canonical security scanning
- `AdvancedSecurityAnalyzer` as a compatibility facade over the canonical pipeline

## Security Pipeline

The canonical pipeline is implemented in [`src/security/pipeline.rs`](src/security/pipeline.rs).

Pipeline stages:

1. Parse source with `Parser`
2. Run AST-backed structural analysis
3. Run declarative `.scm` rule evaluation from [`rules/`](rules)
4. Run heuristic/OWASP detectors
5. Run taint analysis when there are staged findings
6. Upgrade confidence when taint flows confirm a finding
7. Apply deterministic filtering and confidence thresholds
8. Return normalized `ScoredFinding` values with a `ConfidenceSource`

The declarative rule engine lives in [`src/security/rule_engine.rs`](src/security/rule_engine.rs). It compiles checked-in `.scm` queries at runtime from YAML metadata, so adding rules does not require Rust code changes.

Cross-file propagation work lives primarily in:

- [`src/semantic_graph.rs`](src/semantic_graph.rs)
- [`src/taint_analysis.rs`](src/taint_analysis.rs)

## Feature Flag Hierarchy

The crate now assumes a minimal default surface:

- `default = ["std", "serde"]`

Primary opt-in features:

- `cli`: binaries and terminal-only dependencies
- `ml`: embeddings and model-backed intent mapping
- `net`: async runtime, HTTP, rate limiting, retry middleware
- `db`: SQLx-backed persistence
- `wiki`: markdown/wiki generation plus `net`
- `demo`: examples only
- `full`: broad compatibility alias combining the main optional surfaces

For the exact dependency-to-feature mapping, see [`docs/FEATURE_FLAGS.md`](docs/FEATURE_FLAGS.md).

## MCP Tool Interface

The current MCP adapter is TypeScript-based and lives in [`integration/mcp/server`](integration/mcp/server). It does not call library internals directly. Instead, it shells out to the CLI and wraps the CLI's JSON output in a stable envelope.

Current tools:

- `analyze_codebase`
- `get_symbols`
- `query_code`
- `scan_security`
- `analyze_dependencies`
- `query_semantic_graph`

Schema files live in [`integration/mcp/schemas`](integration/mcp/schemas). Adapter-side graph filtering for `query_semantic_graph` lives in [`integration/mcp/server/src/semantic-graph.ts`](integration/mcp/server/src/semantic-graph.ts).

This split keeps the agent-facing interface typed and stable while allowing CLI evolution behind it.

## Benchmark and CI Shape

Performance regression coverage now has two layers:

1. Local Criterion benches in [`benches/parser_bench.rs`](benches/parser_bench.rs) and [`benches/security_bench.rs`](benches/security_bench.rs)
2. CI benchmark gating in [`.github/workflows/ci.yml`](.github/workflows/ci.yml), with threshold enforcement in [`scripts/check_benchmark_regression.sh`](scripts/check_benchmark_regression.sh)

The parser benchmark intentionally excludes `Parser::new()` from the measured hot path, and the security benchmark uses in-memory source instead of temp-file I/O.
