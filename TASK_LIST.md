# Roadmap and Task List

This roadmap organizes high‑impact features into pragmatic releases with owners and CI gates. Each task is small, testable, and reversible. Default style is Pure TDD and FP per INSTRUCTIONS.md.

## Release R1: Output + Dependencies + Security Baseline (2–3 weeks)

- SARIF polish: validate schema, add rule metadata, stable IDs. Owner: CLI. CI: sarif_output_tests.
- PR annotations: GitHub review comments via SARIF + annotations. Owner: CLI. CI: e2e smoke on PR.
- Dependency scanning v2: OSV/CVE lookup scaffold + CycloneDX SBOM generation. Owner: deps. CI: dependency_analysis_unit_tests.
- JS import detection v2: scoped packages, side-effect imports, export-from (Done), add test coverage for edge cases. Owner: deps. CI: tests.
- Minimal schema validations for manifests (Done): cargo/package.json error messages. Owner: deps. CI: tests.
- CLI flags: include-dev (Done), enable-security (Analyze/Security). Owner: CLI. CI: cli_determinism.

## Release R2: Performance + Watch Mode (2 weeks)

- Incremental cache: hash-based file cache + AST reuse. Owner: core. CI: performance_optimization_tests.
- Watch mode: file watcher + incremental analyze; debounced. Owner: CLI. CI: e2e smoke.
- Parallelism controls: adaptive threads + cancellation. Owner: core. CI: perf benches.

## Release R3: Security Depth (3–4 weeks)

- Taint tracking v1: sources/sinks/sanitizers for Rust/JS/Python. Owner: sec. CI: taint unit tests.
- Secrets scanning v2: curated patterns + entropy tuning + suppressions. Owner: sec. CI: secrets_detector.
- License policy: SPDX detection + policy-as-code (allow/deny). Owner: compliance. CI: policy tests.

## Release R4: IDE/LSP + Auto-Fix (4–6 weeks)

- LSP server: diagnostics + code actions + quick-fix. Owner: IDE. CI: protocol tests.
- Auto-fixes v1: safe transforms for common issues (innerHTML→textContent, shell→argv, read_to_string validation). Owner: refactor. CI: transformation tests.

## Release R5: Policy Platform + Dashboards (4 weeks)

- Policy engine: YAML/TOML rules, repo overrides, CI gates. Owner: platform. CI: policy e2e.
- Dashboard: basic TUI/Web summary (trends, hotspots). Owner: platform. CI: snapshot tests.

---

## Active TODOs (Short Term)

1. Add `--enable-security` flag to `analyze` and `security` commands; wire to `AnalysisConfig`. [Owner: CLI]
2. Add OSV/CVE lookup scaffold (no network calls yet) with typed results and stubs. [Owner: deps]
3. Add CycloneDX SBOM serializer for `DependencyAnalysisResult`. [Owner: deps]
4. Add watch mode scaffold (`tree-sitter-cli watch`) with no-op scan loop. [Owner: CLI]

## CI Gates

- All: `cargo fmt --check`, `clippy -D warnings`, `cargo test`.
- SARIF: schema shape test(s) must pass.
- Perf: `performance_optimization_tests` under threshold.
- Security: no panics; baseline tests pass.

## Notes

- Keep new modules feature-gated (`ml`, `net`, `db`) to preserve fast default builds.
- Favor pure functions and immutable data; isolate IO at boundaries.

