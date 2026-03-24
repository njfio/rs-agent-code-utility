# Repository Guidelines

## Project Structure & Module Organization
- `src/lib.rs`: Core library exports and modules (analysis, security, parsing).
- `src/bin/main.rs`: CLI entry for `tree-sitter-cli`.
- `src/bin/rts.rs`: Secondary CLI binary, also gated behind `cli`.
- `src/security/`: Canonical security pipeline, rule engine, filters, and AST analyzers.
- `rules/`: Declarative security rules (`.yaml` metadata + `.scm` queries).
- `integration/mcp/`: TypeScript MCP adapter and JSON schemas.
- `benches/`: Criterion parser and security benchmarks.
- `scripts/`: Small CI/helper scripts such as benchmark regression checks.
- `examples/`: Runnable samples (e.g., `basic_usage.rs`).
- `tests/`: Integration tests (e.g., `complexity_analysis_unit_tests.rs`).
- `docs/`: Additional docs; `.github/` contains CI and templates.
- Top-level `test_*.rs`: Additional tests colocated at repo root.

## Build, Test, and Development Commands
- Build library: `cargo build` — compiles lib and checks deps.
- Build CLI: `cargo build --bin tree-sitter-cli --features cli` — CLI only.
- Run CLI: `cargo run --bin tree-sitter-cli --features cli -- --help` — usage info.
- Run example: `cargo run --example basic_usage --features demo` — quick demo.
- Test all: `cargo test` — unit + integration tests.
- Lint: `cargo clippy --all-targets --all-features` — static checks.
- Format: `cargo fmt --all` (check: `cargo fmt --all -- --check`).
- Benchmarks: `cargo bench --bench parser_bench --bench security_bench`.

## Coding Style & Naming Conventions
- Rust 2021; 4-space indentation; no tabs.
- Names: modules/files `snake_case`; types/traits `PascalCase`; funcs/vars `snake_case`; consts `UPPER_SNAKE_CASE`.
- Document public APIs with Rust doc comments; prefer `Result<T, E>` errors.
- Run `cargo fmt` and `cargo clippy` locally; fix or justify warnings.

## Testing Guidelines
- Framework: `cargo test`.
- Unit tests in `#[cfg(test)]` modules; integration tests in `tests/`.
- Use descriptive names (e.g., `test_language_detection`). Include edge and error paths.
- Filtered runs: `cargo test parser_comprehensive_tests`.

## Commit & Pull Request Guidelines
- Conventional Commits (e.g., `feat(cli): add map command`, `fix(parser): handle incremental edits`).
- PRs include description, rationale, testing notes (tests, clippy, fmt), and screenshots/sample CLI output when relevant.
- Link related issues; update `README.md`, `docs/CLI.md`, `docs/FEATURE_FLAGS.md`, `integration/mcp/README.md`, `ARCHITECTURE.md`, and `CHANGELOG.md` when their surfaces change.

## Security & Configuration Tips
- Do not commit secrets; prefer env-based config. Use feature flags per `Cargo.toml` thoughtfully.
- When updating deps, run `cargo update -p <crate>` and verify `cargo test`, `clippy`, and `fmt` all pass.
