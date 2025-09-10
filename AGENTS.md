# Repository Guidelines

## Project Structure & Module Organization
- `src/lib.rs`: Core library exports and modules (analysis, security, parsing).
- `src/bin/main.rs`: CLI entry for `tree-sitter-cli`.
- `examples/`: Runnable samples (e.g., `basic_usage.rs`).
- `tests/`: Integration tests (e.g., `complexity_analysis_unit_tests.rs`).
- `docs/`: Additional docs; `.github/` contains CI and templates.
- Top-level `test_*.rs`: Additional tests colocated at repo root.

## Build, Test, and Development Commands
- Build library: `cargo build` — compiles lib and checks deps.
- Build CLI: `cargo build --bin tree-sitter-cli` — CLI only.
- Run CLI: `cargo run --bin tree-sitter-cli -- --help` — usage info.
- Run example: `cargo run --example basic_usage` — quick demo.
- Test all: `cargo test` — unit + integration tests.
- Lint: `cargo clippy --all-targets --all-features` — static checks.
- Format: `cargo fmt --all` (check: `cargo fmt --all -- --check`).

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
- Link related issues; update `README.md`, `CLI_README.md`, and `CHANGELOG.md` for user-facing changes.

## Security & Configuration Tips
- Do not commit secrets; prefer env-based config. Use feature flags per `Cargo.toml` thoughtfully.
- When updating deps, run `cargo update -p <crate>` and verify `cargo test`, `clippy`, and `fmt` all pass.

