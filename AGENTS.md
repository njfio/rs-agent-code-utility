# Repository Guidelines

## Project Structure & Module Organization
- `src/lib.rs`: Core library exports and modules (analysis, security, parsing).
- `src/bin/main.rs`: CLI entry (`tree-sitter-cli`).
- `examples/`: Runnable examples (e.g., `basic_usage.rs`).
- `tests/`: Integration tests (e.g., `complexity_analysis_unit_tests.rs`).
- `docs/`: Additional documentation; `.github/` for CI and templates.
- Top-level `test_*.rs`: Additional tests colocated at repo root.

## Build, Test, and Development Commands
- Build library: `cargo build`
- Build CLI: `cargo build --bin tree-sitter-cli`
- Run CLI: `cargo run --bin tree-sitter-cli -- --help`
- Run example: `cargo run --example basic_usage`
- Test all: `cargo test`
- Lint: `cargo clippy --all-targets --all-features`
- Format: `cargo fmt --all` (check: `cargo fmt --all -- --check`)

## Coding Style & Naming Conventions
- Rust 2021 edition; 4-space indentation; no tabs.
- Naming: modules/files `snake_case`; types/traits `PascalCase`; functions/vars `snake_case`; constants `UPPER_SNAKE_CASE`.
- Keep public APIs documented with Rust doc comments; prefer `Result<T, E>` error handling.
- Run `cargo fmt` and `cargo clippy` before committing; fix warnings or justify in PR.

## Testing Guidelines
- Framework: `cargo test` (unit tests in `#[cfg(test)]` modules; integration tests in `tests/`).
- Naming: descriptive test fn names (`test_language_detection`); files grouped by feature (e.g., `performance_optimization_tests.rs`).
- Add tests for new modules, CLI flags, and bug fixes; include edge cases and error paths.
- Example filtered run: `cargo test parser_comprehensive_tests`.

## Commit & Pull Request Guidelines
- Commits: Conventional Commits (e.g., `feat(cli): add map command`, `fix(parser): handle incremental edits`).
- PRs must include: clear description, rationale, testing notes (`cargo test`, `clippy`, `fmt --check`), and screenshots/sample output for CLI changes.
- Link related issues; update `README.md`, `CLI_README.md`, and `CHANGELOG.md` when user-facing behavior changes.
- Keep changes focused; separate refactors from feature/bug PRs.

## Security & Configuration Tips
- Do not commit secrets; prefer env-based config. Use `--features` thoughtfully (see `Cargo.toml`).
- When touching dependencies, run `cargo update -p <crate>` locally and verify tests/CLI still pass.

