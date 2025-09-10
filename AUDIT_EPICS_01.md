# Repository Audit: Epics, Stories, and Milestones

This audit reviews the current Rust codebase, CLI, tests, features, and tooling. It translates findings into actionable epics with decomposed stories and concrete milestones.

## Executive Summary (Key Findings)
- Binaries: Duplicate entry points (`src/bin/main.rs`, `src/bin/rts.rs`, plus stray `src/main.rs`).
- Defaults: Heavy default features (`ml`, `net`, `db`) inflate builds and attack surface.
- Error handling: Multiple `unwrap/expect` in non-test code (panic risk) and unchecked I/O formatting (`writeln!(...).unwrap()`).
- Safety: `unsafe` in `embeddings.rs` and `advanced_memory.rs` without invariant docs or tests.
- CLI UX: Free-form strings for enums (e.g., `depth`, `format`) and flag duplication (`enable_security`).
- Language support: TODOs for symbol extraction across non-Rust languages.
- Security: Secrets/vuln detectors exist but lack policy gating, rate-limits, and SARIF parity across commands.
- Testing/CI: Strong base CI, but missing feature-matrix, doctests, fuzzing integration, and minimal build checks.
- API surface: Very large `lib.rs` re-exports; no `prelude`, unclear stability surface.

---

## Epic 1: Build & Feature-Flag Hardening
- Goal: Ship a minimal, secure-by-default core; opt-in to heavy capabilites.
- Stories:
  - Make default features minimal: `default = ["std", "serde"]`; move `ml`, `net`, `db` to opt-in.
  - Add build profiles (`release-lto=true`, `panic=abort` for CLI) and MSRV (`rust-version` in `Cargo.toml`).
  - Document feature sets in `README.md` and `CLI_README.md` with examples.
  - CI matrix: minimal, full, and per-feature builds; `--no-default-features` check.
- Milestones:
  - M1 Minimal default build passes (fmt, clippy, tests).
  - M2 CI matrix green across Linux/macOS; publish size/time deltas.
  - M3 Docs updated; release notes highlight changes.

## Epic 2: Panic-Free Error Handling
- Goal: Eliminate panics in library/CLI paths; return `Result` consistently.
- Stories:
  - Replace `unwrap/expect` in non-test code (`parser.rs`, `advanced_parallel.rs`, `cli/*`, etc.).
  - Swap `writeln!(...).unwrap()` to `write!`/`writeln!` with `?` and bubble up via `Execute::Error`.
  - Add lint gates: `#![deny(clippy::unwrap_used, clippy::expect_used)]` in non-test crates.
  - Extend tests for error branches and IO failures.
- Milestones:
  - M1 Audit complete; panic count to zero in `rg` checks (non-test).
  - M2 Clippy denies pass; regressions blocked in CI.

## Epic 3: Memory & Unsafe Review
- Goal: Ensure safety invariants and portability around `memmap2` and tensor ops.
- Stories:
  - Document safety invariants at unsafe sites; add unit tests guarding invariants.
  - Feature-gate embeddings and memory-mapped paths; provide buffered fallback.
  - Benchmarks for mmap vs. buffered read; automated perf threshold checks.
- Milestones:
  - M1 Safety docs and tests land; no UB patterns in review.
  - M2 Perf report attached; fallback verified on non-Unix.

## Epic 4: CLI UX Consistency & Validation
- Goal: Strongly-typed flags and consistent semantics across commands.
- Stories:
  - Replace string flags with `ValueEnum` (e.g., `depth`, `format`, `map_type`, `min_severity`).
  - Centralize common flags (output, depth, schema) in helpers; dedupe `enable_security` semantics.
  - Add `--log-level` and `RUST_LOG` support via `tracing-subscriber`.
  - Snapshot tests for `--help` output; golden files in `tests/`.
- Milestones:
  - M1 All commands compile with enums; help text aligned.
  - M2 Snapshot tests added; UX review complete.

## Epic 5: Language Support Completeness
- Goal: Close TODOs in `symbol_table.rs` and analyzer for JS/Python/C/CPP/Go/Java/Ruby/Swift/Kotlin/PHP.
- Stories:
  - Implement minimal symbol extraction per language, or explicit “not supported yet” to avoid false promises.
  - Add language-specific fixtures; unit tests per language path.
  - Update `supported_languages()` versions to match `Cargo.toml` crates.
- Milestones:
  - M1 Explicit stubs with tests; no misleading outputs.
  - M2 First two languages fully implemented; follow-on tickets for remaining.

## Epic 6: Security Hardening & Reporting
- Goal: Safer defaults and consistent output.
- Stories:
  - Default offline mode; network calls only behind `net` feature and explicit CLI flag.
  - Rate limiting and backoff in `infrastructure/http_client.rs`; test determinism.
  - SARIF parity: `security`, `ast-security`, and `symbols` schemas unified; schema tests.
  - Add `cargo deny` and `cargo audit` checks in CI (advisory allowlist configurable).
- Milestones:
  - M1 Offline-by-default validated; CI adds deny/audit.
  - M2 SARIF schema stable; sample reports checked into `docs/`.

## Epic 7: Testing Strategy & Fuzzing
- Goal: Broaden coverage and increase robustness.
- Stories:
  - Enable doctests; add targeted doc examples for public APIs.
  - Add `cargo-fuzz` harness for parser inputs; seed corpus from `test_files/`.
  - Introduce slow-test label; split CI for smoke vs. extended.
- Milestones:
  - M1 Doctests pass; smoke CI fast (<5 min).
  - M2 Fuzz CI nightly; crashes triaged automatically.

## Epic 8: CI/CD & Release Engineering
- Goal: Reliable releases with binaries and changelogs.
- Stories:
  - Add GitHub Releases with cross-compiled binaries (Linux/macOS) via `cross`.
  - Cache tuning; separate `fmt/clippy/test/build` jobs; artifact upload for binaries.
  - Conventional Changelog automation; release notes template.
- Milestones:
  - M1 Multi-job CI green; artifacts published on tagged pushes.
  - M2 Automated changelog in PRs; signed provenance optional.

## Epic 9: API Surface & Documentation
- Goal: Clear stability story and smaller import burden.
- Stories:
  - Introduce `prelude` for common types; reduce `lib.rs` re-exports.
  - Mark unstable modules `#[doc(cfg(feature = ...))]`; audit public vs. crate-private.
  - Sync `README.md`, `CLI_README.md`, `docs/` with examples and feature gates.
- Milestones:
  - M1 Prelude published; docs build clean (`RUSTDOCFLAGS=-D warnings`).
  - M2 API guide in `docs/` with migration notes.

## Epic 10: Binary Consolidation
- Goal: One clear default CLI, optional alias.
- Stories:
  - Remove `src/main.rs`; keep `src/bin/main.rs` (tree-sitter-cli) and optional alias `rts-cli`.
  - Update Cargo targets, docs, tests, and CI to reference canonical binary.
- Milestones:
  - M1 No duplicate binaries in `cargo build --bins`.
  - M2 Docs/CI updated; deprecation note added to CHANGELOG.

## Epic 11: Observability & Telemetry
- Goal: Consistent logging and optional metrics.
- Stories:
  - Standardize `tracing` spans across analyzer, CLI, and security modules.
  - Optional metrics export (feature-gated) with `metrics` crate and simple stdout sink.
- Milestones:
  - M1 Tracing enabled; `--log-level` verified.
  - M2 Metrics gated behind `telemetry` feature; docs updated.

## Epic 12: Repository Hygiene
- Goal: Predictable structure and contributions.
- Stories:
  - Enforce module/file naming; remove stale guides in `src/*.md` to `docs/`.
  - Add CODEOWNERS; refine issue/PR templates for features vs. bugs.
- Milestones:
  - M1 Files moved; links fixed.
  - M2 Templates live; contributor onboarding simplified.

---

### Tracking & Acceptance
- Each story carries acceptance checks (tests pass, clippy deny passes, docs updated).
- Create GitHub Project board: columns by epic; milestones M1–M3 mapped to quarters.
- Add `A-epic`, `S-story`, `M-milestone` labels and feature flags in issue templates.
