---
title: "refactor: Comprehensive Codebase Improvement - All 18 Ideation Points"
type: refactor
status: active
date: 2026-03-23
origin: docs/ideation/2026-03-23-full-codebase-ideation.md
deepened: 2026-03-23
---

## Enhancement Summary

**Deepened on:** 2026-03-23
**Sections enhanced:** 15
**Research agents used:** Architecture Strategist, Security Sentinel, Performance Oracle, Pattern Recognition Specialist, Code Simplicity Reviewer, Best Practices Researcher, Framework Documentation Researcher

### Key Improvements
1. **CRITICAL BUILD-BREAKING BUG FOUND:** `ai_false_positive_filter.rs` and `ml_filter.rs` have unguarded `tokio::sync::RwLock` imports that will break compilation when `net` feature is removed from defaults in Phase 1. Must be fixed in Phase 0 or early Phase 1.
2. **Factual corrections:** `GraphNode.file_path` already exists in `semantic_graph.rs`; `SecurityFinding.confidence: f64` already exists in `ast_analyzer.rs`; MCP server already has 9 tool registrations (not 0). Plan updated accordingly.
3. **Scope simplification recommendations:** Consider starting with 3 MCP tools (parse, complexity, security) instead of 8; reduce test corpus from 96 fixtures to 12 high-signal ones initially; Phase 4 should be a separate plan, not in this document.
4. **Performance insights:** Benchmarks have measurement errors (parser creates new Parser per iteration, security bench writes tempfiles per iteration); tree-sitter queries should use single-pass traversal; `find_similar()` in semantic_graph.rs is O(N^2).
5. **Security research:** SARIF output missing required `$schema`, `tool.driver.rules[]`, and `partialFingerprints` fields; sqlx 0.8 requires `SqlSafeStr` trait; `rmcp` crate available for native Rust MCP server (future option).

### New Considerations Discovered
- Phase 1 feature removal will cause compile errors in security modules due to unconditional tokio imports
- The ~50 crate target for default features is likely 80-120 without more aggressive gating
- `HashMap` keys in `taint_analysis.rs` are compile-time string literals and should use `&'static str`
- `SecurityPipeline` must clarify relationship with existing `AdvancedSecurityAnalyzer` to avoid confusion
- MCP tool output should include JSON schema version field for forward compatibility

---

# Comprehensive Codebase Improvement Plan

## Overview

Transform `rust_tree_sitter` from a feature-bloated monolith with broken AI stubs and unreliable security scanning into a focused, credible code analysis engine that serves as an MCP tool provider for AI agents.

This plan addresses all 25 improvement areas identified during ideation (7 strategic survivors + 18 tactical items), organized into 5 sequential phases with explicit dependencies and acceptance criteria.

**Scope:** ~94K lines of Rust across 126 files, 506 dependency crates, 2 CI workflows, 1 TypeScript MCP adapter.

**Semver policy:** Phase 1's default-feature change is a breaking change. All phases through Phase 3 ship as a single `0.2.0` release with a CHANGELOG migration guide.

## Problem Statement / Motivation

The Grok audit gave this codebase a B- rating. Specific problems:

1. **Credibility gap:** ~15K lines of AI code are stubs returning `Vec::new()`. Performance analysis detects hotspots by checking function *names* for strings like "nested" and "alloc". The dependency analyzer returns 0 dependencies.
2. **Security scanner is unusable:** High false-positive rate from 3 overlapping filter layers (deterministic, "ML", "AI") that share no taint state. No inline suppression mechanism. No confidence scores.
3. **Dependency bloat:** 506 crates (34 direct, 472 transitive) with known CVEs (ring 0.17.9, sqlx 0.7.4). Default features force ML, HTTP, and database deps on all consumers.
4. **CI is broken:** Duplicate steps, missing `.ci/security-baseline.json`, 100+ clippy warnings, failing fmt/tests on the current branch.
5. **Strategic misalignment:** The project tries to be an AI consumer (calling LLMs) when its real value is providing structured code facts to AI tools.

## Proposed Solution

Five sequential phases, each delivering standalone value:

- **Phase 0:** Fix the foundation (CI, deps, cleanup)
- **Phase 1:** Dependency diet + feature stratification
- **Phase 2:** Analysis credibility (security pipeline, AST-based analysis, dogfooding)
- **Phase 3:** Strategic pivot to MCP tool server
- **Phase 4:** Advanced analysis (cross-file taint, rule DSL, benchmarks)

---

## Technical Approach

### Architecture

The target architecture has three layers:

```
┌─────────────────────────────────────────────────┐
│  MCP Tool Server (TypeScript adapter or native)  │  <-- Phase 3
├─────────────────────────────────────────────────┤
│  CLI Binaries (tree-sitter-cli, rts-cli)         │  <-- Phase 1 (feature-gated)
├─────────────────────────────────────────────────┤
│  Analysis Layer                                   │
│  ┌──────────┐ ┌──────────────┐ ┌─────────────┐  │
│  │ Security  │ │ Complexity   │ │ Performance │  │  <-- Phase 2
│  │ Pipeline  │ │ Analysis     │ │ Analysis    │  │
│  └──────────┘ └──────────────┘ └─────────────┘  │
│  ┌──────────┐ ┌──────────────┐ ┌─────────────┐  │
│  │ Taint    │ │ Semantic     │ │ Dependency  │  │  <-- Phase 4
│  │ Analysis │ │ Graph        │ │ Analysis    │  │
│  └──────────┘ └──────────────┘ └─────────────┘  │
├─────────────────────────────────────────────────┤
│  Core Layer (parser, tree, query, languages)     │  <-- Phase 0-1
└─────────────────────────────────────────────────┘
```

### Research Insights: Architecture

**JSON Schema Versioning:** All MCP tool outputs should include a `"schema_version": "0.2.0"` field at the top level. This allows clients to detect breaking changes and adapt. Follow semver for the schema independent of the library version.

**Dependency-to-Feature Mapping:** Create a table mapping every direct dependency to its feature gate. This serves as both documentation and a verification checklist during Phase 1:

```
| Dependency | Feature Gate | Justification |
|-----------|-------------|---------------|
| clap      | cli         | CLI argument parsing |
| reqwest   | net         | HTTP client for AI providers |
| sqlx      | db          | Database integration |
| candle-*  | ml          | ML inference |
| tokio     | net (full), core (async) | Async runtime |
```

**Security Module Re-exports:** Narrow `src/security/mod.rs` glob re-exports (`pub use module::*`) to explicit item re-exports. This prevents accidental API surface growth and makes it clear what's public.

**Native Rust MCP (Future):** The `rmcp` crate (on crates.io) provides a native Rust MCP server implementation. Consider this as a Phase 3+ option to eliminate the TypeScript adapter entirely, but for now the TS adapter is lower risk.

### Implementation Phases

---

#### Phase 0: Foundation Fixes

**Goal:** Get CI green, fix known vulnerabilities, remove dead code and stale artifacts.

**Duration estimate:** 1-2 days

##### Task 0.1: Fix CI Pipeline

- [x] Remove duplicate "Security Analysis Validation" step in `.github/workflows/ci.yml` (lines 44 and 49-50)
- [x] Split single sequential CI job into parallel jobs: `fmt`, `clippy`, `test`, `build`, `mcp-test`
- [x] Create `.ci/security-baseline.json` with empty baseline `{}` so `security_scan.yml` stops failing
- [x] Fix 100+ clippy warnings (run `cargo clippy --all-targets --all-features -- -D warnings`)
- [x] Fix failing `cargo fmt --all -- --check`
- [x] Fix any failing tests on current branch
- [x] Set `WIKI_FETCH_ASSETS=0` in CI to prevent macOS SystemConfiguration hangs

**Acceptance criteria:**
- `cargo fmt --all -- --check` passes
- `cargo clippy --all-targets --all-features -- -D warnings` passes
- `cargo test --workspace` passes
- Both CI workflows run green on a PR

**Key files:**
- `.github/workflows/ci.yml`
- `.github/workflows/security_scan.yml`

### Research Insights: CI Pipeline

**Parallel CI best practice:** Use GitHub Actions job-level parallelism with `needs:` for dependencies. The `fmt` and `clippy` jobs can run in parallel with no dependencies. `test` and `build` can also run in parallel. Only `mcp-test` needs `build` to complete first.

**Cache strategy:** Add `actions/cache` for `~/.cargo/registry` and `target/` keyed on `Cargo.lock` hash. This typically saves 2-5 minutes per CI run.

##### Task 0.2: Upgrade Vulnerable Dependencies

- [ ] Upgrade `ring` transitively (via `reqwest`/`rustls` version bumps) to >= 0.17.12 (RUSTSEC-2025-0009)
- [ ] Upgrade `sqlx` from 0.7.4 to 0.8.1+ (RUSTSEC-2024-0363) -- note: API breaking changes in sqlx 0.8
- [x] Replace unmaintained `backoff` with `exponential-backoff`
- [x] Audit `instant`, `paste`, `proc-macro-error` for maintained alternatives or removal

**Note:** The `ring` and `sqlx` upgrades become less critical once Phase 1 removes `net` and `db` from defaults, since they'll only affect opt-in users. However, they should still be upgraded for users who do opt in.

**Implementation note (2026-03-24):** `reqwest` was bumped to `0.12` and `hf-hub` to `0.5.0` with explicit `rustls-tls`, but that alone does not clear `ring` because `sqlx 0.7.4` still brings in `rustls 0.21` and keeps `ring 0.17.9` in the graph. Attempting `sqlx 0.8.6` exposed the real blocker: `libsqlite3-sys 0.30.x` requires `cc ^1.1.6`, while the current `tree-sitter 0.20` parser stack still constrains `cc` to the old line. A straightforward parser-stack upgrade is also blocked by `tree-sitter-kotlin`, whose latest published crate still requires `tree-sitter < 0.23`. Finishing Task 0.2 likely needs either a broader tree-sitter migration strategy or a Kotlin parser replacement.
**Implementation note (2026-03-24, later):** The follow-up audit of `instant`, `paste`, and `proc-macro-error` showed that `instant` only remains on a target-specific dev-only path through `wiremock`, `paste` remains fully transitive under the optional `ml` and `db` stacks (`candle-*`, `tokenizers`, `sqlx`) rather than the default surface, and `proc-macro-error` came from the direct `tabled` dependency on the `cli` feature. The CLI now uses a crate-local text-table renderer instead of `tabled`, so `proc-macro-error` is no longer pulled in by `cargo tree --features cli`.

### Research Insights: sqlx 0.8 Migration

**Breaking changes in sqlx 0.8:**
- Feature flags restructured: split `runtime-tokio-rustls` into separate runtime and TLS features
- New `SqlSafeStr` trait required for string types in queries -- any custom string newtypes need to implement this
- `query!` macro may require re-running `cargo sqlx prepare` for offline mode
- Connection pool configuration API changed slightly

**Migration approach:** Since sqlx is gated behind `db` feature and will be non-default, prioritize correctness over speed. Run the full sqlx test suite after migration.

**Acceptance criteria:**
- `cargo audit` reports 0 known vulnerabilities
- All tests still pass after upgrades

**Key files:**
- `Cargo.toml` (lines 13-90)
- `src/infrastructure/database.rs` (sqlx migration)

##### Task 0.3: Remove Dead Code and Stale Artifacts

- [x] Delete `cc = "1.0"` from `[build-dependencies]` (no `build.rs` exists)
- [x] Delete stray `src/main.rs` (duplicates `src/bin/main.rs`)
- [x] Delete root-level development artifacts: `debug_cpp.rs`, `simple_embedded_test.rs`, `test_cli.rs`, `test_epic2.rs`, `test_rate_limiter.rs`, `test_ai_filtering.rs`, `test_code_map.rs`
- [x] Delete committed output: `security_report.json`, `comprehensive_todo_list.md.backup`
- [x] Add to `.gitignore`: `security_report.json`, `*.backup`
- [x] Delete stale planning docs at root (verify list first -- preserve `AGENTS.md`, `claude.md`, `README.md`, `CONTRIBUTING.md`, `SECURITY.md`, `LICENSE`, `CHANGELOG.md`, `INSTRUCTIONS.md`). Target for deletion:
  - `AUDIT_EPICS_01.md`
  - `CODEX_SECURITY_SCAN_HARDENING_EPICS.md`
  - `CODEBASE_IMPROVEMENT_DOCUMENT.md`
  - `COMPREHENSIVE_TODO_LIST.md`
  - `CodeReview_Resolution_Plan.md`
  - `IMPLEMENTATION_PLAN.md`
  - `IMPLEMENTATION_STATUS.md`
  - `Plan.md`
  - `REALISTIC_DEVELOPMENT_ROADMAP.md`
  - `SECURITY_ANALYSIS_IMPROVEMENT_ROADMAP.md`
  - `TASK_LIST.md`
  - `TESTING_ENHANCEMENTS.md`
  - `src/CLAUDE_CODE_TASK_OFFLOADING_GUIDE.md`
  - `src/GEMINI_CLI_TASK_OFFLOADING_GUIDE.md`
- [x] Retire the stale fuzz-target subtask (`fuzz/` no longer exists in the repo)

**Implementation note (2026-03-24):** The originally listed dead files are already absent from the tracked repo, `.gitignore` already covers `security_report.json` and backup artifacts, and there are no stray root-level `.rs` files left. The old `fuzz/Cargo.toml` action item is obsolete because the repository no longer contains a `fuzz/` harness.

**Acceptance criteria:**
- No stale `.md` planning docs at root (except functional docs)
- No stray `.rs` files at root
- `.gitignore` covers output artifacts
- No plan steps refer to removed in-repo infrastructure like the old `fuzz/` harness

##### Task 0.4: Incremental Panic-Free Error Handling

**Approach:** Apply `#![deny(clippy::unwrap_used)]` incrementally per module, not globally. Use `#[allow(clippy::unwrap_used)]` escape hatches on modules not yet converted.

- [x] Add `#![deny(clippy::unwrap_used, clippy::expect_used)]` to `src/lib.rs` with per-module `#[allow]` overrides for all existing modules
- [x] Convert the 5 highest-impact modules first (modules used by CLI and MCP):
  - [x] `src/parser.rs`
  - [x] `src/analyzer.rs`
  - [x] `src/cli/mod.rs` and subcommands (replace `writeln!(...).unwrap()` with `?`)
  - [x] `src/tree.rs`
  - [x] `src/query.rs`
- [x] Track remaining modules as a follow-up issue (one PR per module batch) in `docs/plans/2026-03-24-002-follow-up-unwrap-hardening-batches.md`

**Acceptance criteria:**
- Core parsing/analysis path is panic-free
- CLI does not panic on malformed input
- Remaining modules have explicit `#[allow]` annotations (not silent)

##### Task 0.5: Fix Tokio Import Guards (CRITICAL for Phase 1)

**DISCOVERED DURING DEEPENING:** `src/security/ai_false_positive_filter.rs` and `src/security/ml_filter.rs` have unconditional `use tokio::sync::RwLock` imports. When Phase 1 removes `net` from default features, these will cause compilation failures even for the default feature set.

- [x] Wrap `use tokio::sync::RwLock` in `ai_false_positive_filter.rs` with `#[cfg(feature = "net")]`
- [x] Confirm the old `ml_filter.rs` path is obsolete and no equivalent Tokio import remains in `heuristic_filter.rs`
- [x] Audit all other source files for unconditional imports of feature-gated dependencies (grep for `use tokio::`, `use reqwest::`, `use sqlx::`, `use candle_`, `use hf_hub::`)
- [x] Replace any found unconditional imports with `#[cfg(feature = "...")]` guards

**Implementation note (2026-03-24):** The current repo no longer has `ml_filter.rs` (it was renamed to `heuristic_filter.rs`, which is sync-only). The actual feature-boundary bugs found during execution were broader module-gating issues: `enhanced_security`, `vulnerability_db`, and `vulnerability_correlation` required `net + db`, while `infrastructure::rate_limiter` required `net`. Those boundaries were tightened, and `cargo check` now passes for `--no-default-features`, `--features net`, `--features db`, and `--features "net db"`.

**Acceptance criteria:**
- `cargo build --no-default-features` compiles without tokio/reqwest/sqlx/candle import errors
- No unconditional imports of feature-gated dependencies exist outside their feature-gated modules

**Key files:**
- `src/security/ai_false_positive_filter.rs`
- `src/security/ml_filter.rs`

---

#### Phase 1: Dependency Diet + Feature Stratification

**Goal:** Reduce default dependency footprint from 506 crates to ~80-120 (realistic target, not ~50 which would require more aggressive gating).

**Duration estimate:** 2-3 days

**Prerequisite:** Phase 0 complete (CI green, vulnerable deps upgraded, tokio imports fixed)

##### Task 1.1: Restructure Feature Flags

- [x] Change `Cargo.toml` default features: `default = ["std", "serde"]`
- [x] Create `cli` feature gating for the current CLI dependency set: `clap`, `colored`, `indicatif`, `rustyline`, `syntect`, `tracing-subscriber`
- [x] Add `required-features = ["cli"]` to both `[[bin]]` entries (`tree-sitter-cli` and `rts-cli`)
- [x] Verify `ml` feature correctly gates: `candle-core`, `candle-nn`, `candle-transformers`, `tokenizers`, `hf-hub`
- [x] Verify `net` feature correctly gates: `reqwest`, `tokio` (full runtime -- core tokio for async may stay)
- [x] Verify `db` feature correctly gates: `sqlx`
- [x] Create `full` feature alias: `full = ["std", "serde", "ml", "net", "db", "cli", "wiki", "mmap", "extended-languages"]`
- [x] Audit remaining direct deps for additional gating opportunities:
  - `pulldown-cmark` -> gate behind `wiki` feature
  - `tower`, `governor` -> gate behind `net` (rate limiting only needed for AI providers)
  - `rustyline`, `syntect` -> already gated behind `cli`
  - `memmap2` -> gate behind dedicated `mmap` feature; keep `advanced_memory` usable with buffered fallback when disabled
- [x] Update CI to test: `--no-default-features`, default features, `--all-features`
- [x] Create dependency-to-feature mapping table (see Architecture Research Insights above) and store in `docs/FEATURE_FLAGS.md`

**Implementation note (2026-03-24):** The feature split is already live in the repo: default features are `["std", "serde"]`, both CLI bins require `cli`, `docs/FEATURE_FLAGS.md` documents the mapping, and current builds pass for `cargo build`, `cargo build --no-default-features`, `cargo check --features ml`, `cargo check --features net`, `cargo check --features db`, and `cargo check --all-features`. `memmap2` has now been moved behind a dedicated `mmap` feature while keeping `advanced_memory` available through a buffered fallback in the default build. The remaining open item in Task 1.1 is the next reduction pass over other always-on dependencies.
**Implementation note (2026-03-24, later):** `num_cpus`, the crate's direct `dirs` usage, the direct `dashmap` edge from infrastructure caching, the always-on `config` dependency, the unused `exponential-backoff` dependency, the unused `sha2` dependency, the direct `async-trait` dependency, the always-on `anyhow` dependency, the always-on `uuid` dependency, the always-on `chrono` dependency, the always-on `tracing` dependency, the always-on `crc32fast` dependency, the always-on `flate2` dependency, the direct `walkdir` dependency, the direct `crossbeam-channel` dependency, the direct `base64` dependency, and the direct `parking_lot` dependency have now been removed from the direct core dependency surface. Thread-pool and analysis defaults use `std::thread::available_parallelism()`, infrastructure default paths now use internal std-based platform helpers, the cache backend now uses std `RwLock<HashMap<...>>` with poison-tolerant helper accessors, the external `config` crate is only enabled when `net` or `db` infrastructure is requested, HTTP retry logic already uses a small internal exponential backoff implementation, the crate no longer carries the dead `sha2` dependency because it had no live call sites, the async dyn-trait surfaces now use boxed std futures instead of the external macro crate, `anyhow` is now feature-local to `ml`/`net`/`db` after removing its last core-only usage from the OWASP detector, runtime string IDs now use a crate-local generator while the `uuid` crate is only needed for the gated demo example, core/reporting timestamps now use std-based helpers while `chrono` remains only on the `db` path for typed advisory/database timestamps, core builds now route log macros through crate-local no-op shims while `tracing` remains direct only on the `cli`/`net`/`db` paths, wiki filename sanitization and diagram hashing now keep `crc32fast` behind the `wiki` feature, the `advanced_cache` disk layer now stores plain JSON `.cache` files instead of gzip-compressed JSON so `flate2` is no longer baseline-only, declarative rule loading plus AST security file discovery now use std-based recursive traversal instead of a direct `walkdir` edge, the `advanced_parallel` scheduler now uses std `mpsc` channels instead of a direct `crossbeam-channel` edge, the secrets detector now uses a crate-local base64url decoder instead of a direct `base64` edge for JWT validation, the last direct `parking_lot` usage in infrastructure caching plus advanced parallel scheduling now uses std `RwLock`, and the JavaScript/Python/C/C++/TypeScript/Go/Java/PHP/Ruby/Swift/Kotlin grammars now sit behind a dedicated `extended-languages` feature instead of the baseline parser surface. Internal analysis paths now use the feature-aware language registry so all-features scans still cover those grammars even though the top-level public helper surface is baseline-only, and reduced builds now skip declarative security rules that require gated languages instead of aborting the whole rule load. Those reductions have now dropped the measured default/no-default `cargo tree` count to `420`. `dirs` still remains transitively under `ml` through `hf-hub`, `dashmap` still remains transitively under `net` through `governor`, `async-trait` still remains transitively under `net`/`db` through `config`, `crc32fast` still appears in the all-features graph both directly through `wiki` and transitively through `syntect`/`flate2` plus `candle-core`/`zip`, `flate2` still appears transitively under `cli` through `syntect`, `walkdir` still remains transitively in the no-default graph through always-on `ignore` and dev-only `criterion`, `base64` still remains transitively in the no-default graph through dev-only `wiremock`, `parking_lot` still remains transitively in the no-default graph through dev-only `tokio`/`wiremock`, and `anyhow` plus `tracing` still remain transitively in the no-default graph through dev-only `wiremock`, so the next reduction pass would need deeper work on the remaining always-on parser/utility footprint rather than more easy direct-dependency gating.

### Research Insights: Feature Stratification

**Realistic crate count:** The ~50 crate target may be optimistic. tree-sitter grammars alone pull significant transitive deps. A more realistic target is 80-120 crates for `["std", "serde"]` defaults. Measure after implementation and adjust the success metric accordingly.

**Compile-time verification:** After restructuring, run `cargo tree --no-default-features | wc -l` and `cargo tree | wc -l` to measure actual crate counts. Add these numbers to the CI output for tracking.

**Acceptance criteria:**
- `cargo build --no-default-features` compiles successfully (core parsing only)
- `cargo build` (default features) compiles with < 120 crates (measure and tighten over time)
- `cargo build --all-features` compiles with full feature set
- All tests pass under `--all-features`
- CI matrix tests all 3 feature configurations

**Key files:**
- `Cargo.toml` (lines 88-100 for features)
- `src/lib.rs` (conditional module declarations)

##### Task 1.2: Fix Broken Dependency Analyzer

- [x] Investigate why `dependency_analysis.rs` returns 0 dependencies
- [x] Fix Cargo.toml parser to correctly extract direct dependencies
- [x] Fix the `Clone` impl that drops `provider` field to `None`
- [x] Add integration test: analyze this project's own `Cargo.toml`, verify current manifest deps are found
- [x] Add integration test: analyze a known `package.json`, verify deps found

**Implementation note (2026-03-24):** The dependency analyzer no longer exhibits the original "0 dependencies" behavior. `src/dependency_analysis.rs` now extracts manifest dependencies, preserves the optional vulnerability provider across `Clone`, tracks per-package-manager counts, and deduplicates inferred source imports against manifest entries. Coverage now includes both the provider-preservation unit test and repo-level characterization in `tests/dependency_analysis.rs`, which verifies that analyzing this repository returns the current Cargo manifest dependency set instead of a hard-coded historical count.

**Acceptance criteria:**
- Running dependency analysis on `rust_tree_sitter` itself returns the current Cargo manifest dependency count, as verified by the repo-level characterization test
- `DependencyAnalyzer::clone()` preserves the provider

**Key files:**
- `src/dependency_analysis.rs`

##### Task 1.3: Version Bump and Migration Guide

- [x] Bump version to `0.2.0` in `Cargo.toml`
- [x] Write `CHANGELOG.md` entry documenting:
  - Default features changed from `["std", "serde", "ml", "net", "db"]` to `["std", "serde"]`
  - Migration: add `features = ["full"]` to restore previous behavior
  - Vulnerable deps upgraded
  - Stale docs removed

---

#### Phase 2: Analysis Credibility

**Goal:** Make the security scanner and performance analyzer produce trustworthy results. Establish dogfooding.

**Duration estimate:** 1-2 weeks

**Prerequisite:** Phase 1 complete (feature flags working, dep analyzer fixed)

##### Task 2.1: Replace String Heuristics with AST Traversal

- [x] In `src/performance_analysis.rs`, replace all `symbol.name.contains(...)` and `text.contains(...)` heuristics with tree-sitter AST node traversals:
  - Nested loop detection: walk AST for `for_expression`/`while_expression`/`loop_expression` nodes nested inside each other
  - Allocation hotspot detection: walk AST for function calls to `Vec::new()`, `HashMap::new()`, `String::new()`, `.clone()`, `.to_string()`, `.collect()` inside loops
  - Indexing pattern detection: walk AST for array indexing nodes inside loop bodies
- [x] Implement language-specific patterns using tree-sitter queries (`.scm` syntax) for: Rust, JavaScript, Python (the 3 most common)
- [x] Add regression tests: create test fixtures with known hotspots, verify detection
- [x] Add negative tests: functions named "loop_handler" or "allocation_tracker" must NOT be flagged

### Research Insights: Tree-sitter Query Patterns

**Single-pass traversal mandate:** All AST-based detection should use a single tree traversal with `TreeCursor`, collecting all findings in one pass. Do NOT traverse the tree once per pattern. This is critical for maintaining the 2ms/1K LOC performance target.

**Batch node lookup:** Consider adding a `find_nodes_by_kinds(&[&str])` helper to collect multiple node types in a single traversal, reducing per-pattern overhead.

**Example .scm query for nested loops in Rust:**
```scm
;; Detect nested for loops
(for_expression
  body: (block
    (for_expression) @inner_loop)) @outer_loop
```

**Example .scm query for allocation in loop:**
```scm
;; Detect Vec::new() inside a loop body
(for_expression
  body: (block
    (let_declaration
      value: (call_expression
        function: (scoped_identifier
          path: (identifier) @type_name
          name: (identifier) @method_name)))))
```

**Acceptance criteria:**
- Zero grep hits for `name.contains("nested")`, `name.contains("loop")`, `name.contains("alloc")` etc. in `performance_analysis.rs`
- Test suite includes >= 10 positive and >= 5 negative test cases
- Detection uses actual AST node types, not string matching
- Existing tests still pass (no regression)

**Key files:**
- `src/performance_analysis.rs` (lines 924-1535)

##### Task 2.2: Security Pipeline Consolidation (Facade Pattern)

**Approach:** Add a `SecurityPipeline` facade that orchestrates existing modules as stages. Do NOT merge files -- preserve the modular structure in `src/security/`.

- [x] Create `src/security/pipeline.rs` with `SecurityPipeline` struct:
  ```
  Parse -> Taint Analysis -> AST Detection -> OWASP Check -> Specialized Detectors -> Filter -> Score -> Report
  ```
- [x] Wire taint state from `taint_analysis.rs` into the detection stages so detectors share taint context
- [x] Extend existing `confidence: f64` field (already on `SecurityFinding` in `ast_analyzer.rs`) to all finding types
- [x] Implement confidence scoring logic:
  - High (0.8-1.0): Finding confirmed by taint analysis with source-to-sink path
  - Medium (0.5-0.8): AST pattern match without taint confirmation
  - Low (0.0-0.5): Heuristic-only match (string patterns, name-based)
- [x] Default output threshold: only show findings with confidence >= 0.5 (configurable via `--min-confidence`)
- [x] Replace "ML" filter (`security/ml_filter.rs`) internals with honest deterministic rules (rename to `heuristic_filter.rs`)
- [x] Keep the `deterministic_filter.rs` as the primary filter
- [x] Gate `ai_false_positive_filter.rs` behind `net` feature (it requires AI providers)
- [x] Clarify relationship between new `SecurityPipeline` and existing `AdvancedSecurityAnalyzer` -- document which one is the canonical entry point, and deprecate the other

### Research Insights: Security Pipeline

**Existing confidence field:** `SecurityFinding.confidence: f64` already exists in `ast_analyzer.rs`. Don't create a new one -- extend the existing field's usage across all finding types. Ensure the scoring logic is consistent.

**Pipeline vs AdvancedSecurityAnalyzer:** The existing `AdvancedSecurityAnalyzer` has overlapping functionality. The new `SecurityPipeline` should subsume it. Mark `AdvancedSecurityAnalyzer` as `#[deprecated]` and delegate its methods to `SecurityPipeline` internally to avoid breaking existing callers.

**Async considerations:** Some filter stages (especially `ai_false_positive_filter.rs`) are async. The pipeline should support both sync and async execution paths. The sync path skips AI filtering; the async path includes it when the `net` feature is enabled.

**Taint analysis lazy loading:** Don't run taint analysis on every file unconditionally. Run AST pattern detection first, then only invoke taint analysis on files that have at least one medium-confidence finding. This avoids the O(n) cost of taint analysis on clean files.

**Acceptance criteria:**
- Single entry point: `SecurityPipeline::analyze(source_code, language) -> Vec<ScoredFinding>`
- All findings have a confidence score
- Default output hides findings below 0.5 confidence
- `ml_filter.rs` renamed, no references to "ML" or "machine learning" in deterministic code
- Existing security tests pass (may need score threshold adjustments)
- `AdvancedSecurityAnalyzer` deprecated with delegation to `SecurityPipeline`

**Key files:**
- `src/security/mod.rs`
- `src/security/pipeline.rs` (new)
- `src/security/ml_filter.rs` -> `src/security/heuristic_filter.rs`
- `src/security/ast_analyzer.rs`
- `src/taint_analysis.rs`

##### Task 2.3: Inline Suppression Comments

- [x] Implement `// rts-ignore[rule-id]` comment parsing:
  - Scope: suppresses findings on the immediately following line (N+1), matching ESLint's `eslint-disable-next-line`
  - Also support `// rts-ignore` (no rule-id) to suppress all findings on next line
  - Support language-appropriate comment syntax: `//` (Rust, JS, TS, C, C++, Go), `#` (Python)
  - Parse comments from tree-sitter AST (use `comment` node type)
- [x] Add suppressed findings to SARIF output with `"suppressions"` array per SARIF 2.1.0 spec
- [x] Inline suppressions take precedence over baseline suppressions
- [x] Add tests for each supported comment syntax

**Acceptance criteria:**
- `// rts-ignore[sql-injection]` on line N suppresses sql-injection findings on line N+1
- `# rts-ignore` in Python suppresses all findings on next line
- Suppressed findings appear in SARIF with `"kind": "inSource"` suppression
- Unsuppressed findings unaffected

##### Task 2.4: Security Test Corpus

**Scope note (from simplicity review):** Start with 12 high-signal test fixtures (2 true positives + 1 true negative per vulnerability class), not 96. Expand the corpus iteratively as false positive/negative patterns emerge from dogfooding.

- [x] Create `tests/fixtures/security-corpus/` directory
- [x] Add initial ground-truth test files (12 minimum):
  - `sql-injection/` -- 2 true positives, 1 true negative (Rust or JS)
  - `command-injection/` -- 2 true positives, 1 true negative
  - `secrets/` -- 2 true positives, 1 true negative
  - `xss/` -- 2 true positives, 1 true negative (JS)
- [x] Write integration tests that run the pipeline against the corpus and assert:
  - True positives detected (recall)
  - True negatives not flagged (precision)
  - Confidence scores within expected range
- [x] Add proptest strategies for generating syntactic variants of known vulnerable patterns
- [x] Track precision/recall metrics and gate CI on regression (< 80% recall or < 70% precision fails)
- [ ] Expand corpus over time as dogfooding reveals gaps (currently 50 fixtures; target 50+ by end of Phase 2)

**Implementation note (2026-03-24):** The baseline corpus and proptest coverage now pass again in reduced builds after tightening the fallback detector path and the corpus harness. Because the default build intentionally lacks the extended JS/Python grammars, `tests/security_corpus.rs` now validates the string-based fallback for those fixtures instead of depending on AST parsing to be available. The fallback detector now catches Python `%`-formatted SQL construction, plain `exec(...)` command construction, and short quoted hardcoded API tokens, and the corpus harness now counts specialized `injection_vulnerabilities` results for CWE-backed XSS/command/sql cases instead of treating those findings as misses. Corpus expansion remains the only open Task 2.4 item.
**Implementation note (2026-03-24, latest):** The corpus has now reached 50 fixtures by adding JavaScript insert-concatenation and Python static-query SQL cases, a Python `subprocess.Popen(..., shell=True)` command case, Rust and JavaScript JWT secret coverage, and additional XSS fixtures around `document.write`, `insertAdjacentText`, and `append(...)`. The reduced-build corpus still passes end-to-end with the current precision/recall gate at this larger size.
**Implementation note (2026-03-24, later):** The corpus has now grown from 18 to 24 fixtures by adding Python f-string and parameterized SQL cases, Python `subprocess.run` command-injection positive/negative cases, and additional API key/env-token secret cases. The reduced-build corpus still passes end-to-end with the current precision/recall gate after these additions.
**Implementation note (2026-03-24, later):** The corpus has now grown again from 30 to 36 fixtures by adding Python `.format(...)` SQL construction, a static Rust SQL negative, Python `subprocess.check_output(...)` and safe `subprocess.Popen([...])` command cases, a hardcoded Python password secret case, and a safe JavaScript `createTextNode(...)` XSS negative. The current reduced-build corpus still passes with the same precision/recall gate.
**Implementation note (2026-03-24, latest):** The corpus has now grown from 36 to 42 fixtures by adding a safe `subprocess.check_output([...])` command case, a JavaScript hardcoded-password secret, and broader XSS coverage across `innerHTML`, `document.write`, `innerText`, and `createTextNode` patterns. The reduced-build corpus still passes end-to-end with the existing precision/recall threshold.

**Acceptance criteria:**
- >= 12 test fixtures across 4 vulnerability classes
- Integration tests assert detection and non-detection
- CI fails if precision or recall drops below threshold

##### Task 2.5: Complete SARIF Output

- [x] Audit `src/cli/sarif.rs` against SARIF 2.1.0 spec
- [x] Add missing required fields:
  - `$schema` field pointing to the SARIF 2.1.0 JSON schema
  - `tool.driver.rules[]` array with rule metadata (id, name, shortDescription, helpUri)
  - `partialFingerprints` on each result for deduplication across runs
  - `security-severity` in `properties` for GitHub Advanced Security severity mapping
- [x] Add `properties.confidence` to each result (from Task 2.2)
- [x] Add `suppressions` array support (from Task 2.3)
- [x] Add CodeClimate JSON output as alternative format (`--format codeclimate`)
- [x] Wire `.github/workflows/security_scan.yml` to `github/codeql-action/upload-sarif` for the default-scope SARIF on pushes and same-repo pull requests

### Research Insights: SARIF Compliance

**GitHub SARIF requirements:** GitHub Advanced Security does NOT honor the `suppressions` field natively. Suppressed findings will still appear in the Security tab unless filtered out before upload. Consider a `--exclude-suppressed` flag for CI integration.

**Required SARIF fields currently missing:**
1. `$schema`: Must be `"https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json"`
2. `tool.driver.rules[]`: Each rule referenced by results must have a corresponding entry
3. `partialFingerprints`: Required for GitHub to deduplicate results across commits
4. `security-severity`: Must be a string numeric value (e.g., `"8.5"`) in CVSS scale for GitHub to assign severity levels

**Acceptance criteria:**
- SARIF output validates against the official schema
- GitHub Advanced Security ingests the output without errors
- CodeClimate format accepted by GitLab CI

**Key files:**
- `src/cli/sarif.rs`

##### Task 2.6: Self-Analyzing Dogfood CI

- [x] Add CI step to `.github/workflows/ci.yml`:
  ```yaml
  dogfood:
    runs-on: ubuntu-latest
    needs: [build]
    steps:
      - uses: actions/checkout@v4
      - name: Run self-analysis
        run: cargo run --bin rts-cli --features cli -- analyze src/ --format json > self-analysis.json
      - name: Check analysis quality
        run: |
          # Parse JSON, check that:
          # - complexity hotspots identified > 0
          # - security findings have confidence scores
          # - no panic in output
  ```
- [x] Define initial quality thresholds (start permissive, tighten over time)
- [x] Upload self-analysis results as CI artifact for trend tracking

**Acceptance criteria:**
- CI runs self-analysis on every PR
- Self-analysis does not panic or return empty results
- Results uploaded as artifact

##### Task 2.7: Opportunistic Clone Reduction

**Not a dedicated sprint -- apply Clippy lint and fix opportunistically during Phase 2 work.**

- [x] Add to `clippy.toml` or CI: `cargo clippy -- -W clippy::redundant_clone`
- [x] Fix redundant clones in files touched during Phase 2 (security modules, performance_analysis.rs)
- [x] In `DependencyAnalyzer::clone()`, fix the provider field being dropped to `None`

### Research Insights: Performance Quick Wins

**`taint_analysis.rs` HashMap keys:** The HashMap keys in taint analysis are compile-time string literals. Change from `String` to `&'static str` to eliminate allocation overhead in the taint engine's hot path.

**`semantic_graph.rs` find_similar():** This function is O(N^2) -- it compares every node against every other node. Not urgent at current scale, but add a `// TODO: O(N^2) -- consider indexing if graph exceeds 10K nodes` comment to flag for future optimization.

**Benchmark measurement errors:**
- `benches/parser_bench.rs`: Creates a new `Parser` on every iteration, measuring construction + parsing instead of just parsing. Move parser creation to setup.
- `benches/security_bench.rs`: Creates a tempfile and writes to disk on every iteration, measuring filesystem I/O. Use an in-memory string instead.

Fix these benchmark errors during Phase 2 to get accurate baseline measurements before Phase 4's regression gate.

---

#### Phase 3: Strategic Pivot - MCP Tool Server

**Goal:** Delete AI consumer stubs, expose working analysis as MCP tools.

**Duration estimate:** 1-2 weeks

**Prerequisite:** Phase 2 complete (security pipeline credible, performance analysis uses AST)

##### Task 3.1: Delete Placeholder AI Code

- [x] Delete stub provider implementations:
  - `src/ai/providers/azure.rs`
  - `src/ai/providers/google.rs`
  - `src/ai/providers/local.rs`
  - `src/ai/providers/ollama.rs`
  - `src/ai/providers/anthropic.rs` (confirmed: "Placeholder implementation" at line 121)
- [x] Keep `src/ai/providers/openai.rs` and `src/ai/providers/groq.rs` (have substantive code)
- [x] Remove deleted variants from `AIProvider` enum
- [x] Delete `src/advanced_ai_analysis.rs` (~2,281 lines, self-documented as "MOSTLY PLACEHOLDER CODE")
- [x] Delete `src/ai_analysis.rs` (no real AI calls)
- [x] Delete `src/smart_refactoring.rs` (generic, not actionable suggestions)
- [x] Delete `src/reasoning_engine.rs` (aspirational, no real inference)
- [x] Gate `src/intent_mapping.rs` and `src/embeddings.rs` behind `ml` feature (already partially done)
- [x] Update `src/lib.rs` to remove deleted module declarations
- [x] Update any tests that reference deleted modules

### Research Insights: Stub Deletion

**Simplicity recommendation:** Consider moving stub deletion to Phase 0 or Phase 1 instead of Phase 3. The stubs add compilation time, confuse new contributors, and inflate the crate. Deleting early reduces noise for all subsequent phases. The only risk is if something in Phase 2 depends on an AI type -- grep for all deleted type names before removal.

**Acceptance criteria:**
- ~15K lines of stub code removed
- `AIProvider` enum has only `OpenAI` and `Groq` variants (behind `net` feature)
- `cargo build` (default features) does not compile any AI provider code
- All remaining tests pass

**Key files:**
- `src/ai/providers/mod.rs`
- `src/ai/mod.rs`
- `src/lib.rs`

##### Task 3.2: Define MCP Tool Interface

**Scope note (updated after audit on 2026-03-24):** The repository did not actually contain a checked-in MCP server with 9 tools. `integration/mcp/server/` only contained orphaned `node_modules/` and a `.package-lock.json` footprint. Start by recreating a small, honest adapter around CLI commands that already emit stable JSON, then expand once additional CLI contracts exist.

- [x] Audit existing MCP footprint in `integration/mcp/server/` -- result: no checked-in server source, only orphaned package artifacts
- [x] Design MCP tool definitions for the library's currently working JSON capabilities:
  - [x] `analyze_codebase` -- Wrap `tree-sitter-cli analyze --format json`
  - [x] `get_symbols` -- Wrap `tree-sitter-cli symbols --format json`
  - [x] `query_code` -- Wrap `tree-sitter-cli query --format json`
  - [x] `scan_security` -- Wrap `tree-sitter-cli security --format json`
  - [x] `analyze_dependencies` -- Wrap `tree-sitter-cli dependencies --format json`
  - [ ] `parse_file` -- blocked until a dedicated stable CLI JSON contract exists
  - [ ] `analyze_complexity` -- blocked until a dedicated stable CLI JSON contract exists
  - [x] `query_semantic_graph` -- Build semantic graph via `analyze --include-graph` and query it in the adapter
  - [ ] `analyze_taint` -- blocked until a dedicated stable CLI JSON contract exists
  - [ ] `analyze_performance` -- blocked until a dedicated stable CLI JSON contract exists
- [x] Define JSON schemas for each shipped tool's input/output, including `schema_version` field
- [x] Document tool capabilities and limitations honestly in `integration/mcp/README.md`

**Acceptance criteria:**
- Each shipped MCP tool has a defined JSON input/output schema
- Shipped schemas are documented in `integration/mcp/schemas/`
- All shipped tool outputs include `schema_version` field

##### Task 3.3: Upgrade MCP Adapter

**Approach:** Keep TypeScript MCP server. Replace ad-hoc shell-out with typed JSON contract. This is option (c) from SpecFlow Q4 -- lowest risk, fastest delivery.

- [x] Recreate the missing TypeScript MCP package in `integration/mcp/server/` with checked-in source, config, and tests
- [x] Upgrade the recovered `@modelcontextprotocol/sdk@1.18.0` footprint to a non-vulnerable release (`1.27.1`)
- [x] Define a stable CLI JSON output contract (`schema_version`, `tool`, `command`, `path`, `report`)
- [x] Update each shipped MCP tool handler to:
  - [x] Call `tree-sitter-cli` with a specific subcommand and `--format json`
  - [x] Parse typed JSON response
  - [x] Map to MCP tool result format
- [x] Add timeout handling (120s default) and `NO_COLOR=1`
- [x] Add Vitest tests covering each shipped tool handler
- [x] Add a client-facing `tools/list` smoke test for the MCP package
- [x] Wire the MCP package into CI

### Research Insights: MCP Implementation

**Native Rust option (future):** The `rmcp` crate on crates.io provides a native Rust MCP server. This would eliminate the TypeScript adapter, the shell-out latency, and the JSON serialization overhead. However, the TypeScript adapter works now and `rmcp` adds complexity. Flag this as a post-Phase 4 consideration.

**MCP best practices:**
- Include `$schema` in tool input/output definitions for client-side validation
- Return structured errors with error codes, not just strings
- Use streaming for large results (e.g., full AST dumps) if MCP SDK supports it
- Log invocations for debugging without exposing source code in logs

**Acceptance criteria:**
- All shipped MCP tools functional via TypeScript adapter
- Each shipped tool has a Vitest test
- Timeouts prevent hanging invocations
- MCP server starts and responds to `tools/list` correctly

**Key files:**
- `integration/mcp/server/`
- `integration/mcp/package.json`

##### Task 3.4: Wire Semantic Graph as Structured Context

- [x] Add `--format json --include-graph` flag to relevant CLI commands (`analyze` shipped first)
- [x] Serialize semantic graph nodes and edges as JSON (node types, relationships, weights)
- [x] MCP `query_semantic_graph` tool returns this structured data
- [x] AI consumers can now request structured graph context through `analyze_codebase { includeGraph: true }` instead of receiving only raw file analysis

**Note:** `GraphNode.file_path: PathBuf` already exists in `semantic_graph.rs` -- no need to add it. Focus on serialization and the CLI flag.

**Acceptance criteria:**
- `tree-sitter-cli analyze --format json --include-graph` includes semantic graph in output
- Graph serialization includes node types, edge types, and relationship metadata
- MCP tools now expose this data through both `analyze_codebase { includeGraph: true }` and the dedicated `query_semantic_graph` tool

---

#### Phase 4: Advanced Analysis (Stretch Goals)

**Goal:** Build genuinely differentiating capabilities. These are higher-risk, higher-reward items.

**Duration estimate:** 2-4 weeks

**Prerequisite:** Phase 3 complete (MCP tools working, stubs deleted)

### Research Insights: Phase 4 Scope

**Simplicity recommendation:** Phase 4 should be a separate plan document, not part of this one. Its scope is speculative and depends heavily on how Phases 0-3 play out. Keep the tasks here as a roadmap outline, but do NOT treat them as committed work. Create a new plan document after Phase 3 ships.

##### Task 4.1: Extend Semantic Graph to Cross-File Scope

**Note:** `GraphNode` already has `file_path: PathBuf`. This task focuses on cross-file edge creation, not adding the field.

- [x] Implement cross-file edge creation:
  - [x] Parse `use`/`import`/`require` statements to create `Imports` edges (Rust and JavaScript/TypeScript checkpoint landed on 2026-03-24)
  - [x] Match exported symbols across files to create `Calls` edges for simple Rust and JavaScript import patterns (checkpoint landed on 2026-03-24)
  - [x] Track re-exports for transitive resolution (checkpoint landed on 2026-03-24)
- [x] Build cross-file graph incrementally (parse each file, merge into unified graph; parallel analyzer checkpoint landed on 2026-03-24)
- [x] Add graph query functions:
  - [x] `find_callers(symbol)`
  - [x] `find_callees(symbol)`
  - [x] `trace_data_flow(source_file, sink_file)`

**Acceptance criteria:**
- Semantic graph connects symbols across files
- Query: "what calls function X in file A?" returns results from file B
- Works for at least Rust and JavaScript

**Key files:**
- `src/semantic_graph.rs`
- `src/symbol_table.rs`

##### Task 4.2: Cross-File Taint Analysis

- [x] Extend `TaintSource` and `TaintSink` with `file_path: PathBuf` field (checkpoint landed on 2026-03-24)
- [x] Connect taint analysis to cross-file semantic graph (Task 4.1) via `TaintAnalyzer::analyze_codebase_with_graph` and semantic-graph `Calls` edges (checkpoint landed on 2026-03-24)
- [x] Implement interprocedural taint propagation:
  - [x] When a tainted value is passed as argument to a function in another file, propagate taint to that function's parameter (Rust/JavaScript checkpoint landed on 2026-03-24)
  - [x] When a tainted return value crosses a file boundary, propagate taint to the caller (Rust/JavaScript checkpoint landed on 2026-03-24)
- [x] Start with Rust and JavaScript only
- [x] Add test fixtures: multi-file vulnerable patterns (request handler -> service -> query builder)

**Acceptance criteria:**
- Taint flows tracked across at least 2 file boundaries
- Test: Rust/JS request handler passing user input to a query function in another file is detected
- False positive rate on cross-file flows < 30%

**Key files:**
- `src/taint_analysis.rs`
- `src/semantic_graph.rs`

##### Task 4.3: Language-Agnostic Security Rule DSL

**Approach:** Use tree-sitter's existing `.scm` query language as the pattern language. Extend with YAML metadata for severity, confidence, and taint annotations. Do NOT design a new DSL from scratch.

- [x] Define rule file format (`*.yaml` metadata with either inline `pattern:` or external `pattern_file: *.scm`) (checkpoint landed on 2026-03-24)
  ```yaml
  id: sql-injection-concat
  severity: high
  confidence: 0.8
  languages: [javascript, python]
  description: "SQL query built via string concatenation"
  pattern: |
    (binary_expression
      left: (string) @sql_prefix
      operator: "+"
      right: (identifier) @user_input)
  taint_requirement: "@user_input is tainted from ExternalInput"
  ```
- [x] Implement rule loader that compiles `.scm` patterns to tree-sitter queries
- [x] Integrate rule evaluation into `SecurityPipeline` as a stage
- [x] Ship 10-20 built-in rules covering OWASP Top 5 for Rust, JS, Python (checkpoint landed on 2026-03-24)
- [x] Store rules in `rules/` directory at repo root

**Acceptance criteria:**
- Rules defined as YAML + `.scm` patterns, not Rust code
- Rule engine evaluates all loaded rules against parsed files
- Adding a new rule requires no Rust code changes
- Built-in rules cover SQL injection, command injection, XSS, secrets, path traversal

##### Task 4.4: Differential Benchmark Regression Gate

- [x] Fix existing benchmark measurement errors first (checkpoint landed on 2026-03-24):
  - `benches/parser_bench.rs`: Move `Parser::new()` to setup, not measured iteration
  - `benches/security_bench.rs`: Use in-memory string instead of tempfile I/O per iteration
- [x] Wire existing Criterion benchmarks into CI (checkpoint landed on 2026-03-24)
- [x] Use `critcmp` or `bencher` to compare PR benchmarks against base branch
- [x] Fail CI if parsing performance regresses by > 10% (start permissive)
- [x] Store benchmark results as CI artifacts for historical tracking

### Research Insights: Benchmarking

**Criterion 0.5 changes:** Criterion 0.5 changed the default statistics backend. Verify the project is using a compatible version. `critcmp` works with Criterion's JSON output (enable with `--save-baseline`).

**CI benchmark stability:** GitHub Actions runners have variable performance. Use `criterion::measurement::WallTime` and set `--warm-up-time 3` to reduce noise. Consider requiring 2 consecutive regressions before failing CI to avoid flaky failures.

**Acceptance criteria:**
- CI runs benchmarks on every PR
- PR blocked if parser bench regresses > 10%
- Benchmark history visible in CI artifacts

---

## Alternative Approaches Considered

| Approach | Why Rejected |
|----------|-------------|
| Workspace split (multi-crate) | Multi-week refactor with no user-visible value; feature flags achieve same dependency isolation |
| LSP server mode | Enormous implementation burden; fix analysis accuracy first, then revisit |
| WASM build | Half the deps are WASM-incompatible today; requires Phase 1 dep diet first, revisit after Phase 1 |
| Arena-allocated AST metadata | Premature optimization; the current 2ms/1K LOC parsing speed is adequate |
| Flip architecture (tree-sitter as plugin) | YAGNI; tree-sitter is the entire value proposition |
| Streaming/event-driven API | Same burden as LSP; no demonstrated need |
| tree-sitter 0.24+ upgrade | Mechanical maintenance; defer until grammar incompatibility forces the issue |
| Native Rust MCP server (rmcp) | Lower risk to keep TS adapter now; revisit after Phase 3 proves the tool interface |

---

## System-Wide Impact

### Interaction Graph

```
Phase 0 (CI/deps)
  ├── Task 0.5 (tokio import guards) -- CRITICAL prerequisite for Phase 1
  └── Phase 1 (feature flags)
        ├── Phase 2 (analysis credibility)
        │     ├── Task 2.2 (security pipeline) triggers taint_analysis.rs changes
        │     ├── Task 2.5 (SARIF) depends on Task 2.2 confidence scores
        │     └── Task 2.6 (dogfood) depends on all other Phase 2 tasks
        └── Phase 3 (MCP pivot)
              ├── Task 3.1 (delete stubs) changes lib.rs public API
              ├── Task 3.3 (MCP adapter) depends on Task 3.2 (tool schemas)
              └── Phase 4 (advanced)
                    ├── Task 4.1 (cross-file graph) prerequisite for Task 4.2
                    └── Task 4.3 (rule DSL) integrates with Task 2.2 pipeline
```

### Error Propagation

- Phase 0 Task 0.5: if tokio imports are not guarded, Phase 1 feature removal WILL break compilation. This is the highest-risk dependency in the plan.
- Phase 1 feature-gating: if a module uses an ungated dep, compilation fails immediately with clear error. Low risk -- compiler catches all issues.
- Phase 2 security pipeline: new `SecurityPipeline` facade must propagate errors from each stage. If taint analysis fails, detection should still run (degraded mode, lower confidence).
- Phase 3 MCP adapter: shell-out failures must be caught with timeouts and returned as MCP error responses, not crashes.

### State Lifecycle Risks

- Phase 0 dep upgrades: `sqlx 0.8` migration may change query macro behavior. Test all database paths.
- Phase 1 feature removal: no persistent state affected. Feature flags are compile-time only.
- Phase 3 AI code deletion: verify no database tables or config files reference deleted providers.

### API Surface Parity

- After Phase 3, the public Rust API loses: `AIAnalyzer`, `AdvancedAIAnalyzer`, `SmartRefactoring`, `ReasoningEngine`, and 5 AI provider types
- The MCP tool API gains: 8 new tool endpoints (or 3 initially per simplicity recommendation)
- CLI API is additive only (new flags like `--min-confidence`, `--include-graph`)

### Integration Test Scenarios

1. **Feature-gated build matrix:** `--no-default-features`, default, `--all-features` all compile and pass tests
2. **Security pipeline end-to-end:** Parse a vulnerable file -> taint analysis -> detection -> filtering -> SARIF output with confidence scores
3. **MCP tool round-trip:** MCP client calls `scan_security` -> adapter shells out to CLI -> JSON parsed -> MCP response returned
4. **Self-analysis CI:** `rts-cli analyze src/` completes without panic, returns non-empty results
5. **Cross-file taint (Phase 4):** Multi-file test project with known taint flow detected across 2+ files

---

## Acceptance Criteria

### Functional Requirements

- [ ] Default `cargo add rust_tree_sitter` pulls < 120 crates (down from 506; tighten threshold as measured)
- [ ] Security scanner produces confidence-scored findings with < 30% false positive rate on test corpus
- [ ] `// rts-ignore[rule-id]` suppresses findings per spec
- [ ] Performance analysis uses AST traversal, not string matching
- [ ] Dependency analyzer returns correct results for Cargo.toml
- [ ] 3-8 MCP tools functional and tested (start with 3, expand to 8)
- [ ] ~15K lines of stub AI code removed
- [ ] CI green with parallel jobs, dogfood analysis, and benchmark gate

### Non-Functional Requirements

- [ ] Parse speed remains < 3ms/1K LOC (no regression from Phase 2 changes)
- [ ] `cargo build` (default features) completes in < 30 seconds on CI
- [ ] Zero known CVEs in dependency tree
- [ ] Zero panics in library code paths (non-test)

### Quality Gates

- [ ] All phases pass `cargo clippy --all-targets --all-features -- -D warnings`
- [ ] All phases pass `cargo fmt --all -- --check`
- [ ] Test coverage does not decrease (currently 667 test functions)
- [ ] Each phase is a separate PR, reviewed before merge

---

## Success Metrics

| Metric | Current | Phase 0 | Phase 1 | Phase 2 | Phase 3 | Phase 4 |
|--------|---------|---------|---------|---------|---------|---------|
| Dependency crate count (default) | 506 | 506 | 80-120 | 80-120 | ~75-115 | ~75-115 |
| Known CVEs | 3 | 0 | 0 | 0 | 0 | 0 |
| Stub/placeholder lines | ~15K | ~15K | ~15K | ~15K | ~0 | ~0 |
| Security false positive rate | High | High | High | < 30% | < 30% | < 20% |
| Security test corpus size | 0 | 0 | 0 | 12-50+ | 50+ | 80+ |
| MCP tools available | 9 (mostly stubs) | 9 | 9 | 9 | 3-8 (working) | 8 (working) |
| CI dogfood analysis | No | No | No | Yes | Yes | Yes |
| String heuristics in perf analysis | Yes | Yes | Yes | No | No | No |
| Stale planning docs at root | ~22 | 0 | 0 | 0 | 0 | 0 |

---

## Dependencies & Prerequisites

| Phase | Depends On | Blocks |
|-------|-----------|--------|
| Phase 0 | Nothing | Phase 1, 2, 3, 4 |
| Phase 0 Task 0.5 | Nothing | Phase 1 (CRITICAL -- tokio import guards) |
| Phase 1 | Phase 0 | Phase 2 (feature-gated test matrix), Phase 3 (lean API surface) |
| Phase 2 | Phase 1 | Phase 3 (credible analysis for MCP tools), Phase 4 (pipeline for rule DSL) |
| Phase 3 | Phase 2 | Phase 4 (MCP tools for cross-file analysis) |
| Phase 4 | Phase 3 + Task 4.1 | Nothing (stretch goals -- create separate plan) |

---

## Risk Analysis & Mitigation

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| **Tokio import guards missed** | **High** | **High** | **Task 0.5 added explicitly; grep-audit all feature-gated imports** |
| sqlx 0.8 migration breaks database code | Medium | Medium | Gate behind `db` feature; most users won't need it |
| Feature-gating misses a dep, breaking --no-default-features | Medium | Low | CI matrix catches immediately |
| Security pipeline consolidation breaks existing tests | High | Medium | Facade pattern preserves existing modules; add, don't merge |
| AI code deletion removes something actually used | Low | High | Grep for all deleted types before removal; check test references |
| MCP SDK breaking changes | Medium | Low | Pin to specific version, upgrade later |
| Cross-file taint analysis too complex | High | Medium | Phase 4 is stretch; project delivers value through Phase 3 |
| User backlash on default feature change | Low | Medium | Document migration clearly; provide `full` feature alias |
| Default crate count higher than ~50 target | High | Low | Revised target to 80-120; measure and improve iteratively |

---

## Documentation Plan

- [x] Update `README.md` with new feature flag documentation (checkpoint landed on 2026-03-24)
- [x] Update `AGENTS.md` to reflect deleted AI modules
- [x] Create `ARCHITECTURE.md` (replaces deleted planning docs) documenting:
  - Module organization
  - Security pipeline stages
  - Feature flag hierarchy
  - MCP tool interface
- [x] Update `CHANGELOG.md` for 0.2.0 release
- [x] Update `integration/mcp/README.md` with new tool definitions
- [x] Create `docs/FEATURE_FLAGS.md` with dependency-to-feature mapping table

---

## Sources & References

### Origin

- **Origin document:** [docs/ideation/2026-03-23-full-codebase-ideation.md](docs/ideation/2026-03-23-full-codebase-ideation.md) -- 7 strategic survivors + 18 tactical items from adversarial-filtered ideation. Key decisions: MCP pivot over AI client, facade pattern over file merge for security, AST traversal over string heuristics.

### Internal References

- Security pipeline: `src/security/mod.rs`, `src/security/ast_analyzer.rs`
- Performance heuristics: `src/performance_analysis.rs:924-1535`
- AI stubs: `src/advanced_ai_analysis.rs:1-23` ("MOSTLY PLACEHOLDER CODE")
- Dependency analyzer: `src/dependency_analysis.rs`
- Taint analysis: `src/taint_analysis.rs`
- Semantic graph: `src/semantic_graph.rs`
- MCP adapter: `integration/mcp/server/`
- CI workflows: `.github/workflows/ci.yml`, `.github/workflows/security_scan.yml`
- Feature flags: `Cargo.toml:88-100`
- **Critical imports:** `src/security/ai_false_positive_filter.rs` (unguarded tokio), `src/security/ml_filter.rs` (unguarded tokio)

### External References

- SARIF 2.1.0 spec: OASIS standard
- SARIF JSON schema: `https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json`
- MCP specification: Model Context Protocol
- tree-sitter query syntax: tree-sitter documentation
- `rmcp` crate: Native Rust MCP server (future consideration)
- sqlx 0.8 migration guide: breaking changes include SqlSafeStr, feature flag restructuring

### Related Work

- Grok audit: `docs/grok_audit.md` (B- rating)
- Dependency audit: `docs/DEPENDENCY_AUDIT_REPORT.md` (3 CVEs)
- Memory safety audit: `docs/MEMORY_SAFETY_AUDIT.md` (200+ clones)
- Security roadmap: `SECURITY_ANALYSIS_IMPROVEMENT_ROADMAP.md` (to be deleted, superseded by this plan)
