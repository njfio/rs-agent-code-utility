---
title: Pre-Pivot Cleanup and Public-Surface Tightening (3-PR Arc)
type: refactor
status: active
date: 2026-05-22
origin: docs/brainstorms/2026-05-22-pre-pivot-cleanup-and-public-surface-tightening-requirements.md
---

# Pre-Pivot Cleanup and Public-Surface Tightening (3-PR Arc)

## Revision History

This plan was first drafted 2026-05-22 and then deepened with 4 reviewer/researcher agents (code-simplicity, architecture-strategist, best-practices, framework-docs). The current version integrates the required + strong revisions; the audit trail of decisions is preserved in the **Decisions Applied** section at the end.

### Key changes from the initial draft

- **DELETED `CodebaseAnalyzer` entirely** (was: demote to `pub(crate)`). After PR-A's surgery, the type is just an unamortized parser cache — the daemon's only call site constructs a fresh instance per invocation. The cleaner architectural cut is delete + hoist, not demote.
- **DROPPED the `pub struct ParseError` wrapper.** `error::Error` is already public at `rts-core/src/lib.rs:90` and the daemon already uses it via `query_cache.rs:93`. Wrapping it would hide the rich `ParseErrorDetails` context (file_path, line, column, source_snippet) at `error.rs:74-78`.
- **CORRECTED the `cargo public-api` mechanism.** The `--deny=all` flag is invalid on the bare command. Replaced the CLI-workflow approach with a Rust test using `public_api::assert_eq_or_update` (the cargo-public-api library's canonical CI pattern). Folds into existing `cargo test --workspace` — no new workflow file.
- **EXPANDED the kept-public surface enumeration by 3 items.** Added `pagerank::*` (used by `outline.rs:33`, `symbol_pagerank.rs:62`), `signature::render_*` (13 entry points called from `language.rs:333-388`), and `error::Error` + `error::Result` (used by `query_cache.rs:93`). Original draft undercounted.
- **REPLACED B4 blanket-relocate with per-test disposition.** Each of the 4 affected integration tests gets its own fate — delete-with-A2, delete-as-dead, rewrite-against-parse_content, or read-before-deciding — rather than a single "relocate as unit tests" recipe.
- **ADDED `cargo-shear` pre-flight verification** at A1 start + A3 end to confirm the deletion inventory is complete and no orphan `.rs` files remain.
- **ADDED `ParseOutcome` struct as the recommended return shape** (`{ symbols: Vec<Symbol>, partial_errors: Vec<String> }`) — addresses the known partial-parse gap documented at `writer.rs:807-815` (Java/C/C++ extraction silently returns empty `Vec<Symbol>` on successful parse). Decision deferred to planning if the maintainer prefers the simpler `Result<Vec<Symbol>, Error>` shape.
- **FOLDED A7, B5, C4** (standalone "PR description + changelog fragment" units) into each PR's Definition of Done. Changelog fragments are project convention, not implementation units.
- **EXTENDED A6** to update `analyzer.rs:25, :47, :66` rustdoc examples (original draft only covered `lib.rs` preamble).
- **C2 metadata test** uses `toml = "0.8"` parsing instead of regex (workspace-inheritance fragility — `version.workspace = true` would silently false-pass under regex). Dropped the version-consistency assertion entirely since A6 strips version strings from preambles.

## Overview

Three coordinated PRs that close the drift between what rts is and what its code claims to be, surfaced after the 24-PR v0.6 arc:

- **PR-A** (deletion + rts-core surgery + preamble cleanup + cargo-shear verification) — deletes ~12.2 MB / ~552 files / ~34k LoC of pre-pivot weight: 13 dead rts-core modules, the entire `archive/` tree, the entire `wiki_site_test/` tree. Includes non-trivial surgery in `analyzer.rs` (strip `FileCache` + `SemanticGraphQuery` field/methods), edits to CI semantic-eval corpora that hardcode now-deleted symbols, and updates to `analyzer.rs` rustdoc examples + `lib.rs` preamble.

- **PR-B** (extraction hoist + facade + daemon migration + CodebaseAnalyzer delete + per-test cleanup) — hoists `extract_symbols` to a `pub(crate) fn`; adds `pub fn parse_content(content: &str, language: Language) -> Result<ParseOutcome, Error>` built from primitives; migrates the daemon's sole callsite at `writer.rs:763` to use it; **deletes `CodebaseAnalyzer` and `AnalysisConfig` / `AnalysisResult` / `FileInfo` / `AnalysisDepth` entirely**; per-test disposition for 4 affected integration tests (delete some, rewrite some, audit residual).

- **PR-C** (metadata + tests + public-api test-snapshot gate) — fixes root Cargo.toml placeholders; adds an integration test using `toml = "0.8"` that asserts no placeholder strings; adds a test-based `public_api::assert_eq_or_update` gate for rts-core + rts-mcp via `tests/snapshots/public-api.txt` files. No new CI workflow — the gate runs as part of `cargo test --workspace`.

PR-A → PR-B sequential (B depends on A's analyzer.rs surgery). PR-C runs in parallel with either.

### After: rts-core's kept-public surface

Verified against the daemon's import graph (`crates/rts-daemon/src/` + `crates/rts-mcp/src/` + `crates/rts-bench/src/`):

- **Tree-sitter primitives:** `Parser`, `SyntaxTree`, `Node`, `TreeCursor`, `Language`
- **Query primitives:** `Query`, `QueryBuilder`, `QueryMatch`, `QueryCapture`
- **Symbol type:** `Symbol` (daemon's serialization payload)
- **Facade (new):** `parse_content`, `ParseOutcome` (or `Vec<Symbol>` if the simpler shape is preferred)
- **`pagerank::*`** — `pagerank::Edge`, `pagerank::compute`, `pagerank::edge_weight` (consumed by `outline.rs:33`, `symbol_pagerank.rs:62`)
- **`signature::render_*`** — 13 per-language entry points (consumed by `language.rs:333-388`)
- **`error::Error`, `error::Result`** — already public at `lib.rs:90` (consumed by `query_cache.rs:93`)
- **`supported_languages`, `detect_language_from_extension`** — language registry helpers (note: ideation survivor #6 collapses these to one source of truth in separate work; out of scope here)

**Deleted publicly:** `CodebaseAnalyzer`, `AnalysisConfig`, `AnalysisResult`, `FileInfo`, `AnalysisDepth`, `SymbolTable`, `SymbolDefinition`, `SymbolReference`, `SemanticGraphQuery`, `code_map::build_call_graph`, plus the 13 dead modules.

## Problem Statement / Motivation

(See origin: `docs/brainstorms/2026-05-22-pre-pivot-cleanup-and-public-surface-tightening-requirements.md` § Problem Frame.)

Verified drift on 2026-05-22:
- 7+ rts-core modules publicly exported but consumed by **zero** code in rts-daemon, rts-mcp, or rts-bench
- `archive/` (190 files, 34,587 LoC) + `wiki_site_test/` (362 files, 9.0 MB) carry pre-pivot weight that pays no rent
- Root `Cargo.toml` ships `authors = ["Your Name <your.email@example.com>"]` and `repository = "https://github.com/yourusername/rust_tree_sitter"`
- `crates/rts-core/src/lib.rs:1` says `(0.2.0-alpha: in-progress retrieval pivot)` while the workspace version is `0.5.5`

Without cleanup: `cargo publish` ships placeholder identity to crates.io; future agents (and humans) waste cycles on phantom modules; rts-core's public API advertises an analyzer surface no consumer uses.

## Technical Considerations

### Five blockers (research-confirmed pre-flight)

| # | Blocker | Where | Resolution |
|---|---------|-------|-----------|
| 1 | `analyzer.rs` uses `FileCache` + `CacheStats` from `file_cache` | `crates/rts-core/src/analyzer.rs:86, :285, :300, :835, :2437-2453` | PR-A unit A2: strip `FileCache` field + caching methods; use plain `std::fs::read_to_string`. |
| 2 | `analyzer.rs` uses `SemanticGraphQuery` from `semantic_graph` | `analyzer.rs:89, :284, :299, :416-417, :548, :2412-2433` | PR-A unit A2: delete `semantic_graph: Option<SemanticGraphQuery>` field + `enable_semantic_graph` / `disable_semantic_graph` / `semantic_graph` / `semantic_graph_mut` / `is_semantic_graph_enabled` methods. |
| 3 | CI semantic-eval corpora hardcode `FileCache`, `SymbolTable`, `CacheStats` in `expected_top_k` | `corpus/semantic-eval-rts-core.toml:53-57, :88-93` + `corpus/semantic-eval-rts-core-blind-v2.toml:61-69` | PR-A unit A6: delete the cache-and-symbol-table query blocks. |
| 4 | 4 integration tests use `CodebaseAnalyzer`/`AnalysisConfig` from outside the crate | `crates/rts-core/tests/analyzer_cache_tests.rs:1`, `analyzer_depth.rs:1`, `symbol_listing.rs:1`, `basic_integration_tests.rs:167` | PR-B unit B4: per-test disposition (delete some, rewrite against `parse_content`, audit residual). |
| 5 | Daemon's actual usage is content-based, NOT path-based | `crates/rts-daemon/src/writer.rs:763` calls `analyzer.analyze_content(content, language)` | PR-B unit B1: facade is `parse_content(content: &str, language: Language) -> Result<ParseOutcome, Error>` — built from `Parser::new + extract_symbols`, NOT wrapping `CodebaseAnalyzer`. |

### Daemon callsite verification (research-confirmed)

- `crates/rts-daemon/src/writer.rs:22` is `use rust_tree_sitter::{Language, Symbol};` — `Symbol` stays public, so this line needs no change.
- `crates/rts-daemon/src/writer.rs:763` is the only `CodebaseAnalyzer` usage in the entire workspace outside rts-core itself.
- `crates/rts-mcp`, `crates/rts-bench`, `agent-bench/` — verified zero usage of `CodebaseAnalyzer`, `AnalysisConfig`, `AnalysisResult`, `FileInfo`, `AnalysisDepth`.

### Architecture impact

- `rts-core` public surface shrinks but retains the 4 surfaces the daemon actually depends on (tree-sitter primitives, Symbol, pagerank, signature, error::Error) plus the new `parse_content` facade.
- After B1 + B3, `CodebaseAnalyzer` is gone — `parse_content` is a 3-line free function over `Parser::new + extract_symbols`. No struct, no caching, no construction ceremony.
- No protocol-v0 surface changes. No on-disk schema changes. No daemon behavior changes beyond the facade migration.

### Performance / size

- Working tree drops by ~12.2 MB (≈ 552 files).
- rts-core compile-time benefit: removing 7+ unused modules cuts the per-build work proportionally. Estimated 20-30% faster `cargo check -p rts-core` after PR-A.
- After PR-B's `CodebaseAnalyzer` deletion, the daemon's per-call path drops from `let mut a = CodebaseAnalyzer::new()?; a.analyze_content(...)?` (constructs + hashmap allocation + caching scaffold) to `parse_content(content, language)?` (single function call, no allocation beyond the parser). Marginal — daemon was constructing fresh per call anyway, so the cache provided no amortization.
- No runtime performance change for the daemon's net behavior.

## System-Wide Impact

### Interaction graph
- PR-A deletion → `cargo build --workspace` recompiles rts-core without dead modules. The daemon's `writer.rs:763` continues to work because PR-A keeps `CodebaseAnalyzer` accessible until PR-B.
- PR-A corpus edits → CI's semantic-eval baseline (ci.yml:65-85) runs against the trimmed corpora; `answerable_coverage` thresholds (0.95 / 0.75) stay intact.
- PR-B `CodebaseAnalyzer` deletion → only consumer outside rts-core is `writer.rs:763`, which the same PR migrates to `parse_content`. After the migration + per-test disposition (B4), nothing references `CodebaseAnalyzer`.
- PR-C metadata test → reads root `Cargo.toml` via `toml = "0.8"` (already a workspace dep). No new deps beyond what's already present.
- PR-C public-api tests → run as part of `cargo test --workspace`. No new CI workflow.

### Error propagation
- PR-A: any active reference to a deleted symbol surfaces as a compile error. `cargo check` after each module-deletion commit catches it.
- PR-B: `parse_content` returns `Result<ParseOutcome, Error>` using the already-public `error::Error`. Daemon's existing `?` propagation in `writer.rs:763` works unchanged. `Error::ParseError { details: ParseErrorDetails }` rich context preserved for diagnostics.
- PR-C: metadata test failures point to the specific Cargo.toml line + violating string. public-api test failures show a unified diff against the snapshot.

### State lifecycle risks
- PR-A: nothing persists state during deletion. Workspace rebuilds from scratch.
- PR-B: facade migration is a single-commit replacement at one callsite. No partial state possible.
- PR-C: public-api snapshot files are committed alongside the tests; missing snapshot causes the test to fail with a clear `UPDATE_SNAPSHOTS=yes cargo test` regen hint.

### API surface parity
- Only rts-core has a `pub` surface that matters. After PR-B's `CodebaseAnalyzer` deletion, no out-of-crate references to deleted types remain (verified via cargo-shear post-flight in A3).
- No MCP-side or CLI-side parity work — PR #121's tool-description audit already covered those surfaces.

### Integration test scenarios

1. **Stale module references break compile** — delete `crates/rts-core/src/code_map.rs` standalone; `cargo check -p rts-core` should fail with a clear error pointing at every `use rust_tree_sitter::code_map::*;` site. Verifies the deletion isn't silently swallowed.
2. **Public-API drift detection** — add `pub fn experimental_foo() {}` to `rts-core/src/lib.rs`; the `public_api` test in `crates/rts-core/tests/public_api.rs` should fail with a unified diff against `tests/snapshots/public-api.txt` + a `UPDATE_SNAPSHOTS=yes` regen hint.
3. **Metadata regression** — reintroduce `authors = ["Your Name"]` in root Cargo.toml; `cargo test --workspace` should fail at the metadata test with a clear message naming the offending value.
4. **Daemon round-trip after facade migration** — `cargo test -p rts-daemon` (the full reconciliation + cancel + grep integration tests) should pass unchanged — proves `parse_content` is behaviorally equivalent to the inlined `CodebaseAnalyzer::analyze_content` calls.
5. **CI semantic-eval coverage** — after PR-A's corpus edits, `cargo run -p rts-bench --release -- semantic --corpus corpus/semantic-eval-rts-core.toml --check-coverage 0.95` should still exit 0 with the trimmed query set.

## Implementation Units

Each unit carries: Goal, Files, Patterns to follow, Test scenarios, Verification.

### PR-A: Stale tree deletion + rts-core surgery + preamble cleanup + verification

#### A1. Delete leaf-dead rts-core modules (11 files) — with cargo-shear pre-flight

- **Goal:** Remove the 11 rts-core modules with zero internal AND zero external consumers.
- **Pre-flight:** `cargo install --locked cargo-shear && cargo shear` to confirm the deletion inventory is complete (one-time, ~3 min).
- **Files:**
  - DELETE: `crates/rts-core/src/{complexity_analysis,control_flow,dependency_analysis,memory_tracker,performance_analysis,semantic_context,symbol_table,advanced_parallel,code_map,analysis_common,analysis_utils}.rs`
  - EDIT: `crates/rts-core/src/lib.rs` — remove the corresponding `pub mod` + `pub use` lines
- **Approach:** One module per commit; run `cargo check -p rts-core` between each. Verifies no transitive consumer breaks.
- **Patterns to follow:** None — pure deletion. Use `git rm` for clean blame.
- **Test scenarios:** `cargo check -p rts-core` after each commit; `cargo test -p rts-core --tests` at the end.
- **Verification:** All 11 files removed; lib.rs no longer references them; workspace `cargo check` passes.

#### A2. Strip FileCache + SemanticGraphQuery from analyzer.rs

- **Goal:** Remove the two "dead" modules' surfaces from the surviving `analyzer.rs` so units A3 + A1 leave a green workspace.
- **Files:**
  - EDIT: `crates/rts-core/src/analyzer.rs` — remove:
    - `use crate::file_cache::{FileCache, CacheStats};` at `:86`
    - `use crate::semantic_graph::SemanticGraphQuery;` at `:89`
    - `file_cache: FileCache` field (around `:285`); inline `std::fs::read_to_string` at the cache lookup sites (`:300, :835`)
    - `cache_stats(&self) -> CacheStats` method (`:2437-2453`)
    - `semantic_graph: Option<SemanticGraphQuery>` field (around `:284`); delete every reference including constructor wiring (`:299, :416-417, :548`)
    - `enable_semantic_graph` / `disable_semantic_graph` / `semantic_graph` / `semantic_graph_mut` / `is_semantic_graph_enabled` methods (`:2412-2433`)
- **Approach:** Two commits — one for FileCache strip, one for SemanticGraphQuery strip. Each followed by `cargo check -p rts-core` + `cargo test -p rts-core --lib`. The FileCache strip touches read paths; replace with `fs::read_to_string` + a comment noting the cache was removed.
- **Patterns to follow:** Existing `std::fs` calls elsewhere in `analyzer.rs`.
- **Test scenarios:** existing `analyzer_*` integration tests still pass (they test the public surface).
- **Verification:** Both fields + their dependent methods removed; `analyzer.rs` compiles with no `file_cache` / `semantic_graph` references; same-crate tests green.

#### A3. Delete file_cache.rs + semantic_graph.rs (with cargo-shear post-flight)

- **Goal:** Remove the 2 modules made leaf-dead by A2.
- **Files:**
  - DELETE: `crates/rts-core/src/file_cache.rs`
  - DELETE: `crates/rts-core/src/semantic_graph.rs`
  - EDIT: `crates/rts-core/src/lib.rs` — remove `pub mod file_cache;` + `pub mod semantic_graph;` + their `pub use` lines
- **Post-flight:** `cargo shear` again to confirm no orphan `.rs` files remain in `crates/rts-core/src/`.
- **Approach:** One commit per file deletion; `cargo check -p rts-core` between.
- **Verification:** Workspace `cargo check` passes; no module references remain; `cargo shear` exits 0.

#### A4. Delete archive/ + wiki_site_test/ trees + Cargo.toml workspace `exclude` cleanup

- **Goal:** Remove the two stale subtrees from the repo root.
- **Files:**
  - DELETE: `archive/` (190 files, 34,587 LoC, 3.2 MB)
  - DELETE: `wiki_site_test/` (362 files, 9.0 MB)
  - EDIT: `Cargo.toml:16` — remove the `exclude = ["archive"]` line
  - EDIT: `Cargo.toml:9` — remove the comment explaining the exclude
  - EDIT: `AGENTS.md:308` — strip the "Excluded from the workspace; preserved for git history" mention of `archive/`
- **Approach:** Two commits — `git rm -r archive/` first, then `git rm -r wiki_site_test/`. Edit Cargo.toml + AGENTS.md in a third commit.
- **Verification:** `git status` shows 552 file deletions; workspace `cargo check` passes.

#### A5. Delete dead integration test files

- **Goal:** Remove integration tests that reference the deleted modules.
- **Files:**
  - DELETE: `crates/rts-core/tests/{dependency_analysis,simple_memory_test,complexity_analysis_unit_tests,file_cache_tests}.rs`
  - EDIT: `crates/rts-core/tests/basic_integration_tests.rs` — delete the `test_basic_complexity_analysis` fn (lines `:161-189`)
  - EDIT: `crates/rts-core/tests/performance_optimization_tests.rs` — delete the `test_complexity_analysis_performance` fn
  - EDIT: `crates/rts-core/tests/performance_optimizations_tests.rs` — delete the `test_performance_analysis_optimizations` fn
- **Approach:** One commit. `cargo test -p rts-core --tests` after.
- **Verification:** `cargo test -p rts-core` passes; no test references a deleted module.

#### A6. Edit semantic-eval corpora + rewrite lib.rs + analyzer.rs preambles

- **Goal:** Keep CI's semantic-eval gate green, and rewrite preambles to match post-cleanup reality.
- **Files:**
  - EDIT: `corpus/semantic-eval-rts-core.toml` — delete the `[[query]]` blocks at `:53-57` (FileCache/CacheStats) and `:88-93` (SymbolTable/SymbolStatistics)
  - EDIT: `corpus/semantic-eval-rts-core-blind-v2.toml` — delete the `[[query]]` block at `:61-69`
  - EDIT: `crates/rts-core/src/lib.rs:1-35` — rewrite the preamble doc-comment:
    - Remove `(0.2.0-alpha: in-progress retrieval pivot)` framing
    - Remove the "Removed in 0.2.0" archaeology block
    - Remove the reference to `archive/README.md`
    - Replace with a 5-10 line doc-comment accurately describing what rts-core IS now (tree-sitter wrapper providing `Parser`, `SyntaxTree`, `Language`, `Query`, the `Symbol` type, `pagerank::*`, `signature::render_*`, the `Error` type, and the `parse_content` facade)
  - EDIT: `crates/rts-core/src/analyzer.rs:25, :47, :66` — update rustdoc examples to use `parse_content` (which will land in PR-B); for PR-A, temporarily mark these examples as `ignore` or update to a non-CodebaseAnalyzer code path
  - EDIT: `crates/rts-core/Cargo.toml:67` — strip the comment "Dependency-manifest parsing (for the `dependency_analysis` module)" since dependency_analysis is gone
- **Approach:** One commit.
- **Test scenarios:** `cargo run -p rts-bench --release -- semantic --corpus corpus/semantic-eval-rts-core.toml --check-coverage 0.95` exits 0; `cargo doc --no-deps -p rts-core` produces clean docs.
- **Verification:** CI's semantic-eval workflow stays green; preambles match post-cleanup reality.

#### A-DoD. Definition of Done for PR-A

(Folded in from the original A7 unit. Changelog fragments are project convention, not an implementation unit.)
- `changelog.d/A-feat-pre-pivot-cleanup.md` fragment added (renamed to PR number at merge time)
- PR description includes the drift inventory + before/after file counts
- `cargo-shear` exit 0 both pre-flight (before A1) and post-flight (after A3)
- All 5 acceptance criteria for PR-A pass (see Acceptance Criteria below)

### PR-B: Extraction hoist + facade + daemon migration + CodebaseAnalyzer delete + per-test cleanup

#### B0. Hoist `extract_symbols` to `pub(crate) fn`

- **Goal:** Make symbol extraction usable as a free function so `parse_content` (B1) doesn't need to construct a `CodebaseAnalyzer`.
- **Files:**
  - EDIT: `crates/rts-core/src/analyzer.rs` (or a new `crates/rts-core/src/extraction.rs`) — extract the body of `CodebaseAnalyzer::extract_symbols(&self, tree, content, language)` into a `pub(crate) fn extract_symbols(tree: &Tree, content: &str, language: Language) -> Result<Vec<Symbol>, Error>` free function (or `Result<ParseOutcome, Error>` if O1 from Decisions Applied is adopted)
  - The original method becomes a thin wrapper that delegates to the free function (it's deleted in B3 entirely; B0 just makes the function callable without `self`)
- **Approach:** Single commit. Mechanical extraction; the method body doesn't actually depend on `self.config` for the extraction logic — it dispatches on `language` and walks the tree.
- **Patterns to follow:** Free functions elsewhere in rts-core that take primitive arguments (e.g., language-detection helpers).
- **Test scenarios:** `cargo test -p rts-core` passes; the extracted function is callable via `crate::analyzer::extract_symbols(...)` (or `crate::extraction::extract_symbols(...)`).
- **Verification:** `extract_symbols` is a `pub(crate) fn`; the method-form delegates to it.

#### B1. Add `parse_content` facade (built from primitives)

- **Goal:** Introduce the daemon-facing entry point that builds on `Parser` + `extract_symbols` directly — NOT a wrapper over `CodebaseAnalyzer`.
- **Files:**
  - ADD to `crates/rts-core/src/lib.rs` (no dedicated `facade.rs` — 5-line function doesn't need its own module):

    ```rust
    pub fn parse_content(content: &str, language: Language) -> Result<ParseOutcome, Error> {
        let mut parser = Parser::new(language)?;
        let tree = parser.parse(content, None)?;
        let symbols = extraction::extract_symbols(&tree, content, language)?;
        Ok(ParseOutcome { symbols, partial_errors: Vec::new() })
    }

    pub struct ParseOutcome {
        pub symbols: Vec<Symbol>,
        pub partial_errors: Vec<String>, // For Java/C/C++ silent-empty case at writer.rs:807-815
    }
    ```

  - Uses the already-public `error::Error`. No new `ParseError` type.
  - If maintainer prefers the simpler shape `Result<Vec<Symbol>, Error>` (drop `ParseOutcome`), the signature collapses to `pub fn parse_content(content: &str, language: Language) -> Result<Vec<Symbol>, Error>` and `extract_symbols` still returns `Vec<Symbol>` directly. Decision deferred to implementation.
- **Approach:** One commit. Verify via unit tests that the new function behaves identically to the old `CodebaseAnalyzer::new()?.analyze_content(...)` chain on representative inputs.
- **Patterns to follow:** Free-function exports elsewhere in `lib.rs`.
- **Test scenarios:**
  - Unit test: `parse_content("fn foo() {}", Language::Rust)` returns a non-empty result with `foo` in the symbols
  - Unit test: malformed input returns `Err(Error::ParseError { ... })` (preserves the rich context from `error.rs:74-78`)
  - Unit test: unsupported-language extraction returns `Ok` with empty `symbols` (current behavior at `writer.rs:807-815`) — and if `ParseOutcome` is used, `partial_errors` documents this case
- **Verification:** New function compiles + tests pass; identical extraction output to the pre-migration daemon path.

#### B2. Migrate daemon's writer.rs:763 callsite to `parse_content`

- **Goal:** Daemon no longer constructs `CodebaseAnalyzer`.
- **Files:**
  - EDIT: `crates/rts-daemon/src/writer.rs:763` — replace `use rust_tree_sitter::CodebaseAnalyzer;` + `let mut analyzer = CodebaseAnalyzer::new()?;` + `analyzer.analyze_content(content, language)` with `rust_tree_sitter::parse_content(content, language)?` (adapting to `outcome.symbols` if `ParseOutcome` is used)
  - EDIT: comments at `writer.rs:733, :746, :759` mentioning `CodebaseAnalyzer` → reference `parse_content`
- **Approach:** One commit. Verify daemon-side integration tests pass before B3.
- **Test scenarios:**
  - `cargo test -p rts-daemon` (full integration: reconciliation, cancel, grep, telemetry, v0.6 round-trips) passes unchanged
  - Spot-check `rts-bench real-repos run` against tokio/flask/gin fixtures — symbol counts identical (extraction-equivalence proof)
- **Verification:** No `CodebaseAnalyzer` import in `crates/rts-daemon/`; daemon tests pass; real-repo bench symbol counts unchanged.

#### B3. Delete `CodebaseAnalyzer` + sibling types entirely

- **Goal:** After B2 migrates the daemon and B0/B1 expose `parse_content`, there are no remaining users of `CodebaseAnalyzer` outside its own definition. Delete it.
- **Files:**
  - EDIT: `crates/rts-core/src/analyzer.rs` — delete the `CodebaseAnalyzer` struct, its `impl` blocks, and the now-unused `AnalysisConfig`, `AnalysisResult`, `FileInfo`, `AnalysisDepth` types
  - EDIT: `crates/rts-core/src/lib.rs` — delete the `pub use analyzer::{CodebaseAnalyzer, AnalysisConfig, AnalysisResult, FileInfo, AnalysisDepth};` line
  - `Symbol` re-export at `lib.rs` stays (consumed by daemon + serialization)
- **Approach:** One commit. `cargo check --workspace` must pass post-deletion.
- **Patterns to follow:** None — straight deletion.
- **Test scenarios:** `cargo check --workspace` passes; `extract_symbols` (the surviving extraction logic, hoisted in B0) still callable via `parse_content`.
- **Verification:** Grep `CodebaseAnalyzer` across workspace → zero hits; grep `AnalysisConfig`/`AnalysisResult`/`FileInfo`/`AnalysisDepth` → zero hits outside the `archive/` deletion's git-history scope.

#### B4. Per-test disposition for 4 affected integration tests

- **Goal:** Each of the 4 tests gets the disposition that matches what it actually tests.
- **Files:**

  | Test file | Tests what | Disposition |
  |-----------|-----------|-------------|
  | `crates/rts-core/tests/analyzer_cache_tests.rs` | `FileCache` behavior | **DELETE.** PR-A's A2 already removed `FileCache`. Test cannot compile. |
  | `crates/rts-core/tests/analyzer_depth.rs` | `AnalysisDepth` enum | **AUDIT then likely DELETE.** Daemon doesn't observe depth (calls `analyze_content` with no depth param). Test exercises dead behavior. |
  | `crates/rts-core/tests/symbol_listing.rs` | Symbol extraction | **REWRITE against `parse_content`.** This is exactly what the new facade does. Keeps as first-class integration test; tests the post-cleanup public surface. |
  | `crates/rts-core/tests/basic_integration_tests.rs:167` | Single `CodebaseAnalyzer::new()` usage | **READ FIRST.** Likely rewrite against `parse_content`; possibly delete if it duplicates `symbol_listing.rs`. |

- **Approach:** One commit per file disposition. After all dispositions: `cargo test -p rts-core` passes; no test references `CodebaseAnalyzer`.
- **Verification:** `cargo test --workspace` green; integration tests for the new public surface (`parse_content`) exist; tests of deleted code are gone.

#### B-DoD. Definition of Done for PR-B

- `changelog.d/B-feat-rts-core-public-surface-tightening.md` fragment added
- PR description cites PR-A as prerequisite + names the new `parse_content` facade + lists the deleted types
- All B-unit acceptance criteria pass

### PR-C: Metadata + tests + public-api test-snapshot gate

#### C1. Fix root Cargo.toml workspace metadata

- **Goal:** Replace placeholder identity strings with real values.
- **Files:**
  - EDIT: `Cargo.toml:21` — `authors = ["Your Name <your.email@example.com>"]` → `["njfio <7220+njfio@users.noreply.github.com>"]`
  - EDIT: `Cargo.toml:23` — `repository = "https://github.com/yourusername/rust_tree_sitter"` → `"https://github.com/njfio/rs-agent-code-utility"`
  - Confirm `license`, `edition`, `rust-version` are correct
- **Approach:** One commit.
- **Test scenarios:** `cargo publish -p rts-core --dry-run` succeeds with no placeholder-string warnings.
- **Verification:** Cargo.toml shows real authors + repository.

#### C2. Add metadata integration test (toml-crate parsing, no version-consistency check)

- **Goal:** Lock in C1's fix so future placeholder regressions fail CI. Use `toml = "0.8"` parsing (already a workspace dep) instead of regex.
- **Files:**
  - ADD: `crates/rts-core/tests/metadata.rs` (or workspace-level `tests/metadata.rs`)
  - Reads root `Cargo.toml` via `std::fs::read_to_string` then `toml::from_str::<toml::Value>(&contents)`
  - Assertions:
    - `authors` does NOT contain any of: `"Your Name"`, `"your.email@example.com"`, `"example.com"`
    - `repository` matches `^https://github\.com/[a-zA-Z0-9_-]+/[a-zA-Z0-9_.-]+/?$`
    - (Version-consistency assertion DROPPED — A6 strips version strings from preambles so the check is against an empty set)
- **Patterns to follow:** `crates/rts-daemon/tests/protocol_schemas.rs:55-57` uses `env!("CARGO_MANIFEST_DIR")` + relative path traversal to reach repo files.
- **Test scenarios:** Test passes against current state; mutating any placeholder back into Cargo.toml causes the test to fail with a clear message.
- **Verification:** `cargo test --workspace` includes the metadata test + passes.

#### C3. Add `cargo public-api` test-snapshot gate

- **Goal:** Lock the public API of rts-core + rts-mcp. Future changes require an explicit snapshot update in the same PR. **Uses the test-based mechanism, not a CI workflow.**
- **Files:**
  - ADD: `crates/rts-core/tests/public_api.rs`:

    ```rust
    #[test]
    fn public_api() {
        rustup_toolchain::install(public_api::MINIMUM_NIGHTLY_RUST_VERSION).unwrap();
        let rustdoc_json = rustdoc_json::Builder::default()
            .toolchain(public_api::MINIMUM_NIGHTLY_RUST_VERSION)
            .build()
            .unwrap();
        let public_api = public_api::Builder::from_rustdoc_json(rustdoc_json)
            .build()
            .unwrap();
        public_api.assert_eq_or_update("./tests/snapshots/public-api.txt");
    }
    ```

  - ADD: `crates/rts-mcp/tests/public_api.rs` — identical structure
  - ADD: `crates/rts-core/tests/snapshots/public-api.txt` — generated via `UPDATE_SNAPSHOTS=yes cargo test -p rts-core public_api`
  - ADD: `crates/rts-mcp/tests/snapshots/public-api.txt` — generated via `UPDATE_SNAPSHOTS=yes cargo test -p rts-mcp public_api`
  - EDIT: `crates/rts-core/Cargo.toml`:

    ```toml
    [dev-dependencies]
    public-api = "0.45"
    rustdoc-json = "0.9"
    rustup-toolchain = "0.1"
    ```

  - EDIT: `crates/rts-mcp/Cargo.toml` — same dev-deps
  - ADD: `docs/public-api-gate.md` documenting:
    - What the gate catches (any change to public surface)
    - How to regenerate snapshots: `UPDATE_SNAPSHOTS=yes cargo test --workspace -- public_api`
    - Pinning: `public_api::MINIMUM_NIGHTLY_RUST_VERSION` (library exposes the constant; no separate tool pin needed)
- **Approach:** One commit. The test runs as part of `cargo test --workspace` — no new CI workflow file.
- **Patterns to follow:** cargo-public-api's own README documents this pattern as canonical.
- **Test scenarios:**
  - On this PR itself: snapshot matches state → test passes
  - Locally add `pub fn experimental_foo() {}` to `rts-core/src/lib.rs` and re-run → test fails with a unified diff against the snapshot + a `UPDATE_SNAPSHOTS=yes` regen hint
- **Verification:** Two snapshot files present; both `public_api` tests pass on this PR; regeneration command works.

#### C-DoD. Definition of Done for PR-C

- `changelog.d/C-feat-metadata-and-public-api-gate.md` fragment added
- PR description includes the metadata-fix + the snapshot-gate mechanism + a one-line note that this PR runs in parallel with PR-A and PR-B
- All C-unit acceptance criteria pass

## Requirements Trace

Mapping origin doc's R1-R8 to plan units (post-revision):

| Requirement | Units | PR |
|-------------|-------|----|
| R1. Delete dead rts-core modules | A1 + A2 + A3 | A |
| R2. Delete archive/ tree | A4 | A |
| R3. Delete wiki_site_test/ tree | A4 | A |
| R4. Facade + daemon migration + analyzer types removed | B0 + B1 + B2 + B3 + B4 | B |
| R5. Fix root Cargo.toml metadata | C1 | C |
| R6. Strip 0.2.0-alpha header from lib.rs + analyzer.rs rustdoc | A6 | A |
| R7. Add metadata integration test | C2 | C |
| R8. Add public-API baseline gate | C3 (test-based, not CLI-workflow) | C |

## Acceptance Criteria

### Functional

- [ ] All 13 dead rts-core modules deleted (A1 + A3); `cargo shear` exits 0 (A1 pre-flight + A3 post-flight)
- [ ] `analyzer.rs` no longer references `FileCache` or `SemanticGraphQuery` (A2)
- [ ] `archive/` and `wiki_site_test/` directories no longer exist (A4); `Cargo.toml`'s `exclude = ["archive"]` line removed
- [ ] CI semantic-eval corpora trimmed; both `--check-coverage` thresholds (0.95 / 0.75) still pass (A6)
- [ ] `rts-core/src/lib.rs` preamble + `analyzer.rs:25, :47, :66` rustdoc examples match post-cleanup reality (A6)
- [ ] `pub(crate) fn extract_symbols(...)` exists and is the single entry point for symbol extraction (B0)
- [ ] `pub fn parse_content(content: &str, language: Language) -> Result<ParseOutcome, Error>` exists in rts-core, built from `Parser::new` + `extract_symbols`, NOT wrapping `CodebaseAnalyzer` (B1)
- [ ] Daemon's `writer.rs:763` uses `parse_content`; no `CodebaseAnalyzer` import in rts-daemon (B2)
- [ ] `CodebaseAnalyzer`, `AnalysisConfig`, `AnalysisResult`, `FileInfo`, `AnalysisDepth` are DELETED (B3) — grep exits with zero hits
- [ ] 4 integration tests dispositioned per the B4 table (delete some, rewrite some) — `cargo test -p rts-core` passes
- [ ] Root `Cargo.toml` shows real authors + repository (C1)
- [ ] Metadata integration test asserts placeholder-absence + repository-URL validity using `toml = "0.8"` parsing (C2)
- [ ] `crates/rts-core/tests/public_api.rs` + `crates/rts-mcp/tests/public_api.rs` exist; snapshot files committed; both tests pass on this PR (C3)

### Quality gates

- [ ] `cargo check --workspace` passes after each unit
- [ ] `cargo test --workspace` passes after each PR (includes the new metadata + public_api tests)
- [ ] `cargo fmt --all --check` clean
- [ ] `cargo clippy -p rts-daemon -p rts-mcp -p rts-bench --all-targets` clean at lefthook scope
- [ ] CI semantic-eval workflow stays green
- [ ] No `unsafe` blocks introduced
- [ ] Each PR has a `changelog.d/` fragment per the project convention
- [ ] Each PR's body cites the dependency on prior PR (B cites A; C is independent)
- [ ] Each PR's body includes Post-Deploy Monitoring & Validation section ("No additional operational monitoring required: pure refactor")

## Success Metrics

- Repository working tree shrinks by ~12.2 MB / ~552 files (verified via `git diff --stat`)
- `cargo check -p rts-core` is measurably faster (estimate: 20-30% reduction in per-build work)
- A new PR adding `pub fn foo()` to rts-core fails `cargo test --workspace` at the `public_api` test with a unified-diff message
- A new PR re-introducing `"Your Name"` in Cargo.toml fails `cargo test --workspace` at the metadata test with a clear message
- `cargo publish -p rts-core --dry-run` succeeds with no placeholder-string warnings
- Grep `CodebaseAnalyzer` across the workspace → zero hits (proves the deletion is complete)

## Dependencies & Risks

### Sequencing
- PR-A must merge before PR-B starts (B depends on A's analyzer.rs surgery)
- PR-C is independent and can ship in parallel with either A or B

### Risks (post-revision)

| Risk | Likelihood | Mitigation |
|------|-----------|-----------|
| A2's FileCache strip breaks `analyzer.rs` hot-path behavior in subtle ways | Medium | Cache wasn't load-bearing for the daemon's path; inline `fs::read_to_string` for remaining callsites. Verify via real-repo bench symbol counts. |
| A6's corpus edits drop semantic-eval coverage below thresholds | Medium | The CI thresholds (0.95 / 0.75) are loose; removing 2-3 queries from a 30+ query corpus won't move the needle materially. |
| B1's `ParseOutcome` adds public-API surface that `cargo public-api` then locks | Low | Acceptable — `ParseOutcome` is the chosen shape. If maintainer prefers simpler `Result<Vec<Symbol>, Error>`, drop `ParseOutcome` at B1 implementation. |
| `cargo public-api`'s `MINIMUM_NIGHTLY_RUST_VERSION` upgrades on tool minor-version bumps; baselines drift on tool upgrade | Low | Pin `public-api = "0.45"` (or current pinned version) in dev-deps; bump deliberately with snapshot regen. Library exposes the constant exactly for this. |
| B3's `CodebaseAnalyzer` deletion misses a test/example reference that wasn't grep-visible | Low | B0/B1/B2/B4 run with `cargo check --workspace` between each commit; any residual reference surfaces as a compile error. Use `cargo-shear` post-flight to catch orphan files. |
| C2's `toml = "0.8"` parsing adds compile time | Low | Already a workspace dep per A6's comment-strip note — no new dependency. |

### Out of scope (deliberate non-goals)

(See origin: `docs/brainstorms/2026-05-22-pre-pivot-cleanup-and-public-surface-tightening-requirements.md` § Scope Boundaries.)

- Crate rename (`rts-core` keeps its name)
- Crate split (no umbrella + peer crates)
- Protocol-v0 changes
- Daemon-side feature changes
- v0.6.0 tag cut + experimental gate (ideation survivor #3)
- Promise-token pattern (deferred to its own brainstorm)
- `methods/index.rs` decomposition (ideation survivor #4)
- Language registry collapse (ideation survivor #6)
- Surface manifest gates (ideation survivor #2)
- Secrets-safe boundary cuts (ideation survivor #5)
- 1.0 commitment (best-practices reviewer raised this; deferred to a separate decision — see Decisions Applied O5)

## Resource Requirements

- ~1-2 days focused work (single maintainer or parallel-agent dispatch)
- macOS + Linux smoke tests for the daemon-side facade migration
- No external infrastructure changes
- No new production dependencies; three new dev-dependencies (`public-api`, `rustdoc-json`, `rustup-toolchain`) for the test-snapshot gate; `cargo-shear` installed once for pre/post-flight verification

## Sources & References

### Origin
- **Origin document:** [`docs/brainstorms/2026-05-22-pre-pivot-cleanup-and-public-surface-tightening-requirements.md`](../brainstorms/2026-05-22-pre-pivot-cleanup-and-public-surface-tightening-requirements.md). Key decisions carried forward: DELETE not archive (R1-R3); 3-PR sequence (A→B sequential, C parallel); per-crate baselines locked for library crates.
- **Ideation predecessor:** [`docs/ideation/2026-05-21-drift-remediation-ideation.md`](../ideation/2026-05-21-drift-remediation-ideation.md) — this work is survivor #1.

### Internal references (research-verified)
- 13 dead modules: `crates/rts-core/src/{complexity_analysis,control_flow,dependency_analysis,memory_tracker,performance_analysis,semantic_context,semantic_graph,symbol_table,advanced_parallel,file_cache,code_map,analysis_common,analysis_utils}.rs`
- `analyzer.rs` blockers: `crates/rts-core/src/analyzer.rs:86, :89, :284-285, :299-300, :416-417, :548, :835, :2412-2453`
- Daemon callsite: `crates/rts-daemon/src/writer.rs:763`
- Tests breaking on PR-A: `crates/rts-core/tests/{dependency_analysis,simple_memory_test,complexity_analysis_unit_tests,file_cache_tests}.rs`
- Tests breaking on PR-B: `crates/rts-core/tests/{analyzer_cache_tests,analyzer_depth,symbol_listing}.rs` + `basic_integration_tests.rs:167`
- CI semantic-eval workflow: `.github/workflows/ci.yml:65-85`
- CI semantic-eval corpora: `corpus/semantic-eval-rts-core.toml:53-57, :88-93` + `corpus/semantic-eval-rts-core-blind-v2.toml:61-69`
- Daemon depends on `signature::render_*`: `crates/rts-daemon/src/language.rs:333-388` (13 entry points)
- Daemon depends on `pagerank::*`: `crates/rts-daemon/src/outline.rs:33`, `crates/rts-daemon/src/symbol_pagerank.rs:62`
- Daemon depends on `error::Error`: `crates/rts-daemon/src/methods/grep_v2/query_cache.rs:93`
- Repo URL: `https://github.com/njfio/rs-agent-code-utility`

### External references
- `cargo public-api` library docs + canonical CI test pattern: <https://github.com/cargo-public-api/cargo-public-api>
- `cargo-shear` (orphan-file detection): <https://crates.io/crates/cargo-shear>
- `thiserror` (error-type patterns, considered + rejected for B1): <https://docs.rs/thiserror>
- Effective Rust Item 22 (Minimize visibility): <https://effective-rust.com/visibility.html>
- PR #122 (Protocol-v0 JSON Schema export) — the institutional pattern this plan's C3 mirrors (test-based gate, locked baseline)

### Related work
- PR #122: Protocol-v0 JSON Schema export — establishes the locked-baseline test pattern
- PR #121: MCP tool descriptions audit — establishes the regression-test-the-prose pattern
- PR #130: README + CHANGELOG refresh — closed an adjacent doc-drift gap on 2026-05-21

---

## Decisions Applied (audit trail from /deepen-plan)

### Required fixes (factually corrected; would have failed at runtime or shipped wrong information)

- **F1 ✅** Dropped `cargo public-api --deny=all` from prose. The flag is invalid on the bare command.
- **F2 ✅** Adopted the test-based `public_api::assert_eq_or_update` mechanism. Dropped the `.github/workflows/public-api-check.yml` workflow file. Snapshots live at `crates/<name>/tests/snapshots/public-api.txt`.
- **F3 ✅** Extended "After: rts-core publicly exports" enumeration to include `pagerank::*`, `signature::render_*` (13 entry points), `error::Error`, `error::Result`.
- **F4 ✅** Extended A6 to update `analyzer.rs:25, :47, :66` rustdoc examples (not just `lib.rs` preamble).

### Strong recommendations (high-confidence improvements)

- **S1 ✅** Dropped the `pub struct ParseError` wrapper. `parse_content` returns `Result<ParseOutcome, Error>` using the already-public `error::Error`.
- **S2 ✅** Delete `CodebaseAnalyzer` entirely (B3) — not pub(crate) demotion. After PR-A strips its dependencies, the struct is unamortized scaffolding. Architecturally cleaner.
- **S3 ✅** Per-test disposition for B4 (delete `analyzer_cache_tests` with A2; audit `analyzer_depth` for likely delete; rewrite `symbol_listing` against `parse_content`; read `basic_integration_tests.rs:167` before deciding).
- **S4 ✅** Pin via `public_api::MINIMUM_NIGHTLY_RUST_VERSION` (library-exposed constant). No `taiki-e/install-action` version pin needed since no CI workflow.
- **S5 ✅** C2 uses `toml = "0.8"` parsing instead of regex (already a workspace dep; avoids workspace-inheritance fragility).
- **S6 ✅** Dropped C2 version-consistency assertion. A6 strips version strings from preambles so the check is against an empty set.
- **S7 ✅** Added `cargo-shear` pre-flight (A1 start) + post-flight (A3 end) for orphan-file verification.

### Optional improvements (defensible either way; current decisions noted)

- **O1 ✅ ADOPTED:** `parse_content` returns `Result<ParseOutcome, Error>` where `ParseOutcome { symbols: Vec<Symbol>, partial_errors: Vec<String> }`. Surfaces the known partial-parse gap at `writer.rs:807-815`. Maintainer can simplify to `Result<Vec<Symbol>, Error>` at B1 implementation if preferred.
- **O2 ⏸ DEFERRED:** Keep C1 (metadata fix) as its own PR-C unit. Splitting from PR-A preserves the 3-PR structure that matches the project's small-focused-PR norm.
- **O3 ✅ ADOPTED:** Dropped A7, B5, C4 as standalone units. Folded into per-PR "Definition of Done" notes (A-DoD, B-DoD, C-DoD above).
- **O4 ⏸ DEFERRED:** rts-bench public-API gate scope check. If rts-bench has a meaningful lib crate with public types, gate it too. Verify during C3 implementation.
- **O5 ⏸ DEFERRED:** 1.0 commitment. Best-practices reviewer raised this as the right moment, but it's bigger than the cleanup arc. Owned by ideation survivor #3 (v0.6 release engineering).

### Rejected pushbacks (considered, kept the plan as-is)

- **Drop the public-api gate entirely; defer until first crates.io publish** (code-simplicity reviewer). Gate has compound value as a PR-diff reviewer's tool even pre-publish. After F2 (test-based mechanism), the cost dropped materially. Mirrors the PR #122 lockfile pattern that's been compounding all session.
- **Switch to builder pattern for facade** (considered). Daemon's callsite is 2 arguments with no configuration; builder is over-engineering.
- **Switch to trait-based facade (`pub trait Parseable`)** (considered). Premature abstraction; one impl.
- **Collapse to 2 PRs** (code-simplicity reviewer). A→B sequential dependency is real (analyzer.rs surgery + facade migration); C-parallel is correctly independent. The 3-PR split yields cleaner review surfaces.
