### Refactor: delete pre-pivot weight from rts-core, archive, and wiki_site_test

PR-A of the 3-PR drift-remediation arc (plan: `docs/plans/2026-05-22-001-refactor-pre-pivot-cleanup-and-public-surface-tightening-plan.md`).

#### What

- **rts-core surgery:** strip `FileCache` + `SemanticGraphQuery` from `crates/rts-core/src/analyzer.rs` (fields, constructor wiring, and the dependent cache / semantic-graph methods). The on-disk read path is now a direct `std::fs::read_to_string`.
- **13 dead rts-core modules deleted:** `advanced_parallel`, `analysis_common`, `analysis_utils`, `code_map`, `complexity_analysis`, `control_flow`, `dependency_analysis`, `file_cache`, `memory_tracker`, `performance_analysis`, `semantic_context`, `semantic_graph`, `symbol_table`. None had any consumer outside their own crate — verified via grep + `cargo check -p rust_tree_sitter --lib` between every deletion. `CodebaseAnalyzer` stays public; PR-B owns its removal.
- **Two stale subtrees deleted:** `archive/` (190 files / ~34k LoC / ~3.2 MB of pre-pivot library + CLI + AI/security analyzers) and `wiki_site_test/` (362 files / ~9 MB of generated wiki output).
- **Root `Cargo.toml` cleanup:** drop the `exclude = ["archive"]` workspace entry and the explanatory comment now that the directory is gone. Workspace metadata placeholders (`authors`, `repository`) are not touched here — PR-C owns those.
- **AGENTS.md cleanup:** strip the three remaining mentions of `archive/` (preamble, grep-still-right-tool list, "What's archived, and why" section).
- **Dead integration tests deleted:** `dependency_analysis`, `simple_memory_test`, `complexity_analysis_unit_tests`, `file_cache_tests`, `analyzer_cache_tests`. Inline-removed: `test_basic_complexity_analysis`, `test_complexity_analysis_performance`, `test_performance_analysis_optimizations`, `test_string_optimization_detection`. The surviving test suite (~261 tests) stays green.
- **CI semantic-eval corpora trimmed:** removed three query blocks in `corpus/semantic-eval-rts-core.toml` + `corpus/semantic-eval-rts-core-blind-v2.toml` that hardcoded `FileCache`, `CacheStats`, `SymbolTable`, `SymbolStatistics`. Both `--check-coverage` gates (0.95 / 0.75) still pass.
- **Preambles rewritten:** `crates/rts-core/src/lib.rs` now describes the post-cleanup public surface (parser/query primitives, `Symbol`, `pagerank::*`, `signature::render_*`, `Error`/`Result`). `crates/rts-core/src/analyzer.rs` rustdoc examples are marked `ignore` with a note pointing at the upcoming `parse_content` facade from PR-B.

#### Sets up

- **PR-B** will hoist `extract_symbols` to a `pub(crate) fn`, add `pub fn parse_content(content, language) -> Result<ParseOutcome, Error>`, migrate `crates/rts-daemon/src/writer.rs:763` to it, and delete `CodebaseAnalyzer` / `AnalysisConfig` / `AnalysisResult` / `FileInfo` / `AnalysisDepth`.
- **PR-C** will fix the root `Cargo.toml` `authors` + `repository` placeholders, add a metadata integration test (`toml = "0.8"` parsing), and lock the public API of rts-core + rts-mcp behind a snapshot-based `public_api::assert_eq_or_update` gate.

#### Out of scope

- Removing `CodebaseAnalyzer` — owned by PR-B (B3). It stays accessible in this PR so the daemon's only out-of-crate caller (`writer.rs:763`) keeps working.
- Workspace metadata fix — owned by PR-C (C1).
- `cargo public-api` gate — owned by PR-C (C3).

#### Post-deploy monitoring

No additional operational monitoring required: this is a pure refactor with no runtime behavior change. The semantic-eval CI gate already covers the corpus edits.
