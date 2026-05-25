### Refactor: rts-core public surface tightening — parse_content facade + CodebaseAnalyzer delete

PR-B of the 3-PR drift-remediation arc (plan: `docs/plans/2026-05-22-001-refactor-pre-pivot-cleanup-and-public-surface-tightening-plan.md`). Builds on PR-A (#133) which stripped FileCache + SemanticGraphQuery from the analyzer.

#### What

- **`extract_symbols` hoisted to `pub(crate) fn` (B0):** moved out of `impl CodebaseAnalyzer` into a new `pub(crate) mod extraction` (`crates/rts-core/src/extraction.rs`). 18 free functions, one dispatch entry point. The helpers never used `&self` — the conversion was mechanical.
- **`parse_content` facade added (B1):** `pub fn parse_content(content: &str, language: Language) -> Result<ParseOutcome>` in `crates/rts-core/src/lib.rs`. Built from `Parser::new` + `extraction::extract_symbols` directly — NOT wrapping a stateful analyzer. `ParseOutcome { symbols, partial_errors }` reserves a slot for future extractor self-reporting of the known Java/C/C++ silent-empty path (writer.rs:807-815). Uses the already-public `error::Error` — no new `ParseError` wrapper.
- **Daemon migrated (B2):** `crates/rts-daemon/src/writer.rs:763` now calls `rust_tree_sitter::parse_content` instead of `CodebaseAnalyzer::new()?.analyze_content(...)`. No `CodebaseAnalyzer` import remains in `rts-daemon/src/**`. All 247 daemon lib tests + the full integration battery (reconciliation, cancel-in-flight, grep v2, schemas, telemetry, fuzz) pass unchanged.
- **`CodebaseAnalyzer` + sibling types deleted (B3):** `CodebaseAnalyzer`, `AnalysisConfig`, `AnalysisResult`, `FileInfo`, `AnalysisDepth` removed from rts-core entirely. `analyzer.rs` (1607 LoC) deleted. `Symbol` relocated to new `crates/rts-core/src/symbol.rs` next to its only producer; re-exported from lib.rs as before so `use rust_tree_sitter::Symbol` works unchanged.
- **15 extraction tests preserved (B3):** moved from the deleted `analyzer.rs` test module into `extraction::tests`, rewritten to use `parse_content` (the public API). Coverage of go/jsdoc/rust-const+static/ruby/java/swift/csharp/php (interface/trait/namespaced)/rust-trait+type+union+macro doc-comment + symbol extraction is fully preserved against the post-cleanup public surface.
- **Integration tests dispositioned (B4):**
  - `analyzer_cache_tests.rs` — already deleted by PR-A (A5)
  - `analyzer_depth.rs` — DELETED (depth was internal; daemon never observed it)
  - `symbol_listing.rs` — REWRITTEN against `parse_content` (this IS what the new facade does)
  - `basic_integration_tests.rs` — 4 tests REWRITTEN against `parse_content`; the file-system error-handling test was dropped since `parse_content` takes content, not a path
  - `performance_optimization_tests.rs` — 5 tests REWRITTEN against `parse_content` / `Parser`; the sequential-only `test_concurrent_analysis_performance` was dropped since rayon parallelism lives in the daemon and is exercised by daemon integration tests
- **Public-API snapshot regenerated:** `crates/rts-core/tests/snapshots/public-api.txt` shrinks by 894 lines net (1016 deletions, 122 additions). The deletion is the analyzer's massive surface (50+ methods, 5 sibling types with full auto-derive chains); the additions are `parse_content`, `ParseOutcome`, the relocated `symbol::Symbol`. `crates/rts-mcp/tests/snapshots/public-api.txt` is unchanged — rts-mcp never re-exported anything from the deleted types.

#### Post-PR-B rts-core public surface

Daemon-facing (verified via `grep "use rust_tree_sitter::"` against `crates/rts-{daemon,mcp,bench}/src/`):

- **Parsing:** `Parser`, `SyntaxTree`, `Node`, `TreeCursor`, `Language`
- **Querying:** `Query`, `QueryBuilder`, `QueryMatch`, `QueryCapture`
- **Facade:** `parse_content`, `ParseOutcome`
- **Symbols:** `Symbol`
- **Ranking:** `pagerank::*` (Edge, compute, edge_weight)
- **Signatures:** `signature::render_*` (13 per-language entry points)
- **Errors:** `Error`, `Result`
- **Language utilities:** `supported_languages`, `detect_language_from_extension`, `detect_language_from_path`

#### Equivalence proof

- `parse_content` is a behavioural alias for the pre-PR-B `CodebaseAnalyzer::new()?.analyze_content(content, language)` chain. The B1 commit shipped a `parse_content_matches_codebase_analyzer_output` unit test pinning this; B3 dropped the analyzer half (so the test was rewritten to a multi-kind sanity check) but the behavioural equivalence carries forward through the daemon's full test suite passing unchanged.
- Daemon's writer hot-path tests (`parse_and_extract_returns_*`) keep passing — they're integration tests against the new code path, exercising the same Symbol-output contract.

#### Out of scope

- Filling in the Java/C/C++ extractor stubs — known issue, documented at `writer.rs:805-815` and reserved-room-for in `ParseOutcome::partial_errors`.
- Filling in `ParseOutcome::partial_errors` from extractor self-reporting — the slot exists, the wiring is for a future PR.
- Renaming or merging the `extraction` module into something else — `pub(crate)` is the right visibility for now.

#### Post-deploy monitoring

No additional operational monitoring required: pure refactor; daemon behavior unchanged. The daemon's existing real-repo regression bench (PR #123) provides the symbol-count equivalence proof.
