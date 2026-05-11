# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0-alpha.4] - 2026-05-11

P5 of the agentic-retrieval pivot: doc-only. Ships the `protocol-v0`
design document — the daemon↔MCP wire-protocol spec that P6 (daemon)
and P7 (MCP server) will both implement against. Pure documentation;
no code changes.

### Added

- **`docs/protocol-v0.md`** — comprehensive design doc for the
  daemon↔MCP wire protocol. Sections:
  1. Trust model (single-user, local-only, single-uid boundary)
  2. Architecture overview
  3. Wire format (newline-delimited JSON, 16 MiB cap, `content_version`)
  4. Capability negotiation (not single-version semver)
  5. Workspace identity (`(dev, inode, canonical_path)` binding;
     per-OS canonicalisation matrix)
  6. Path safety (refuse symlinked components, per-read prefix check,
     `.rtsignore` extension)
  7. Method catalog (10 methods + 1 notification):
     `Daemon.Ping`/`Telemetry`, `Workspace.Mount`/`Unmount`/`Status`,
     `Index.Outline`/`FindSymbol`/`ReadSymbol`/`ReadRange`,
     `Session.Open`/`Close`. `Daemon.Cancel` and `Session.MarkDeduped`
     dropped from v0 per the deepening reviews.
  8. Cold-state semantics (`partial: true` + `progress`)
  9. Concurrency model (single writer-drain task, parse-parallel +
     commit-serial, bounded mpsc, 16-in-flight cap)
  10. Cancellation contract (connection drop + 30s soft deadline; no
      explicit `Daemon.Cancel` in v0)
  11. Token counting (`bytes / 3` approximator; oracle = Anthropic
      `countTokens` offline only)
  12. Auth boundary (per-OS peer-creds, `umask(0077)`,
      refuse-to-run-as-root, `prctl(PR_SET_DUMPABLE, 0)`)
  13. Default secrets policy (filename blocklist + content scanner +
      code-extension allowlist for body returns)
  14. Error code catalog (string codes, ~20 entries)
  15. State lifecycle (startup, mount, stale PID handling, redb
      corruption recovery, auto-spawn race resolution)
  16. Resource limits (concrete numbers + env-var overrides)
  17. Telemetry/observability (opt-in `RTS_TELEMETRY=1`; 64 MiB
      rotation × 3 retention; silent-drop on ENOSPC)
  18. JSON Schema fragments for each method's `params`
  - Appendix A: Local-auth recipes per OS (Linux/macOS/Windows-v1.1)
  - Appendix B: What's intentionally not in v0
  - Appendix C: Decisions resolved from the deepening (cross-ref
    table linking 24 specific decisions back to the originating
    review)
  - Appendix D: Open questions deferred to P6
  - Appendix E: Wire-protocol versioning policy

The doc is the source of truth for P6 (rts-daemon) and P7 (rts-mcp).
The MCP-facing tool surface remains governed by
`docs/plans/2026-05-10-001-feat-pivot-to-agentic-retrieval-mcp-server-plan.md`
and the MCP 2025-11-25 spec.

### Verification

- `cargo build --workspace`: green (no code changes; doc-only).
- `cargo test --workspace`: still 281 passed, 0 failed, 2 ignored.

## [0.2.0-alpha.3] - 2026-05-11

P4 of the agentic-retrieval pivot: convert to a Cargo workspace with
`crates/rts-core/` as the surviving primitive library, bump to Rust 2024
edition, and ship three smaller cleanups flagged by the deepening reviews.

### Changed

- **Cargo workspace layout.** Root `Cargo.toml` is now a workspace
  manifest with `resolver = "3"` and a single member, `crates/rts-core`.
  `src/` moved to `crates/rts-core/src/`, `tests/` to
  `crates/rts-core/tests/`, `test_files/` to `crates/rts-core/test_files/`.
  Future workspace members (`rts-daemon`, `rts-mcp`, `rts-bench`) land
  alongside as separate crates.
- **Rust 2024 edition, MSRV 1.85** declared at the workspace level
  (`[workspace.package]`); members inherit via `edition.workspace = true`
  / `rust-version.workspace = true`.
- **`spikes/p0-*` and `archive/` are excluded** from the workspace via
  `[workspace.exclude]`. The spike binaries remain independent crates;
  archived modules are pure history.
- **LRU caches** (perf-oracle critical fix). Both `file_cache.rs` and
  `parser.rs` previously used `HashMap` + "first-key from HashMap
  iteration" eviction — effectively random under `HashMap`'s rehash
  seed. Replaced with `lru::LruCache` so eviction is deterministic and
  recency-aware. The file cache also moved from
  `Arc<RwLock<HashMap>>` to `Arc<Mutex<LruCache>>` because
  `LruCache::get` is `&mut self` (it bumps recency). Tests now include
  explicit LRU semantics (oldest-evicted, touch-prevents-eviction).
  - New dep: `lru = "0.12"`.

### Security / hygiene

- **`#![forbid(unsafe_code)]` on `crates/rts-core/src/lib.rs`.** The
  pivot plan called for `forbid` on rts-core (leaf library); verified
  no `unsafe` survives the cut after archiving `advanced_memory.rs`
  (its single `unsafe { mmap... }` block was the only one in the
  surviving core; the module wasn't used by anything else and the
  daemon's segment-store path was already dropped in alpha.1 in favour
  of redb blobs).
- **Workspace-level `unsafe_code = "deny"`** in `[workspace.lints.rust]`
  applies to every future workspace member; individual crates can
  override via `#[allow(unsafe_code)]` on a specific item. The plan's
  intended split (forbid on rts-core, deny on rts-daemon/rts-mcp) is
  set up.
- **Removed silent `eprintln!` log** in `file_cache.rs::insert`'s
  poisoned-lock branch. Replaced with `tracing::warn!` under target
  `rust_tree_sitter::file_cache`. The daemon's tracing subscriber
  will surface this; previously it was lost to stderr.

### Removed

- **`src/advanced_memory.rs`** → `archive/src/advanced_memory.rs`.
  Contained the only `unsafe` block in the surviving core (mmap via
  `memmap2`) and was unused outside its own module. Plan path forward:
  the daemon doesn't need it (segments are redb blobs per
  alpha.1 decision); revisit only if a future profile shows actual
  memory-mmap'd primitives are load-bearing.
- **`semantic_graph::build_file_relationships`** (perf-oracle critical
  fix). The function emitted a `same_file` edge with weight 0.3 between
  every pair of symbols in a file — O(n²) per file, ~625k spurious
  edges on a 100k-LOC repo. Garbage data that would have polluted any
  future PageRank pass. Removed entirely; real edges return in P8 from
  tags.scm-derived (def, ref) tuples.
- `test_get_statistics` now asserts `total_edges == 0` instead of
  `> 0`; the old assertion was validating the O(n²) garbage.

### Verification

- `cargo build --workspace`: green.
- `cargo test --workspace`: **281 passed, 0 failed, 2 ignored** (was
  286; delta: -5 from archiving `advanced_memory` tests).

### Deferred

- **`ThreadedRodeo` symbol interning.** Per-plan P4 deliverable; this
  refactor changes `SymbolDefinition::name` from `String` to
  `Symbol(u32)` and ripples through every consumer. Big enough to
  warrant its own PR; will land alongside the P6 daemon work when the
  hot-path latency matters most.

## [0.2.0-alpha.2] - 2026-05-11

P1 of the agentic-retrieval pivot: tree-sitter ABI bump and Query API migration.

### Changed

- **`tree-sitter = "0.26"`** (was `0.20`). All 12 language grammars bumped to
  matching 0.23+ versions: `tree-sitter-{rust,javascript,typescript,python,c,cpp,go,java,php,ruby} = "0.23"`,
  `tree-sitter-swift = "0.7"`.
- **New direct dep `streaming-iterator = "0.1"`**, required because tree-sitter
  0.26's `QueryCursor::matches` and `QueryCursor::captures` are
  `StreamingIterator`s, not regular `Iterator`s. The `for m in cursor.matches(…)`
  pattern no longer compiles; use `while let Some(m) = it.next()` with
  `use streaming_iterator::StreamingIterator` in scope.
- **`tree_sitter::Query::new(language, pattern)` → `Query::new(&language, pattern)`**.
- **`parser.set_language(language)` → `parser.set_language(&language)`**.
- **Grammar API conversion**: `tree_sitter_<lang>::language()` → `LANGUAGE.into()`
  (a `LanguageFn` const). TypeScript uses `LANGUAGE_TYPESCRIPT`; PHP uses
  `LANGUAGE_PHP`. Some `HIGHLIGHT_QUERY` constants were renamed to
  `HIGHLIGHTS_QUERY` (plural); the renames are inconsistent across grammars
  (e.g. `tree-sitter-javascript` still exports `HIGHLIGHT_QUERY` while
  `tree-sitter-rust` switched to `HIGHLIGHTS_QUERY`).
- **`Node::child` takes `u32`** in 0.26 (was `usize`). Crate-wrapper API kept
  on `usize` with an internal `u32::try_from` conversion.
- **`Parser::set_timeout_micros` removed.** Per-parser cancellation in 0.26 is
  cooperative via `ParseOptions::progress_callback(cb)` returning
  `ControlFlow::Break`. `Parser::set_options` is the new entry point. The
  historical `options.timeout_millis` field is currently a no-op; cooperative
  timeout support is a follow-up.

### Removed

- **`Language::Kotlin` and the `tree-sitter-kotlin` dependency.** The
  community-maintained grammar's 0.3.x line is hard-pinned to
  `tree-sitter = "0.20"`, and the C `links = "tree-sitter"` uniqueness rule
  prevents two majors of the runtime in one dep graph. The plan's
  v1.1 disposition: restore once an upstream release ships against
  tree-sitter 0.26+ ABI.
  - `src/languages/kotlin.rs` archived to `archive/src/languages_kotlin.rs`.
  - Removed from `Language::all()`, `Language::name()`, `Language::file_extensions()`,
    `Language::version()`, `Language::supports_highlights()`, all query maps,
    the analyzer's `extract_kotlin_symbols`, `symbol_table.rs`'s
    `extract_kotlin_symbol_definition`, and the from-`&str` parser.

### Added

- **Per-language smoke test**: `languages::tests::test_every_language_loads_and_parses_a_snippet`
  loads every variant of `Language::all()`, creates a `Parser`, and parses a
  minimal valid snippet per language. Asserts the root node is neither MISSING
  nor ERROR. This is the canonical regression test the P1 plan called for —
  any future grammar version bump that breaks runtime loading or first-parse
  will fail this test.

### Known issues (deferred to P8)

- `tests/missing_language_features_tests::test_go_missing_features` and
  `test_rust_missing_features` are now `#[ignore]`'d. The 0.23 grammars' node-kind
  names for Go interface elements and Rust lifetime nodes shifted subtly from
  the 0.20-era nodes these tests assert on. Revisit during the P8 per-language
  `SignatureRenderer` work, which already requires a per-grammar node-types audit.

### Verification

- `cargo build --lib`: green.
- `cargo test --workspace`: **285 passed, 0 failed, 2 ignored** (was 286 before;
  delta: +1 new smoke test, -2 grammar-shift tests now ignored).
- 11 supported languages (was 12); Kotlin returns in v1.1.

## [0.2.0-alpha.1] - 2026-05-11

This is the first alpha of the **agentic-retrieval MCP pivot**. The crate
is being repositioned from "library that calls LLMs for code analysis"
to a focused parsing/indexing core for the upcoming `rts-daemon` + `rts-mcp`
stack that serves AI coding agents (Claude Code, Cursor, Cline, Aider) over
the Model Context Protocol.

See `docs/brainstorms/2026-05-10-agentic-retrieval-mcp-requirements.md` and
`docs/plans/2026-05-10-001-feat-pivot-to-agentic-retrieval-mcp-server-plan.md`
for the full design rationale.

### BREAKING CHANGES

- **`FileInfo.security_vulnerabilities` field removed.** Anything that
  read this field on `FileInfo` no longer compiles. Use one of the
  archived security analyzers (under `archive/src/`) if you still need
  per-file vulnerability data.
- **`AnalysisConfig.enable_security` field removed.** The flag and its
  underlying security passes are gone from the default analyzer.
- **`CodebaseAnalyzer.security_analyzer` field removed.** No public method
  changed but the type is no longer constructible with a security pass.
- **The `default` Cargo feature set is reduced** from
  `["std", "ml", "net", "db"]` to `["std"]`. The `ml`, `net`, `db`, and
  `demo` features and all their gated dependencies have been removed.
- **The `tree-sitter-cli` and `rts-cli` binaries are no longer built** by
  this crate. Both wrapped `src/cli/`, which is archived. The new entry
  points are coming as separate workspace crates (`rts-daemon`,
  `rts-mcp`, `rts-bench`) per the plan.

### Removed

The following ~30k LOC of modules and their public re-exports have been
**archived** (moved to `archive/src/`, kept in git history, not built by
default). Recovery: `git mv archive/src/<mod> src/<mod>` and add the
`pub mod` declaration back.

- **AI service layer**: `ai/`, `ai_analysis.rs`, `advanced_ai_analysis.rs`,
  `embeddings.rs`, `intent_mapping.rs`, `intent_mapping_stub.rs`,
  `reasoning_engine.rs`.
- **Security analyzers**: `taint_analysis.rs`, `sql_injection_detector.rs`,
  `command_injection_detector.rs`, `security/`, `enhanced_security.rs`,
  `advanced_security.rs`.
- **Refactoring + AST transform**: `smart_refactoring.rs`,
  `refactoring.rs`, `ast_transformation.rs`.
- **Wiki + dev tooling**: `wiki/`, `fuzz_testing.rs`,
  `integration_testing.rs`, `test_coverage.rs`, `ci_cd_integration.rs`,
  `performance_benchmarking.rs`, `code_evolution.rs`.
- **CLI + binaries**: `cli/`, `bin/main.rs`, `bin/rts.rs`.
- **Infrastructure shells**: `infrastructure/` (HTTP / sqlx / rate-limiter
  shells archived; cache and config kept inline if needed).
- **Over-engineered cache**: `advanced_cache.rs`.

### Security

- Archiving the AI service layer + sqlx + reqwest removes the transitive
  dependencies that carried open `RUSTSEC` advisories on `ring`, `sqlx`,
  and `paste` per `docs/DEPENDENCY_AUDIT_REPORT.md`. The new
  `rust_tree_sitter` v0.2.0-alpha.1 has zero outbound HTTP dependencies.

### Internal

- `src/analyzer.rs` ↔ `src/advanced_security.rs` coupling severed at all
  reference sites (the field on `FileInfo`, the field on
  `CodebaseAnalyzer`, both analyze paths, the `Default` impl, and two
  module-level doctest examples).
- `src/lib.rs` rewritten from 478 lines to ~170 lines, exposing only the
  surviving parsing + analysis primitives. The crate doc no longer
  references removed AI/security features.
- Workspace pre-archive audit confirmed only **one** structural coupling
  between surviving core and cut buckets; `semantic_context.rs`'s
  earlier taint-analyzer dependency had already been commented out.
- 286 lib + integration tests pass on the slim build (was 49 test files;
  surviving file count is 15 plus the lib's 171 unit tests).

### Coming next (planned, not in this alpha)

- P1: Tree-sitter `0.20 → 0.26.8` bump with the `Query → QueryCursor +
  streaming_iterator` API migration — much smaller surface to migrate
  now that ~30k LOC is archived.
- P4: Cargo workspace split into `rts-core`, `rts-daemon`, `rts-mcp`,
  `rts-bench`. Rust 2024 edition. `#![forbid(unsafe_code)]` on
  `rts-core`.
- P5: Daemon ↔ MCP protocol-v0 design doc.
- P6 / P7: The daemon and the MCP server itself.

### Previously in [Unreleased]

The pre-pivot 0.1.x backlog (additional security CLI flags, SARIF
extensions, secrets-detector validators, deterministic false-positive
filter modes) is now in `archive/`. None of those features are part of
the agentic-retrieval product surface and they will not return in v0.2.x.

## [0.1.0] - 2024-12-19

### Added

#### Core Library
- **Multi-language parsing support** for Rust, JavaScript, Python, C, and C++
- **Safe tree-sitter wrapper** with proper Rust lifetimes and memory management
- **Comprehensive syntax tree navigation** with intuitive API
- **Advanced query system** for pattern matching and code analysis
- **Incremental parsing** for efficient code updates
- **Thread-safe parser management** for concurrent usage
- **AI-friendly codebase analysis engine** with structured output
- **Symbol extraction** for functions, classes, structs, enums, and more
- **Language detection** from file extensions and paths
- **Comprehensive error handling** with custom error types

#### Smart CLI Interface
- **`analyze` command**: Comprehensive codebase analysis with detailed metrics
- **`insights` command**: AI-friendly intelligence reports with recommendations
- **`map` command**: Visual code structure mapping with multiple formats
- **`query` command**: Advanced pattern matching with tree-sitter queries
- **`find` command**: Symbol search with wildcard support and filtering
- **`stats` command**: Detailed codebase statistics and metrics
- **`interactive` command**: Real-time codebase exploration
- **`languages` command**: Information about supported languages

#### Output Formats
- **JSON**: Structured data for programmatic processing
- **Markdown**: Documentation-ready format with rich formatting
- **Table**: Clean, readable tables for terminal viewing
- **Text**: Concise summaries with colored output
- **ASCII**: Simple tree structures for compatibility
- **Unicode**: Beautiful tree structures with icons
- **Mermaid**: Diagram generation for documentation

#### Visual Code Mapping
- **Tree structure visualization** with file metrics
- **Symbol distribution mapping** by type and visibility
- **Directory organization analysis** with size and complexity metrics
- **Mermaid diagram generation** for documentation
- **Configurable depth and filtering** options
- **Language-specific mapping** capabilities

#### Examples and Documentation
- **Basic usage example** demonstrating core functionality
- **Incremental parsing example** showing efficient updates
- **Codebase analysis example** for AI agents
- **Comprehensive README** with usage examples
- **CLI documentation** with detailed command reference
- **Implementation status** tracking

#### Testing and Quality
- **37 comprehensive tests** (22 unit + 15 integration)
- **100% test pass rate** across all functionality
- **Integration tests** for real-world usage scenarios
- **Example validation** ensuring documentation accuracy
- **Error handling tests** for robustness

#### Developer Experience
- **Beautiful CLI interface** with colors and progress indicators
- **Intuitive command structure** with helpful error messages
- **Extensive configuration options** for customization
- **Multiple output formats** for different workflows
- **Interactive exploration mode** for real-time analysis

### Technical Details
- **Language Support**: Rust, JavaScript, Python, C, C++
- **Dependencies**: tree-sitter 0.22, clap 4.0, serde 1.0, colored 2.0
- **Minimum Rust Version**: 1.70+
- **Platform Support**: Cross-platform (Windows, macOS, Linux)
- **Performance**: Optimized for large codebases with progress feedback

### Architecture
- **Modular design** with clear separation of concerns
- **Safe abstractions** over tree-sitter C library
- **Memory efficient** processing with minimal overhead
- **Thread-safe** parser management
- **Extensible** language support system
- **Configurable** analysis pipeline

### Use Cases
- **AI code agents** requiring structured codebase understanding
- **Developer tools** for code analysis and navigation
- **Documentation generation** with visual diagrams
- **Code quality assessment** with metrics and insights
- **Architecture reviews** with structural analysis
- **Team onboarding** with visual project overviews

[Unreleased]: https://github.com/njfio/rust-treesitter-agent-code-utility/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/njfio/rust-treesitter-agent-code-utility/releases/tag/v0.1.0
