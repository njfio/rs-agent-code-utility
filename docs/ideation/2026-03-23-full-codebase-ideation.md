---
date: 2026-03-23
topic: full-codebase-improvement
focus: full codebase
---

# Ideation: Full Codebase Improvement

## Codebase Context

**rust_tree_sitter** is a Rust library (~94K lines, 50+ modules) for tree-sitter-based code analysis with AI-powered capabilities. It supports 7 languages (Rust, JS, TS, Python, C, C++, Go) and ships two CLI binaries.

Key characteristics:
- Core parsing is production-ready (~2ms/1K LOC, ~5ms/1K LOC analysis)
- AI features (6 provider backends) are stubs/placeholders (~15K lines)
- Security scanning has high false positive rate (14 files, ~16K lines, 3 overlapping filters)
- 506 crates (34 direct, 472 transitive) -- heavy dependency tree
- Known CVEs: ring 0.17.9, sqlx 0.7.4
- 200+ .clone() calls in hot paths
- Performance analysis uses function-name string matching instead of AST traversal
- TDD enforced, functional patterns preferred, Builder pattern for complex config

## Ranked Ideas

### 1. MCP Tool Server Pivot (Strategic Combo)
**Description:** Stop being an AI client with broken stubs. Become an AI tool provider. Delete ~15K lines of placeholder AI code, slim the dependency tree, and expose the library's working capabilities (parsing, semantic graph, taint analysis, complexity metrics) as an MCP tool server. Any AI agent can then call this tool for ground-truth code analysis.
**Rationale:** The AI provider abstraction has 6 backends, all stubs. The project can't compete as an AI client. But it can provide structured code facts that AI tools lack. MCP is designed for exactly this pattern.
**Downsides:** MCP is nascent; ecosystem adoption uncertain. Multi-phase effort.
**Confidence:** 85%
**Complexity:** High
**Status:** Unexplored

### 2. Replace String Heuristics with Real AST Analysis
**Description:** The performance_analysis.rs module detects hotspots by checking function names for strings like "nested", "loop", "alloc". Replace with actual tree-sitter AST traversals.
**Rationale:** A tree-sitter tool that pattern-matches on function names is a contradiction. Existential credibility issue.
**Downsides:** Requires per-language AST patterns. Moderate effort per language.
**Confidence:** 92%
**Complexity:** Medium
**Status:** Unexplored

### 3. Unified Security Pipeline with Confidence Scoring
**Description:** Consolidate 14 security files (~16K lines) into a single SecurityPipeline with pluggable stages. Add confidence scores and `// rts-ignore[rule-id]` inline suppressions. Replace the "ML" filter with honest deterministic rules.
**Rationale:** High false-positive rate is the #1 adoption blocker. Three overlapping filter layers share no taint state. Confidence scores + suppressions are table stakes for CI-integrated scanners.
**Downsides:** Largest single effort. Risk of breaking existing security tests.
**Confidence:** 80%
**Complexity:** High
**Status:** Unexplored

### 4. Dependency Pruning + Feature Stratification
**Description:** Change default features from `["std", "serde", "ml", "net", "db"]` to `["std", "serde"]`. Gate CLI-only deps behind `cli` feature. A `cargo add rust_tree_sitter` should give parsing + analysis in ~30 crates, not 506.
**Rationale:** Supply chain liability (known CVEs), compile-time tax, embedding impracticality. Prerequisite for future WASM target.
**Downsides:** Breaking change for downstream users. Requires careful dependency audit.
**Confidence:** 90%
**Complexity:** Medium
**Status:** Unexplored

### 5. Cross-File Taint Analysis
**Description:** Extend intra-procedural taint analysis to track data flows across function calls, module boundaries, and language boundaries using the existing semantic graph.
**Rationale:** Only open-source competitor with cross-file taint is Semgrep Pro (paid). Real vulnerabilities rarely live in a single file. Infrastructure exists but isn't connected.
**Downsides:** Research-grade problem. High risk of incomplete implementation.
**Confidence:** 55%
**Complexity:** High
**Status:** Unexplored

### 6. Language-Agnostic Security Rule DSL
**Description:** Define security rules as declarative data files (YAML + tree-sitter query patterns) that reference semantic relationships and taint paths, not just syntax.
**Rationale:** Adding language coverage currently requires new Rust modules. A DSL lets security researchers contribute without knowing Rust. Differentiates from Semgrep's syntax-only patterns.
**Downsides:** DSL design is its own project. Could use tree-sitter .scm queries to reduce scope.
**Confidence:** 65%
**Complexity:** High
**Status:** Unexplored

### 7. Self-Analyzing Dogfood CI
**Description:** Add one CI step: run `rts-cli analyze src/` on every commit. Track metrics over time. Fail CI if self-analysis score drops below threshold.
**Rationale:** Cheapest way to surface real bugs. Makes every analyzer improvement self-discovering. Most credible demo for users.
**Downsides:** May expose embarrassing false-positive rate on own code (which is also the point).
**Confidence:** 95%
**Complexity:** Low
**Status:** Unexplored

## Rejection Summary

| # | Idea | Reason Rejected |
|---|------|-----------------|
| 1 | Eliminate .clone() epidemic | Micro-optimization; fix opportunistically via Clippy lints |
| 2 | Module consolidation / workspace split | Multi-week refactor, no user-visible value; feature flags suffice |
| 3 | LSP server mode | Enormous implementation burden; fix analysis accuracy first |
| 4 | WASM build | Half deps WASM-incompatible; dependent on dep diet; premature |
| 5 | Delete 22 stale markdown docs | Trivial janitorial work, not strategic (just do it) |
| 6 | Upgrade tree-sitter to 0.24+ | Mechanical maintenance; no user-facing differentiation |
| 7 | Incremental analysis pipeline | Tool runs at 2ms/1K LOC; no demonstrated perf problem |
| 8 | Wire semantic graph into AI pipeline | AI pipeline doesn't work; relevant only after MCP pivot |
| 9 | Differential benchmark regression gate | Easy CI task but not strategic; just wire up critcmp |
| 10 | Streaming/event-driven API | LSP-lite repackaged; same burden, no demonstrated need |
| 11 | Fix broken dependency analyzer | Bug fix; important but just fix it |
| 12 | Flip architecture: tree-sitter as plugin | Architectural astronautics; YAGNI |
| 13 | Replace ML false-positive filter | Sub-task of security pipeline consolidation (#3) |
| 14 | Adversarial input fuzzing for detectors | Sub-task of security pipeline consolidation (#3) |
| 15 | Property-test security detectors | Sub-task of security pipeline consolidation (#3) |
| 16 | Structured output (SARIF/CodeClimate) | Already partially implemented; finish as part of security work |
| 17 | Arena-allocated AST metadata | Interesting but premature optimization |
| 18 | Confidence-scored security (standalone) | Absorbed into unified security pipeline (#3) |

## Session Log
- 2026-03-23: Initial ideation -- 48 raw ideas generated across 6 frames, deduped to 25 unique + 4 cross-cutting combinations, 7 survived adversarial filtering. Plan handoff requested.
