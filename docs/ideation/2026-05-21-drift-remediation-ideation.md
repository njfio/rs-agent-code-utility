---
date: 2026-05-21
topic: drift-remediation
focus: docs and code drift after the 24-PR v0.6 arc — placeholders, version skew, function-set divergence, comment claims, public-surface bloat, security gap, file-size hotspot, feature surface bloat
---

# Ideation: Drift Remediation After the 24-PR v0.6 Arc

## Codebase Context

Across 2026-05-19 / 05-20 / 05-21 the project shipped 22 PRs (#109–#131; +2 docs polish to #131) adding capabilities (Index.Grep v2, persisted cold-mount, cancellation, telemetry, MCP resilience, AST queries 6→10 languages, schemas, real-repo bench, dogfood harness, GC, adversarial fuzzing harness). Each PR's quality gate caught the prior PR's regressions; six automated infrastructure dividends (schema drift, tool descriptions, real-repo bench, two flake-fix templates, adversarial fuzz) compounded.

Despite that velocity, the maintainer noticed **drift between what the code is and what the code claims to be**. Verified on 2026-05-21 with direct file reads:

| Drift item | Evidence |
|------------|----------|
| Root `Cargo.toml` ships placeholders | `authors = ["Your Name <your.email@example.com>"]`, `repository = "https://github.com/yourusername/rust_tree_sitter"` |
| Version skew between workspace and crate | Workspace `0.5.5` ↔ `crates/rts-core/src/lib.rs:1` claims `0.2.0-alpha: in-progress retrieval pivot` |
| Two divergent language-set functions | `supported_languages()` (lib.rs:143) returns 7; `detect_language_from_extension()` (lib.rs:184) supports 12 (Java/PHP/Ruby/Swift/C#/cjs/hh detected but not advertised) |
| Top-of-file comment stale | `crates/rts-mcp/src/server.rs:1-6` claims "four MCP tools"; file has 10 `#[tool]` attributes |
| `rts-core` public surface broad | Publicly exports `CodebaseAnalyzer`, `AnalysisConfig`, `AnalysisResult`, `Symbol`, `SemanticGraphQuery`, `code_map::build_call_graph` — pre-pivot kitchen-sink that the daemon doesn't use |
| `methods/index.rs` is a maintenance hotspot | 3258 LoC; 25+ functions across 7 protocol verbs (validation + grep + symbol + body reading + PageRank + closure walking + response shaping) |
| Secrets-safe boundary gap | `crates/rts-daemon/src/filter.rs:113` allows body reads of `md, toml, yaml, yml, json, xml`; content scanning is deferred per the file's own preamble; config files often carry secrets |
| Feature surface bloat for pre-1.0 | PageRank, doc-comment retrieval, Grep v2, structural queries, within-symbol grep, telemetry, doctor, CLI, benchmarks, cold-mount, reconnect loops — broad surface that the README's "retrieval stack" framing undersells |

**Ground-truth verification by agent A:** confirmed zero imports of `complexity_analysis`, `control_flow`, `dependency_analysis`, `memory_tracker`, `performance_analysis`, `semantic_context`, `semantic_graph` (plus `symbol_table`, `advanced_parallel`, `file_cache`, `code_map`, `analysis_common`, `analysis_utils`) from rts-daemon, rts-mcp, or rts-bench. These rts-core modules are publicly exported but never consumed.

## Ranked Ideas

### 1. rts-core dead-module archive + public-surface tightening + metadata cleanup

**Description:** Triple cleanup of `rts-core`. **(a)** Archive `complexity_analysis`, `control_flow`, `dependency_analysis`, `memory_tracker`, `performance_analysis`, `semantic_context`, `semantic_graph` (plus `symbol_table`, `advanced_parallel`, `file_cache`, `code_map`, `analysis_common`, `analysis_utils`) — agent A verified ZERO imports from the daemon/MCP/bench crates. **(b)** Demote `CodebaseAnalyzer` / `AnalysisConfig` / `AnalysisResult` / `Symbol` re-exports to `pub(crate)` and expose a tiny `rts_core::parse_file(path) -> Vec<Symbol>` facade (only callsites are `writer.rs:763` and `writer.rs:22`). **(c)** Fix Cargo.toml placeholder authors + repo URL; strip the `0.2.0-alpha` header from `rts-core/lib.rs:1`; add a `tests/metadata.rs` that asserts no placeholder strings + version consistency; add `cargo public-api --deny-changes` against a checked-in baseline.
**Rationale:** Highest-evidence removal of the bunch — 7+ modules with zero usage that contradict rts-core's own "Removed in 0.2.0" claim. Tightening the public surface stops library consumers (and future agents) from believing `CodebaseAnalyzer::analyze_directory` is a supported retrieval entry point. The `cargo public-api` baseline turns "oh we accidentally exported X" into a reviewed diff forever after.
**Downsides:** Diff is large (multiple crates touched); requires careful import-graph verification before archiving each module; introduces `cargo public-api` as a new dev-dep; external consumers who imported `complexity_analysis` from a previous version get a breaking change (mitigated by pre-1.0 status + CHANGELOG note).
**Confidence:** 95%
**Complexity:** Medium
**Status:** Explored — brainstormed 2026-05-21

### 2. Surface manifest drift-detection — generalize PR #122's lockfile pattern

**Description:** Extend PR #122's schema-drift mechanism into a workspace-wide `surfaces/<crate>.toml` manifest enumerating every public surface: MCP tools, daemon methods, CLI subcommands, language registry, file-type handlers, capability strings. A `cargo xtask surfaces-check` step re-derives each list via `syn` AST walking (`#[tool]`, `register_method!`, clap subcommands) and diffs against the manifest. CI fails on diff; updating the manifest is a deliberate file edit in the PR. Complement with `insta`-style snapshots on prose-shaped surfaces (`--help`, MCP capability resource, tool description list) so reviewers see "4 tools became 10" as a 6-line diff.
**Rationale:** Catches drift items #3 (language sets), #4 (top-comment claim mismatch), and the entire class of "prose enumerates N things but code has M." The single mechanism replaces 3-4 narrower per-class gates. PR-review experience becomes "look at the surface diff" — review surface scales with surface size, not arbitrarily. Generalizes the existing PR #122 dividend.
**Downsides:** ~1-2 days to build the syn-AST walkers; new mental model for contributors (the manifest is the contract); mistakes in the walkers cause false-positive CI failures that erode trust. Mitigation: ship one surface at a time, start with MCP tool list.
**Confidence:** 90%
**Complexity:** Medium
**Status:** Unexplored

### 3. v0.6 release-engineering bundle (tag + experimental gate + noun + retire pre-release)

**Description:** Three coordinated moves, all depending on the v0.6 tag cut. **(a)** Cut `v0.6.0` tag from current HEAD; replace "Active pre-release" framing with "v0.6 — stable for daily use; pre-1.0 means we may still break protocol-v0". **(b)** Lock v0.6 MCP-tool + CLI-subcommand surface; new work lands as `experimental_*` prefix (MCP) / `--experimental` flag (CLI) / `#[cfg(feature = "experimental")]` (code), with a 30-day promotion ladder + stabilization PR. **(c)** Standardize "code KB" as canonical noun across README lead, crate preambles, plans, commit titles. The noun is already half-adopted internally (README line 9: "persistent code knowledge graph"; plan filename `2026-05-13-001-feat-v0.3-code-graph-kb-plan.md`).
**Rationale:** "Retrieval" undersells PageRank, ImpactOf, doc-IDF, structural grep, within-symbol scope — all code-intelligence features. Calling them "retrieval" makes them feel like scope creep; calling the product a "code KB" makes them feel like table of contents. Cutting v0.6.0 also removes the "everything is alpha" linearization that lets accretion feel cheap. The experimental gate gives new work somewhere to land without inflating the v0.6 stable surface.
**Downsides:** Tagging v0.6.0 commits to honoring protocol-v0 as it stands — any current ambiguity becomes a real backcompat constraint. Vocabulary changes have a long tail. Experimental-vs-stable distinction adds reviewer overhead.
**Confidence:** 80%
**Complexity:** Low-Medium
**Status:** Unexplored

### 4. methods/index.rs decomposition + max-file-length lint gate

**Description:** Split the 3258-line `crates/rts-daemon/src/methods/index.rs` into per-verb sibling files (`methods/index/find_symbol.rs`, `methods/index/grep.rs`, `methods/index/read_range.rs`, `methods/index/read_symbol.rs`, `methods/index/read_symbol_at.rs`, `methods/index/outline.rs`, `methods/index/callers.rs` + `impact_of`); shared validation/util in `methods/index/util.rs`. Then add an `xtask check-budgets` CI step with hard cap (1500 lines hard / 1000 warn) and an explicit `budgets.toml` override that requires a justification comment to bump.
**Rationale:** 3258 LoC across 25+ functions covering 7 protocol verbs is the canonical maintenance hotspot. One-time decomposition fixes it; lint prevents recurrence. The override-with-justification pattern keeps the gate from being a productivity tax while still making oversize files reviewable diff events.
**Downsides:** Large diff for the initial split (blame disruption mitigated via `git log --follow`); CI step adds ~5s. Some methods may benefit from co-location (shared private helpers) — mitigated by `util.rs`.
**Confidence:** 90%
**Complexity:** Medium
**Status:** Unexplored

### 5. Secrets-safe boundary: immediate cut of config extensions

**Description:** Strip `md, toml, yaml, yml, json, xml` from `crates/rts-daemon/src/filter.rs::BODY_ALLOWED_EXTENSIONS` immediately. Until the deferred content scanner (high-entropy + known-token regexes) lands, body reads of `pyproject.toml`, `.github/*.yml`, `package.json`, `composer.json`, `appsettings.json`, `web.xml`, project READMEs with embedded creds are a foot-gun. Add a `proptest` harness that throws adversarial payloads at the allowlist's surviving extensions to lock in the cut. Re-additions require either (a) the content scanner shipping or (b) the deferred Promise-token pattern providing an alternative invariant (deferred to its own brainstorm).
**Rationale:** Closes a real secrets-exfiltration vector with one deletion. Config files are where `aws_access_key_id`, OAuth tokens, `.env`-via-yaml, CI secret blocks actually live; trusting the filename-only blocklist for them is the bet the preamble warned against. Matches AGENTS.md Rule 12 (fail loud, not silently permissive).
**Downsides:** Removing the six extensions narrows the daemon's usefulness for grep'ing markdown docs / config files — a real loss until the content scanner ships. Some legitimate use cases (find a string in `pyproject.toml`, search a Helm chart) become impossible until then.
**Confidence:** 95%
**Complexity:** Low
**Status:** Unexplored

### 6. Single-source language registry (collapse to one const table)

**Description:** Refactor `supported_languages()` and `detect_language_from_extension()` so they both derive from one `const LANGUAGES: &[LanguageDef]` table in `rts-core/src/languages.rs` (language name + extensions + tree-sitter language constructor). Add a `#[test]` that exercises every row in both directions, plus a grep test that fails CI if any language-name string literal appears outside the registry module.
**Rationale:** Verified gap (`supported_languages()` lists 7; `detect_language_from_extension()` supports 12). Eliminates the class structurally, not just detection-after-the-fact. Establishes a pattern: anywhere two functions enumerate the same domain, collapse to a const table + test that exercises every row.
**Downsides:** Touches every callsite that imports either function; one-time migration cost. Honest note: this is a HYGIENE move, not a TRAJECTORY move — shipping it alone leaves the project only marginally better in 30 days.
**Confidence:** 95%
**Complexity:** Low
**Status:** Unexplored

## Rejection Summary

| Rejected idea | Source | Reason rejected |
|---|---|---|
| Deprecate the human CLI (rts find/grep/callers/outline) | A#8 | Just shipped in PR #113; dogfood harness (#125) actively measures tool-selection impact — deprecating discards signal |
| Fold `find_callers` + `impact_of` into `find_symbol` | A#9 | Premature unification; no expressed pain with current surface; agents already gate via comparative tool descriptions from PR #121 |
| Rename `rts-core` → `rts-parse` + `rts-graph` | C#1 | Disruptive package-name churn; survivor #1's dead-module archive achieves the scope-tightening goal without rename pain |
| Split project into umbrella + rts-kb + rts-mcp + rts-cli + rts-eval | C#4 | Too disruptive for a remediation arc; warrants its own dedicated ideation round |
| Treat rts-bench as a separate `rts-eval` product | C#7 | Same scope-too-large concern; can be revisited as its own ideation once #1 ships |
| Reframe as MCP-and-CLI peer (separate from #3) | C#6 | Already implicit in PR #130's docs refresh; doesn't need separate work |
| Weekly drift-detector cron workflow | D#7 | Per-PR surface manifest gate from survivor #2 catches most; cron-shaped variant is defense-in-depth, can ship later if needed |
| Hard numeric ceilings (12 MCP tools, 8 CLI subcommands) | D#2 | Too brittle for a solo-maintainer pre-1.0 project; experimental gate (in survivor #3) provides the same forcing function more flexibly |
| Mandatory PR-template checklist | D#9 | Over-engineered for a solo maintainer; would ossify and become rubber-stamped |
| Promise-token pattern for type-enforced safety claims | D#6 | Speculative type-system design; right shape isn't clear without working through 2-3 concrete callsites first — DEFERRED to its own brainstorm rather than rejected |

## Session Log

- 2026-05-21: Initial ideation — 34 raw candidates generated across 4 frames (inversion/removal, drift-detection automation, reframing, pre-1.0 surface policy), merged/deduped to 12, critiqued to 7 survivors. Second adversarial pass (strict rubric: "would I ship this if it were the ONLY remediation move?") consolidated to 6 refined survivors; dropped hard ceilings + PR checklist as over-engineered; deferred Promise pattern to its own brainstorm.
- 2026-05-21: User selected idea #1 (rts-core dead-module archive + public-surface tightening + metadata cleanup) for brainstorming.
