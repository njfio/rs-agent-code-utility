# Wiki Refactor and Empowerment Plan

This document is a concrete, actionable task list to refactor, clean up, and enhance the Wiki generation system. Tasks are grouped into phases with acceptance criteria, code touch-points, and test notes. We will execute phases in order; phases can overlap when noted safe.

Goals

- Modularity: split the monolithic `src/wiki/mod.rs` into focused modules.
- Reliability: reduce duplication, reuse AI services/runtimes, harden filename handling, keep pages valid when assets fail.
- UX/Readability: improve navigation, search, accessibility, and page structure.
- Performance: avoid repeated builds/fetches; enable optional concurrency; bound network timeouts.
- Maintainability: centralize assets, JS, and templates; add targeted tests.


Phase 0 — Design + Baseline (short)

- Inventory current responsibilities in `src/wiki/mod.rs` and map each into a new module (see Phase 1 structure).
- Snapshot current behavior by running existing tests and generating a sample wiki; note any regressions we must avoid.
  - Acceptance: test suite passes locally; a sample wiki builds without runtime JS errors in browser console.


Phase 1 — Module Split (no new deps)

Target structure (Rust modules):

- `src/wiki/assets.rs`: write CSS/JS assets; highlight.js/mermaid bundling; CDN fallback; post-processors.
- `src/wiki/search.rs`: search index struct + JSON/JS writer; `assets/search.js` content.
- `src/wiki/diagrams.rs`: sequence/control-flow/class diagram builders; CFG helpers.
- `src/wiki/templates.rs`: HTML composition helpers for index, file, symbols, security pages (string-based, no template engine yet).
- `src/wiki/ai_integration.rs`: AI JSON/text rendering helpers; parsing/rendering functions; unify provider building.
- `src/wiki/util.rs`: `html_escape`, `sanitize_filename`, `url_encode_path`, `markdown_to_html`, `anchorize`.
- Keep `src/wiki/security_enhancements.rs` and `src/wiki/enhanced_ai.rs` as-is; wire them via the new modules.

Tasks:

- Create files above with module skeletons; move functions from `src/wiki/mod.rs` into appropriate modules with minimal churn.
- Update `src/wiki/mod.rs` to orchestrate (public surface: `WikiConfig`, `WikiGenerator`, `WikiGenerationResult`).
- Keep function signatures stable where possible to limit blast radius.

Acceptance:

- `cargo build` succeeds; tests under `tests/wiki_*` pass.
- `src/wiki/mod.rs` shrinks substantially; most HTML/JS/CSS strings live in `assets.rs` and `templates.rs`.

Notes:

- Avoid adding new crates yet. We’ll evaluate Askama/Tera later (Phase 11 optional).


Phase 2 — AI Service Unification

Problems now: duplicate provider config and multiple Tokio runtimes (`generate_file_ai_insights_sync`, `generate_ai_insights_sync`, JSON-mode flows).

Tasks:

- Add field to `WikiGenerator`: `ai_service: Option<crate::ai::service::AIService>`, `rt: Option<tokio::runtime::Runtime>`.
- Implement `fn ensure_ai(&mut self) -> Result<()>` that builds and stores a single runtime and AI service (respecting `ai_use_mock`, env vars, provider preference).
- Replace scattered builder/runtime blocks in:
  - Project AI: `generate_project_ai_block`
  - File AI: `generate_file_ai_insights_sync`, `generate_file_ai_block_and_tags`
- Centralize JSON parsing/rendering in `ai_integration.rs`.

Acceptance:

- Only one runtime/service is constructed per wiki generation run.
- Behavior unchanged in tests; AI mock tests still pass.


Phase 3 — Robust Filename Sanitization (cross‑platform)

Tasks:

- Replace `sanitize_filename` with a whitelist-based approach:
  - Replace or strip characters invalid on Windows/macOS/Linux: `\\ / : * ? " < > |` and control chars.
  - Normalize whitespace to `_`; collapse repeats; cap length (e.g., 200 chars) with a stable hash suffix if truncated.
- Update all page/file/asset link generation to use the new sanitizer.

Acceptance:

- New unit tests: reserved chars, Windows-style paths, long names, Unicode. Links resolve to existing pages.
- Existing wiki tests pass on all platforms (CI if available).


Phase 4 — Extract Inline Scripts to `assets/main.js`

Tasks:

- Move shared page JS (theme toggle, Mermaid init+parse fallback, copy buttons, sidebar toggle with persistence) from embedded `<script>` blocks into a new emitted asset `assets/main.js`.
- Update HTML templates to include `assets/main.js` and remove duplicated inline script logic.
- Keep critical small inlined bootstraps minimal if necessary (e.g., a tiny loader) but prefer external JS.

Acceptance:

- Page HTML significantly cleaner; site works identically offline.
- Browser caches `assets/main.js`; no console errors.


Phase 5 — Navigation UX

Tasks:

- Current-page highlight: mark active sidebar link (compare normalized `location.pathname`), add `.active` styling.
- Breadcrumbs at top of file pages: `Home / src / wiki / mod.rs` with links back to folder anchors or index.
- Persist open folder `<details>` states in localStorage; restore on load (keyed by folder path).

Acceptance:

- Manual check: active link styled; breadcrumbs render; expanding/collapsing folders persists across reloads.
- Add a simple test that generated HTML for a file page contains breadcrumb markup and an `.active` nav link.


Phase 6 — Search UX Enhancements

Tasks:

- Keyboard shortcuts: `/` focuses input; `Escape` clears; up/down navigate list; `Enter` opens selected.
- Show result count and time to filter; include file path under title; highlight matched terms in title/symbols.
- Add “Clear” button and chip-like facet indicators; keep language/kind filters.
- Keep slice limit (200), but expose a `--wiki-max-results` or config value to tune.

Acceptance:

- `assets/search.js` upgraded; index.json/js unchanged in format; UI reflects features.
- Tests: string checks for count label and presence of highlighted `<mark>` on a known term.


Phase 7 — Performance/Resilience

Tasks:

- Asset fetch timeouts: use a shared `reqwest::Client` with ~2s timeout for CDN fetches; handle failures silently.
- Optional parallel page generation (non-AI paths) using a scoped thread pool; guard AI calls to avoid rate-limit bursts (sequential or small async pool with backoff).
- Add a config knob for maximum indexed symbols per file to reduce search index size on large repos.

Acceptance:

- Timeouts are enforced; generation succeeds offline; logs remain clean.
- Integration tests unaffected; a large synthetic project doesn’t balloon `search_index.json` unexpectedly when capped.


Phase 8 — CLI Flags and Docs

Tasks:

- Split `--ai` fan-out into explicit toggles in `src/cli/commands/mod.rs` + `src/cli/commands/wiki.rs`:
  - `--wiki-ai`, `--wiki-ai-json`, `--wiki-security`, `--wiki-diagrams`, `--wiki-examples`, `--wiki-max-results <N>`, `--wiki-max-index-symbols <N>`, `--wiki-templates <DIR>`.
- Preserve backwards compatibility: `--ai` maps to `--wiki-ai --wiki-ai-json` unless explicitly disabled.
- Update `CLI_README.md` and `docs/CLI.md` with examples; include a short “Wiki” section in `README.md` with screenshots if possible.

Acceptance:

- New flags parsed and passed into `WikiConfig` fields; old behavior still works.
- Docs updated and build/test pass.


Phase 9 — Accessibility and Polish

Tasks:

- Add ARIA labels for buttons/inputs; mark code gutters `aria-hidden="true"`; ensure focus rings.
- Add a “Skip to content” link; support `prefers-reduced-motion`; optional high-contrast toggle.
- Ensure anchor copy buttons on symbol headers include accessible labels.

Acceptance:

- Lighthouse/aXe checks improve; manual keyboard navigation works across interactive elements.


Phase 10 — Content Quality Improvements

Tasks:

- Index page cards: Top Languages, Largest Files, and Entry Points sections connecting to relevant pages.
- File pages: add top-level “Open in editor” link; symbol sections include a small “copy link” button near anchors.
- Security pages: highlight files by severity; link to per-file sections.

Acceptance:

- New sections render; tests check for presence of headings/links.


Phase 11 — Optional: Adopt a Template Engine (Askama/Tera)

Tasks:

- Evaluate adding Askama or Tera to move HTML out of Rust strings.
- Port index, file, symbols, security pages to templates; use `include_str!` for CSS/JS or keep asset writers.
- Measure build time and binary size impact.

Acceptance:

- Templates compile; pages identical in output (whitespace aside); tests still pass.


Phase 12 — Tests Expansion

Tasks:

- Unit: `sanitize_filename`, `anchorize`, breadcrumb builder, nav active matcher.
- Integration: search enhancements (count, highlight), breadcrumbs rendered, active link present.
- Regression: sequence/flow/class diagram presence paths remain intact (keep existing tests: `tests/wiki_generator*.rs`, `tests/wiki_sequence_*.rs`).

Acceptance:

- New tests pass locally and in CI; coverage for new utilities is in place.


Phase 13 — Backward Compatibility + Cleanup

Tasks:

- Deprecate legacy implicit `--ai` fan-out in help text; keep mapping for now.
- Remove dead code left in `src/wiki/mod.rs` after splits; ensure re-exports keep public API stable.
- Run `cargo clippy --all-targets --all-features` and fix warnings.

Acceptance:

- No public-breaking API changes; lints are clean or justified.


Implementation Pointers (current code references)

- Asset writers and replacements: `src/wiki/mod.rs` write_* at approximately lines around: style/search/hljs/mermaid (620–760), and `postprocess_cdn_refs` (~520–560).
- Search index: `write_search_index` (~1400s) and embedded script includes on index/pages (~740, ~1683).
- AI flows: file/project JSON/text builders (~1120–1340, ~1835–1920) and `parse_ai_json` (~212–239).
- Diagrams: `build_sequence_diagram`, `build_control_flow`, `build_sequence_or_flow_blocks`, `file_has_branching` (~860–1100, ~1300s).
- Utilities: `html_escape`, `sanitize_filename`, `url_encode_path`, `markdown_to_html` (~1910–2000s).


Definition of Done

- Modular codebase with assets/search/templates/ai/util split.
- Single AI service/runtime reused; no duplicate provider config blocks.
- Cleaner HTML pages that reference `assets/main.js`; improved nav, search UX, and accessibility.
- Tests updated and green; docs updated; CLI flags explicit and backward compatible.


Rollout Plan

1. Phase 1 + 2 + 3 (module split, AI unification, filename fix).
2. Phase 4 + 5 + 6 (assets/main.js, nav/search UX).
3. Phase 7 + 8 (performance timeouts + CLI flags/docs).
4. Phase 9 + 10 (A11y and content polish).
5. Phase 11 (optional templates) after stability.
6. Phase 12 + 13 (tests expansion + cleanup/deprecations).

Owner/Review

- Primary owner: Wiki module maintainers.
- Reviewers: CLI maintainers (flags/docs), Security module owners (security pages), AI team (AI integration).

