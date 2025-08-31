High-Impact Improvements

Templating and modularization

Split src/wiki/mod.rs into submodules: assets.rs (CSS/JS writers), templates.rs (HTML rendering), ai.rs (AI specifics), security_pages.rs, diagrams.rs, search.rs, util.rs.
Move HTML out of rust strings to templates. Consider Askama or Tera. Start with index, file, symbols, security pages to gain readability and testability.
Add a tiny renderer trait so pages are composable and testable as pure functions.
Reuse AI service and Tokio runtime

Build AIService once and reuse for the project + files. Create it in WikiGenerator::new or first-use, store in the struct (Option<AIService>), and reuse (src/wiki/mod.rs:1120, :1835).
Extract “build_ai_service” helper to remove repeated provider config blocks.
Safer filenames cross‑platform

Update sanitize_filename to replace \\ / : * ? \" < > | and whitespace. Use a fixed whitelist or sanitize-filename crate if acceptable (src/wiki/mod.rs:1910).
Move inline scripts to assets/

Extract page init (theme toggle, mermaid init, copy buttons, sidebar toggle) to assets/main.js; keep HTML leaner and browser-cacheable (src/wiki/mod.rs:716–:968, :1680–:1760).
Nav and page affordances

Current-page highlight: add JS to mark the active link in the sidebar (compare normalized location.pathname) and CSS to emphasize it (src/wiki/mod.rs:1346).
Breadcrumbs: add “Home / src / wiki / mod.rs” in the page header using the file.path parts with links to folder anchors in nav (src/wiki/mod.rs:1697).
Persist expanded folders: store open <details> states per folder in localStorage and restore on load.
Search UX

Add keyboard shortcuts: “/” focuses search, up/down to navigate results, Enter opens; track selected result index (assets/search.js).
Show results count, highlight matched terms, include file path under title for context.
Lightweight fuzziness: simple subsequence scoring or use a small fuzzy scorer (no heavy deps).
Add facet chips (language, kinds) and clear button.
Content structure and clarity

Add “Open file in editor” link near title for the whole file (not just per snippet) (src/wiki/mod.rs:1680).
Symbol headers: add “copy link” hover icon for deep-linkable anchors (src/wiki/mod.rs:1567–:1606).
Code blocks: mark gutter aria-hidden="true", add aria-label for copy buttons (src/wiki/mod.rs:1561).
TOC on index is good; also add “Top Languages” and “Largest Files” cards with links to filtered views (src/wiki/mod.rs:706—project snapshot source is nearby at :210).
Accessibility and polish

Add ARIA labels to toggles and form controls; add a “Skip to content” link near <header>.
Provide high-contrast mode toggle; ensure focus rings are consistent.
Respect prefers-reduced-motion for animations and Mermaid rendering.
Performance and reliability

Bound asset fetch timeouts (e.g., 1–2s per asset) and swallow failures cleanly (src/wiki/mod.rs:704, :724).
Limit search index size by truncating symbol arrays per file or indexing only names and kinds; optionally gate with a --wiki-max-index flag.
Parallelize page generation (scoped threads) once AI service is reusable; don’t parallelize AI calls unless rate limit aware.
CLI and configuration

Expose flags separately instead of reusing --ai for all features (src/cli/commands/mod.rs:107):
--wiki-ai, --wiki-ai-json, --wiki-security, --wiki-diagrams, --wiki-examples, --wiki-templates <dir>, --wiki-max-index <n>.
Document wiki command thoroughly in CLI_README.md and docs/CLI.md with examples and screenshots.
Concrete Code Targets

src/wiki/mod.rs:1910 sanitize filenames: handle backslashes and reserved characters.
src/wiki/mod.rs:1120, :1835 factor AI builder to a single helper, stored on the struct; reuse a single tokio runtime.
src/wiki/mod.rs:716–:968, :1680–:1760 extract inline JS to assets/main.js.
src/wiki/mod.rs:1346 highlight active nav link; persist folder states via localStorage.
src/wiki/mod.rs:1561 mark code gutters aria-hidden, add aria-label for copy buttons.
src/cli/commands/mod.rs:107 split wiki flags; src/cli/commands/wiki.rs:1 handle new flags in the builder.
Make It More Useful (Content Ideas)

Project landing: “Getting Started” hint based on entrypoints found; “Commands to run” if rust main/bin detected (src/wiki/mod.rs:221 uses basic entrypoint detection).
Cross-file relations: a page showing “who calls this function” using CFG + simple heuristics for references already in place (src/wiki/mod.rs:996).
Quality signals: show files with high symbol count/lines; basic hotspots on index with links.
Security: add “Files by severity” section and direct links to hotspots (already generating dedicated pages; promote them on index).
Testing Additions

Windows path tests for sanitize_filename and index links.
Active nav highlight and breadcrumb presence tests.
Search: keyboard shortcut behavior and results count in a minimal fixture.
AI JSON mode: ensure graceful fallback when parse fails.