---
title: "feat: markdown indexing — first-class prose retrieval"
type: feat
status: active
date: 2026-05-26
origin: docs/brainstorms/2026-05-26-markdown-indexing-prose-retrieval-requirements.md
---

# feat: markdown indexing — first-class prose retrieval

## Enhancement Summary

**Deepened on:** 2026-05-26 (same day). 8 parallel review agents
(architecture-strategist, code-simplicity-reviewer, agent-native-reviewer,
pattern-recognition-specialist, performance-oracle, security-sentinel + 2
skill-applying agents for dependency-audit and implementation-strategy).

### Corrections applied
1. **`BODY_ALLOWED_EXTENSIONS` already contains `"md"`** — original U4 was
   factually wrong about the gate. Only `"markdown"` (long form) needs
   adding. The actual short-circuit today is `info_for_path()` returning
   `None` at `crates/rts-daemon/src/language.rs:391`. Plan corrected.
2. **PageRank dangling-mass was misdescribed.** "Headings get min PageRank"
   is wrong: nodes with zero out-edges have their rank redistributed via
   the teleport vector each iteration, landing roughly at the uniform
   baseline — potentially *above* real code symbols with weak in-edges, and
   dilutes every code SID's share by growing the denominator. **New
   mitigation**: post-PageRank × 0.1 weight for `kind=="heading"` in
   `edge_weight` (mirrors the existing leading-underscore × 0.1 rule).
3. **`kind` flattened to `"heading"`** (was `"heading-1"`..`"heading-6"`).
   Reasons: matches the established single-word lowercase convention
   (`function`, `struct`, `enum`, `method`, …); depth is conveyed by
   `signature` (rendered as `## Installation`) and the hierarchical
   `qualified_name`; no new lexical shape (hyphen + digit) for downstream
   consumers to learn.
4. **Dead state dropped**: `MARKDOWN_REFS_CACHE: OnceLock<Option<Query>>`
   (always `None` in v1) and the empty `languages/markdown.rs` sub-module.
   C, C++, and C# are the precedent — they have neither. Cargo-culting
   pattern shape without payload.

### Additions
- **`documentation` field populated** from the first paragraph of body
  text following each heading. Enables `find_symbol --kind heading
  --doc-contains "retry"` queries (the `find_symbol_doc_filter`
  capability already wired for code).
- **Per-file 4 MB byte cap on `.md`** as a parser-DoS guard
  (`Parser::set_timeout_micros` is a documented no-op since tree-sitter
  0.26 — pre-existing limitation; byte cap is the cheap v1 mitigation).
- **CLI-vs-MCP parity assertion** in the integration test (was implicit;
  now explicit).
- **Dispatch-agreement invariant test**: iterate `Language::all()` and
  assert `info_for_path` ⇔ `extract_symbols` dispatch agree (catches the
  C# omission class of bug for future languages).
- **`non_exhaustive` check on `Language` enum** before snapshot regen
  (if not `non_exhaustive`, the additive variant is technically breaking
  for downstream exhaustive matchers — still safe under 0.x but a
  deliberate decision).
- **Changelog fragment language strengthened** to call out the behavior
  change (existing workspaces gain markdown rows on upgrade) — not just
  a feature add.

### Findings noted but not changing the plan
- **C# omission deferral remains correct** (don't bundle unrelated fixes
  into a feature PR — confuses snapshot diff).
- **`MarkdownParser` two-pass deferral remains correct** (inline grammar
  is only useful when links-as-references lands; deferred to v2).
- **Test filename `markdown_indexing.rs` vs `indexing_markdown.rs`**
  (per `call_edges_<lang>.rs` precedent): mild deviation, acceptable.
- **Release build adds ~6–15 s per target**: minor; no mitigation needed.
- **Sigstore attestation auto-extends to new dep**: no workflow change.

### Risks added
- **NAME_TO_SID collision storm** on common heading names ("Installation",
  "Usage", "Overview" repeat across many files).
- **Cold-walk stalls on monorepo `docs/` trees** (docusaurus / k8s-docs:
  3–10 k `.md` files; first-mount post-upgrade could stall MCP calls
  5–30 s).

## Overview

Add **markdown as a 13th indexed language** to rts, unlocking AST-precise prose
retrieval (README, AGENTS.md, design docs, CHANGELOG, `changelog.d/`,
agent-authored notes) through the *same* tools that retrieve code today —
`find_symbol`, `outline_workspace`, `grep`. **No new MCP tool, no new CLI
subcommand**: additive behavior behind the v0.6 frozen surface.

The brainstorm reframed the original "should we add memory to rts" question as
a broader **prose-retrieval** feature, with cross-session agent notes as one
use case it enables. This plan executes that reframe.

Target release: **v0.7.0** (minor bump per 0.x semver — new capability, no
breaking change).

## Problem Statement / Motivation

rts indexes 12 code languages but **not markdown**. Every project's prose —
READMEs, design docs, AGENTS.md, CHANGELOG, agent notes — is invisible to
`find_symbol`, `outline_workspace`, and `grep`. The agent falls back to `Bash`
`rg`/`find` on those files (the exact behavior `.claude/hooks/rts-nudge.sh`
discourages everywhere else), exposing an inconsistency between the rts pitch
and what rts actually covers.

This gap was hit directly during the v0.6 cleanup arc this month — `rts grep
"retrieval stack"` returned 0 hits because the term lived in README/CHANGELOG/
docs, which aren't indexed. Indexing markdown closes that class of bug.

See origin: [docs/brainstorms/2026-05-26-markdown-indexing-prose-retrieval-requirements.md](../brainstorms/2026-05-26-markdown-indexing-prose-retrieval-requirements.md).

## Proposed Solution

**Block-only `tree-sitter-md` integration** + a handwritten heading-extraction
query, surfacing markdown headings as `Symbol` records with `kind="heading"`
(flat — depth in `signature`/`qualified_name`). v1 deliberately scopes:

- **Block grammar only** — `tree_sitter_md::LANGUAGE`. The inline grammar (and
  the `parser`-feature two-pass `MarkdownParser`) stays out of v1; deferred to
  v2 when "markdown links as references" lands.
- **Headings only as symbols** — no paragraphs, no list items, no code blocks
  (industry consensus from ctags / Marksman / VSCode / JetBrains — anti-pattern
  A1 from best-practices research).
- **`kind="heading"` (flat)** — `Symbol.kind` is a free-form `String`, but the
  existing 15 emitted values are all single-word lowercase nouns. Depth (H1–H6)
  is conveyed by the `signature` field (`## Installation`) and the hierarchical
  `qualified_name`. No new lexical shape; no Symbol field addition.
- **Hierarchical `qualified_name`** — e.g. `README.md > Installation > Prebuilt`
  (flat list of symbols with hierarchy encoded in the qualified name; matches
  Marksman's documented best practice — anti-pattern A2 avoided).
- **`documentation` field captured** from the first paragraph of body text
  immediately following the heading. Enables `find_symbol --doc-contains` to
  work over prose (the existing `find_symbol_doc_filter` capability).
- **All tracked `.md`/`.markdown` files** indexed (gitignore-aware, same rule
  as code; no curated default, no opt-out config in v1).
- **Heading PageRank weight: × 0.1** in `edge_weight` (mirrors the existing
  leading-underscore × 0.1 weight). Dangling-mass redistribution would
  otherwise push headings to a roughly-uniform baseline that can crowd out
  weakly-connected code symbols.
- **Per-file 4 MB byte cap** on `.md` extraction as a parser-DoS guard
  (`Parser::set_timeout_micros` is a documented no-op since tree-sitter 0.26).
- **One capability flag**: `"index_markdown"` added to
  `Daemon.Ping.capabilities[]`.

The v0.6 frozen surface (10 MCP tools + 10 CLI subcommands, names + argument
shapes) is **untouched** — markdown is additive *behavior* behind existing
tools.

## Implementation Units

### U1. Cargo dep + `Language::Markdown` variant + facade updates

**Goal**: register `tree-sitter-md` as a workspace dep and add
`Language::Markdown` as the 13th variant, with all `impl Language` matches
and facade entries.

**Files**:
- `crates/rts-core/Cargo.toml` — add `tree-sitter-md = "0.5.3"` (default
  features only; the `parser` feature pulls in two-pass `MarkdownParser`
  which v1 doesn't use).
- `crates/rts-core/src/languages/mod.rs` — add `Markdown` variant at
  `:19-44`; extend matches at `:52-67, 70-85, 88-103, 106-121, 124-139,
  145-160, 163-178, 181-196, 199-214, 233-256`.
- `crates/rts-core/src/lib.rs` — add markdown entry to `supported_languages()`
  at `:140-205` (`version: "0.5"`); add `("md", Language::Markdown),
  ("markdown", Language::Markdown)` to `detect_language_from_extension` at
  `:208-224`.

**Approach**: characterization-first. Add the `Markdown` variant; build the
workspace; iterate adding match arms until `cargo build --workspace` compiles.
Existing tests must still pass with the new variant before extraction logic
lands.

**No per-language sub-module.** C, C++, and C# already lack `pub mod
languages::<lang>` (these languages have no language-specific syntax helpers
to expose). `python.rs` is 1187 lines of real Python-specific helpers;
markdown has no equivalent surface. Following the C/C++/C# precedent saves a
file and a snapshot entry. (The C# omission flagged in repo-research is a
separate consistency cleanup — out of scope for this PR; the omission is
correct *by absence-of-need*, not a bug.)

**Patterns to follow**:
[docs/plans/2026-05-18-005-feat-ast-precise-call-edges-java-php-swift-csharp-plan.md](2026-05-18-005-feat-ast-precise-call-edges-java-php-swift-csharp-plan.md)
is the direct precedent for adding a new language.

**Verification**: `cargo build --workspace`, `cargo test -p rust_tree_sitter`
(existing tests pass), `cargo clippy -p rust_tree_sitter --all-targets` clean.

### U2. Symbol extraction — `extract_markdown_symbols`

**Goal**: extract `atx_heading` and `setext_heading` nodes as `Symbol`
records with `kind="heading"`, `name = trimmed inline text`, `qualified_name
= hierarchical path`, `documentation = first paragraph of body`, `signature
= "<#…> <name>"`.

**Files**: `crates/rts-core/src/extraction.rs` — add `extract_markdown_symbols`;
add arm to dispatch at `:18-59`.

**Approach**: test-first. Write tests in the inline `mod tests` first
(precedent: `crates/rts-core/src/extraction.rs:1285-1707`) covering:
- ATX H1–H6 each produce one symbol with `kind="heading"` and the correct
  `signature` (e.g. `### Installation`).
- Setext H1 (`===`) and H2 (`---`) underlines produce symbols with
  `signature` rendered in ATX form (`# Foo`, `## Foo`) for consistency.
- Heading text trimmed of leading/trailing `#`s + whitespace (CommonMark
  closing-`#` syntax).
- Hierarchical `qualified_name` (`Outer > Inner > Innermost`) when a deeper
  heading follows a shallower one; reset when a higher heading reopens scope.
- **`documentation` populated** from the first paragraph immediately
  following the heading (up to ~512 chars, single-line collapsed).
- Headings inside fenced code blocks NOT extracted (`fenced_code_block.code_fence_content`
  opacity).
- Multiple H1s in one file (siblings; each `qualified_name = "<H1 text>"`).

Then implement using a tree-sitter `Query`:

```scheme
(atx_heading
  marker: [(atx_h1_marker) (atx_h2_marker) (atx_h3_marker)
           (atx_h4_marker) (atx_h5_marker) (atx_h6_marker)] @level
  heading_content: (inline) @name) @heading

(setext_heading
  heading_content: (paragraph) @name
  underline: [(setext_h1_underline) (setext_h2_underline)] @level) @heading
```

Depth derived from `@level` node kind, threaded into the rendered
`signature` and used to maintain a stack while walking the cursor for the
`qualified_name` and body-paragraph capture.

**Patterns**: `extract_python_symbols` (simplest single-grammar pattern) for
shape; doc-comment patterns (e.g., `extract_rust_doc_comments`) for the
`documentation` capture style (though markdown's "doc comment" is the body
paragraph below the heading, not above).

**Verification**: `cargo test -p rust_tree_sitter -- extract_markdown` green,
`cargo build --workspace` clean.

### U3. Signature renderer for markdown headings

**Goal**: `signature::render_markdown` returning the heading's canonical
display string (e.g., `## Installation`).

**Files**: `crates/rts-core/src/signature.rs` — new `pub fn render_markdown`.

**Approach**: simplest case — given a heading symbol, render
`"#".repeat(level) + " " + name`. Always emit ATX form (even for Setext-source
headings) for output consistency. Test it.

**Verification**: `cargo test -p rust_tree_sitter -- signature` green.

### U4. Daemon registry: filter allowlist + language dispatch + capability flag + PageRank weight + DoS cap

**Goal**: teach the daemon to actually index `.md`/`.markdown` files; ensure
they rank reasonably in PageRank; bound parse time on adversarial input.

**Files**:
- `crates/rts-daemon/src/filter.rs:109-114` — add **`"markdown"`** to
  `BODY_ALLOWED_EXTENSIONS`. (`"md"` is **already** present today; the gate
  that drops `.md` files currently is `info_for_path` returning `None` at
  `crates/rts-daemon/src/language.rs:391`, not the filter. Confirm with a
  characterization test before changing the dispatch.)
- `crates/rts-daemon/src/language.rs:325-393` — new arm in `info_for_path()`
  for markdown extensions; new `LanguageInfo` entry with `signature_renderer:
  Some(rust_tree_sitter::signature::render_markdown)`, `refs_query: None`.
  **Do NOT add a `MARKDOWN_REFS_CACHE: OnceLock<Option<Query>>` cell** —
  C and C++ have no entry in the cache table either; the `refs_query: None`
  path is already exercised correctly without a dead cell.
- `crates/rts-daemon/src/filter.rs` — add a per-file byte cap (4 MB) for
  markdown files only. tree-sitter is generally resilient but
  `Parser::set_timeout_micros` is a documented no-op since tree-sitter 0.26
  (`crates/rts-core/src/parser.rs:124-129`), so a byte cap is the v1 DoS
  guard. (A proper `ParseOptions::progress_callback` is a separate
  cross-cutting follow-up.)
- `crates/rts-daemon/src/methods/daemon.rs:23-157` — add `"index_markdown"`
  to `DAEMON_CAPABILITIES`.
- `crates/rts-core/src/pagerank.rs:edge_weight` (or the post-PageRank pass)
  — apply a **× 0.1 weight to `kind=="heading"` symbols**. Mirrors the
  existing leading-underscore × 0.1 rule. Counters PageRank's dangling-mass
  redistribution (zero out-edge nodes converge toward the uniform teleport
  baseline, not min).
- `crates/rts-mcp/src/server.rs` `find_symbol.kind` description — add
  `"heading"` to the documented kinds list, so agents see it in tool
  discovery (this is the only visible signal beyond the capability flag).

**Approach**: characterization — add the entries, run existing daemon tests,
confirm none regress. Add a unit test that confirms the PageRank multiplier
is applied (e.g., a fixture with one heading + one code symbol with no
in-edges; assert the code symbol ranks above the heading).

**Verification**: `cargo test -p rts-daemon -- language::tests`, `cargo test
-p rust_tree_sitter -- pagerank`, `cargo build --workspace`.

### U5. End-to-end integration test (incl. CLI parity + outline shape)

**Goal**: prove a real markdown file in a real workspace gets indexed
end-to-end and is retrievable via the three tools, via *both* MCP and CLI.

**Files**: `crates/rts-daemon/tests/markdown_indexing.rs` (new) — model on
the per-language `call_edges_<lang>.rs` precedent.

**Approach**:
- Create a temp workspace with `README.md` containing 2–3 headings, a
  `docs/notes/note.md` with one heading, a `target/doc/index.md` (rustdoc
  output simulation), and a `bad.md` with a heading inside an unclosed
  fenced code block.
- Mount via the daemon test harness; await cold-walk completion.
- Assertions:
  1. `find_symbol(name="Installation", kind="heading")` returns the README
     heading with `signature="## Installation"`, `qualified_name="README.md >
     Title > Installation"`, correct `start_line`, and `documentation`
     populated from the paragraph below.
  2. `outline_workspace` includes the .md file with **flat heading list**
     (each heading rendered via `signature` field; hierarchy encoded in
     `qualified_name` not in tree structure).
  3. `grep(text="installation")` returns matches from .md files with
     `enclosing_qualified_name = "README.md > Installation"`.
  4. The `target/doc/index.md` (gitignored) is NOT indexed.
  5. The heading inside the fenced code block in `bad.md` is NOT extracted
     as a symbol.
  6. **CLI parity**: `rts find Installation --kind heading --output json`
     returns rows equivalent to assertion 1 (same name + kind + file +
     line + qualified_name).

**Verification**: `cargo test -p rts-daemon --test markdown_indexing` green.

### U6. Smoke-test addition + dispatch invariant + public-api snapshot regen

**Goal**: add markdown to the `Language::all()` smoke test; assert
`info_for_path` and `extract_symbols` dispatch agree for every language;
regenerate the public-api snapshot for the additive `Markdown` variant +
`signature::render_markdown` fn.

**Files**:
- `crates/rts-core/src/languages/mod.rs:311-355` — add `(Language::Markdown,
  "# Heading\n")` to the snippet table.
- `crates/rts-daemon/tests/language_dispatch_invariant.rs` (new) — iterate
  `Language::all()`; for each, fabricate a path with one of its
  `file_extensions()` and assert (a) `info_for_path` returns `Some`, and
  (b) the corresponding `extract_symbols` arm is non-empty/non-`unimplemented!`.
  Catches the C#-style omission class of bug.
- `crates/rts-core/tests/snapshots/public-api.txt` — regenerated.

**Approach**:
```sh
# Verify Language enum is `#[non_exhaustive]` before regen
rg -n 'non_exhaustive' crates/rts-core/src/languages/mod.rs
# (If not marked non_exhaustive, the additive variant is technically
# breaking for downstream exhaustive matchers — a deliberate decision
# under 0.x semver. Document the decision in the U6 commit message.)

# Regen via rustup-managed nightly (Homebrew cargo 1.90 doesn't understand
# +nightly — this session has hit that twice)
PATH="$HOME/.rustup/toolchains/nightly-2025-08-02-aarch64-apple-darwin/bin:$PATH" \
  UPDATE_SNAPSHOTS=yes cargo test -p rust_tree_sitter --test public_api
```

**Verification**: `cargo test -p rust_tree_sitter --test public_api` green,
`cargo test -p rts-daemon --test language_dispatch_invariant` green.

### U7. Semantic-eval corpus check

**Goal**: confirm neither corpus's coverage gate breaks from the new
markdown symbols entering the pool (and from the PageRank multiplier
applied in U4).

**Files**: none expected (corpus stays unchanged unless gate breaks).

**Approach**:
```sh
cargo run -p rts-bench -- semantic --corpus corpus/semantic-eval-rts-core.toml \
  --workspace . --check-coverage 0.95
cargo run -p rts-bench -- semantic --corpus corpus/semantic-eval-rts-core-blind-v2.toml \
  --workspace . --check-coverage 0.75
```

Also diff top-32 ordering for queries already in the corpus (e.g., `Symbol`,
`parse`, `commit_batch`) before/after to confirm the PageRank multiplier
doesn't perturb ranking for code-shaped queries.

If a gate trips (low likelihood given the × 0.1 heading weight), add minimal
negative-control adjustments per the [#137 corpus recalibration
precedent](https://github.com/njfio/rs-agent-code-utility/pull/137).

**Verification**: both gates exit 0; top-32 diff on the canonical queries
is empty or trivially equivalent.

### U8. Changelog fragment

**Goal**: drop a `changelog.d/xxx-feat-markdown-indexing.md` fragment that
rolls up into `[0.7.0]`, **explicitly calling out the user-visible behavior
change** (existing workspaces gain markdown rows on upgrade).

**Files**: `changelog.d/xxx-feat-markdown-indexing.md` (new). Rename to
`<PR#>-feat-markdown-indexing.md` after the PR opens.

**Content shape**:
```
### Feature: markdown indexing (first-class prose retrieval)

[summary]

**Behavior change on upgrade:** workspaces with tracked `.md`/`.markdown`
files will index them automatically on first mount post-upgrade. To opt out
of any specific path, use `.gitignore` (gitignore precedence still holds).
The change is purely additive — existing code queries return identical
results.
```

**Verification**: convention check (top-level `###` header, plain markdown)
per [`changelog.d/README.md`](../../changelog.d/README.md).

## Technical Considerations

- **Two-grammar architecture** (block + inline) was a brainstorm gap.
  `tree-sitter-md` 0.5.3 ships `LANGUAGE` (block) + `INLINE_LANGUAGE`
  (inline). v1 uses **block-only** to preserve rts's "one grammar per
  Language variant" invariant. Inline enters in v2 when `[text](#anchor)`
  links land as a reference graph. **v2 ADR note** (document at the
  dispatch site): v2 will need `LanguageInfo` to carry an optional
  secondary grammar for inline-link refs; the current 1:1 `Language →
  grammar` invariant will become 1:N. Helix's two-Language-registration
  pattern is the v2 reference.
- **kind encoding: `"heading"` (flat).** All 15 existing kind values are
  single-word lowercase nouns; introducing `heading-N` would break that
  lexical shape for downstream consumers (tool-description docs, CLI
  table rendering, agent query patterns). Depth is conveyed by `signature`
  (`## Installation`) and the hierarchical `qualified_name`.
- **PageRank dangling-mass mitigation: × 0.1 weight for `kind=="heading"`.**
  PageRank's standard dangling-node handling redistributes mass via the
  teleport vector each iteration, NOT pinning at min. Without a counter,
  thousands of dangling heading SIDs land near the uniform baseline and
  can surface above weakly-connected code symbols. The × 0.1 multiplier
  mirrors the existing leading-underscore rule in `edge_weight` and is
  cheaper than introducing a refs query just for ranking.
- **Parser DoS posture**: `tree-sitter::Parser::set_timeout_micros` is a
  documented no-op since tree-sitter 0.26 (`crates/rts-core/src/parser.rs:
  124-129`). v1 mitigation is a per-file byte cap (4 MB on `.md`); a
  proper `ParseOptions::progress_callback` rewire is a separate
  cross-cutting follow-up affecting all 13 languages.
- **`Symbol.kind` is a free-form `String`** today
  (`crates/rts-core/src/symbol.rs:16-33`). Adding new kind values triggers
  **no public-api snapshot change**. Collapses the brainstorm's "kind
  enum extension" concern entirely.
- **Capability flag follows additive convention** (`index_grep_v2`,
  `cancellable_queries`, `daemon_stats_v2`, etc. — additive-only on
  `Daemon.Ping.capabilities[]`).
- **Public-api snapshot will diff** for the `Language::Markdown` variant
  and `pub fn signature::render_markdown`. Both additive — no breaking
  change. **Verify `non_exhaustive` state on `Language` before regen**;
  document the decision either way.
- **Pre-existing extension-table inconsistency** between
  `Language::file_extensions()` and `supported_languages()` (`.phtml`,
  `.cjs`, `.rake` differ) is **out of scope**. Markdown added consistently
  to both; fixing the pre-existing drift is a separate follow-up.

## System-Wide Impact

### Interaction Graph

File on disk (`README.md`) → ignore-walker
(`crates/rts-daemon/src/reconciler.rs:108-116`, `follow_links(false)`) →
filter (`crates/rts-daemon/src/filter.rs:127-165` — `"md"` already
allowlisted; `"markdown"` newly added) → **language dispatch
(`crates/rts-daemon/src/language.rs::info_for_path:325-393` — new
`Markdown` arm; this is the *actual* gate, not the filter)** →
`ParserPool::parse_and_extract` (`crates/rts-daemon/src/writer.rs:761`) →
`rust_tree_sitter::parse_content` (`crates/rts-core/src/lib.rs:110`) →
`extraction::extract_symbols` dispatch
(`crates/rts-core/src/extraction.rs:18-59`) → `extract_markdown_symbols`
(new) → `Vec<Symbol>` → daemon writes to redb → reverse-index updates →
PageRank pass applies heading × 0.1 weight → file-watcher hooks the same
path on subsequent edits.

**Two-dispatch-site coupling**: `info_for_path` (in rts-daemon) and
`extract_symbols` (in rts-core) are independent decision sites. Both must
agree on "which language is this." The U6 dispatch-invariant test pins
this contract.

### Error & Failure Propagation

- **Grammar load failure** (extremely unlikely): daemon refuses to start
  with a `LanguageLoadError`. Surfaced at startup, never silent.
- **Parse failure on malformed markdown**: tree-sitter is resilient;
  partial AST returned. Headings present in the valid prefix get
  extracted; the rest reported as `partial_errors` per the existing
  `ParseOutcome` contract.
- **Adversarial large input**: per-file 4 MB cap (U4) drops files
  exceeding it with a `SkipReason::OversizedFile`; recoverable, daemon
  stays up.
- **Extraction-query compile failure** (developer error): caught at first
  call; falls through to no-symbols result, daemon stays up.

### State Lifecycle Risks

- **Existing index has no markdown rows on upgrade.** The reconciliation
  worker (v0.6) handles this transparently. Markdown files become
  "missing" from rts's perspective and are picked up on the next walk.
  No manual re-index step needed. **Watch**: on doc-heavy monorepos
  (docusaurus/k8s-docs with 3–10 k `.md` files), the first reconciliation
  pass could stall MCP calls 5–30 s. Captured in Risks.
- **Schema additions**: redb's per-row format already accepts `Symbol`
  records uniformly; no schema bump needed. Pre-1.0 schema-mutable
  carve-out covers any minor adjustment.

### API Surface Parity

- The 10 MCP tools all accept `kind: Option<String>` (free-form filter)
  and `language: Option<Vec<String>>` (free-form list). New values
  `"heading"` and `"markdown"` are *additive* to those filters; no schema
  change. **U4 also extends the `find_symbol.kind` tool description** to
  include `"heading"` so agents discover it via tool schema (not just the
  capability flag, which agents don't inspect).
- The 10 `rts` CLI subcommands consume `Symbol.kind` for table rendering
  (`crates/rts-mcp/src/cli.rs:267`); the `"heading"` value renders
  identically. **U5 includes a CLI parity assertion** to pin equivalence.
- `outline_workspace` will surface `.md` files alongside code files in
  its file tree. Format unchanged: flat symbol list per file, hierarchy
  encoded in `qualified_name` (not nested tree).

### Integration Test Scenarios (cross-layer, real objects)

1. Workspace contains `README.md` with `# Title`, `## Installation`,
   `### Prebuilt`. `find_symbol(name="Installation", kind="heading")`
   returns one symbol with `signature="## Installation"`,
   `qualified_name="README.md > Title > Installation"`, `documentation`
   populated from the next paragraph, correct `start_line`.
2. Workspace contains `docs/api.md` with the same heading name as a Rust
   struct (`API`). `find_symbol(name="API")` returns BOTH symbols —
   `kind="struct"` AND `kind="heading"`, ranked by PageRank (the struct
   should win given the heading × 0.1 weight).
3. Markdown file inside a gitignored dir (`target/doc/index.md`) is NOT
   indexed.
4. File-watcher: agent edits `AGENT_NOTES.md` mid-session; within the
   150 ms debounce window, `find_symbol` against a new heading reflects
   the edit.
5. Malformed markdown (unclosed fenced code block with `# Heading`
   inside): the heading inside the code fence is NOT indexed.
6. CLI ⇔ MCP: `rts find Installation --kind heading --output json` and
   `find_symbol(name="Installation", kind="heading")` return equivalent
   rows.
7. Oversized markdown (>4 MB): file is skipped; daemon stays up.

## Acceptance Criteria

### Functional (user-visible)

- [ ] **Markdown files indexed.** After `cargo install` + mount, `.md`
      and `.markdown` files under tracked paths show up via `find_symbol`,
      `grep`, and `outline_workspace`.
- [ ] **`find_symbol --kind heading` works.** Returns matching markdown
      headings with correct `signature`, `qualified_name`, and
      `documentation` (first paragraph) fields.
- [ ] **`outline_workspace` shows headings.** Flat list per file with
      hierarchy in `qualified_name`; signature renders as
      `## Installation`-style ATX form.
- [ ] **Integration test green.** `cargo test -p rts-daemon --test
      markdown_indexing` covers all 7 scenarios above (including
      gitignore skip, fenced-code-block skip, CLI parity, oversized
      skip).

### Non-Functional (gates)

- [ ] **Frozen-surface gates green**: cargo-public-api snapshot regen
      contains only additive entries; the tool-description regression
      test stays green (no new tool, no new subcommand).
- [ ] **Dispatch invariant green**: `cargo test -p rts-daemon --test
      language_dispatch_invariant` (new) confirms `info_for_path` ⇔
      `extract_symbols` agree across all 13 languages.
- [ ] **`non_exhaustive` decision documented** in the U6 commit message
      (whether `Language` is `non_exhaustive` was confirmed; additive
      variant either preserves exhaustive-match safety or is a deliberate
      0.x minor break).
- [ ] **Semantic-eval gates green**: 0.95 (v1) and 0.75 (blind-v2)
      coverage thresholds hold after new markdown rows enter the pool;
      top-32 ordering for canonical queries unchanged.
- [ ] **Workspace clippy clean** (`cargo clippy -p rust_tree_sitter -p
      rts-daemon -p rts-mcp -p rts-bench --all-targets` zero warnings).
- [ ] **`#![forbid(unsafe_code)]` in rts-core preserved**: the `unsafe`
      inside `tree-sitter-md` is encapsulated; rts consumes only the
      safe `LANGUAGE.into()` interface.

### Quality Gates

- [ ] `cargo test --workspace` green.
- [ ] `cargo build --workspace --release` builds cleanly on the 3 release
      targets (verifiable via `workflow_dispatch` dry-run on the feature
      branch before merge).
- [ ] All v0.6 freeze gates green.

## Success Metrics

- `rts grep "retrieval stack"` (run on the rts repo) returns hits in
  README/CHANGELOG/docs — the v0.6 gap is closed.
- `find_symbol "Installation" --kind heading` returns the README's
  Installation heading in this and other repos, with `documentation`
  populated for `--doc-contains` queries to work over prose.
- `outline_workspace` shows the heading hierarchy of `.md` files
  alongside code-symbol outlines.
- Code-only queries unchanged: `find_symbol "parse" --kind fn`,
  `find_callers --name "commit_batch"`, `impact_of --name "Symbol"`
  return identical result sets to v0.6.x (no regression in top-32).
- The cross-session-notes use case works end-to-end: an agent writes a
  note in `AGENT_NOTES.md`; the next session retrieves it via `grep`
  (content match) or `find_symbol --kind heading --doc-contains` (anchor
  on the heading + body).

## Dependencies & Risks

- **Dep**: `tree-sitter-md = "0.5.3"` — actively maintained (v0.5.3
  published 2026-02-26), built against `tree-sitter 0.26.6` (matches
  workspace pin), pure-C scanner via `cc-rs 1.2`. License MIT. **Audit
  result (CLEAN)**: 0 CVEs in RustSec, 0 net-new transitive deps (the
  one transitive `tree-sitter-language 0.1.7` is already pulled by the
  other 11 grammars), 0 license issues, 0 maintenance concerns. Risk
  profile indistinguishable from the 11 existing grammar deps.
- **Risk: per-target build behavior** — adds ~6–15 s per target to the
  release pipeline (3 × ~10 s ≈ 30 s total cold). **Mitigation**:
  dry-run `release.yml` on the feature branch before merge.
- **Risk: two-grammar architecture trap** — `tree-sitter-md`'s
  block+inline split breaks "one grammar per Language" if someone
  reaches for inline. **Mitigation**: explicitly defer to v2; document
  at the dispatch site with the v2 ADR note above.
- **Risk: PageRank ordering perturbation** — *mitigated* by the × 0.1
  heading weight (U4). Verified by U7 (top-32 diff on canonical
  queries).
- **Risk: NAME_TO_SID collision storm** — common heading names
  ("Installation", "Usage", "Overview", "Configuration") repeat across
  hundreds of files in large monorepos. `find_symbol "Installation"`
  could exceed the default 256 limit. **Mitigation**: in v1, the
  hierarchical `qualified_name` lets users disambiguate; if real users
  hit it, a future patch can default-include file-stem in resolution
  hints.
- **Risk: cold-walk stalls on doc-heavy monorepos** — docusaurus /
  k8s-docs with 3–10 k `.md` files could stall first-mount post-upgrade
  by 5–30 s. **Mitigation**: monitor; if real users hit it, add a
  lower-priority reconcile queue for prose extensions.
- **Risk: adversarial markdown DoS** — `Parser::set_timeout_micros` is a
  no-op since tree-sitter 0.26. **Mitigation**: per-file 4 MB byte cap
  on `.md` (U4). Progress-callback rewire is a separate cross-cutting
  follow-up.
- **Risk: extension-table drift** between
  `Language::file_extensions()` and `supported_languages()` (pre-existing
  on `.phtml`/`.cjs`/`.rake`). **Mitigation**: keep both in sync for
  markdown; pre-existing inconsistency tracked as a separate follow-up.

## Requirements Trace

| Brainstorm requirement | This plan |
|---|---|
| **R1**: markdown as 13th indexed language, gitignore-aware | U1 (Cargo dep + Language variant), U4 (daemon allowlist + capability), U5 (integration test scenarios 3 + 4 cover gitignored skip + file-watcher) |
| **R2**: markdown headings as first-class symbols (`kind="heading"`, flat) | U2 (`extract_markdown_symbols` emits `kind="heading"`, depth via `signature` + `qualified_name`), U3 (signature renderer), U5 (scenarios 1 + 2 cover MCP path) |
| **R3**: markdown content grep-able with enclosing-heading qualified name | U2 (`qualified_name` = hierarchical path), U5 (grep + outline shape assertions) |
| **R4**: no surface expansion (10 MCP + 10 CLI frozen) | All units: no new tool registration, no new CLI subcommand. The find_symbol.kind tool-description update is **content extension** within the existing schema, not a shape change. |
| **R5**: default-on at v0.7.0, no `experimental` gate | U8 (changelog fragment for `[0.7.0]` with explicit behavior-change call-out); version bump at release-cut time |

## Sources & References

### Origin

- **Origin document**:
  [docs/brainstorms/2026-05-26-markdown-indexing-prose-retrieval-requirements.md](../brainstorms/2026-05-26-markdown-indexing-prose-retrieval-requirements.md)
  — 5 product decisions resolved (memory-as-prose-retrieval reframe;
  all tracked .md; headings ARE symbols; v0.7.0 default-on; no
  experimental gate). 7 deferred-to-planning items addressed in
  Technical Considerations + Implementation Units.

### Internal Patterns

- **Direct precedent** for adding a language:
  [docs/plans/2026-05-18-005-feat-ast-precise-call-edges-java-php-swift-csharp-plan.md](2026-05-18-005-feat-ast-precise-call-edges-java-php-swift-csharp-plan.md)
  (Java/PHP/Swift/C# call-edges).
- **Language enum + extension dispatch**:
  `crates/rts-core/src/languages/mod.rs:19-44`.
- **Extraction dispatch precedent**:
  `crates/rts-core/src/extraction.rs:18-59`; mirror `extract_python_symbols:420`.
- **Daemon registry**: `crates/rts-daemon/src/language.rs:325-393`.
- **Filter allowlist**: `crates/rts-daemon/src/filter.rs:109-114`.
- **Capability flags**: `crates/rts-daemon/src/methods/daemon.rs:23-157`.
- **Parser timeout no-op**: `crates/rts-core/src/parser.rs:124-129`.
- **PageRank `edge_weight`** (leading-underscore × 0.1 precedent):
  `crates/rts-core/src/pagerank.rs`.
- **Symbol-level PageRank**: `crates/rts-daemon/src/symbol_pagerank.rs`.
- **Public-api gate docs**: [docs/public-api-gate.md](../public-api-gate.md).

### External

- **`tree-sitter-md` 0.5.3** —
  [crates.io](https://crates.io/crates/tree-sitter-md) |
  [GitHub: tree-sitter-grammars/tree-sitter-markdown](https://github.com/tree-sitter-grammars/tree-sitter-markdown)
  | [docs.rs](https://docs.rs/tree-sitter-md/latest/tree_sitter_md/).
  Two-grammar split (block + inline); `parser` feature for combined
  two-pass parsing (not used in v1).
- **Heading-as-symbol convention**: [universal-ctags markdown parser](https://docs.ctags.io/en/latest/man/ctags-lang-markdown.7.html);
  [Marksman LSP docs](https://github.com/artempyanykh/marksman/blob/main/docs/features.md)
  (flat list + hierarchical qualified-name precedent).
- **Link-as-reference precedent** (deferred to v2):
  [Marksman issue #445](https://github.com/artempyanykh/marksman/issues/445).
- **String SymbolKind sanctioned**:
  [LSP issue #1186](https://github.com/microsoft/language-server-protocol/issues/1186).

### Related Work

- v0.6.0 stability line + frozen surface:
  [docs/plans/2026-05-25-001-release-cut-v0-6-0-code-kb-stability-line-plan.md](2026-05-25-001-release-cut-v0-6-0-code-kb-stability-line-plan.md).
- Pre-pivot cleanup:
  [docs/plans/2026-05-22-001-refactor-pre-pivot-cleanup-and-public-surface-tightening-plan.md](2026-05-22-001-refactor-pre-pivot-cleanup-and-public-surface-tightening-plan.md).

### Deepen-Plan Review Agents

8 parallel agents validated the plan and surfaced the corrections /
additions in the Enhancement Summary: `architecture-strategist`,
`code-simplicity-reviewer`, `agent-native-reviewer`,
`pattern-recognition-specialist`, `performance-oracle`,
`security-sentinel`, plus skill-applying sub-agents for
`dependency-audit` (CLEAN) and `implementation-strategy`
(safe-with-one-caution → v0.7.0 minor classification confirmed).
