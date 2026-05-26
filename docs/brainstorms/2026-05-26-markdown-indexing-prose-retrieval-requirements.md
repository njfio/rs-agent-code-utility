---
date: 2026-05-26
topic: markdown-indexing-prose-retrieval
---

# Markdown indexing — first-class prose retrieval (with cross-session agent notes as a use case)

## Problem Frame

rts indexes 12 code languages but **does not index markdown**. The README,
`AGENTS.md`, `CHANGELOG.md`, `docs/`, and `changelog.d/` fragments — every
project's prose — are invisible to `find_symbol`, `outline_workspace`, and
`grep`. Today the agent has to fall back to `Bash` `rg`/`find` on those files
(the exact behavior `.claude/hooks/rts-nudge.sh` discourages everywhere else),
exposing an inconsistency between the rts pitch and what rts actually covers.

The trigger for this brainstorm was a "should we add memory to rts" question.
The deliberate reframe: **don't build a write-mutable memory tool** (it would
break rts's read-only model and the v0.6 frozen surface, and Claude Code's
own `/memory` + `CLAUDE.md` already cover that). Instead, **let agents write
notes the way they already do** — in tracked markdown files (`docs/notes/*.md`,
`AGENT_NOTES.md`, or anywhere) — and have **rts index that prose**. The same
change pays off well beyond memory: README, AGENTS.md, design docs, and
CHANGELOG become first-class retrievable through the existing tools.

**Audience:** the solo maintainer using rts daily; outside users navigating
the project's docs alongside its code; AI coding agents (Claude Code, Cursor,
Aider, Continue, Cline) whose query patterns already work on code and would
extend naturally to prose.

## Requirements

- **R1. Markdown is a 13th indexed language.** rts walks tracked `.md` (and
  `.markdown`) files the same way it walks code today: respects gitignore,
  participates in the cold walk + live file-watcher, lives in the same
  per-workspace redb index. Same correctness contract as code.

- **R2. Markdown headings are first-class symbols.** ATX/Setext headings
  (`#`/`##`/…) become symbols with `kind=heading` (or equivalent — name
  finalized at planning). `find_symbol "Installation"` returns the matching
  README heading alongside any code symbols of the same name, kind-tagged so
  callers can filter with the existing `--kind` parameter. The same heading
  hierarchy populates `outline_workspace` for `.md` files.

- **R3. Markdown content is grep-able.** The `grep` tool returns matches from
  `.md` files. `grep --language markdown "TODO"` scopes to prose; existing
  `grep --language rust "panic!"` stays code-only. Matches carry the
  enclosing-heading qualified name where present (the prose analog of
  enclosing-function on code matches).

- **R4. No surface expansion.** No new MCP tool, no new CLI subcommand. The
  v0.6 frozen surface (10 MCP tools + 10 CLI subcommands; names + argument
  shapes) is untouched — markdown indexing is additive *behavior* behind the
  same tools. The cargo-public-api gate + the tool-description regression
  test stay green.

- **R5. Default-on at v0.7.0.** Ships as a regular minor bump per 0.x semver
  (additive new capability). On by default; documented as a behavior change
  in the release notes (existing queries may surface additional prose
  matches, kind-tagged for easy filtering). The `experimental` Cargo feature
  is not used — R5 of the v0.6 brainstorm scoped that gate to new
  tool/subcommand *surface*, not new indexer languages.

## Success Criteria

- After upgrading to v0.7.0, `rts grep "retrieval stack"` (or any prose
  search) returns hits in `README.md`/`CHANGELOG.md`/`docs/**` — the gap
  discovered during the v0.6 cleanup is closed.
- `find_symbol "Installation" --kind heading` returns the README's
  Installation heading (in this repo and others).
- `outline_workspace` on a workspace containing `.md` files shows the heading
  hierarchy alongside code-symbol outlines.
- Code-only queries are unaffected: `find_symbol "parse" --kind fn`,
  `find_callers --name commit_batch`, `impact_of --name Symbol` return
  identical result sets to v0.6.x.
- The cross-session-notes use case is unlocked: an agent writes a note in
  `AGENT_NOTES.md` or `docs/notes/2026-05-26-pagerank-quirk.md`; the next
  session retrieves it via `grep` or `find_symbol --kind heading`.
- `cargo test --workspace` + the semantic-eval gates + the v0.6 freeze gates
  (cargo-public-api, tool-description) stay green.

## Scope Boundaries

- **Not a writable memory tool.** No `note_add` / `note_get` MCP tool, no
  `rts note` CLI subcommand. Agents author notes with their existing tools
  (Edit/Write); rts only reads.
- **Not a new MCP tool or CLI subcommand.** The v0.6 frozen surface is
  preserved — this is purely an additive indexer-language extension behind
  existing tools.
- **Not a markdown-link-as-reference graph.** `find_callers` / `impact_of`
  on a markdown heading return empty in v1; treating `[text](#heading)` links
  as "callers" of headings is a future enhancement (see Deferred to Planning).
- **Not other prose formats.** No `.rst`, `.txt`, `.org`, `.adoc` — markdown
  only. (Future minor bumps can add formats as additional indexed languages.)
- **Not a curated default set or opt-out config.** All tracked `.md` files
  are indexed (gitignore-aware, same rule as code); no `markdown_exclude`
  config knob in v1 — added later only if a real noise problem emerges.
- **Not pre-1.0 schema migration support.** redb schema additions for
  markdown follow the existing pre-1.0 mutable schema rule — auto-rebuild on
  upgrade. No backward-compat shim for v0.6.x indexes.

## Key Decisions

- **Memory framing reframed as "first-class prose retrieval."** Cross-session
  agent notes are one use case; the primary win is that every project's
  prose (READMEs, design docs, CHANGELOG, AGENTS.md) becomes retrievable
  with the same tools and query patterns that work on code. Path A
  (doc-comments as notes) was considered: it works today via
  `find_symbol --doc-contains` and doesn't require any rts change, but it
  pollutes code with agent ephemera. Available unilaterally as a habit;
  orthogonal to this brainstorm.
- **Markdown headings ARE symbols (kind=heading).** Same `find_symbol` tool
  with kind-filtered disambiguation; same `outline_workspace` for hierarchy.
  Maximum compounding value vs the alternative (prose-only-in-grep, code-only-
  in-find_symbol), which leaves `outline_workspace` awkward for `.md` files
  and loses the "find the README section about X" query.
- **All tracked .md, no curated default.** Simplest, matches the existing
  gitignore-aware mental model for code. Bikeshed-prone defaults
  (`README.md` + `docs/**` + …) are avoided; an opt-out glob can be added
  later if a real need emerges.
- **v0.7.0 default-on; no `experimental` gate.** Additive language is a
  natural minor bump per 0.x semver. The `experimental` Cargo feature was
  introduced specifically for new tool/CLI surface and doesn't naturally
  gate indexer-language additions.
- **Code-edge tools (`find_callers`, `impact_of`) return empty on markdown
  headings in v1.** Markdown links as references is a real semantic
  parallel (a `[text](#heading)` IS a reference to that heading) but it's
  meaningful enough to defer to a follow-up rather than bundle.

## Dependencies / Assumptions

- `tree-sitter-md` exists and is maintainable (verify version + activity at
  planning time).
- The daemon's gitignore-aware walker is already correctness-tested on code
  files and extends to `.md` without changes.
- The `kind` enum is additively extensible — adding `heading` as a variant
  doesn't break protocol-v0 wire compatibility (capability flags or
  conservative deserialization handle unknown kinds gracefully on older
  clients).
- The v0.6 frozen-surface gates (cargo-public-api, tool-description
  regression test, lefthook clippy/fmt) remain authoritative; nothing here
  should require an `UPDATE_SNAPSHOTS=yes` regen.

## Outstanding Questions

### Resolve Before Planning

*(none — all five product decisions resolved in this brainstorm)*

### Deferred to Planning

- **[Affects R1][Technical]** `tree-sitter-md` crate version pin + parsing
  semantics: ATX (`#`) and Setext (`===`) headings, fenced code blocks
  (don't index code-block contents as prose), inline links (deferred from
  R5 anyway), HTML-in-markdown (skip).
- **[Affects R2][Technical]** Exact `kind` variant name: `heading`, `section`,
  or `markdown_heading`? Should the heading *level* (H1–H6) be a separate
  field on the symbol or encoded in the kind? Does heading text need
  normalization (collapsing whitespace, stripping `#` anchors)?
- **[Affects R2][Technical]** `outline_workspace` output shape for `.md`
  files: flat list of headings or nested tree mirroring the heading
  hierarchy? Aligns with the existing code-symbol output convention.
- **[Affects R3][Technical]** `grep` `enclosing_qualified_name` semantics on
  markdown: matches inside a section get the heading path
  (`README.md > Installation > Prebuilt`)? Same field on the existing
  response shape, no wire-format change.
- **[Affects R5][Technical]** PageRank: do markdown headings participate in
  PageRank scoring (and what does in-degree mean for a heading — markdown
  link references, once implemented)? Or are headings ranked by a simpler
  signal (file PageRank + heading depth) in v1?
- **[Affects R5][Needs research]** cargo-public-api snapshot impact: adding
  a new public variant to the `kind` enum (or wherever the language is
  exposed publicly) — confirm the snapshot remains additive-only and
  doesn't trigger a "breaking change" gate failure.
- **[Future]** Markdown links as a reference graph: `[text](#installation)`
  → `find_callers --name "Installation" --kind heading` returns the link
  call sites. Real semantic parallel to code call edges, but scoped out of
  v1.

## Next Steps

→ `/ce:plan` for structured implementation planning. Pass this requirements
document path as input.
