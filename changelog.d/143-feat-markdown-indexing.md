### Feature: markdown indexing — first-class prose retrieval

rts now indexes Markdown alongside the 12 code grammars. `.md` and
`.markdown` files contribute first-class symbols with `kind="heading"`
for every ATX (`#`–`######`) and Setext (`===` / `---`) heading. The
same `find_symbol`, `outline_workspace`, and `grep` tools that retrieve
code now retrieve prose — closing the v0.6 gap where
`rts grep "retrieval stack"` returned 0 hits because the term lived
only in `README.md` / `CHANGELOG.md`.

Highlights:

- **`kind="heading"` (flat)** — H1–H6 all share one wire kind. Depth
  is conveyed by the rendered `signature` (`## Installation`) and a
  hierarchical path prefix stored in the heading's `documentation`
  field (`"Project Title > Installation\n\nBody…"`), which makes
  `find_symbol --doc-contains "Project Title"` work over ancestor
  names.
- **Body-paragraph capture** — the first paragraph immediately after
  each heading populates `documentation` (single-line collapsed, ≤512
  chars), enabling `find_symbol --doc-contains` to search prose
  content the same way it searches doc comments today.
- **Gitignore-aware** — markdown files under `target/`, `node_modules/`,
  or anything matched by `.gitignore` / `.rtsignore` are skipped, same
  rule as code.
- **PageRank dampener** — heading SIDs are multiplied × 0.1 in the
  final rank pass. Headings have no outbound references in v1, so
  PageRank's dangling-mass redistribution would otherwise lift them
  near the uniform baseline and crowd weakly-connected code symbols;
  the dampener mirrors the leading-underscore × 0.1 rule already in
  `edge_weight`.
- **Per-file 4 MiB byte cap** is satisfied by the existing global
  `OVERSIZE_THRESHOLD_BYTES` — adversarial input never reaches the
  parser. (`Parser::set_timeout_micros` is a documented no-op in
  tree-sitter ≥ 0.26.)
- **Capability flag** `index_markdown` advertised on `Daemon.Ping`.
- **CLI parity** — `rts find Installation --kind heading --json`
  returns equivalent rows to the MCP `Index.FindSymbol` call.

**Behavior change on upgrade:** workspaces with tracked
`.md` / `.markdown` files will index them automatically on first
mount post-upgrade. On doc-heavy monorepos (3–10 k `.md` files in a
`docs/` tree) the first reconciliation pass can take 5–30 seconds —
plan accordingly, or use `.gitignore` to opt specific paths out.
The change is purely additive — existing code queries return
identical results (top-32 ordering verified unchanged for canonical
queries; `semantic-eval-rts-core` corpus coverage holds at 1.000
post-change; `semantic-eval-rts-core-blind-v2` at 0.857).

**Public-API additions** (additive only, no breaking change):

- `pub enum rust_tree_sitter::Language::Markdown` variant.
- `pub fn rust_tree_sitter::signature::render_markdown(bytes: &[u8])
  -> Option<String>` — ATX/Setext heading signature renderer
  (always emits ATX form for output consistency).

Internal additions (no public surface):

- `SymbolKind::Heading = 11` (rts-daemon store schema).
- `Store::iter_workspace_sids_with_kind()` (rts-daemon).

The `Language` enum is not `#[non_exhaustive]`; adding the
`Markdown` variant is technically breaking for downstream exhaustive
matchers under semver, but accepted under 0.x — matches the precedent
of v0.5+ adding `Swift` and `CSharp` the same way.
