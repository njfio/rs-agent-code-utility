### `Index.Grep` v2 — multi-line regex + structural queries + within-symbol scope

The three known shortcomings that pushed agents back to shell `rg` mid-session — patterns that cross newlines, "find every `impl` that contains an `unsafe fn`", "find every `panic!` inside `fn parse_request`" — now compose on the same MCP tool. Five additive optional input fields on `Index.Grep`; v1 callers pass nothing new and see byte-identical responses on the unchanged code path.

#### What

**Five new optional input fields** on `Index.Grep`/`mcp__rts__grep`, fully composable:

- `multiline: bool` (default `false`) — on the regex path, sets `dot_matches_new_line + multi_line` and scans the file as one buffer. Rejected on the literal path (`MULTILINE_REQUIRES_REGEX`) because literal substring search already crosses newlines.
- `structural_query: string` — a raw tree-sitter S-expression query, evaluated against the parsed tree of every file matching `language`. Per-match `captures: {name: [{start, end, text, truncated?}]}` returned on the response.
- `within_symbol: string` + `within_symbol_allow_overload: bool` — post-filter to matches whose byte range lies strictly inside the def byte range of the named symbol. Overloaded names (>16 defs) reject with `WITHIN_SYMBOL_TOO_MANY_DEFS` unless the caller opts in.
- `language: string[]` — file-set filter applicable to every scan mode (literal, regex, structural). Required when `structural_query` is set; optional otherwise. Intersects with `file_glob` (AND).

**Four new capability strings** on `Daemon.Ping`: `index_grep_multiline`, `index_grep_structural`, `index_grep_within_symbol`, and the bundle `index_grep_v2`. Clients gate on the relevant string before sending v2 fields.

**Eleven new `data.code` sub-codes** under `INVALID_PARAMS` — `MULTILINE_REQUIRES_REGEX`, `STRUCTURAL_REQUIRES_LANGUAGE`, `NO_SEARCH_SOURCE_PROVIDED`, `INVALID_TEXT_LENGTH`, `STRUCTURAL_QUERY_INVALID`, `STRUCTURAL_QUERY_PREDICATE_NOT_ALLOWED`, `WITHIN_SYMBOL_NOT_FOUND`, `WITHIN_SYMBOL_TOO_MANY_DEFS`, `REGEX_TOO_COMPLEX`, `STRUCTURAL_QUERY_TIMEOUT`, `UNKNOWN_LANGUAGE` — each carrying a stable string so agents branch without parsing free-form messages.

**Predicate whitelist (v1)** on agent-supplied S-expression queries: `#eq?`, `#not-eq?`, `#match?`, `#not-match?`, `#any-of?`, `#is?`, `#is-not?`. Anything else returns `STRUCTURAL_QUERY_PREDICATE_NOT_ALLOWED`. `#match?` / `#not-match?` compile under a 256 KiB DFA budget separate from the outer regex.

**Explicit resource budgets**: `MULTILINE_DFA_SIZE_LIMIT = 32 MiB`, `STRUCTURAL_WALL_CLOCK_MS = 5 000`, `STRUCTURAL_MAX_ROWS = 4 096`, `STRUCTURAL_MAX_CAPTURE_BYTES = 8 192`, `WITHIN_SYMBOL_MAX_DEFS = 16`, `QUERY_LRU_CAPACITY = 64`. Cap breaches return `truncated: true` + metadata, not errors.

**Three new `Daemon.Stats` sub-counters** as siblings of `index_grep`: `index_grep_multiline`, `index_grep_structural`, `index_grep_within_symbol`. Each bumps when its param is set and active.

#### Why this matters

Today an agent that needs "every `panic!` inside one function" runs `grep` for `panic!`, runs `find_symbol` for the function, byte-range-intersects the results in its head, and burns context on three round-trips. Multi-line patterns silently return zero hits and the agent reaches for `Bash rg` without a hint about why. Structural matching — "every `impl` that contains an `unsafe fn`" — isn't expressible at all and forces a multi-call walk through `rg` output.

v2 collapses all three into the same single-call surface. Composition is the contract: `structural_query + text` is the intersection, `within_symbol` post-filters either, `language` scopes the file set. The tool surface stays at one MCP entry; the JsonSchema grows by five optional fields; every v1 caller is unaffected.

The conservative shape avoids new attack surface. Raw S-expression queries are validated via `Query::new` at request time and cached in an LRU keyed on `(language, query_text)`. Predicates are whitelisted. `#match?` regexes compile under a separate, tighter DFA budget. Wall-clock budgets are checked between files. Adversarial inputs (`(?s).*` on 4 MiB; `(.*a){50}` inside a predicate; structural queries against 100k LOC) return structured errors, not OOM or hangs.

#### Verification

- Full plan: [`docs/plans/2026-05-18-002-feat-index-grep-v2-plan.md`](../docs/plans/2026-05-18-002-feat-index-grep-v2-plan.md)
- Origin brainstorm: [`docs/brainstorms/2026-05-18-index-grep-v2-requirements.md`](../docs/brainstorms/2026-05-18-index-grep-v2-requirements.md)
- Composition matrix (source of truth): `crates/rts-daemon/src/methods/grep_v2/compose.rs`
- Error code catalog: `crates/rts-daemon/src/methods/grep_v2/errors.rs`
- Protocol-v0 §7.8b "v0.6 additions" documents the full wire shape, capabilities, error codes, predicate whitelist, and resource budgets.
- v1 round-trip: a frozen golden response fixture asserts byte-equality on the unchanged code path.
- New integration tests cover each composition-matrix cell, each error code, the predicate whitelist, the resource-cap responses, the sub-counter bumps, and the cross-language `partial_failures[]` shape.

#### Out of scope (filed for follow-up)

- **Named-pattern catalog** (e.g. `fn_with_attr`, `impl_containing`). Raw S-expression queries only in v1; a v2.1 catalog can be informed by observed agent usage.
- **Cross-file structural matching.** Queries run per-file and union; no graph-shaped structural search.
- **Captures-as-rewrite-suggestions.** v2 is read-only; transforms live in a future `Index.RenamePreview`-shaped tool.
- **Structural queries on `Index.FindCallers` / `Index.ImpactOf`.** `Index.Grep` only in v1.
- **Streaming structural results.** Buffered, truncated at the row cap.
- **Grammar-version invalidation.** Grammars are statically linked; a bump requires a daemon binary rebuild.
- **`--output lines` parity for the new response fields.** The CLI exposes the v1 line shape only; new fields are JSON-only via the MCP path.
