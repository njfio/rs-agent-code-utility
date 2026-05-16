### `Index.Grep.params.regex` + `Index.Grep.params.file_glob` — scoped pattern search

v0.5.4 shipped `Index.Grep` as literal-substring only. Real agent dogfooding immediately wanted two more things:

- **Regex.** "Find every `TODO(name)`" needs a pattern, not a literal. So does "find unused `unwrap()` outside `tests/`" — `\bunwrap\(\)` is the minimum-viable shape.
- **Path scoping.** "Where do we log this string?" is a different query in `crates/rts-daemon/**/*.rs` vs the whole workspace — and walking 50k indexed files when you know it's in 50 of them is wasted I/O.

Both are now opt-in `GrepParams` fields.

#### Wire shape

```jsonc
// Literal mode (unchanged from v0.5.4)
{ "text": "timeout reading MCP response" }

// Regex mode (v0.5.5+)
{ "text": "\\bunsafe\\b", "regex": true }
{ "text": "TODO\\(.*?\\)", "regex": true, "case_insensitive": false }

// File-path scoping (v0.5.5+)
{ "text": "tokio::spawn", "file_glob": "crates/**/*.rs" }
{ "text": "version = ", "file_glob": "*.toml" }

// Combined
{ "text": "panic!\\(", "regex": true, "file_glob": "crates/rts-daemon/**/*.rs" }
```

The response shape is unchanged: `matches[].{file, range, line_text}` + `files_scanned` + `files_with_matches` + `truncated`.

#### Regex mode

- Backed by `regex::bytes::Regex` (already a daemon dep). Byte-level matching means no UTF-8 cost on the haystack.
- `case_insensitive` still defaults to `true` and applies in both modes via `RegexBuilder::case_insensitive(true)`.
- Compilation failures surface as `INVALID_PARAMS` with the `regex` crate's diagnostic surfaced verbatim — agents can self-correct (`"bad pattern: regex parse error: ..."`) without a round-trip to the user.
- Zero-width matches (`(?i)^`, `\b`) are dropped during iteration — they'd otherwise loop forever and aren't useful grep results.

#### File-glob mode

- Backed by `globset::Glob` (a transitive dep through `ignore`, now promoted to an explicit dep so we compile against a stable interface).
- Match is **path-only**, applied **before** the file read. A tight glob (`crates/rts-core/**/*.rs`) keeps `files_scanned` honest: we don't count files the user asked us to skip.
- Workspace-relative paths — same as every other path field in protocol-v0.
- Empty string + invalid glob both surface as `INVALID_PARAMS` (separate diagnostics: "must be non-empty" vs the `globset` parser's error).

#### Verification

Extended `crates/rts-daemon/tests/grep_round_trip.rs` from 6 cases (F) to 13 (M):

- G: regex matches with default case-insensitivity (`\btimeout\b` hits both `a.rs` and `b.rs`).
- H: regex with `case_insensitive: false` (only the lowercase hit).
- I: invalid regex returns `INVALID_PARAMS` with `regex` in the error message.
- J: `file_glob: "a.rs"` restricts matches *and* `files_scanned`.
- K: `*.rs` matches all three test files; `*.toml` matches none.
- L: invalid glob (`[unclosed`) → `INVALID_PARAMS`.
- M: empty `file_glob` → `INVALID_PARAMS`.

Full suite: `cargo test -p rts-daemon -p rts-mcp --release` — 160+ tests pass.

#### Out of scope (filed for follow-up)

- **Enclosing-symbol resolution.** Today's response carries `(file, range, line_text)`. Adding `enclosing_qualified_name` (the same field find_callers returns) would let "find every panic!() in the daemon" surface the containing function name — much higher signal-per-match. Filed as a separate PR because the shape change deserves its own review.
- **PageRank ranking.** Grep currently returns matches in file-walk order. Sorting by the enclosing file's mean symbol PageRank would put hits in the busiest, most central code at the top — matches `find_symbol`'s default ordering and avoids agents having to re-rank client-side. Filed alongside enclosing-symbol resolution since the implementations share the same enclosing-def lookup.
- **Multiline regex (`(?m)`, `(?s)`).** Today's `line_text` resolution treats each match as single-line — the start byte's line bounds dictate the response field. Multi-line matches would need a richer range-and-text shape; not worth doing until a real query needs it.
