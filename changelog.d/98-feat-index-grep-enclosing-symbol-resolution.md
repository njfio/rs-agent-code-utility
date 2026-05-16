### `Index.Grep` — enclosing-symbol resolution per match

v0.5.4 + #97 shipped `Index.Grep` returning `(file, range, line_text)` per match. Real agent use immediately wanted "which function is this match inside?" — every follow-up step (read the surrounding code, write a fix, find callers of the enclosing fn) starts there. Until now agents resolved that with a second `read_symbol_at` per match. Round-trip overhead aside, that's a dance the daemon should run itself.

Each match now carries three new fields, populated by the same `pick_innermost_def` lookup `read_symbol_at` uses:

```jsonc
{
  "matches": [
    {
      "file": "crates/rts-daemon/src/methods/index.rs",
      "range": { "start_line": 1156, "end_line": 1156,
                 "start_byte": 38420, "end_byte": 38449 },
      "line_text": "    if let Some(g) = &glob {",
      // NEW in v0.5.5:
      "enclosing_qualified_name": "grep",
      "enclosing_kind": "fn",
      "enclosing_def_range": {
        "start_byte": 36800, "end_byte": 42100,
        "start_line": 1098, "end_line": 1287
      }
    }
  ],
  "truncated": false,
  "files_scanned": 245,
  "files_with_matches": 1
}
```

#### Resolution rules

- **Innermost def wins.** When multiple defs cover the match line (nested closure, impl block + method), `pick_innermost_def` returns the smallest line-range one — ties broken by `(span, start_byte)` for stable output across calls.
- **Single redb txn per file.** The naive shape would be one `defs_in_file` lookup per match. We hoist it to one per file-with-matches, keeping the hot path `O(files_with_matches)` rather than `O(matches)`. On `crates/rts-daemon` with ~200 matches concentrated in ~30 files, that's 30 lookups vs 200.
- **File-scope matches surface explicit `null`s.** When no def covers the match (top-level comment, module-level statement, `use` line), all three enclosing fields are JSON `null` — distinct from "missing" so agents can tell "outside any def" from "field absent."
- **Storage errors degrade gracefully.** If `defs_in_file` fails for a specific file (torn read, writer race), the match data is still valid; we log a warning and surface the matches with `enclosing_*: null` rather than failing the whole query.

#### Backward compatibility

Three new fields on a result object. Existing callers that only read `file`, `range`, `line_text` see no behavior change. Tests for the existing fields still pass byte-for-byte.

#### Verification

`grep_round_trip.rs` goes from 13 cases (M) to 15 (O):

- **N**: `timeout reading MCP response` is on line 2 of `a.rs`, inside `pub fn a()`. Response must surface `enclosing_qualified_name == "a"`, `enclosing_kind == "fn"`, `enclosing_def_range.start_line == 1` covering the match.
- **O**: `Comment about TIMEOUT` is on line 1 of `b.rs`, outside any function — all three enclosing fields must be JSON `null`.

Full suite: `cargo test -p rts-daemon -p rts-mcp --release` — 160+ tests pass.

#### Out of scope (filed for follow-up)

- **PageRank ranking of matches.** Now that each match has an enclosing def, sorting by that def's PageRank is the next obvious step — puts hits in the workspace's busiest, most central code at the top, matching `find_symbol`'s default ordering. Filed as the next PR in this Index.Grep arc.
- **`enclosing_qualified_name` is bare-name, not path-qualified.** Same shape as `Index.FindCallers.callers[].enclosing_qualified_name`; both inherit the underlying store schema where names aren't path-qualified. A separate `path` schema upgrade would surface `module::Type::method` consistently across both endpoints. Not a v0.5.5 deliverable.
