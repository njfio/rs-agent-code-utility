# rts Regex-correct, Ranked & Bounded `code_grep` Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `code_grep` run the model's patterns as regex (with automatic literal fallback) and return rank-ordered, bounded results with enclosing-function context, so the useful-hit rate rises and broad searches stop dumping tokens.

**Architecture:** All search-execution and ranking changes live in the daemon grep handler (`crates/rts-daemon/src/methods/index.rs::grep`) and its validator (`crates/rts-daemon/src/methods/grep_v2/compose.rs`); the per-hit human formatting lives in the CLI (`crates/rts-mcp/src/cli.rs`). The ranking signal (`rank_score`) and enclosing-symbol metadata already exist on every grep match — we sort and bound by them rather than build anything new. No new redb tables, no new extraction pass.

**Tech Stack:** Rust, `regex` crate (`regex::bytes`), tree-sitter (unchanged), redb (untouched), JSON-RPC protocol-v0, `cargo test`. Spec: `docs/superpowers/specs/2026-06-20-rts-regex-ranked-grep-design.md`.

---

## File Structure

- **`crates/rts-daemon/src/methods/grep_v2/compose.rs`** — `validate()` + `ValidationInput`. Owns the literal-vs-regex *decision*. Change: regex becomes the default; add `literal` and `all` inputs; adjust the multiline rule.
- **`crates/rts-daemon/src/methods/index.rs`** — `grep` handler. Owns *execution* + *response shape*. Change: literal fallback on regex compile error; rank-then-truncate to `GREP_DEFAULT_BUDGET`; summary fields; honor `--all`.
- **`crates/rts-mcp/src/cli.rs`** — `rts grep` CLI: clap flags + the ripgrep-style human formatter (renders the daemon's JSON). Change: add `--literal`/`--fixed`, `--all`; keep `--regex` as accepted no-op; show `enclosing_qualified_name` per hit + a summary footer.
- **Tests:** `crates/rts-daemon/src/methods/grep_v2/compose.rs` `#[cfg(test)] mod tests` (line 234) for the pure validator; `crates/rts-daemon/tests/grep_round_trip.rs` (mirror its harness) for daemon behavior; `crates/rts-mcp/src/cli.rs` `#[cfg(test)]` (line 924) for the formatter.

---

## Phase 1 — Regex default + literal fallback

### Task 1: Validator defaults to regex; add `literal`/`all` inputs

**Files:**
- Modify: `crates/rts-daemon/src/methods/grep_v2/compose.rs` — `ValidationInput` struct (~line 96), `validate()` (line 122), the multiline rule (step 4), and the final mode-resolution (`else if regex_mode` / `else`).
- Test: same file, `#[cfg(test)] mod tests` (line 234).

Behavior contract:
- `text` present, neither `literal` nor `regex=false` forcing literal → **`Regex`** (new default).
- `literal: Some(true)` (or `fixed`) → **`Literal`**, regardless of `regex`.
- `regex: Some(true)` → `Regex` (now a no-op alias — same as default).
- `multiline: true` is now allowed with the default regex; only `literal:true + multiline:true` is the conflict → reject `MultilineRequiresRegex`.
- `all` is a pass-through shared filter (consumed in Phase 2); add the field now so the struct/CLI wiring is done once.

- [ ] **Step 1: Add fields to `ValidationInput` and `SharedFilters`**

In `ValidationInput` (the struct ending ~line 110) add:
```rust
    pub literal: Option<bool>,
    pub all: Option<bool>,
```
In `SharedFilters` (the struct ~line 88) add:
```rust
    pub all: bool,
```

- [ ] **Step 2: Write failing validator tests**

Add to `mod tests` in `compose.rs`:
```rust
fn input(text: &str) -> ValidationInput {
    ValidationInput { text: Some(text.to_string()), ..Default::default() }
}

#[test]
fn defaults_to_regex_not_literal() {
    let (call, _) = validate(&input("a|b|c")).unwrap();
    assert!(matches!(call, ValidatedGrepCall::Regex { multiline: false, .. }),
        "bare text must default to Regex, got {call:?}");
}

#[test]
fn literal_flag_forces_literal_even_for_regexy_text() {
    let mut i = input("a.b");
    i.literal = Some(true);
    let (call, _) = validate(&i).unwrap();
    assert!(matches!(call, ValidatedGrepCall::Literal { .. }));
}

#[test]
fn regex_true_is_a_noop_alias_for_default() {
    let mut i = input("a|b");
    i.regex = Some(true);
    let (call, _) = validate(&i).unwrap();
    assert!(matches!(call, ValidatedGrepCall::Regex { .. }));
}

#[test]
fn multiline_allowed_without_explicit_regex_now() {
    let mut i = input("a\\n.*b");
    i.multiline = Some(true);
    let (call, _) = validate(&i).unwrap();
    assert!(matches!(call, ValidatedGrepCall::Regex { multiline: true, .. }));
}

#[test]
fn literal_plus_multiline_is_rejected() {
    let mut i = input("ab");
    i.literal = Some(true);
    i.multiline = Some(true);
    let err = validate(&i).unwrap_err();
    assert_eq!(err.code, GrepValidationCode::MultilineRequiresRegex);
}

#[test]
fn all_flows_into_shared_filters() {
    let mut i = input("x");
    i.all = Some(true);
    let (_, shared) = validate(&i).unwrap();
    assert!(shared.all);
}
```
(If `err.code` is not a public field, assert via the existing accessor used elsewhere in this test module.)

- [ ] **Step 3: Run the tests — expect failure**

Run: `cargo test -p rts-daemon --lib grep_v2::compose`
Expected: the new tests FAIL (still literal-by-default; `literal`/`all` fields missing compile or behavior wrong).

- [ ] **Step 4: Implement the new defaulting**

In `validate()`:
- Replace `let regex_mode = input.regex.unwrap_or(false);` with an explicit force-literal computation:
```rust
    let force_literal = input.literal.unwrap_or(false);
    // Regex is the default; only an explicit literal/fixed flag opts out.
    let use_regex = !force_literal;
```
- Replace the multiline rule (step 4) so the conflict is *literal + multiline*:
```rust
    if multiline && force_literal {
        return Err(GrepValidationError::new(
            GrepValidationCode::MultilineRequiresRegex,
            "`multiline: true` conflicts with `literal`; multiline is a regex-only flag",
        ));
    }
```
- In the mode-resolution `match`/`if` at the end, the **structural `combine`** must use `use_regex` (so a composed filter defaults to regex too): change `(Some(text), false) => Literal{…}` / `(Some(text), true) => Regex{…}` to branch on `force_literal` (literal only when forced), else Regex with `multiline`.
- Change the plain (non-structural) tail from `else if regex_mode { Regex } else { Literal }` to:
```rust
    } else if force_literal {
        ValidatedGrepCall::Literal { text: input.text.clone().unwrap(), case_insensitive }
    } else {
        ValidatedGrepCall::Regex { pattern: input.text.clone().unwrap(), case_insensitive, multiline }
    };
```
- Set `all: input.all.unwrap_or(false)` in the `SharedFilters` constructor.

- [ ] **Step 5: Run the tests — expect pass**

Run: `cargo test -p rts-daemon --lib grep_v2::compose`
Expected: PASS. Also run the full validator module to catch matrix regressions: `cargo test -p rts-daemon --lib grep_v2`.

- [ ] **Step 6: Commit**

```bash
git add crates/rts-daemon/src/methods/grep_v2/compose.rs
git commit -m "feat(grep): default to regex, add literal/all inputs to validator"
```

### Task 2: Literal fallback when the regex fails to compile

**Files:**
- Modify: `crates/rts-daemon/src/methods/index.rs` — the `Regex` arm of the `match validated` block (the `RegexBuilder::build()` site, ~line 150) and the response serialization (~line 1818, where the `truncated`/`files_with_matches` object is built).
- Test: `crates/rts-daemon/tests/grep_round_trip.rs` (mirror its existing harness).

Contract: when the pattern is regex by default but fails to compile (e.g. `def foo(`), retry as a `GrepScanner::Literal` over the same text, and add `"matched": "literal"` to the response (default `"matched": "regex"`). Multiline cannot fall back — a failed multiline regex returns the existing compile error.

- [ ] **Step 1: Write failing round-trip tests**

In `grep_round_trip.rs`, mirroring the setup helper already in that file (index a temp workspace, call `Index.Grep`), add:
```rust
#[test]
fn alternation_matches_union_of_alternands() {
    // workspace containing `astroid` and `tomlkit` on different lines
    let resp = grep(&ws, json!({ "text": "astroid|tomlkit" }));
    let lines: Vec<_> = resp["matches"].as_array().unwrap().iter()
        .map(|m| m["line_text"].as_str().unwrap()).collect();
    assert!(lines.iter().any(|l| l.contains("astroid")));
    assert!(lines.iter().any(|l| l.contains("tomlkit")));
    assert_eq!(resp["matched"], "regex");
}

#[test]
fn uncompilable_regex_falls_back_to_literal() {
    // workspace containing the literal text `def foo(`
    let resp = grep(&ws, json!({ "text": "def foo(" }));
    assert!(!resp["matches"].as_array().unwrap().is_empty(),
        "must find the literal `def foo(` via fallback");
    assert_eq!(resp["matched"], "literal");
}
```
(Use the file's existing `grep(&ws, params)` helper name; if it differs, match it.)

- [ ] **Step 2: Run — expect failure**

Run: `cargo test -p rts-daemon --test grep_round_trip alternation uncompilable`
Expected: FAIL — `astroid|tomlkit` finds nothing (literal default) and the bad regex errors instead of falling back; `matched` field absent.

- [ ] **Step 3: Implement the fallback**

In the `Regex` arm (~line 135–159), capture whether `build()` (single-line) or `compile_multiline_regex` (multiline) failed. Replace the `.map_err(...)` that returns the error for the **single-line** case with a fallback:
```rust
    // Regex is the default; if a non-multiline pattern fails to compile
    // (e.g. `def foo(`), retry it as a literal substring so the model's
    // natural patterns never dead-end. Multiline cannot fall back.
    let mut matched_kind = "regex";
    let scanner = if multiline {
        let re = super::grep_v2::multiline::compile_multiline_regex(&pattern, case_insensitive)
            .map_err(/* existing error mapping */)?;
        GrepScanner::Regex(re)
    } else {
        let mut builder = regex::bytes::RegexBuilder::new(&pattern);
        builder.case_insensitive(case_insensitive);
        match builder.build() {
            Ok(re) => GrepScanner::Regex(re),
            Err(_) => {
                matched_kind = "literal";
                GrepScanner::Literal { text: pattern.clone(), case_insensitive }
            }
        }
    };
    (pattern, case_insensitive, multiline, scanner)
```
Thread `matched_kind` down to the response builder. In the Literal arm, `matched_kind = "literal"` too (an explicit `--literal` is literal). In the serialization object (~line 1818) add: `"matched": matched_kind,`.

- [ ] **Step 4: Run — expect pass**

Run: `cargo test -p rts-daemon --test grep_round_trip`
Expected: PASS (new + existing grep round-trip tests).

- [ ] **Step 5: Commit**

```bash
git add crates/rts-daemon/src/methods/index.rs crates/rts-daemon/tests/grep_round_trip.rs
git commit -m "feat(grep): literal fallback when regex fails to compile (matched field)"
```

### Task 3: CLI flags — `--literal`/`--fixed`, `--all`, `--regex` no-op

**Files:**
- Modify: `crates/rts-mcp/src/cli.rs` — the `grep` subcommand clap args (where `--regex`, `--case-sensitive`, `--multiline` are defined) and the code that builds the `Index.Grep` params object.
- Test: `crates/rts-mcp/src/cli.rs` `#[cfg(test)]` (line 924).

- [ ] **Step 1: Write a failing CLI param-mapping test**

In the cli.rs test module, mirror an existing arg→params test:
```rust
#[test]
fn literal_and_all_flags_map_into_params() {
    let p = grep_params_from_args(&["grep", "--literal", "--all", "--", "a|b"]);
    assert_eq!(p["literal"], true);
    assert_eq!(p["all"], true);
    assert_eq!(p["text"], "a|b");
}

#[test]
fn regex_flag_is_accepted_as_noop() {
    // --regex must still parse (back-compat) and produce regex semantics,
    // which is now the default → no `literal` key, or literal:false.
    let p = grep_params_from_args(&["grep", "--regex", "--", "a|b"]);
    assert_ne!(p.get("literal"), Some(&serde_json::Value::Bool(true)));
}
```
(Use the file's real helper for building params from parsed args; if there is none, construct the clap `Grep` args struct directly and assert on the JSON it serializes to.)

- [ ] **Step 2: Run — expect failure**

Run: `cargo test -p rts-mcp --lib cli`
Expected: FAIL — `--literal`/`--all` are unknown flags.

- [ ] **Step 3: Implement the flags**

Add to the grep clap args struct (beside `regex`, `case_sensitive`):
```rust
    /// Force literal-substring matching (disable the default regex).
    #[arg(long, visible_alias = "fixed")]
    literal: bool,
    /// Return every match in scan order, unranked and unbounded.
    #[arg(long)]
    all: bool,
```
Keep the existing `--regex` flag (now semantically a no-op alias; do not remove). When building the params object, set `"literal": self.literal` and `"all": self.all`. Leave `regex` plumbed as today (harmless — daemon treats regex as default).

- [ ] **Step 4: Run — expect pass**

Run: `cargo test -p rts-mcp --lib cli`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/rts-mcp/src/cli.rs
git commit -m "feat(grep cli): add --literal/--fixed and --all; keep --regex as no-op alias"
```

---

## Phase 2 — Rank, bound, enclosing context, summary

### Task 4: Rank-then-truncate grep matches to `GREP_DEFAULT_BUDGET`

**Files:**
- Modify: `crates/rts-daemon/src/methods/index.rs` — the grep result assembly where `final_matches` is truncated to `limit` (~lines 1740–1820). Add a module const near the other grep consts (`DEFAULT_LIMIT`, ~line 1366).
- Test: `crates/rts-daemon/tests/grep_round_trip.rs`.

**Budget model (decided here — read before coding):** three distinct numbers.
- `GREP_DEFAULT_BUDGET = 40` — the **response cap** (matches returned) when `limit` is unset and `all` is false. Implemented by changing the validator's unset-`limit` default from 256 to 40 (Step 1b).
- `RANK_POOL = 256` — the **ranking candidate pool**: normal-mode scan retains at most this many matches to rank (so the top-40 is chosen from a real pool, not an arbitrary first-40). `RANK_POOL` is `max(RANK_POOL, limit)` so an explicit `--limit 500` still ranks from ≥500.
- `total_matches` — a **counter** of every match the scan encounters up to the existing hard ceiling (`MAX_LIMIT = 4096`), incremented even past `RANK_POOL`, so the footer can honestly say "40 of 918".

Contract: normal mode sorts the retained pool by `rank_score` descending (mirror `find_symbol`'s `SortMode::Rank` at `index.rs:1094`), stable tie-break by `(file, start_byte)`; hits with no enclosing symbol get `rank_score = 0.0` so they sort last; then truncates to `limit` (40 default / N if set). `all` mode (Task 5) retains every match in scan order, no rank, no truncate. The response gains `total_matches` and `shown` (= returned count) and keeps `files_with_matches` + `truncated`.

- [ ] **Step 1: Add the constants**

Near the existing grep consts in `index.rs` (~line 1366):
```rust
/// Default number of ranked matches returned when `limit` is unset and
/// `all` is false. Flagged in the design as possibly tight; one-line tunable.
const GREP_DEFAULT_BUDGET: usize = 40;
/// Ranking candidate pool: how many matches normal-mode scan retains to
/// rank from (independent of how many are returned). Raised to `limit`
/// when an explicit larger `--limit` is requested.
const RANK_POOL: usize = 256;
```

- [ ] **Step 1b: Default the response cap to 40 in the validator**

In `compose.rs` change the unset-`limit` default from `DEFAULT_LIMIT` (256) to 40 so a bare `code_grep` returns the budgeted set:
```rust
    limit: input.limit.unwrap_or(40),
```
Update the `DEFAULT_LIMIT` doc-comment to note grep's response default is now 40 (the 256 value survives only as `RANK_POOL` in the handler). Add/adjust a `compose.rs` test asserting `validate(&input("x")).1.limit == 40`.

- [ ] **Step 2: Write failing round-trip tests**

```rust
#[test]
fn matches_are_ranked_by_rank_score_desc() {
    let resp = grep(&ws, json!({ "text": "Config" }));
    let scores: Vec<f64> = resp["matches"].as_array().unwrap().iter()
        .map(|m| m["rank_score"].as_f64().unwrap()).collect();
    assert!(scores.windows(2).all(|w| w[0] >= w[1]), "not rank-desc: {scores:?}");
}

#[test]
fn default_budget_bounds_to_40() {
    // workspace with > 40 matches for the pattern
    let resp = grep(&ws_many, json!({ "text": "import" }));
    assert_eq!(resp["matches"].as_array().unwrap().len(), 40);
    assert_eq!(resp["truncated"], true);
    assert!(resp["total_matches"].as_u64().unwrap() > 40);
    assert_eq!(resp["shown"], 40);
}
```

- [ ] **Step 3: Run — expect failure**

Run: `cargo test -p rts-daemon --test grep_round_trip ranked default_budget`
Expected: FAIL — matches are in scan order; default cap is 256; `total_matches`/`shown` absent.

- [ ] **Step 4: Implement count-all + rank-pool + truncate**

`limit` here is already `40` by default (Step 1b) or the explicit value. In the scan-result assembly (~1740–1760), apply the budget model. Keep counting matches into `total_matches` independent of what is retained:
```rust
    // `total_matches` counts everything scanned (already accumulated, or
    // add a counter in the scan loop); `final_matches` holds the retained set.
    let pool_cap = RANK_POOL.max(limit);              // normal-mode retain cap
    let total_matches = final_matches.len();          // floor if scan ceiling hit

    if !shared_filters.all {
        // Retain only the pool, rank it (mirror find_symbol index.rs:1094),
        // then truncate to the response budget `limit`.
        final_matches.truncate(pool_cap);
        final_matches.sort_by(|a, b| {
            b.rank_score.partial_cmp(&a.rank_score)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then(a.file.cmp(&b.file))
                .then(a.start_byte.cmp(&b.start_byte))
        });
        final_matches.truncate(limit);
    }
    let truncated = total_matches > final_matches.len();
```
(Confirm the match element's field names — `rank_score`, `file`, `start_byte`; if `rank_score` is `Option<f64>`, map `None` → `0.0` before comparing. If the scan currently stops at `limit`, raise its internal cap so it counts/retains up to `MAX_LIMIT` for the counter and `pool_cap` for retention.) In the serialization object add `"total_matches": total_matches,` and `"shown": final_matches.len(),`; recompute `files_with_matches` from the **final** retained matches.

- [ ] **Step 5: Run — expect pass**

Run: `cargo test -p rts-daemon --test grep_round_trip`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add crates/rts-daemon/src/methods/index.rs crates/rts-daemon/tests/grep_round_trip.rs
git commit -m "feat(grep): rank by rank_score and bound to GREP_DEFAULT_BUDGET=40"
```

### Task 5: `--all` escape bypasses ranking and the budget

**Files:**
- Modify: `crates/rts-daemon/src/methods/index.rs` (the same block — verify `all` is honored; it was wired in Task 4's `effective_limit`/sort guards).
- Test: `crates/rts-daemon/tests/grep_round_trip.rs`.

- [ ] **Step 1: Write failing test**

```rust
#[test]
fn all_returns_every_match_in_scan_order() {
    let resp = grep(&ws_many, json!({ "text": "import", "all": true }));
    let n = resp["matches"].as_array().unwrap().len();
    assert!(n > 40, "expected all matches, got {n}");
    assert_eq!(resp["truncated"], false);
    // scan order = ascending by (file, start_byte), NOT rank
    let keys: Vec<(String,u64)> = resp["matches"].as_array().unwrap().iter()
        .map(|m| (m["file"].as_str().unwrap().to_string(),
                  m["range"]["start_byte"].as_u64().unwrap())).collect();
    let mut sorted = keys.clone(); sorted.sort();
    assert_eq!(keys, sorted, "all mode must preserve scan order");
}
```

- [ ] **Step 2: Run — expect failure (or pass if Task 4 already covers it)**

Run: `cargo test -p rts-daemon --test grep_round_trip all_returns`
Expected: FAIL if scan-order/`truncated:false` not yet honored under `all`.

- [ ] **Step 3: Implement**

The `if !shared_filters.all { … }` guard from Task 4 already skips the pool-truncate, rank, and budget-truncate under `all`, leaving `final_matches` as the full scan-order set with `truncated = total_matches > final_matches.len()` evaluating to `false`. Verify the scan retains every match (up to `MAX_LIMIT`) when `all` is set — if the scan loop caps retention at `RANK_POOL`/`limit`, gate that cap on `!shared_filters.all`. This task adds the explicit scan-order assertion + test.

- [ ] **Step 4: Run — expect pass**

Run: `cargo test -p rts-daemon --test grep_round_trip`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/rts-daemon/src/methods/index.rs crates/rts-daemon/tests/grep_round_trip.rs
git commit -m "feat(grep): --all bypasses ranking and the budget (scan order, unbounded)"
```

### Task 6: CLI shows enclosing function per hit + summary footer

**Files:**
- Modify: `crates/rts-mcp/src/cli.rs` — the ripgrep-style human formatter for `Index.Grep` results (~line 326).
- Test: `crates/rts-mcp/src/cli.rs` `#[cfg(test)]` (line 924).

Contract: each hit line shows its enclosing symbol when present —
`path:line: <enclosing_qualified_name>(): <line_text>` (omit the `<name>():` segment when `enclosing_qualified_name` is null). When `truncated` is true, append a footer line:
`… showing {shown} of {total_matches} matches across {files_with_matches} files. Narrow with --glob, or --limit N / --all for more.`

- [ ] **Step 1: Write failing formatter tests**

```rust
#[test]
fn formats_hit_with_enclosing_symbol() {
    let resp = json!({
        "matches": [{
            "file": "a.py", "line_text": "    raise ProtocolError()",
            "range": {"start_line": 12},
            "enclosing_qualified_name": "send", "rank_score": 0.1
        }],
        "shown": 1, "total_matches": 1, "truncated": false, "files_with_matches": 1
    });
    let out = render_grep_human(&resp);
    assert!(out.contains("a.py:12: send(): "));
    assert!(!out.contains("showing"));
}

#[test]
fn appends_summary_footer_when_truncated() {
    let resp = json!({
        "matches": [{ "file": "a.py", "line_text": "x", "range": {"start_line": 1},
                      "enclosing_qualified_name": null, "rank_score": 0.0 }],
        "shown": 40, "total_matches": 918, "truncated": true, "files_with_matches": 6
    });
    let out = render_grep_human(&resp);
    assert!(out.contains("showing 40 of 918 matches across 6 files"));
}
```
(Use the real formatter function name from line ~326; `render_grep_human` is a placeholder for it.)

- [ ] **Step 2: Run — expect failure**

Run: `cargo test -p rts-mcp --lib cli`
Expected: FAIL — no enclosing segment, no footer.

- [ ] **Step 3: Implement the formatter changes**

In the per-match line builder, when `enclosing_qualified_name` is a non-null string, insert `{name}(): ` after the `path:line: ` prefix. After the match loop, if `resp["truncated"] == true`, push the footer line using `shown`/`total_matches`/`files_with_matches`.

- [ ] **Step 4: Run — expect pass**

Run: `cargo test -p rts-mcp --lib cli`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/rts-mcp/src/cli.rs
git commit -m "feat(grep cli): show enclosing function per hit + truncation summary footer"
```

---

## Phase 3 — Validate against the measured baseline

### Task 7: Re-run the measurement harness and confirm the wins

**Files:**
- Use: `/tmp/token_savings.py`, `/tmp/token_fair.py` (built earlier; tiktoken o200k_base in `/tmp/swebench-venv`).
- No source changes — this task gates the work against the spec's success criteria.

- [ ] **Step 1: Build release binaries the harness shells out to**

Run: `cargo build --release -p rts-mcp -p rts-daemon`
Expected: clean build. Ensure the `rts` on PATH points at the new `target/release/rts` (the harness calls `rts grep`).

- [ ] **Step 2: Re-measure useful-hit rate**

Re-run the hit-rate replay over the saved serve-arm patterns (same method as the prior baseline that produced 27%). Compare alternation patterns specifically (`tomlkit|astroid|pytest`, `socket.error|SocketError|ProtocolError`).
Expected: alternations that previously returned nothing now return ranked hits; aggregate useful-hit rate materially above 27%.

- [ ] **Step 3: Re-measure tokens**

Run: `/tmp/swebench-venv/bin/python /tmp/token_fair.py`
Expected: on broad searches (e.g. `astroid`) rts output drops to ≤ ~2k tokens (was ~23k); the per-search median rts/raw ratio does **not** rise above the prior 1.04 (no narrow-search regression).

- [ ] **Step 4: Record results**

Append the before/after numbers (hit-rate, broad-search tokens, narrow-search median ratio) to the spec's §5 success-criteria checklist and note any constant (`GREP_DEFAULT_BUDGET`) tuning suggested by the data.

- [ ] **Step 5: Commit the results note**

```bash
git add docs/superpowers/specs/2026-06-20-rts-regex-ranked-grep-design.md
git commit -m "docs(rts): record regex/ranked-grep re-measurement results"
```

---

## Final verification

After all tasks: `cargo test -p rts-daemon -p rts-mcp` (full grep + validator + CLI suites green), `cargo clippy -p rts-daemon -p rts-mcp` clean, and the Phase 3 numbers meet the spec's success criteria. Then use **superpowers:finishing-a-development-branch** to open the PR.
