# rts sub-project A — Regex-correct, ranked & bounded `code_grep`

**Status:** Design approved (2026-06-20), pending spec review → implementation plan.

**Goal:** Make `code_grep` a strictly-better grep: run the model's patterns as
regex (so `a|b|c` works), and return *ranked, bounded* results with enclosing-
function context instead of a flat scan-order dump — so the useful-hit rate goes
up and broad searches stop burning tokens.

**Scope:** Parts 1 + 2 only (regex semantics + rank/bound). In-code text indexing
(comments/docstrings/string-literals) and semantic search are **out of scope** —
they are sub-projects B/C of the larger program. Non-code search targets
(README, ChangeLog, setup.cfg) remain out of scope by design: the pi-rts
enforcement hook already falls through to raw grep when rts returns nothing.

---

## 1. Motivation (measured)

A 23-task gpt-5.5 A/B + a deterministic token-replay (tiktoken o200k_base)
produced three findings that this sub-project targets:

- **Useful-hit rate is only ~27%.** rts answers ~1 in 4 of the model's searches.
- **Root cause of most misses: literal-mode matching.** `rts grep` defaults to
  *literal substring* (`rts grep --help`: "Default: literal substring"). The
  pi-rts extension calls `rts grep -- <pattern>` with **no `--regex`**, so a
  model pattern like `tomlkit|astroid|pytest` is searched as the literal string
  (pipes included) and finds nothing — even though `astroid` and `tomlkit`
  individually match. Confirmed live: the alternation returns 0; each alternand
  returns hits.
- **Broad searches dump tokens unranked.** `code_grep` already computes a
  per-hit `rank_score` (enclosing-symbol PageRank) and carries
  `enclosing_qualified_name`/`enclosing_kind` in its JSON — but the default
  human output is flat ripgrep-style lines in scan order, capped at `limit`
  (256). So `astroid` (918 hits) returns a ~23k-token unranked dump, and the
  enclosing-function context the tool advertises is not actually shown to the
  model.

The remaining expensive misses are genuinely non-code (changelogs/config/docs);
those are correctly left to raw grep via fall-through and are not addressed here.

## 2. Architecture

Both changes live in the **daemon grep path** so every consumer (CLI, MCP
server, agent-bench) inherits them:

- `crates/rts-daemon/src/methods/index.rs` — `grep` handler (entry ~line 1360),
  `GrepScanner::{Literal,Regex}` (~1463–1498).
- `crates/rts-daemon/src/methods/grep_v2/` — `compose.rs` (`ValidatedGrepCall`
  validation/dispatch), `structural.rs`, `multiline.rs`, `predicates.rs`.
- The human-output formatter for `rts grep` (ripgrep-style line emitter).

**No new redb tables, no new extraction pass, no new index.** The ranking signal
(`rank_score`) and enclosing-symbol metadata already exist per hit; this
sub-project changes search *execution* (regex/literal selection) and result
*formatting* (sort, bound, enclosing context, summary). The pi-rts extension is
unchanged — it keeps calling `rts grep -- <pattern>` and simply receives better
results.

## 3. Part 1 — Regex default + literal fallback

**Behaviour:**

1. Compile the pattern as a `regex`-crate regex (case-insensitive smart-case
   default, matching today's case behaviour).
2. **If compilation succeeds** → run as regex. Recovers `a|b|c`, `foo.*bar`, etc.
3. **If compilation fails** (e.g. `def foo(` → unbalanced paren) → automatically
   retry the pattern as a **literal substring** and return those hits, annotated
   so the model knows the semantics fell back (e.g. a `matched: "literal"` field
   in JSON and a `[literal]` note in the human summary line).
4. **Flags:** add `--literal` (alias `--fixed`) to force literal and skip the
   regex attempt; keep `--regex` as an accepted **no-op alias** (back-compat —
   it was the way to opt into regex; now regex is the default).

**Rationale:** the model writes regex; ripgrep (which `rts grep` claims output
parity with) is regex-by-default. The literal fallback removes the one new
failure mode regex-by-default would introduce (`def foo(` and other
metacharacter-bearing literals).

**Edge cases:**
- Empty pattern with `--structural-query` present → unchanged (structural path).
- `--multiline` still requires a valid regex; if the regex fails to compile,
  multiline cannot fall back to literal (literal is single-line) → return the
  compile error (do not silently change semantics).
- A pattern that compiles as regex but the user *meant* literally (e.g. `a.b`
  matching `axb`) is accepted as regex — this is the documented ripgrep-parity
  behaviour; `--literal` is the escape.

## 4. Part 2 — Rank, bound, enclosing context

Replace the flat scan-order, `limit`-capped default output with:

1. **Sort** all hits by `rank_score` descending (the enclosing-symbol PageRank
   already attached per hit). Hits with no enclosing symbol (module-level,
   inside comments/strings) get a baseline score of `0.0` (real PageRank scores
   are > 0), so they sort last. Stable tie-break by (file path, line).
2. **Group by file**, files ordered by their highest-ranked hit; within a file,
   hits in rank order.
3. **Bound** the default response. The primary limit is a **hit count** —
   `GREP_DEFAULT_BUDGET = 40` (top 40 hits after ranking). The "~1.5–2k tokens"
   figure is the *expected resulting size*, not a second independent limit. (See
   §6: flagged as possibly tight; single named constant, revisit after
   re-measurement.)
4. **Show enclosing context** per hit:
   `path:line  <enclosing_qualified_name>(): <line_text>` (omit the
   `<name>():` segment when there is no enclosing symbol).
5. **Summarize the remainder** when truncated:
   `… showing 40 of 918 matches across 6 of 142 files. Narrow with --glob, or --limit N / --all for more.`

**Flags:**
- `--limit N` — raise the hit cap (existing flag; now applies *after* ranking).
- `--all` — return every hit in **scan order**, unranked, unbounded (escape
  hatch + back-compat for scripts/pipelines that parse line-by-line).
- `--json` — unchanged structured shape (already carries `rank_score`,
  `enclosing_*`, ranges); JSON results are emitted in the new ranked order with a
  `truncated`/`total_matches`/`files_with_matches` summary so programmatic
  consumers see the same ranking.

## 5. Testing

**Unit (rts-core / rts-daemon):**
- Regex path: `a|b|c` compiles → regex → matches union of alternands.
- Fallback: `def foo(` fails regex → retried literal → matches literal text;
  result annotated `matched: literal`.
- `--literal` forces literal even when the pattern is a valid regex
  (`a.b` matches only `a.b`, not `axb`).
- `--regex` no-op alias yields identical results to the default.
- Ranking: given two hits whose enclosing symbols have known PageRank, the
  higher-ranked symbol's hit sorts first; module-level hit sorts last.
- Bounding: > budget hits → exactly `GREP_DEFAULT_BUDGET` returned, summary line
  reports correct `shown/total/files`.
- `--all` → every hit, scan order, no summary truncation.
- `--multiline` + uncompilable regex → returns compile error (no literal
  fallback), per §3 edge case.

**Integration / regression (existing bench harness):**
- Re-run `/tmp/token_savings.py` + the hit-rate measurement after the change.
- **Success criteria:**
  - Useful-hit rate rises materially above the 27% baseline (regex recovers
    code-file alternations).
  - Broad-search tokens drop sharply (e.g. `astroid` 23k → ≤ ~2k).
  - **No regression on narrow searches** — the per-search median rts/raw token
    ratio (was 1.04) does not increase; bounded output never *adds* tokens vs the
    pre-change flat output for the same hit set.

## 5b. Re-measurement results (2026-06-20, release build, pylint workspace)

Measured with the new `rts`/`rts-daemon` against the same patterns the original
token study used (tiktoken o200k_base). All success criteria met:

| Criterion | Baseline | Result |
|---|---|---|
| Alternation hit-rate | 0/4 (literal mode returned nothing) | **4/4 recovered** (`tomlkit\|astroid\|pytest`, `__version__\|2\.`, `towncrier\|bugfix\|feature`, `socket.error\|SocketError\|ProtocolError`) |
| Broad search `astroid` tokens | ~24,333 (unbounded, 870 hits) | **1,123 tokens** (40 ranked hits + footer) — **95% reduction** |
| Enclosing context per hit | absent (despite tool desc) | shown, e.g. `register(): def register(self):` |
| Paren pattern `def run(` | n/a | falls back to literal, finds the defs |

The 40 shown on a broad search are the PageRank-central hits (ranked from the
256-pool), not an arbitrary first-40. Narrow searches are bounded identically
(nothing balloons); the only per-line cost is the short `enclosing():` prefix
(~2–4 tokens/line), an acceptable trade for the context it adds. `--all` returns
the full unbounded set (24,333 tokens for `astroid`) when the agent wants it.

## 6. Open follow-ups (not blocking implementation)

- **Default budget tuning.** ~40 hits / ~2k tokens was flagged at design time as
  *probably too tight*. Shipped as-is behind the `GREP_DEFAULT_BUDGET` constant;
  revisit once the re-measurement shows the token/recall trade-off on real
  searches. Bumping it is a one-line change.
- Parts 3 (in-code text index) and C (semantic search) remain separate
  sub-projects, unblocked by this design.
