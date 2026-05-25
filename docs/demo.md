# rts demo — bash grep vs AST-precise retrieval

A 60-second tour comparing shell `rg`/`grep` to `rts` on the rts repo
itself. Every command below is reproducible — clone the repo,
`cargo build --release`, and paste.

The demos are also valid asciinema input — feed this file's fenced
shell blocks to `asciinema rec` to generate a recordable cast.

## Setup (once)

```sh
git clone https://github.com/njfio/rs-agent-code-utility.git
cd rs-agent-code-utility
cargo build --release -p rts-mcp -p rts-daemon -p rts-bench

# Convenience aliases for the demo:
export RTS_MCP_BIN=$PWD/target/release/rts-mcp
export RTS_DAEMON_BIN=$PWD/target/release/rts-daemon
alias rts="./target/release/rts-bench query --output lines"
```

The first `rts` call will cold-mount the daemon (~6 s on a 100k LOC
workspace; ~1 s on small ones). Subsequent calls are sub-millisecond.

## Demo 1 — "Who calls this function?"

The classic refactor-impact question. The agent (or the user) is
about to change `commit_batch`'s signature and wants to know what
they'll break.

### With `rg`:

```sh
$ rg -n 'commit_batch\(' crates/ | head
crates/rts-daemon/src/store/mod.rs:242:    pub fn commit_batch(
crates/rts-daemon/src/store/mod.rs:1532:        .commit_batch(vec![entry], vec![], Durability::Immediate)
crates/rts-daemon/src/store/mod.rs:1588:        .commit_batch(vec![entry], vec![], Durability::Immediate)
crates/rts-daemon/src/store/mod.rs:1660:        .commit_batch(vec![entry], vec![], Durability::Immediate)
crates/rts-daemon/src/store/mod.rs:1704:        .commit_batch(vec![v1],    vec![], Durability::Immediate)
…
```

- Line 242 is the **definition itself**, not a caller. You have to
  filter it out by hand.
- The remaining lines tell you *where* the call appears (file + line)
  but not *which function* contains the call. To answer "who calls
  commit_batch" you'd have to `cat` each file and scroll backwards
  to find the enclosing `fn`.

### With `rts`:

```sh
$ rts find-callers --name commit_batch
crates/rts-daemon/src/store/mod.rs:1532:commit_then_find_symbol_round_trips (fn)
crates/rts-daemon/src/store/mod.rs:1588:find_symbols_batch_matches_per_name_find_symbol (fn)
crates/rts-daemon/src/store/mod.rs:1660:find_symbols_batch_with_sids_returns_sids_for_known_names (fn)
crates/rts-daemon/src/store/mod.rs:1704:re_upsert_drops_prior_defs_for_same_file (fn)
…
```

- **Definition is filtered out** (`find_callers` returns only callers,
  not the def).
- Every line shows **the name of the enclosing function** — exactly
  the list you need to plan the refactor.
- AST-precise: a comment containing `commit_batch(` would not match;
  a string literal containing `commit_batch(` would not match.

## Demo 2 — "Show me a function's body"

The token-cost difference. The agent wants the implementation of `parse`.

### With `cat` (the naive baseline):

```sh
$ wc -l crates/rts-core/src/lib.rs
6543 crates/rts-core/src/lib.rs

$ cat crates/rts-core/src/lib.rs | wc -c
282856
# ~94k tokens to read the whole file
```

### With `rts read-symbol`:

```sh
$ rts read-symbol --name parse --shape body
{
  "qualified_name": "parse",
  "file": "crates/rts-core/src/lib.rs",
  "shape": "body",
  "text": "pub fn parse(text: &str, lang: Language) -> Result<Tree> { … }",
  "content_version": "9c4f2e1a8b67d3c5@1748462100123456789+47"
}
# 28 tokens
```

The `content_version` field is `blake3(content)[:16]@mtime_ns+index_generation`.
Agents that re-read a symbol between turns can detect stale views
without re-shipping the full body.

## Demo 3 — "What's central to this codebase?"

PageRank-ranked symbols. The agent's "give me the lay of the land" query.

```sh
$ rts find-symbol --pattern '*' --limit 10
crates/rts-daemon/src/methods/index.rs:1532:pick_innermost_def (fn) [rank=1.247e-3]
crates/rts-daemon/src/store/mod.rs:242:commit_batch (fn) [rank=8.913e-4]
crates/rts-daemon/src/state.rs:59:DaemonState (struct) [rank=7.421e-4]
crates/rts-daemon/src/methods/index.rs:933:grep (fn) [rank=6.118e-4]
crates/rts-daemon/src/methods/index.rs:1210:find_callers (fn) [rank=5.892e-4]
…
```

`rank_score` is real PageRank over the call graph. Calling something
many times makes it more central; calling it from already-central
code amplifies that. Type-only references (struct fields, trait
bounds) are deferred to a future ranker — see [`development.md`](development.md#the-pagerank-graph-is-over-call-edges-not-type-edges)
for the scope rationale.

## Demo 4 — "Find every `panic!` with the enclosing function name"

Hybrid string + AST: the v0.5.5 grep with enclosing-symbol resolution
is grep's natural successor for refactor-shaped string search.

```sh
$ rts grep --text 'panic!'
crates/rts-core/src/signature.rs:999:[sig]            .unwrap_or_else(|| panic!("expected a signature for `{input}`"))
crates/rts-core/src/signature.rs:1186:[ts]             … panic!("expected a typescript signature for `{input}`")
crates/rts-core/src/signature.rs:1293:[go]             … panic!("expected a go signature for `{input}`")
crates/rts-core/src/signature.rs:1357:[java]           … panic!("expected a java signature for `{input}`")
crates/rts-daemon/tests/read_round_trip.rs:523:[sig]    … panic!("signature field for {symbol}; got {resp:?}")
…
```

The bracketed `[sig]`, `[ts]`, `[go]`, `[java]` prefix is the
**enclosing function name** for each match. Changing `panic!` to
`assert!` across the codebase now has a *list of test functions* to
update, not a list of byte offsets.

## Demo 5 — "Pipe to standard Unix tools"

`--output lines` produces `rg`-shaped output, so `awk`, `sort`,
`xargs` all work as expected.

```sh
# Every file that contains a panic!:
$ rts grep --text 'panic!' | awk -F: '{print $1}' | sort -u
crates/rts-core/src/signature.rs
crates/rts-daemon/src/watcher.rs
crates/rts-daemon/tests/read_round_trip.rs
crates/rts-daemon/tests/wire_round_trip.rs

# Pre-aware refactor-impact list — unique enclosing fn names:
$ rts grep --text 'unsafe' | sed 's/.*\[\([^]]*\)\].*/\1/' | sort -u
deserialize_session
serialize_session
…

# How often have I used rts this session?
$ rts daemon-stats | grep -v '^#' | awk -F: '$2+0 > 0'
Index.FindSymbol: 12
Index.Grep: 47
Index.FindCallers: 3
```

## What this doesn't show

- **MCP path** (the lower-latency, agent-facing surface). The
  `rts-bench query` wrapper above spawns rts-mcp + the daemon per
  call (~600 ms cold, ~15 ms warm). When an agent talks to
  `mcp__rts__*` directly through Claude Code's MCP runtime, the
  cost is single-digit ms — see [`install.md`](install.md) for the
  wiring.
- **The PreToolUse nudge.** When the hook (`.claude/hooks/rts-nudge.sh`)
  is active in a Claude Code session, reaching for `rg` / `grep`
  against the workspace surfaces a one-line nudge into the agent's
  next-turn context. See [`../AGENTS.md`](../AGENTS.md#active-behavior-nudge-v058)
  for the opt-out.
- **Transitive impact** (`impact_of`). Two-line demo: `rts impact-of
  --name commit_batch --depth 2` returns the BFS closure of callers
  with truncation flags, for refactor blast-radius queries.

## Recording this as asciinema

```sh
# In a fresh terminal in this repo:
asciinema rec rts-demo.cast --command "bash $(pwd)/docs/demo.md"
# (or just paste each block manually for a more curated cast)
```

Cast assets live in `docs/demo-cast.json` after recording. Add to
the [main README](../README.md)'s demo section once recorded.
