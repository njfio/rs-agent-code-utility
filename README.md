# rts — AST-precise code search for AI coding agents

[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)](#license)
[![Languages](https://img.shields.io/badge/languages-12-brightgreen)](#languages)
[![Token reduction](https://img.shields.io/badge/token%20reduction-99.9%25-brightgreen)](#why)

`rts` is a local code-retrieval daemon plus an [MCP](https://modelcontextprotocol.io/) bridge that gives AI coding agents — Claude Code, Cursor, Continue, Aider, Cline — **AST-precise, ranked, sub-millisecond** access to your codebase. It replaces the "agent runs `rg` and reads whole files" pattern with structured tool calls that return *exactly the bytes the agent needs* — typically **99.9% less context** for the same answer.

It's local, offline, and per-workspace. No code leaves the machine.

## What you get over `rg`

```sh
$ rg -n 'commit_batch\(' crates/                          # bash grep
crates/rts-daemon/src/store/mod.rs:242:    pub fn commit_batch(             # ← the definition itself!
crates/rts-daemon/src/store/mod.rs:1532:        .commit_batch(vec![entry], …)
crates/rts-daemon/src/store/mod.rs:1588:        .commit_batch(vec![entry], …)
crates/rts-daemon/src/store/mod.rs:1660:        .commit_batch(vec![entry], …)
crates/rts-daemon/src/store/mod.rs:1704:        .commit_batch(vec![v1],    …)
# …text matches; you still don't know which function is calling commit_batch
```

```sh
$ rts-bench query --output lines find-callers --name commit_batch  # rts
crates/rts-daemon/src/store/mod.rs:1532:commit_then_find_symbol_round_trips (fn)
crates/rts-daemon/src/store/mod.rs:1588:find_symbols_batch_matches_per_name_find_symbol (fn)
crates/rts-daemon/src/store/mod.rs:1660:find_symbols_batch_with_sids_returns_sids_for_known_names (fn)
crates/rts-daemon/src/store/mod.rs:1704:re_upsert_drops_prior_defs_for_same_file (fn)
crates/rts-daemon/src/store/mod.rs:1728:re_upsert_drops_prior_defs_for_same_file (fn)
# AST-precise call sites with the enclosing fn name; no def, no false positives
```

Same five lines worth of work, but: **the definition is filtered out, every match shows the enclosing function**, and the data is sortable by PageRank. A refactor that touches `commit_batch`'s signature now has a *list of functions to update*, not a list of byte offsets.

And for non-symbol text — error messages, version pins, log strings — `grep` still has its place. `rts grep` does it AST-aware too:

```sh
$ rts-bench query --output lines grep --text 'panic!'
crates/rts-core/src/signature.rs:999:[sig]             .unwrap_or_else(|| panic!("expected a signature for `{input}`"))
crates/rts-core/src/signature.rs:1186:[ts]              … panic!("expected a typescript signature for `{input}`")
crates/rts-core/src/signature.rs:1293:[go]              … panic!("expected a go signature for `{input}`")
crates/rts-core/src/signature.rs:1357:[java]            … panic!("expected a java signature for `{input}`")
crates/rts-daemon/tests/read_round_trip.rs:523:[sig]     … panic!("signature field for {symbol}; got {resp:?}")
# The [bracketed] prefix is the enclosing function name — refactoring `panic!` semantics has the list
```

## Why

| problem | with `rg` + `cat` | with `rts` |
|---|---|---|
| **False positives.** "Find `commit_batch`" matches calls, comments, doc strings, the def itself. | every match needs human filtering | AST-precise: `find_callers` returns only callers, not the def |
| **No structure.** "Who calls X?" returns text; the agent must re-parse to find enclosing function names. | the agent grep-then-reads each file | one tool call returns `(file, line, enclosing_function_name, kind)` |
| **No ranking.** Important code looks the same as utility code. | first matches are alphabetical-by-path | PageRank-sorted; central symbols first |
| **Token cost.** Reading whole files to answer "what does X look like?" | ~100k tokens for "show me parse()" on a small repo | `read_symbol parse` returns the body (~30 tokens) |
| **Stale views.** Long-running agents see the codebase at start-of-session. | re-read everything each turn | file-watcher keeps the index live; `content_version` lets agents detect stale reads |

The headline number: on the rts-core crate itself, getting one function's body costs **94,285 tokens via `rg` + read** vs **28 tokens via `rts`**. 99.97% reduction. ([Reproduce](docs/development.md#running-the-benchmark).)

## Quick start

### Install

```sh
# Prebuilt binaries (macOS arm64, Linux x86_64, Linux arm64):
VERSION=0.6.1 TARGET=aarch64-apple-darwin   # or x86_64-unknown-linux-gnu / aarch64-unknown-linux-gnu
curl -fsSL "https://github.com/njfio/rs-agent-code-utility/releases/download/v${VERSION}/rts-${VERSION}-${TARGET}.tar.gz" | tar -xz
# Verify: SHA256SUMS (integrity) + `gh attestation verify` (authenticity, v0.6.1+).
# Browser-downloaded macOS tarballs need `xattr -dr com.apple.quarantine "rts-${VERSION}-${TARGET}/"`.

# Or build from source:
cargo build --workspace --release
```

### Wire into your agent

**Claude Code:**
```sh
claude mcp add rts -- $(which rts-mcp) --workspace "$PWD"
```
A `.mcp.json` in your repo root pins the rts tools as always-loaded (no `ToolSearch` round-trip per session). See [`docs/install.md`](docs/install.md) for Cursor / Continue / Aider / Cline snippets.

That's it. The MCP server auto-spawns the daemon on first connect; the daemon walks the workspace once (~1 s for 10k LOC, ~6 s for 100k) and watches for changes after that.

## What it gives your agent

Ten tools, all read-only. Eight are AST-precise query tools (below); two are observability tools. Full schemas in [`docs/protocol-v0.md`](docs/protocol-v0.md):

| tool | when to reach for it |
|---|---|
| `find_symbol` | "Where is `X` defined?" Exact name or glob. AST-precise; no false positives from comments or strings. |
| `find_callers` | "Who calls `X`?" One indexed-graph lookup. AST-precise. |
| `impact_of` | "If I change `X`, what breaks?" Transitive caller closure (BFS, bounded). Refactor blast radius. |
| `read_symbol` | "Show me `X`'s body." Optional tree-shaken dependency closure; optional callers in the same response. |
| `read_symbol_at` | "What's at `src/foo.rs:42`?" Line-anchored, for compiler-error follow-up. |
| `read_range` | Explicit line range. Stack-trace frames, diff hunks. |
| `outline_workspace` | "I'm new to this repo — where do I start?" Token-budgeted structural map; Aider-style PageRank file ranking. |
| `grep` | Literal substring or regex over indexed bytes. Returns matches with `enclosing_qualified_name` — the only `grep` you've used that says *which function the match is in*. |

The MCP server also exposes two observability tools — `daemon_stats` (per-method call counts) and `daemon_telemetry` (latency percentiles + cache-hit snapshot) — so you (and your agent) can see actual usage rather than guess.

## How it's built

```
   AI coding agent (Claude Code / Cursor / Continue / Aider / Cline)
              │ stdio JSON-RPC, MCP
              ▼
       crates/rts-mcp        per-agent process; exposes 10 tools
              │ Unix-domain socket, protocol-v0
              ▼
      crates/rts-daemon      workspace-pinned, auto-spawned
              │
      ┌───────┴────────────┐
      ▼                    ▼
   redb index         notify watcher
   defs · refs ·      (150 ms debounce,
   docs · pagerank    gitignore-aware,
   · enclosing        poll fallback)
```

**Single-uid**. Refuses to run as root. Sets `umask(0077)`, disables core dumps. **Zero outbound HTTP code paths** in the daemon and MCP build trees (asserted via `cargo tree` in CI). 12 languages indexed via tree-sitter — Rust, JS, TS, Python, C, C++, Go, Java, PHP, Ruby, Swift, C# — with AST-precise call edges on 10 of the 12 (added Java, PHP, Swift, C#) and regex fallback on C and C++.

## Status

**v0.6 — stable for daily use.** Latest release: `v0.6.1`. Used daily by the author on the rts codebase itself; looking for outside users — file an issue or a discussion.

**Landing on `main` (→ v0.7), build from source to try today:**

- **Markdown / prose indexing** — a 13th language. Headings become first-class symbols, so `find_symbol` and `outline_workspace` see your docs the way they see code.
- **Structural grep** — `rts grep --structural-query '(string_literal) @s' --language rust <text>` filters matches to tree-sitter node kinds, so you can ask for *string literals containing X* or *identifier usages of Y* — searches plain `grep` can't express. (`--within-symbol`, `--multiline` too.)
- **Reliability hardening** — cold mount on a real dev workspace is **~20× faster** (the watcher no longer scans `target/`/`node_modules`); a cold-start mount race that could wedge the daemon is fixed; `find_callers`/`impact_of` no longer surface prose mentions as call sites.

Pre-1.0 means the **wire protocol (protocol-v0)** may change additively and the **on-disk redb index** may change between minor versions (the daemon auto-rebuilds on upgrade; a *downgrade* across a schema bump needs a one-time state-dir wipe). The **user-facing surface will not break without a version bump.**

**Frozen in v0.6** (tool/subcommand *names + argument shapes*; additive flags are not frozen):

- **10 MCP tools** — `outline_workspace`, `find_symbol`, `read_symbol`, `read_symbol_at`, `read_range`, `find_callers`, `impact_of`, `grep`, `daemon_stats`, `daemon_telemetry`
- **10 `rts` CLI subcommands** — `mount`, `find`, `grep`, `callers`, `outline`, `read`, `stats`, `doctor`, `completions`, `telemetry`

**Not frozen (pre-1.0 mutable):** the protocol-v0 wire format (additive changes only) and the on-disk redb schema (auto-rebuilt on upgrade).

Also live: the `.claude/hooks/rts-nudge.sh` PreToolUse hook that nudges agents toward rts when they reach for `Bash grep`/`rg`/`find` (opt out via `RTS_HOOK_DISABLED=1`); the PageRank ranker holds `answerable_coverage = 1.000` on the rts-core audited corpus.

What's *not* yet done: macOS Intel prebuilt binaries (build from source), Windows port (Unix sockets; v1.x candidate), full macOS notarization (browser-downloaded tarballs need `xattr -dr com.apple.quarantine`), public agent-bench baseline.

## More documentation

- **[`docs/install.md`](docs/install.md)** — per-agent wiring (Claude Code, Cursor, Continue, Aider, Cline).
- **[`docs/protocol-v0.md`](docs/protocol-v0.md)** — daemon ↔ MCP wire protocol. Capability list, per-method schemas, per-release wire-shape evolution.
- **[`docs/development.md`](docs/development.md)** — bench commands, known limitations, the per-phase status table, building from source, contributing.
- **[`AGENTS.md`](AGENTS.md)** — coding standards, commit conventions, the "use rts, not grep" cheatsheet.
- **[`CHANGELOG.md`](CHANGELOG.md)** — per-release notes.
- **[`agent-bench/README.md`](agent-bench/README.md)** — the SWE-bench-lite harness that measures whether rts actually shifts agent behavior.

## License

MIT OR Apache-2.0. See [`LICENSE-MIT`](LICENSE-MIT) and [`LICENSE-APACHE`](LICENSE-APACHE).
