# Development guide

This doc holds the **maintainer-facing** content that used to live in `README.md`:
phase-by-phase status, known limitations, build / bench commands, internal crate layout,
contributing rules. The top-level `README.md` is the pitch; this doc is the manual.

For coding standards, commit conventions, and the "use rts, not grep" agent cheatsheet,
see [`../AGENTS.md`](../AGENTS.md).

## Status

**Active pre-1.0.** The author uses it daily on the rts codebase itself. Outside-user
contributions wanted — open an [issue](https://github.com/njfio/rs-agent-code-utility/issues)
or a [discussion](https://github.com/njfio/rs-agent-code-utility/discussions).

| Phase | Status |
|---|---|
| P0 — Spikes (rmcp, redb, notify) | ✅ |
| P1 — Tree-sitter 0.20 → 0.26 bump | ✅ |
| P2+P3 — Uncoupling + archive cut | ✅ |
| P4 — Cargo workspace + `rts-core` extraction | ✅ |
| P5 — Protocol-v0 design doc | ✅ (re-spec'd at alpha.30 baseline in U0) |
| P6 — `rts-daemon` (lifecycle + watcher + writer + Index.*) | ✅ |
| P7 — `rts-mcp` (rmcp 1.6 bridge) | ✅ |
| P8 — `SignatureRenderer` + PageRank | ✅ (file-level alpha.18; symbol-level alpha.34) |
| P9 — Benchmarks + install docs + prebuilt binaries | ✅ |
| **v0.3 — Persistent code-graph KB** | ✅ |
| **v0.4 — Semantic eval harness** | ✅ |
| **v0.5 — Doc-comment retrieval** | ✅ |
| **v0.5.5 — Cold-walk ref-graph correctness** (#100) | ✅ |
| **v0.5.6 — Live-edit ref-graph correctness** (#103, UNRESOLVED_REFS) | ✅ |
| **v0.5.7 — `Daemon.Stats` telemetry + shutdown auto-dump** (#104, #105) | ✅ |
| **v0.5.8 — PreToolUse hook + project-local MCP** (#106) | ✅ |
| **agent-bench foundation** (#107) | ✅ (PR-A; PR-B queued) |

See [`../CHANGELOG.md`](../CHANGELOG.md) for the per-release notes.

## Building from source

Requires Rust **1.85+** (Rust 2024 edition). macOS and Linux only;
Windows lands in v1.x.

```sh
git clone https://github.com/njfio/rs-agent-code-utility.git
cd rs-agent-code-utility
cargo build --workspace --release
```

Outputs at `target/release/{rts-mcp,rts-daemon,rts-bench}`. `rts-mcp` is the
only binary you wire into your agent; the daemon auto-spawns and the
bench harness is operator-only.

To work on `agent-bench/` (the SWE-bench-lite A/B harness):

```sh
cd agent-bench
uv sync --dev
uv run pytest          # 28 tests, no Anthropic API key required
uv run agent-bench --status
```

## Crate / dir layout

```
crates/
  rts-core/      Tree-sitter wrapper + analyzer + 12 grammars
  rts-daemon/    Persistent local indexer; protocol-v0 over Unix socket
  rts-mcp/       Agent-facing MCP server (rmcp 1.6 over stdio)
  rts-bench/     Bench harness: rg-baseline vs MCP, the 5 §P9 tasks
agent-bench/     SWE-bench-lite A/B harness (Python; hits Anthropic API
                 ⇒ kept outside the HTTP-free rts-bench crate)
.claude/         PreToolUse hook + project-scoped Claude Code settings
docs/
  protocol-v0.md           Daemon ↔ MCP wire spec
  install.md               Install + per-agent wiring snippets
  development.md           This file
  plans/                   Active and historical plans
  brainstorms/             Origin requirements docs
spikes/                    P0 validation crates (rmcp, redb, notify)
archive/                   Pre-pivot library + CLI (preserved for git history)
.mcp.json                  Project-scoped MCP server registration with
                           alwaysLoad: true (Claude Code v2.1.121+)
changelog.d/               Per-PR fragments; concatenated into CHANGELOG.md
                           at release time via scripts/build-changelog.sh
```

## Running the benchmark

The bench is the only operator-facing CLI in the v0.2 stack.

```sh
# List the baseline + scenario tasks
target/release/rts-bench task list

# Run a single task (writes bench-<short-sha>.json)
target/release/rts-bench task run locate_def \
    --workspace ./crates/rts-core \
    --symbol parse

# Get a token-reduction comparison vs `rg` for a specific module
target/release/rts-bench task run summarize_module \
    --workspace ./crates/rts-core \
    --file src/analyzer.rs \
    --line-budget 50

# Refactor-impact scenario (the v0.3 alpha.35 path)
target/release/rts-bench task run scenario_refactor_impact \
    --workspace ./crates/rts-core \
    --symbol parse \
    --direct-callers analyze_file,build_index

# One-shot daemon queries (no bench scaffolding; talks straight to MCP)
target/release/rts-bench query find-symbol  --pattern '*'           # top symbols by rank
target/release/rts-bench query find-callers --name parse            # direct callers
target/release/rts-bench query impact-of    --name parse --depth 2  # transitive callers

# Bash-pipe-friendly output (v0.5.6+):
target/release/rts-bench query --output lines find-callers --name parse | sort | head -20
target/release/rts-bench query --output lines grep --text 'panic!' | awk -F: '{print $1}' | sort -u

# Telemetry: how often did the agent use rts vs Bash this session?
target/release/rts-bench query --output lines daemon-stats | grep -v '^#'
```

The agent-bench harness lives separately — see [`../agent-bench/README.md`](../agent-bench/README.md).

## Token-reduction numbers

| measurement | baseline (`rg` + `cat`) | rts | reduction |
|---|---:|---:|---:|
| Locate a function's definition (`parse` in `rts-core`) | 259,607 tokens | 148 tokens | **99.9%** |
| Get a function's body (`parse` in `rts-core`) | 94,285 tokens | 28 tokens | **100.0%** |
| Summarize a module (`analyzer.rs`, head 50 lines) | 27,258 tokens | 571 tokens | **97.9%** |
| Refactor-impact closure (transitive callers) | grep + read N files × 2 levels | one `impact_of` call | **≥ 70%** |

Token counter: `bytes / 3` per [`protocol-v0.md`](protocol-v0.md) §11.1. Reproduce
the first three via the `rts-bench task run <id>` commands above; the fourth
via `scenario_refactor_impact`.

## Known limitations

### First-mount on big workspaces takes seconds

Cold-mount cost on synthetic Rust workspaces (post-walker-fix daemon):

| Synthetic LOC | Files | First-mount |
|---:|---:|---:|
| 10k | 154 | ~1.0 s |
| 30k | 462 | ~1.9 s |
| 50k | 770 | ~2.9 s |
| 100k | 1539 | ~6.2 s |

The walker + writer are single-threaded today; each file is parsed in
sequence. Daemon defaults to a 10-minute idle timeout (`RTS_IDLE_SHUTDOWN_SECS=600`),
so first-mount is paid **once per session** and subsequent warm queries
are sub-ms-to-low-ms (`read_symbol` p95 = 2.9 ms post-perf-fixes).

Parallel parsing in the writer is the v0.4+ candidate that would
move this number.

### The PageRank graph is over *call* edges, not *type* edges

v0.3's symbol-level PageRank ranks symbols by how often they're called
(via tree-sitter's `@reference.call` capture and friends). It does
**not** rank symbols by how often they appear in type positions
(function signatures, struct fields, generic bounds, trait impls).
Per the v0.3 plan's Scope Boundaries, type-relationship edges are
deferred to v0.4+.

**Consequence:** running `find_symbol(pattern="*")` on a type-heavy
library (parser, type-system tool, trait-heavy abstraction) surfaces
utility functions and tree-sitter wrappers in the top-K, not the
library's "domain types." For workspaces dominated by call patterns
(web apps, services, CLI tools), the top-K closely matches "what's
central in this codebase."

### Language-prelude artifacts (filtered across 12 languages)

Tree-sitter's `call_expression` pattern captures stdlib/builtin names
the same way it captures real function calls. `Ok(x)`, `print(x)`,
`len(x)`, `malloc(n)`, `panic("...")` all parse as calls, so they
used to dominate the top-K of `find_symbol(pattern="*")` — every
function in the codebase "calls" them.

**Filtered as of v0.4.x.** Two-tier policy in
[`../crates/rts-daemon/src/symbol_pagerank.rs`](../crates/rts-daemon/src/symbol_pagerank.rs):

- **Always filter** (4 names): Rust variant constructors `Ok`, `Err`,
  `Some`, `None`. Filtered unconditionally because tree-sitter's
  tags.scm spuriously promotes `type Err = ()` associated-type
  aliases into def sites, so a def-count guard alone wouldn't catch
  them.
- **Filter if no workspace def** (~120 names): stdlib/builtin call-
  shape names across JavaScript, TypeScript, Python, Go, C, C++,
  Java, PHP, Ruby, Swift. Examples: `print`, `len`, `range`,
  `console`, `Promise`, `parseInt`, `make`, `append`, `panic`,
  `malloc`, `free`, `printf`. The def-count guard preserves
  user-defined symbols whose names collide with a prelude entry.

Filtered names still exist in the symbol table — `find_symbol(name="print")`
still finds them; they just get `rank_score = 0.0` and sink to the
bottom of rank-sorted responses.

Adding a name: edit `PRELUDE_NOISE` / `ALWAYS_FILTER` in
`symbol_pagerank.rs`. Adding a language: add its call-shape stdlib
names to `FILTER_IF_NO_DEF`.

### Single workspace per daemon process

`rts-daemon` is workspace-pinned (protocol-v0 §5.5). Cross-repo
queries require multiple daemon processes — one per workspace hash —
each on its own socket. `rts-mcp` auto-spawns the right one given
a workspace path; agents wiring multiple repos need multiple
`claude mcp add rts-foo --workspace /foo/path` entries.

### Windows is not yet supported

The daemon uses Unix sockets. A Windows port using named pipes is on
the v1.x candidate list — search "Windows" in
[`protocol-v0.md`](protocol-v0.md) for the design sketch.

## The eight tools (full schemas)

All `readOnlyHint=true`, `destructiveHint=false`, `openWorldHint=false`,
`idempotentHint=true`. Full descriptions (with explicit when-to-use-which
prose) are pinned per protocol-v0 §7 in
[`../crates/rts-mcp/src/server.rs`](../crates/rts-mcp/src/server.rs).

| tool | input | returns |
|---|---|---|
| `outline_workspace` | `{ glob?, token_budget?, mentioned_files?, mentioned_idents? }` | Token-budgeted structural map with file-level PageRank (Aider repo-map algorithm). |
| `find_symbol` | `{ name? \| pattern?, kind?, file?, sort?, limit?, doc_contains?, include_signature? }` | List of matches with `qualified_name`, `kind`, `file`, byte range, **real `rank_score`** (symbol-level PageRank), and `doc` (extracted comment, 10 languages). `pattern` is glob; default sort is descending rank. |
| `find_callers` | `{ name, kind?, file? }` | Direct callers — one indexed-graph lookup. Each entry carries the enclosing fn's `qualified_name`, `kind`, def range, call-site range, and `rank_score`. AST-precise. |
| `impact_of` | `{ name, depth?, token_budget?, max_nodes?, exclude_test_paths? }` | Transitive caller closure (BFS depth N, default 2, max 4). Four independent truncation flags (`closure_truncated`, `wall_clock_truncated`, `depth_truncated`, `node_count_truncated`) tell agents *why* a result is partial. |
| `read_symbol` | `{ name, file?, kind?, shape?, token_budget?, include_dependencies?, include_callers? }` | Body bytes + `content_version` + optional tree-shaken dependency closure + optional direct callers. |
| `read_symbol_at` | `{ file, line, column?, shape?, token_budget?, include_dependencies?, include_callers? }` | Line-anchored read for compiler-error flow (`error[E0308] --> src/foo.rs:42:18`). Same wire shape as `read_symbol`. |
| `read_range` | `{ file, start_line, end_line, token_budget? }` | Line slice + `content_version`. For stack traces, diff hunks. |
| `grep` | `{ text, limit?, case_insensitive?, regex?, file_glob? }` | Literal or regex search over indexed bytes. Returns matches with `enclosing_qualified_name`, `enclosing_kind`, `enclosing_def_range`, `rank_score`. |
| `daemon_stats` | `{}` | Per-method RPC counters for this daemon process. |

Every body-returning response carries a `content_version`
(`blake3(content)[:16]@mtime_ns+index_generation`) so v2 safe-edit flows
can detect stale views.

The 25 capability strings the daemon advertises via `Daemon.Ping` —
are documented in [`protocol-v0.md`](protocol-v0.md) §4.1 + Appendix F.

## Contributing

The project is in active pre-1.0 development. Conventions and workflow
live in [`../AGENTS.md`](../AGENTS.md). The short version: Rust 2024 edition,
`#![forbid(unsafe_code)]` on `rts-core` and `deny` workspace-wide,
conventional commits, every workspace member's tests must pass
(`cargo test --workspace`).

Each PR adds **one** changelog fragment to `changelog.d/`; the release
script (`scripts/build-changelog.sh`) concatenates them at release time.
This eliminates the per-PR merge-conflict pattern that historically ate
~30 minutes per release queue (when ~9 PRs landed concurrently in v0.5.4).

PR review uses the workflow + agents documented in `AGENTS.md`. The
`docs/plans/` directory contains the active design artifacts; the
`docs/brainstorms/` directory contains the upstream requirements
docs each plan originates from.
