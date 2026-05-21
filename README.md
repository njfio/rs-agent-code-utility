# rts — Retrieval for agentic coding

`rts` is a workspace-pinned local retrieval daemon plus an MCP (Model
Context Protocol) bridge that gives AI coding agents (Claude Code,
Cursor, Cline, Aider, Continue) precise, token-cheap access to your
codebase. Replaces "the agent ripgreps and then reads whole files" with
"the agent calls one tool that returns exactly the bytes it needs."

As of **v0.3** the daemon is also a **persistent code knowledge graph**: the
reference half of the call graph is indexed at write time, so questions
like _"who calls X?"_, _"if I change X what breaks?"_, and _"what's central
to this codebase?"_ are single redb lookups instead of full workspace scans.

As of **v0.5** the index also carries **doc-comment text** for 10 languages
(`///`, `/** */`, `"""..."""`, `#`), and `find_symbol` accepts a
`doc_contains` substring filter. Behavior-shaped queries — _"find the
cache-eviction code"_ — return any documented symbol whose comment
mentions `evict`, regardless of identifier name. The graph-only ranker
sits at **100% answerable coverage** on a verified rts-core corpus (see
[CHANGELOG](CHANGELOG.md) for the per-PR journey from 40% → 100%).

**v0.6 (HEAD, untagged)** broadens the retrieval surface and hardens the
daemon for long-running agent loops: `Index.Grep` v2 composes multiline
regex, structural tree-sitter queries, and within-symbol scoping on the
same tool; AST-precise call edges now cover 10 of the 12 indexed
languages (added Java, PHP, Swift, C#); persisted cold-mount lets the
daemon trust an existing redb across restarts and falls back to a
reconciliation worker that catches on-disk drift; in-flight queries are
cancellable through a new `Daemon.Cancel` method; the MCP shim survives
daemon hiccups via a heartbeat + reconnect-with-backoff loop; opt-in
anonymous telemetry (`rts telemetry`) lets the project make roadmap
calls on aggregate signal; a new `rts` human CLI (`find`, `grep`,
`callers`, `outline`, `read`, `stats`) sits alongside `rts-mcp`; every
protocol-v0 method now ships a machine-readable JSON Schema under
[`schemas/v0/`](schemas/v0/); and a nightly real-repo regression bench
against tokio / flask / gin gates indexer metrics in CI.

| measurement | baseline | MCP | reduction |
|---|---:|---:|---:|
| Locate a function's definition (`parse` in `rts-core`) | 259,607 tokens | 148 tokens | **99.9%** |
| Get a function's body (`parse` in `rts-core`) | 94,285 tokens | 28 tokens | **100.0%** |
| Summarize a module (`analyzer.rs`, head 50 lines) | 27,258 tokens | 571 tokens | **97.9%** |
| Refactor-impact closure (transitive callers) | grep + read N files × 2 levels | one `impact_of` call | **≥ 70%** (target G2; v0.3 U5) |

Reproduce: `cargo build --workspace && target/debug/rts-bench task run
<id> --workspace <path> [--symbol NAME | --file PATH]`. Token counter is
`bytes / 3` per [docs/protocol-v0.md](docs/protocol-v0.md) §11.1; the
Anthropic SDK oracle (`--with-network`) lands later.

## Status

**Active pre-release.** Latest tag: `v0.5.5`. The v0.6 capability surface
(Grep v2, persisted cold-mount + reconciliation, cancellable queries,
opt-in telemetry, the `rts` human CLI, AST-precise call edges for
Java/PHP/Swift/C#, JSON Schemas under [`schemas/v0/`](schemas/v0/), and
a real-repo CI regression bench) is on HEAD; the `v0.6.0` tag cut is the
maintainer's next release action. Pre-pivot library + CLI live in
[`archive/`](archive/) for git history; no longer maintained.

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
| P9 — Benchmarks + install docs + prebuilt binaries | ✅ (`scenario_compiler_fix` + `scenario_refactor_impact` scenario tasks) |
| **v0.3 — Persistent code-graph KB** | ✅ (`Index.FindCallers`, `Index.ImpactOf`, symbol PageRank, indexed closure walker; U0-U5 shipped alpha.31-alpha.35) |
| **v0.4 — Semantic eval harness** | ✅ (graph-only ranker driven from a verified rts-core corpus; CI invariant locks `combined_answerable_rate`) |
| **v0.5 — Doc-comment retrieval** | ✅ (extractor for 10 languages, `find_symbol.doc` + `doc_contains` + `pre_filter_count`, doc-IDF in the ranker; 100% answerable coverage on the rts-core corpus) |
| **v0.6 — Retrieval breadth (HEAD)** | ✅ (`Index.Grep` v2: multiline regex + structural tree-sitter queries + within-symbol scope; AST-precise call edges for 10/12 languages incl. Java/PHP/Swift/C#) |
| **v0.6 — Daemon resilience (HEAD)** | ✅ (persisted cold-mount + reconciliation worker, cancellable queries via `Daemon.Cancel`, MCP heartbeat + reconnect-with-backoff with `DAEMON_UNAVAILABLE`/`DAEMON_DOWN` error codes) |
| **v0.6 — Operability (HEAD)** | ✅ (`rts-bench doctor`, `Daemon.Stats v2`, `rts` human CLI, opt-in `rts telemetry`, machine-readable JSON Schemas under `schemas/v0/`, nightly real-repo regression bench, `daemon_telemetry` MCP tool) |

## Architecture

```
   Agent (Claude Code, Cursor, …)        Terminal user
              │ stdio JSON-RPC                 │
              │ rmcp 1.6                       │
              ▼                                ▼
       crates/rts-mcp                  rts (human CLI; v0.6+)
       (10 MCP tools;                  shares the rts-mcp library:
        heartbeat + reconnect          socket + daemon_client +
        with backoff; v0.6+)           ConnectionManager
              │                                │
              └──────────────┬─────────────────┘
                             │ Unix-domain socket, protocol-v0
                             ▼
                     crates/rts-daemon   ◀── workspace-pinned, auto-spawned
                             │
                ┌────────────┴─────────────┐
                ▼                          ▼
          redb index                  notify watcher
          ┌─────────────────────┐    (150 ms debounce,
          │ META (v0.6+):       │     gitignore-aware,
          │   schema_version,   │     poll fallback)
          │   fingerprint_*     │    + reconciliation
          │ FILES, DEFS,        │      worker on rehydrate
          │   PATH_TO_FID,      │      (v0.6+)
          │ REFS, FID_REFS,     │
          │   SID_REFS_OUT,     │
          │ UNRESOLVED_REFS     │
          │   (+ GC, v0.6+)     │
          └─────────────────────┘
```

The redb store carries both halves of the code graph: `defs` + `fid_defs`
for "where is X defined?" and (v0.3+) `refs` + `fid_refs` + `sid_refs_out`
for "who calls X?", "what does X reference?", and transitive impact
queries. AST-precise via tags.scm on Rust/Python/Go/Ruby/JS/TS/Java/PHP/Swift/C#
(10 of the 12 indexed languages); regex fallback for C and C++.

The v0.6 `META` table persists a composite fingerprint
(`daemon_binary_version`, `grammar_versions`, `gitignore_content_hash`,
`fingerprint_combined`) so daemon restarts can skip the cold walk and
**rehydrate** from the existing redb when the fingerprint matches —
`Daemon.Stats` reports the decision via the `mount_source` field
(`rehydrate` / `cold_walk` / `cold_walk_after_invalidation:<reason>` /
`cold_walk_after_crash`). The reconciliation worker scans for on-disk
drift after a rehydrate and emits `WatchEvent::Touched`/`Removed` events
into the same writer drain that handles live edits.

Both halves are local-only and offline. The daemon is single-uid via
SO_PEERCRED / LOCAL_PEERCRED, refuses to run as root, sets
`umask(0077)`, and disables core dumps (full trust model:
[docs/protocol-v0.md](docs/protocol-v0.md) §1, §12). The MCP server has
zero outbound HTTP code paths (CI assertion lands with the prebuilt
binary release).

## Quick start

The MCP server auto-spawns the daemon on first connect. There is no
daemon for the user to start by hand.

### Option A: prebuilt tarballs (no Rust toolchain required)

Released on tag push under [Releases](https://github.com/njfio/rs-agent-code-utility/releases).
Each tarball contains `rts-daemon`, `rts-mcp`, `rts-bench`, both
license files, and this README. Available targets:

| target | runner |
|---|---|
| `x86_64-unknown-linux-gnu` | most Linux distros (Ubuntu 20.04+, Debian 11+, RHEL 9+) |
| `aarch64-unknown-linux-gnu` | ARM Linux (Raspberry Pi 64-bit, AWS Graviton) |
| `aarch64-apple-darwin` | Apple Silicon Mac (M1/M2/M3/M4) |

Windows is not yet supported — the daemon uses Unix sockets (a Windows
port lands in v1.x). Intel Mac (x86_64-apple-darwin) prebuilt tarballs
were dropped after the `macos-13` GitHub runner pool started hanging
indefinitely; Intel Mac users should build from source via Option B
below.

```sh
# Pick the right target for your platform
VERSION=0.5.5
TARGET=aarch64-apple-darwin
URL="https://github.com/njfio/rs-agent-code-utility/releases/download/v${VERSION}/rts-${VERSION}-${TARGET}.tar.gz"

curl -fsSL "$URL" | tar -xz
sudo install rts-${VERSION}-${TARGET}/{rts-daemon,rts-mcp,rts-bench} /usr/local/bin/

# Verify (each binary's `--version` should print `<name> ${VERSION}`)
rts-daemon --version
rts-mcp    --version
rts-bench  --version
rts        --version

# Try it from the terminal — no agent setup required.
# The CLI auto-spawns the daemon on first call.
cd path/to/your/project
rts find MyType
rts grep 'TODO' | head

# Wire into Claude Code
claude mcp add rts -- rts-mcp --workspace .
```

Each release ships a `SHA256SUMS` file you can verify against:

```sh
curl -fsSL "https://github.com/njfio/rs-agent-code-utility/releases/download/v${VERSION}/SHA256SUMS" -o SHA256SUMS
sha256sum -c SHA256SUMS --ignore-missing
```

### Option B: build from source

```sh
cargo build --workspace --release

# Sanity-check from the terminal — `rts` auto-spawns the daemon on first call.
target/release/rts find MyType

# Wire into Claude Code (the canonical client)
claude mcp add rts -- target/release/rts-mcp --workspace .
```

Other agents and the full troubleshooting matrix live in
[docs/install.md](docs/install.md). The human-facing CLI surface is
documented in [docs/cli.md](docs/cli.md).

## The ten MCP tools

All `readOnlyHint=true`, `destructiveHint=false`, `openWorldHint=false`,
`idempotentHint=true`. Full descriptions (with explicit when-to-use-which
prose, audited in v0.6 to win the tool-selection moment) are pinned per
protocol-v0 §7 in
[crates/rts-mcp/src/server.rs](crates/rts-mcp/src/server.rs).

| tool | input | returns |
|---|---|---|
| `outline_workspace` | `{ glob?, token_budget?, mentioned_files?, mentioned_idents? }` | Token-budgeted structural map with file-level PageRank (Aider repo-map algorithm). |
| `find_symbol` | `{ name? \| pattern?, kind?, file?, sort?, limit?, doc_contains?, include_signature? }` | List of matches with `qualified_name`, `kind`, `file`, byte range, **real `rank_score`** (symbol-level PageRank), and `doc` (extracted comment, 10 languages). `pattern` is glob (`*`/`?`); default sort is descending rank; pass `sort: "lexical"` to opt out. `doc_contains` substring-filters by doc text (case-insensitive) for behavior-shaped queries; when the filter is active the response also carries `pre_filter_count` so an empty result set is distinguishable from "nothing matched the name". |
| `find_callers` | `{ name, kind?, file? }` | Direct callers — one redb lookup. Each entry carries the enclosing fn's `qualified_name`, `kind`, def range, call-site range, and `rank_score`. AST-precise; replaces `rg <name>`. |
| `impact_of` | `{ name, depth?, token_budget?, max_nodes?, exclude_test_paths? }` | Transitive caller closure (BFS depth N, default 2, max 4). Refactor blast-radius query. Four independent truncation flags (`closure_truncated`, `wall_clock_truncated`, `depth_truncated`, `node_count_truncated`) tell agents *why* a result is partial. |
| `read_symbol` | `{ name, file?, kind?, shape?, token_budget?, include_dependencies?, include_callers?, force_resend? }` | Body bytes + `content_version` + optional tree-shaken dependency closure (alpha.22+) + optional direct callers (alpha.32+). |
| `read_symbol_at` | `{ file, line, column?, shape?, token_budget?, include_dependencies?, include_callers? }` | Line-anchored read for compiler-error flow (`error[E0308] --> src/foo.rs:42:18`). Same wire shape as `read_symbol`. |
| `read_range` | `{ file, start_line, end_line, token_budget? }` | Line slice + `content_version`. For stack traces, diff hunks. |
| `grep` | `{ text?, regex?, case_insensitive?, file_glob?, limit?, multiline?, structural_query?, within_symbol?, within_symbol_allow_overload?, language? }` | AST-aware ranked search across indexed bytes. v0.6 Grep v2 composes multiline regex, structural tree-sitter queries, and within-symbol scoping on the same tool surface; v1 callers pass nothing new and see byte-identical responses on the unchanged code path. |
| `daemon_stats` | `{}` | Per-method call counters for this daemon process (Daemon.Stats v2: `pinned_workspace_path`, `workspace_id`, `index_generation`, `cold_walk_completed_at_ms`, `mount_source`, rehydrate / reconciliation counters). |
| `daemon_telemetry` | `{}` | Counter + latency snapshot for telemetry analysis: per-method `latency_p50_ms`/`p99_ms`, `cache_hit_rate`, `cold_walk_ms_p50`, `languages_indexed`, `error_counts`, `unresolved_refs_count` + GC counters. Same population that the opt-in `rts telemetry` ping would send. |

Every body-returning response carries a `content_version`
(`blake3(content)[:16]@mtime_ns+index_generation`) so v2 safe-edit flows
can detect stale views.

The 35 capability strings the daemon advertises via `Daemon.Ping` —
including the v0.3 graph quartet (`find_callers`, `impact_of`,
`read_symbol.include_callers`, `pagerank_symbolwise`), the v0.5 doc
quartet (`find_symbol_limit_param`, `find_symbol_doc_field`,
`find_symbol_doc_filter`, `find_symbol_pre_filter_count`), and the v0.6
additions (`index_grep_v2` + sub-capabilities, `reconciliation_worker`,
`cancellable_queries`, `daemon_telemetry` + `unresolved_refs_count` /
`unresolved_refs_gc`, `daemon_stats_v2`) — are documented in
[docs/protocol-v0.md](docs/protocol-v0.md) §4.1 + Appendix F.

## Known limitations

### First-mount on big workspaces takes seconds

Cold-mount cost on synthetic Rust workspaces (post-walker-fix daemon):

| Synthetic LOC | Files | First-mount |
|---:|---:|---:|
| 10k | 154 | ~1.0 s |
| 30k | 462 | ~1.9 s |
| 50k | 770 | ~2.9 s |
| 100k | 1539 | ~6.2 s |

The walker + writer are single-threaded today; each file is parsed
in sequence. Daemon defaults to a 10-minute idle timeout
(`RTS_IDLE_SHUTDOWN_SECS=600`), so first-mount is paid **once per
session** and subsequent warm queries are sub-ms-to-low-ms
(`read_symbol` p95 = 2.9 ms post-perf-fixes).

The earlier v0.3.0 release notes claimed 902 ms first-mount on
100k LOC — that number measured a broken daemon that truncated at
~256 files (see CHANGELOG entry "Honest G3"). Real first-mount is
~6 s. Acceptable for a long-running agent loop; **not** acceptable
for one-off shell-pipeline use at 100k LOC — for those, `rg` is
faster end-to-end.

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
library's "domain types." On `crates/rts-core` itself, the top-20
includes `find_nodes_by_kind`, `child_by_field_name`, `children`,
etc. — all genuinely call-central — but **not** `CodebaseAnalyzer`,
`Parser`, `Language` (which are types referenced from type positions
across the workspace, not call targets).

For workspaces dominated by call patterns (web apps, services, CLI
tools), the top-K closely matches "what's central in this codebase."
For type-heavy libraries, the top-K is "what's the busiest helper
machinery" — useful but not the same answer.

### Language-prelude artifacts (filtered across 11 languages)

Tree-sitter's `call_expression` pattern captures stdlib/builtin names
the same way it captures real function calls. `Ok(x)`, `print(x)`,
`len(x)`, `malloc(n)`, `panic("...")` all parse as calls, so they
used to dominate the top-K of `find_symbol(pattern="*")` — every
function in the codebase "calls" them.

**Filtered as of v0.4.x.** Two-tier policy in
[`crates/rts-daemon/src/symbol_pagerank.rs`](crates/rts-daemon/src/symbol_pagerank.rs):

- **Always filter** (4 names): Rust variant constructors `Ok`, `Err`,
  `Some`, `None`. Filtered unconditionally because tree-sitter's
  tags.scm spuriously promotes `type Err = ()` associated-type
  aliases into def sites, so a def-count guard alone wouldn't catch
  them.
- **Filter if no workspace def** (~120 names): stdlib/builtin call-
  shape names across JavaScript, TypeScript, Python, Go, C, C++,
  Java, PHP, Ruby, Swift. Examples: `print`, `len`, `range`,
  `console`, `Promise`, `parseInt`, `make`, `append`, `panic`,
  `malloc`, `free`, `printf`, `Integer`, `puts`. The def-count guard
  preserves user-defined symbols whose names collide with a
  prelude entry (e.g. a Rust function called `print`).

Filtered names still exist in the symbol table — `find_symbol(name="print")`
still finds them; they just get `rank_score = 0.0` and sink to the
bottom of rank-sorted responses.

**Scope decisions:**
- Only names that parse as `call_expression` (or equivalent) get
  listed. Method receivers like `Array.from` aren't listed because
  `Array` is captured as a receiver, not a callee.
- Container types like `Vec`, `HashMap` live in *type* positions,
  not call positions; they're not in the graph at all.

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
[docs/protocol-v0.md](docs/protocol-v0.md) for the design sketch.

## Crate layout

```
crates/
  rts-core/      Tree-sitter wrapper + analyzer + 11 grammars
  rts-daemon/    Persistent local indexer; protocol-v0 over Unix socket
  rts-mcp/       Agent-facing MCP server (rmcp 1.6 over stdio)
  rts-bench/     Bench harness: rg-baseline vs MCP, the 5 §P9 tasks
docs/
  protocol-v0.md           Daemon ↔ MCP wire spec
  install.md               Install + agent-side wiring
  plans/                   Active and historical plans
  brainstorms/             Origin requirements docs
spikes/                    P0 validation crates (rmcp, redb, notify)
archive/                   Pre-pivot library + CLI (preserved for git history)
```

## Building from source

Requires Rust **1.85+** (Rust 2024 edition). macOS and Linux only for
v0.2; Windows lands in v1.1.

```sh
git clone https://github.com/njfio/rs-agent-code-utility.git
cd rs-agent-code-utility
cargo build --workspace --release
```

Outputs at `target/release/{rts-mcp,rts-daemon,rts-bench}`. `rts-mcp` is
the only binary you wire into your agent; the daemon auto-spawns and the
bench harness is operator-only.

## Running the benchmark

The bench is the only operator-facing CLI in the v0.2 stack.

```sh
# List the baseline + scenario tasks
target/release/rts-bench task list

# Run a single task (writes bench-<short-sha>.json)
target/release/rts-bench task run locate_def \
    --workspace ./crates/rts-core \
    --symbol parse

# Without writing the report
target/release/rts-bench task run get_body \
    --workspace ./crates/rts-core \
    --symbol parse \
    --dry-run

# Summarize a specific module
target/release/rts-bench task run summarize_module \
    --workspace ./crates/rts-core \
    --file src/analyzer.rs \
    --line-budget 50

# Scenario: real-agent-loop benches (compiler-error + refactor-impact)
target/release/rts-bench task run scenario_compiler_fix \
    --workspace ./crates/rts-core \
    --file src/parser.rs --line 200 --referenced-symbol Symbol
target/release/rts-bench task run scenario_refactor_impact \
    --workspace ./crates/rts-core \
    --symbol parse --direct-callers analyze_file,build_index

# One-shot queries (no bench scaffolding; talks straight to the daemon)
target/release/rts-bench query find-symbol  --pattern '*'           # top symbols by rank
target/release/rts-bench query find-callers --name parse            # direct callers
target/release/rts-bench query impact-of    --name parse --depth 2  # transitive callers
```

The two scenario tasks (`scenario_compiler_fix` from alpha.24,
`scenario_refactor_impact` from v0.3 alpha.35) measure agent-loop
token reduction against a `rg + read every file` baseline. The legacy
`find_callers` / `fix_imports` baseline tasks were superseded by the
real `Index.FindCallers` method (alpha.32) and the
`scenario_refactor_impact` scenario; running them now surfaces a
pointer to the new commands.

## Languages supported (rts-core)

Rust, JavaScript, TypeScript, Python, C, C++, Go, Java, PHP, Ruby,
Swift, C#. Kotlin is paused pending an upstream `tree-sitter 0.26+`
release (see [CHANGELOG.md](CHANGELOG.md) entry for v0.2.0-alpha.2).

Different features cover different subsets of the 12 indexed languages
— same alphabet, different "10":

| feature | coverage | notes |
|---|---|---|
| **Symbol extraction** (Index.Outline / Index.FindSymbol) | 12 / 12 | all in-tree grammars |
| **Doc-comment retrieval** (v0.5: `find_symbol.doc` + `doc_contains`) | 10 / 12 | Rust `///` + `//!`, JS/TS/Java/PHP/C/C++ `/** */`, Python `"""..."""`, Go `//`, Ruby `#`, Swift `///`, C# `///`. Doc text influences ranker scoring via a doc-IDF weight separate from name-IDF. |
| **AST-precise call edges** (v0.3 → v0.6: tree-sitter `@reference.call`) | 10 / 12 | Rust, Python, Go, Ruby, JS, TS were on the AST-precise path through v0.5; v0.6 added Java, PHP, Swift, C# (#116). C and C++ remain on the regex fallback — function pointers parse identical to identifier references there. |
| **PHP method indexing** (v0.6) | + | `method_declaration` inside class/interface/trait now indexed (#118), unblocking end-to-end PHP `find_callers`. |
| **Index.Grep v2 modes** | 12 / 12 (literal + regex) | structural queries (`structural_query`) supported on every grammar with a compiled tree-sitter parser (v0.6, #110). |

## Documentation

- [docs/install.md](docs/install.md) — install + Claude Code / Cursor /
  Cline / Aider / Continue snippets.
- [docs/protocol-v0.md](docs/protocol-v0.md) — daemon ↔ MCP wire-protocol
  specification (the contract both halves implement). Includes the
  22-capability advertisement list (§4.1), per-method schemas (§7),
  and per-alpha wire-shape evolution (Appendix F).
- [docs/plans/](docs/plans/) — active and historical implementation
  plans. The v0.2 pivot plan:
  [2026-05-10-001-feat-pivot-to-agentic-retrieval-mcp-server-plan.md](docs/plans/2026-05-10-001-feat-pivot-to-agentic-retrieval-mcp-server-plan.md).
  The v0.3 code-graph-KB plan (complete):
  [2026-05-13-001-feat-v0.3-code-graph-kb-plan.md](docs/plans/2026-05-13-001-feat-v0.3-code-graph-kb-plan.md).
- [CHANGELOG.md](CHANGELOG.md) — per-alpha release notes.

## Contributing

The project is in active pre-1.0 development. Conventions and workflow
live in [AGENTS.md](AGENTS.md). The short version: Rust 2024 edition,
`#![forbid(unsafe_code)]` on `rts-core` and `deny` workspace-wide,
conventional commits, every workspace member's tests must pass
(`cargo test --workspace`).

## License

MIT OR Apache-2.0. See [LICENSE-MIT](LICENSE-MIT) and
[LICENSE-APACHE](LICENSE-APACHE).
