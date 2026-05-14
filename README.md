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

**Active pre-release.** Latest alpha: `v0.2.0-alpha.35`. The v0.3
code-graph KB plan is complete; see
[CHANGELOG.md](CHANGELOG.md) for the per-alpha trail. Pre-pivot library
+ CLI live in [`archive/`](archive/) for git history; no longer maintained.

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

## Architecture

```
   Agent (Claude Code, Cursor, …)
              │ stdio JSON-RPC, rmcp 1.6
              ▼
       crates/rts-mcp        ◀── per-agent process; exposes 7 tools
              │ Unix-domain socket, protocol-v0
              ▼
      crates/rts-daemon      ◀── workspace-pinned, auto-spawned
              │
      ┌───────┴────────────────┐
      ▼                        ▼
   redb index             notify watcher
   ┌─────────────────┐    (150 ms debounce,
   │ files, defs,    │     gitignore-aware,
   │ refs (v0.3),    │     poll fallback)
   │ fid_refs,       │
   │ sid_refs_out    │
   └─────────────────┘
```

The redb store carries both halves of the code graph: `defs` + `fid_defs`
for "where is X defined?" and (v0.3+) `refs` + `fid_refs` + `sid_refs_out`
for "who calls X?", "what does X reference?", and transitive impact
queries. AST-precise via tags.scm on Rust/Python/Go/Ruby/JS/TS; regex
fallback on the remaining five languages.

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
| `x86_64-apple-darwin` | Intel Mac |
| `aarch64-apple-darwin` | Apple Silicon Mac |

Windows is not yet supported — the daemon uses Unix sockets (a Windows
port lands in v1.x).

```sh
# Pick the right target for your platform
VERSION=0.2.0-alpha.35
TARGET=aarch64-apple-darwin
URL="https://github.com/njfio/rs-agent-code-utility/releases/download/v${VERSION}/rts-${VERSION}-${TARGET}.tar.gz"

curl -fsSL "$URL" | tar -xz
sudo install rts-${VERSION}-${TARGET}/{rts-daemon,rts-mcp,rts-bench} /usr/local/bin/

# Verify (each binary's `--version` should print `<name> ${VERSION}`)
rts-daemon --version
rts-mcp    --version
rts-bench  --version

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

# Wire into Claude Code (the canonical client)
claude mcp add rts -- target/release/rts-mcp --workspace .
```

Other agents and the full troubleshooting matrix live in
[docs/install.md](docs/install.md).

## The seven tools

All `readOnlyHint=true`, `destructiveHint=false`, `openWorldHint=false`,
`idempotentHint=true`. Full descriptions (with explicit when-to-use-which
prose) are pinned per protocol-v0 §7 in
[crates/rts-mcp/src/server.rs](crates/rts-mcp/src/server.rs).

| tool | input | returns |
|---|---|---|
| `outline_workspace` | `{ glob?, token_budget?, mentioned_files?, mentioned_idents? }` | Token-budgeted structural map with file-level PageRank (Aider repo-map algorithm). |
| `find_symbol` | `{ name? \| pattern?, kind?, file?, sort? }` | List of matches with `qualified_name`, `kind`, `file`, byte range, **real `rank_score`** (symbol-level PageRank). `pattern` is glob (`*`/`?`); default sort is descending rank; pass `sort: "lexical"` to opt out. |
| `find_callers` | `{ name, kind?, file? }` | Direct callers — one redb lookup. Each entry carries the enclosing fn's `qualified_name`, `kind`, def range, call-site range, and `rank_score`. AST-precise; replaces `rg <name>`. |
| `impact_of` | `{ name, depth?, token_budget?, max_nodes?, exclude_test_paths? }` | Transitive caller closure (BFS depth N, default 2, max 4). Refactor blast-radius query. Four independent truncation flags (`closure_truncated`, `wall_clock_truncated`, `depth_truncated`, `node_count_truncated`) tell agents *why* a result is partial. |
| `read_symbol` | `{ name, file?, kind?, shape?, token_budget?, include_dependencies?, include_callers?, force_resend? }` | Body bytes + `content_version` + optional tree-shaken dependency closure (alpha.22+) + optional direct callers (alpha.32+). |
| `read_symbol_at` | `{ file, line, column?, shape?, token_budget?, include_dependencies?, include_callers? }` | Line-anchored read for compiler-error flow (`error[E0308] --> src/foo.rs:42:18`). Same wire shape as `read_symbol`. |
| `read_range` | `{ file, start_line, end_line, token_budget? }` | Line slice + `content_version`. For stack traces, diff hunks. |

Every body-returning response carries a `content_version`
(`blake3(content)[:16]@mtime_ns+index_generation`) so v2 safe-edit flows
can detect stale views.

The 18 capability strings the daemon advertises via `Daemon.Ping` —
including the four v0.3 ones (`find_callers`, `impact_of`,
`read_symbol.include_callers`, `pagerank_symbolwise`) — are documented
in [docs/protocol-v0.md](docs/protocol-v0.md) §4.1 + Appendix F.

## Known limitations

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

### Language-prelude artifacts (Rust filtered; others pending)

Tree-sitter's `call_expression` pattern captures variant constructors
the same way it captures real function calls. `Ok(x)`, `Err(e)`,
`Some(x)`, `None` (used as a unit-variant constructor) all parse as
calls, so they used to dominate the top-K of `find_symbol(pattern="*")`
on Rust workspaces — every function returning a `Result` or `Option`
"calls" them.

**Fixed for Rust** (post-v0.3.0 [Unreleased]): the four Rust prelude
names are filtered out of the PageRank node-set in
`compute_symbol_ranks`. They still exist in the symbol table, so
`find_symbol(name="Ok")` still finds them; they just get
`rank_score = 0.0` and sink to the bottom of rank-sorted responses.
The top-K on `crates/rts-core` now starts with `find_nodes_by_kind`,
`child_by_field_name`, `contains`, `child_count`, `children`, etc. —
uniformly real call-central methods.

**Other languages: not yet filtered.** JavaScript / TypeScript /
Python / etc. have analogous artifacts (`console.log`, `len`,
`Promise.resolve`, etc.), but the daemon doesn't track per-sid
language yet, so filtering them naively would also strip user-defined
collisions. Per-language filter sets driven by the language registry
is v0.4+ work.

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
Swift. Kotlin is paused pending an upstream `tree-sitter 0.26+` release
(see [CHANGELOG.md](CHANGELOG.md) entry for v0.2.0-alpha.2).

## Documentation

- [docs/install.md](docs/install.md) — install + Claude Code / Cursor /
  Cline / Aider / Continue snippets.
- [docs/protocol-v0.md](docs/protocol-v0.md) — daemon ↔ MCP wire-protocol
  specification (the contract both halves implement). Includes the
  18-capability advertisement list (§4.1), per-method schemas (§7),
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
