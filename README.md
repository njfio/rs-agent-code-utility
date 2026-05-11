# rts — Retrieval for agentic coding

`rts` is a workspace-pinned local retrieval daemon plus an MCP (Model
Context Protocol) bridge that gives AI coding agents (Claude Code,
Cursor, Cline, Aider, Continue) precise, token-cheap access to your
codebase. Replaces "the agent ripgreps and then reads whole files" with
"the agent calls one tool that returns exactly the bytes it needs."

| measurement | baseline | MCP | reduction |
|---|---:|---:|---:|
| Locate a function's definition (`parse` in `rts-core`) | 259,607 tokens | 148 tokens | **99.9%** |
| Get a function's body (`parse` in `rts-core`) | 94,285 tokens | 28 tokens | **100.0%** |
| Summarize a module (`analyzer.rs`, head 50 lines) | 27,258 tokens | 571 tokens | **97.9%** |

Reproduce: `cargo build --workspace && target/debug/rts-bench task run
<id> --workspace <path> [--symbol NAME | --file PATH]`. Token counter is
`bytes / 3` per [docs/protocol-v0.md](docs/protocol-v0.md) §11.1; the
Anthropic SDK oracle (`--with-network`) lands later.

## Status

**Pre-release.** Tag `v0.2.0-alpha.11` at the time of writing. The
agentic-retrieval pivot is the focus; the pre-pivot library + CLI have
been archived (see [`archive/`](archive/)).

| Phase | Status |
|---|---|
| P0 — Spikes (rmcp, redb, notify) | done |
| P1 — Tree-sitter 0.20 → 0.26 bump | done |
| P2+P3 — Uncoupling + archive cut | done |
| P4 — Cargo workspace + `rts-core` extraction | done |
| P5 — Protocol-v0 design doc | done |
| P6 — `rts-daemon` (lifecycle + watcher + writer + 4/4 Index.\*) | done minus `Index.Outline` |
| P7 — `rts-mcp` (rmcp 1.6 bridge) | done |
| P8 — `SignatureRenderer` + PageRank | not started |
| P9 — Benchmarks + install docs + prebuilt binaries | partial (3/5 bench tasks; install docs land in this commit) |

## Architecture

```
   Agent (Claude Code, Cursor, …)
              │ stdio JSON-RPC, rmcp 1.6
              ▼
       crates/rts-mcp        ◀── per-agent process
              │ Unix-domain socket, protocol-v0
              ▼
      crates/rts-daemon      ◀── workspace-pinned, auto-spawned
              │
      ┌───────┴────────┐
      ▼                ▼
   redb index    notify watcher
   (symbols,     (150 ms debounce, gitignore-aware)
    defs, refs)
```

Both halves are local-only and offline. The daemon is single-uid via
SO_PEERCRED / LOCAL_PEERCRED, refuses to run as root, sets
`umask(0077)`, and disables core dumps (full trust model:
[docs/protocol-v0.md](docs/protocol-v0.md) §1, §12). The MCP server has
zero outbound HTTP code paths (CI assertion lands with the prebuilt
binary release).

## Quick start

The MCP server auto-spawns the daemon on first connect. There is no
daemon for the user to start by hand.

```sh
# Build
cargo build --workspace --release

# Wire into Claude Code (the canonical client)
claude mcp add rts -- target/release/rts-mcp --workspace .
```

Other agents and the full troubleshooting matrix live in
[docs/install.md](docs/install.md).

## The four tools

All `readOnlyHint=true`, `destructiveHint=false`, `openWorldHint=false`,
`idempotentHint=true`. Full descriptions are pinned per protocol-v0 §7
in [crates/rts-mcp/src/server.rs](crates/rts-mcp/src/server.rs).

| tool | input | returns |
|---|---|---|
| `outline_workspace` | `{ glob?, token_budget? }` | Token-budgeted structural map. Currently `INDEX_NOT_READY` until P8 PageRank ships. |
| `find_symbol` | `{ name, kind?, file? }` | List of matches with `qualified_name`, `kind`, `file`, byte range, `rank_score` (0.0 placeholder pre-P8). |
| `read_symbol` | `{ name, file?, kind?, shape?, token_budget?, include_dependencies?, force_resend? }` | Body bytes + `content_version`. `shape: "signature"` lands with P8. |
| `read_range` | `{ file, start_line, end_line, token_budget? }` | Line slice + `content_version`. For stack traces, diff hunks. |

Every body-returning response carries a `content_version`
(`blake3(content)[:16]@mtime_ns+index_generation`) so v2 safe-edit flows
can detect stale views.

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
git clone https://github.com/njfio/rust-treesitter-agent-code-utility.git
cd rust-treesitter-agent-code-utility
cargo build --workspace --release
```

Outputs at `target/release/{rts-mcp,rts-daemon,rts-bench}`. `rts-mcp` is
the only binary you wire into your agent; the daemon auto-spawns and the
bench harness is operator-only.

## Running the benchmark

The bench is the only operator-facing CLI in the v0.2 stack.

```sh
# List the 5 P9 tasks
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
```

Tasks 3 (`find_callers`) and 5 (`fix_imports`) need the P8 reference
graph and are scaffolded but stubbed; they emit `NotImplemented` with a
pointer to the relevant plan slice.

## Languages supported (rts-core)

Rust, JavaScript, TypeScript, Python, C, C++, Go, Java, PHP, Ruby,
Swift. Kotlin is paused pending an upstream `tree-sitter 0.26+` release
(see [CHANGELOG.md](CHANGELOG.md) entry for v0.2.0-alpha.2).

## Documentation

- [docs/install.md](docs/install.md) — install + Claude Code / Cursor /
  Cline / Aider / Continue snippets.
- [docs/protocol-v0.md](docs/protocol-v0.md) — daemon ↔ MCP wire-protocol
  specification (the contract both halves implement).
- [docs/plans/](docs/plans/) — active and historical implementation
  plans. The v0.2 pivot plan is
  [2026-05-10-001-feat-pivot-to-agentic-retrieval-mcp-server-plan.md](docs/plans/2026-05-10-001-feat-pivot-to-agentic-retrieval-mcp-server-plan.md).
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
