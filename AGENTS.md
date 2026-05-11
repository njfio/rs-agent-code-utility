# Repository Guidelines

This file is the canonical project-coding-standards reference. Treat it
as the source of truth when conventions diverge from anything you find
in pre-pivot artifacts under `archive/`.

## Project layout (post-pivot)

Cargo workspace with `resolver = "3"`, Rust 2024 edition, MSRV 1.85.

- `crates/rts-core/` — surviving tree-sitter wrapper + analyzer + 11
  grammars. Library only; no binaries. `#![forbid(unsafe_code)]`.
- `crates/rts-daemon/` — persistent workspace-pinned daemon. Binary
  `rts-daemon`. Speaks `docs/protocol-v0.md` over a Unix-domain socket.
- `crates/rts-mcp/` — agent-facing MCP server bridge. Binary `rts-mcp`.
  Speaks rmcp 1.6 over stdio to the agent, protocol-v0 to the daemon.
- `crates/rts-bench/` — bench harness. Binary `rts-bench`. The only
  operator-facing CLI in the v0.2 stack.
- `docs/protocol-v0.md` — daemon ↔ MCP wire spec.
- `docs/plans/` and `docs/brainstorms/` — active design artifacts.
- `archive/` — pre-pivot library + CLI + ~30 k LOC of AI/security
  analyzers. Excluded from the workspace; preserved for git history.
- `spikes/p0-*` — independent crates carrying the P0 validation
  experiments (rmcp 1.6, redb 2, notify+debouncer). Excluded from the
  workspace; reproducible via the per-spike README.

## Build, test, lint

```sh
# Build everything (4 workspace members + tests + integration tests).
cargo build --workspace

# All tests, including the daemon + MCP + bench integration tests
# which spawn the actual binaries via stdio/Unix-socket round-trip.
cargo test --workspace

# Lint. Workspace lints in root Cargo.toml: unsafe_code = "deny".
cargo clippy --workspace --all-targets

# Per-crate work.
cargo test -p rts-daemon          # daemon-only
cargo test -p rts-mcp             # MCP-only (needs rts-daemon built)
cargo test -p rts-bench           # bench (needs rts-mcp + rts-daemon)
```

The integration tests in `rts-mcp` and `rts-bench` require their
sibling binaries to be built first. `cargo test --workspace` handles
this correctly; per-crate `cargo test -p` may need an explicit
`cargo build --workspace` first.

## Coding style

- **Edition**: Rust 2024.
- **Unsafe**: forbidden in `rts-core`, denied workspace-wide (overrides
  on a per-item basis only when load-bearing).
- **Naming**: modules / files `snake_case`; types & traits
  `PascalCase`; functions & vars `snake_case`; consts
  `UPPER_SNAKE_CASE`.
- **Errors**: `anyhow::Result` for binaries and internal call sites;
  protocol-level errors are typed (`ProtocolError` in `rts-daemon`,
  `DaemonError` in `rts-mcp`). Bubble up via `?`; do not panic in
  library code.
- **No comments without a "why"**: lean toward self-documenting code.
  Reserve doc comments for public APIs and for invariants a future
  reader couldn't derive from the code alone.
- **Tracing, not println**: every binary initialises
  `tracing_subscriber` to stderr. `rts-mcp` *must* keep stdout for
  JSON-RPC; logging to stdout will break Claude Code's parser.

## Testing conventions

- **Unit tests** in `#[cfg(test)] mod tests` inside each module.
- **Integration tests** in `crates/<member>/tests/<area>_round_trip.rs`.
  These spawn the real binaries and round-trip the protocol; no mocks
  of cross-crate interfaces.
- Descriptive test names (`commit_then_find_symbol_round_trips`,
  `live_create_of_secrets_file_is_filtered`). Include both happy paths
  and negative cases (e.g. `RANGE_OUT_OF_BOUNDS`, `OUT_OF_ROOT`).
- The bench's integration tests gracefully skip when `rg` isn't on
  `PATH` rather than failing — they refuse to silently produce a
  baseline-less measurement.

## Commit & PR conventions

- **Conventional Commits** scoped by crate or doc:
  `feat(rts-daemon): …`, `fix(rts-mcp): …`, `docs(protocol): …`,
  `chore(workspace): …`.
- Each commit references its CHANGELOG entry. Per-alpha bumps land in
  one commit (e.g. `feat(rts-mcp): 0.2.0-alpha.9 — MCP server bridge to
  rts-daemon`).
- PRs include a summary, testing notes (full `cargo test --workspace`
  count), and rollback considerations for changes that touch the
  protocol wire shape.

## Security & configuration

- **Never** commit secrets. The `.gitignore` excludes `.env`,
  credentials, private keys, certs.
- The daemon refuses to run as root, sets `umask(0077)`, sets
  `RLIMIT_CORE=0` (+ `PR_SET_DUMPABLE=0` on Linux). Don't relax these
  for "ergonomics" — they're the security boundary.
- Protocol-v0 §13 secrets policy (filename blocklist + content scanner
  + extension allowlist) lives in
  [`crates/rts-daemon/src/filter.rs`](crates/rts-daemon/src/filter.rs).
  Both the watcher and read handlers consult it; extending the
  blocklist means updating both paths.

## Dependency hygiene

- The daemon and the MCP server link **zero HTTP code paths**. The
  bench's `--with-network` Anthropic SDK adapter (when it lands) is
  gated behind a feature flag + a `RTS_BENCH_ANTHROPIC_API_KEY` env
  var; CI asserts the daemon/MCP build trees stay HTTP-free via
  `cargo tree`.
- `tree-sitter` versions are pinned at the workspace level; per-grammar
  versions track the latest 0.23+ that's runtime-compatible with
  `tree-sitter 0.26`.

## What's archived, and why

If you go looking for a feature that the pre-pivot library shipped
(AI analyzers, taint analysis, SARIF output, the `tree-sitter-cli`
binary), it's in `archive/src/` with the original module names
preserved. Recovery is `git mv archive/src/<mod> src/<mod>` plus the
`pub mod` declaration; the v0.2 product surface deliberately omits all
of it. See [CHANGELOG.md](CHANGELOG.md)'s v0.2.0-alpha.1 entry for the
full archive manifest and rationale.
