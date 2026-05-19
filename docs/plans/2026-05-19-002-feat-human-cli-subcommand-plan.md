---
title: Human CLI Subcommand — `rts find`, `rts grep`, `rts callers`
type: feat
status: active
date: 2026-05-19
---

# Human CLI Subcommand

## Overview

`rts-mcp` speaks JSON-RPC over a Unix domain socket. It is well-designed
for AI agents and well-designed for nothing else. **A human who wants to
try rts before integrating it has nothing to type.**

Every install guide, every tutorial, every demo currently routes through
an MCP-capable host: Claude Code, Cursor, Cline, Codex. This means:

- The "I'm curious" → "I'm convinced" funnel has a manual-integration step
  that gates evaluation.
- The asciinema demo (planned, Round-10 candidate B) must showcase rts
  through an agent harness, which dilutes the message.
- Bug reproduction from external users requires them to set up an MCP
  host, which is enormous friction for a one-line repro.

This plan adds a thin human-facing CLI — `rts find`, `rts grep`,
`rts callers`, `rts outline`, `rts stats`, `rts mount` — that wraps the
same JSON-RPC surface and renders results for terminal humans.

## Problem Statement / Motivation

Three concrete personas blocked by the lack of a CLI:

1. **The Curious Engineer** — sees rts in a blog post, runs
   `brew install rts` (after 006 lands), then... what? There's no
   `rts --help` story. They give up.

2. **The Bug Reporter** — encounters indexing weirdness via Claude Code,
   wants to file an issue. Cannot easily reproduce without re-creating
   the MCP setup. Most won't bother.

3. **The Power User** — uses rts via Claude Code but occasionally wants
   to query the same workspace from a terminal for scripting (`rts grep
   "TODO" | xargs ...`). Currently has to write a JSON-RPC client.

The CLI is **not a replacement for the MCP surface.** It's the missing
human-readable rendering of the same primitives. The MCP surface stays
unchanged; the CLI is a presentation layer.

## Proposed Solution

### Crate / binary shape

Add a new binary `rts` in the existing `rts-mcp` crate (or a new
`rts-cli` crate if dependency hygiene demands). The binary:

1. Resolves the daemon socket path (XDG conventions, same as rts-mcp).
2. Auto-spawns the daemon if not running (same logic as rts-mcp's
   bootstrap).
3. Wraps each MCP method as a subcommand with `clap` parsing.
4. Renders the JSON response as ANSI-colored, terminal-formatted output.
5. Falls back to `--json` for machine-readable output.

```text
rts [GLOBAL OPTIONS] <SUBCOMMAND> [ARGS]

SUBCOMMANDS:
  mount <PATH>           Mount a workspace (default: $PWD)
  find <NAME>            Find symbol by name
  grep <PATTERN>         Search workspace (mirror of Index.Grep)
  callers <SYMBOL>       Show incoming references for a symbol
  outline                Tree-view of the workspace
  read <SYMBOL>          Print a symbol's source
  stats                  Daemon.Stats
  doctor                 Run rts-bench doctor
  help [SUBCOMMAND]      Print help

GLOBAL OPTIONS:
  --workspace <PATH>     Override workspace root (default: $PWD)
  --json                 Output JSON (machine-readable)
  --no-color             Disable ANSI colors
  --timeout <MS>         Request timeout (default: 30000)
```

### Rendering conventions

- **`rts find Foo`** — table: `kind | name | path:line | container`
- **`rts grep "pattern"`** — `path:line:col: line-content` with the match
  highlighted (ripgrep-compatible output shape so it composes with
  existing toolchains).
- **`rts callers Foo`** — tree-grouped by caller file, then by line.
- **`rts outline`** — `tree`-style hierarchy, one symbol per line, indent
  by container depth.
- **`rts stats`** — table of counters; `--watch` flag for periodic
  refresh.

### Bootstrap behavior

Reuse the daemon bootstrap from `crates/rts-mcp/src/bootstrap.rs`:
- Socket exists → connect.
- Socket missing → spawn `rts-daemon` as detached child, wait for socket,
  connect.
- Daemon binary not found → error with install instructions.

### Pipe-friendly output

`rts grep "TODO" | wc -l` should work. `rts grep --json | jq` should work.
Default output goes to stdout with one match per line in
ripgrep-compatible shape: `relative/path.rs:42:5:    // TODO: fix this`.

## Technical Considerations

- **Clap subcommand mode:** use `clap` with `derive` API; matches the
  pattern in `rts-bench`.
- **Color handling:** `is-terminal` crate; respect `NO_COLOR` env per the
  standard.
- **JSON-RPC client:** reuse the existing client from `rts-mcp` rather
  than rewriting. Likely needs a small refactor to extract the transport
  layer.
- **Error rendering:** map daemon error codes to friendly messages.
  `INVALID_STRUCTURAL_QUERY` shouldn't print as a JSON blob; it should
  print as "Structural query failed: missing closing paren at offset 17."
- **Workspace resolution:** if `--workspace` not set, walk up from `$PWD`
  looking for a marker (`.git`, `Cargo.toml`, etc.) — same heuristic the
  agent harnesses use.

## System-Wide Impact

- **Interaction graph:** CLI → JSON-RPC over UDS → daemon → response →
  ANSI renderer → stdout. No new server-side code paths.
- **Error propagation:** daemon errors map to non-zero exit codes:
  `2` = invalid argument, `3` = daemon error, `4` = timeout, `5` = no
  workspace.
- **State lifecycle:** the CLI is stateless. Each invocation reuses the
  shared daemon. No per-CLI state to persist.
- **API surface parity:** **this is exactly the parity work.** Every MCP
  tool gets a CLI subcommand. New methods added later (e.g., the
  cancellation method from Plan 001) get CLI subcommands at the same
  time.
- **Integration test scenarios:**
  1. `rts find Foo` against a fresh workspace finds known symbols, exits
     0.
  2. `rts grep "pattern"` against an empty workspace exits 1 (no
     matches), same shape as `rg`.
  3. `rts find Foo --json | jq .matches[0].name` works.
  4. `rts mount /tmp/nonexistent` errors with exit code 5 and a clear
     message.
  5. `rts find Foo` auto-spawns the daemon on a cold machine, succeeds.

## Acceptance Criteria

### Functional

- [ ] `rts --version` reports a version matching the daemon.
- [ ] `rts --help` lists every subcommand with a one-line description.
- [ ] Six subcommands implemented: `find`, `grep`, `callers`, `outline`,
      `read`, `stats`. Plus `mount`, `doctor`, `help`.
- [ ] `--json` flag works for every subcommand.
- [ ] `--no-color` flag respected; `NO_COLOR` env var honored.
- [ ] Output of `rts grep` is ripgrep-output-compatible (same
      `path:line:col:content` shape).
- [ ] Auto-bootstrap: running `rts find Foo` on a cold machine spawns the
      daemon.
- [ ] Exit codes follow conventional pattern (0 success, 1 no matches, 2
      bad args, 3 daemon error, 4 timeout, 5 workspace error).

### Quality Gates

- [ ] Each subcommand has an integration test
      (`crates/rts-mcp/tests/cli_*.rs`).
- [ ] README updated: replace any agent-only invocation in the install
      section with a CLI invocation that mirrors it.
- [ ] `docs/cli.md` (new) — full reference, one section per subcommand.
- [ ] Shell completions generated (`rts completions bash|zsh|fish`).

## Success Metrics

- A new user can run `brew install rts && rts find MyClass` and see
  results in <60 seconds from a cold machine.
- ≥1 external issue uses `rts find/grep` invocations in its repro
  (vs. requiring an agent harness).
- Asciinema demo (Round-10 candidate B) becomes 60s of pure CLI usage,
  no agent integration shown.

## Dependencies & Risks

- **Dependency:** the daemon must already be production-ready (it is, as
  of #109/#110/#111).
- **Risk:** the CLI ends up "shipping a second API" that drifts from the
  MCP surface. Mitigation: each CLI subcommand calls the MCP method
  directly; if the method signature changes, the CLI compiler-errors
  immediately.
- **Risk:** ripgrep-style output is a target users compare against. We
  must hit baseline parity (path:line:col:content) or we'll be measured
  unfavorably.
- **Risk:** bootstrap auto-spawn could surprise users. Mitigation:
  `RTS_NO_AUTOSPAWN=1` env var; log to stderr when auto-spawning.

## Out of Scope (Non-Goals)

- **TUI / interactive REPL** — `rts repl` would be cool but is
  net-new scope.
- **Watching mode** (`rts watch`) — separate workstream.
- **Profiles / config aliases** — `.rts.toml` is a separate Round-12 plan
  (L).
- **Outputs other than ANSI + JSON** — no LSP, no SARIF, no XML.

## Resource Requirements

- ~3-5 focused days.
- One macOS + one Linux smoke test environment.
- Asciinema recording (post-ship) — separate ~2h.

## Sources & References

### Internal

- MCP transport (reuse): `crates/rts-mcp/src/`
- Bootstrap pattern: `crates/rts-mcp/src/bootstrap.rs`
- Clap derive pattern: `crates/rts-bench/src/main.rs`
- Doctor invocation: `crates/rts-bench/src/doctor/`

### External / Best Practices

- ripgrep output format —
  <https://github.com/BurntSushi/ripgrep/blob/master/GUIDE.md>
- clap derive guide —
  <https://docs.rs/clap/latest/clap/_derive/index.html>
- `NO_COLOR` standard — <https://no-color.org/>
- `is-terminal` crate —
  <https://docs.rs/is-terminal/latest/is-terminal/>

### Related Work

- Plan 006 (Homebrew tap) — `brew install` is the entrypoint that makes
  this CLI discoverable.
- Round-10 candidate B (asciinema demo) — becomes trivially recordable
  once this lands.
