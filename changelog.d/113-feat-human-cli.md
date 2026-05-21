### `rts` — human-facing CLI over the same JSON-RPC surface

Adds a second binary `rts` to the `rts-mcp` crate. The CLI wraps the
daemon's JSON-RPC surface for terminal humans, mirroring every method
the MCP server already exposes to agents. Reuses the existing
`socket` + `daemon_client` modules (now lifted into a thin
`rts_mcp` library) so the MCP and CLI paths can never drift from
each other — when one signature changes, both binaries fail to
compile.

Per [`docs/plans/2026-05-19-002-feat-human-cli-subcommand-plan.md`](../docs/plans/2026-05-19-002-feat-human-cli-subcommand-plan.md).

#### Subcommands

| `rts <cmd>` | Daemon method | Renderer |
|---|---|---|
| `mount [PATH]` | `Workspace.Mount` | one-line status + workspace id |
| `find <NAME> [--pattern]` | `Index.FindSymbol` | `kind | name | path:line | container` table |
| `grep <PATTERN>` | `Index.Grep` | ripgrep shape: `path:line:col:content` |
| `callers <NAME>` | `Index.FindCallers` | tree-grouped by caller file |
| `outline` | `Index.Outline` | passes the daemon's dotted-indent text through |
| `read <NAME>` | `Index.ReadSymbol` | name@file:line header + body |
| `stats` | `Daemon.Stats` | header + per-method counter table |
| `doctor` | (delegates) | runs `rts-bench doctor` |
| `completions <SHELL>` | (clap_complete) | bash, zsh, fish, powershell, elvish |

#### Global flags

`--workspace`, `--json` (machine-readable output, composes with `jq`),
`--no-color` (also honors `NO_COLOR` env per <https://no-color.org/>),
`--timeout <MS>` (wall-clock cap, default 30000).

#### Exit codes (documented contract)

| Code | Meaning |
|---|---|
| 0 | Success with results. |
| 1 | Success with zero results (matches `rg`). |
| 2 | Invalid argument (clap-handled). |
| 3 | Daemon-level error. |
| 4 | Request timeout. |
| 5 | Workspace resolution error (missing path, no marker). |

#### Bootstrap behavior

The CLI reuses `rts-mcp`'s auto-spawn flow: socket present → connect,
socket missing → spawn `rts-daemon` as a detached child + wait up to
5 s for the per-workspace socket to appear. Set
`RTS_NO_AUTOSPAWN=1` to disable (useful in CI / sandboxed
environments where the daemon lifecycle is managed externally).

#### Why a second binary, not a new crate

Adding the CLI as a second `[[bin]]` in `rts-mcp` lets both binaries
share the `socket` + `daemon_client` plumbing via the crate's
library surface — zero duplication, single-point-of-truth on
transport behavior. The added deps (`clap`, `clap_complete`,
`is-terminal`) are small enough that the MCP-server-only build tree
stays lean. A standalone `rts-cli` crate would have meant
duplicating ~150 LOC of socket/auto-spawn logic and re-validating it
in two places.

#### Tests

Ten integration test files in `crates/rts-mcp/tests/cli_*.rs` spin
up isolated XDG runtime/state/home tempdirs, let `rts` auto-spawn
the daemon, and assert the user-facing contract:

- `cli_find` — name + pattern lookup, no-match → exit 1.
- `cli_grep` — ripgrep `path:line:col:content` shape, no-match → exit 1.
- `cli_callers` — file-grouped output with enclosing fn names.
- `cli_outline` — non-empty dotted-indent text.
- `cli_read` — qualified-name header + body.
- `cli_stats` — non-zero method counters after a warmup call.
- `cli_json` — every subcommand's `--json` output is valid JSON.
- `cli_no_color` — `--no-color` AND `NO_COLOR=1` both suppress ANSI.
- `cli_autobootstrap` — first call against a cold tempdir spawns the daemon.
- `cli_exit_codes` — bad workspace → 5; unknown subcommand → 2 (clap).

Plus 9 unit tests in `cli` covering the pure renderers (table, grep
shape, color-disabled identity transform, workspace marker walk).

#### Docs

- New `docs/cli.md` — one section per subcommand with examples.
- README updated: install snippets in both Option A (prebuilt) and
  Option B (source) include a `rts find MyType` smoke test before
  the agent-wiring line, so a curious engineer can verify the install
  without configuring an MCP host.

#### Out of scope (per plan's "Out of Scope" section)

- TUI / interactive REPL (`rts repl`)
- Watch mode (`rts watch` / `rts stats --watch`)
- `.rts.toml` config profiles
- Output formats other than ANSI + JSON (no LSP/SARIF/XML)
