# `rts` — human-facing CLI

`rts` wraps the same JSON-RPC surface that `rts-mcp` exposes to AI
agents. Use it from a terminal to query the indexed workspace without
configuring an MCP host.

The CLI auto-spawns `rts-daemon` on first call (set `RTS_NO_AUTOSPAWN=1`
to disable). Every subcommand mounts the workspace (idempotent) and
issues one RPC.

## Global flags

| Flag | Purpose |
|---|---|
| `--workspace <PATH>` | Workspace root. Defaults to walking up from `$PWD` for a marker (`Cargo.toml`, `package.json`, `.git`, etc.). |
| `--json` | Machine-readable JSON output (composes with `jq`). |
| `--no-color` | Disable ANSI colors. `NO_COLOR` env (any non-empty value) has the same effect. |
| `--timeout <MS>` | Request timeout in milliseconds. Default 30000. |

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success with results. |
| 1 | Success with zero results (matches `rg`'s convention). |
| 2 | Invalid argument (clap-handled). |
| 3 | Daemon-level error. |
| 4 | Request timeout. |
| 5 | Workspace resolution error (no marker found, path missing). |

## Subcommands

### `rts mount [PATH]`

Mount the workspace explicitly. The daemon makes Mount idempotent so
this is safe to repeat.

```sh
rts mount .
# mounted /Users/me/code/myproj (ws-1d2c…)
```

### `rts find <NAME>`

Look up symbols by name (or by glob with `--pattern`).

```sh
rts find make_widget
# KIND   NAME           PATH:LINE                CONTAINER
# fn     make_widget    crates/hub/src/lib.rs:23 hub

rts find 'make_*' --pattern
# fn  make_widget   …:23  hub
# fn  make_circle   …:29  hub
```

Flags: `--pattern`, `--kind <fn|struct|…>`, `--file <REL>`, `--limit <N>`.

### `rts grep [PATTERN]`

Literal-substring search across indexed file bytes. Output is
ripgrep-shaped (`path:line:col:content`), so it composes:

```sh
rts grep TODO | awk -F: '{print $1}' | sort -u
rts grep --regex '\bunsafe\b' --glob 'crates/**/*.rs'
```

`--structural-query` scopes matches to tree-sitter node kinds (requires
`--language`), and combines with `PATTERN`/`--regex` to filter to the text
inside the captured nodes — searches plain text can't express:

```sh
# string literals containing a phrase (not comments or code)
rts grep "connection refused" --structural-query '(string_literal) @s' --language rust
# usages of a symbol as an identifier node
rts grep make_widget --structural-query '(identifier) @i' --language rust
# every call expression in a file (no text filter)
rts grep --structural-query '(call_expression) @c' --language rust --glob 'src/lib.rs'
```

`PATTERN` is optional when `--structural-query` provides the search source.

Flags: `--regex`, `--case-sensitive`, `--glob <PATTERN>`, `--limit <N>`,
`--multiline` (with `--regex`), `--structural-query <QUERY>`,
`--language <LANG>` (repeatable), `--within-symbol <NAME>`,
`--within-symbol-allow-overload`.

### `rts callers <NAME>`

Show direct callers of a symbol, grouped by caller file.

```sh
rts callers make_widget
# callers.rs
#   L:2  caller_a (fn)
#   L:3  caller_b (fn)
```

Flags: `--kind`, `--file`.

### `rts outline`

Token-budgeted workspace tree. Same dotted-indent format the daemon
returns; pipe into `less` for big repos.

```sh
rts outline --token-budget 8192
rts outline --glob 'crates/rts-core/**'
```

### `rts read <NAME>`

Print a symbol's source with a header showing the qualified name and
file:line. Pass `--shape signature` for just the declaration.

```sh
rts read make_widget
# make_widget @ crates/hub/src/lib.rs:23
# ────────────────────────────────────────
# pub fn make_widget(id: u32) -> u32 { id + 1 }
```

### `rts stats`

Daemon per-method call counters. Useful for "am I actually using rts,
or reaching for grep?" reflection.

```sh
rts stats
# daemon v0.5.5
#   uptime: 5393 ms
#   total:  4 calls
# ────────────────────────────────────────
#   Workspace.Mount   2
#   Daemon.Stats      1
#   Index.FindSymbol  1
#   …
```

### `rts doctor`

Delegates to `rts-bench doctor` — install state, daemon reachability,
per-workspace index health.

### `rts completions <SHELL>`

Emit shell-completion scripts to stdout. Supported shells:
`bash`, `zsh`, `fish`, `powershell`, `elvish`.

```sh
# bash
rts completions bash | sudo tee /etc/bash_completion.d/rts

# zsh (add to fpath first)
rts completions zsh > "${fpath[1]}/_rts"

# fish
rts completions fish > ~/.config/fish/completions/rts.fish
```

## Environment

| Var | Purpose |
|---|---|
| `RTS_NO_AUTOSPAWN` | Set non-empty to disable daemon auto-spawn. Useful in CI when you manage daemon lifecycle externally. |
| `NO_COLOR` | Any non-empty value disables ANSI output (per <https://no-color.org/>). |
| `RTS_DAEMON_BIN` | Path to `rts-daemon`. Defaults to the binary next to `rts`, then `$PATH`. |
| `RTS_BENCH_BIN` | Path to `rts-bench` (used by `rts doctor`). |
| `RTS_LOG` | Tracing filter for the CLI itself; defaults to `warn`. |

## See also

- `docs/protocol-v0.md` — daemon JSON-RPC wire spec.
- `crates/rts-mcp/src/server.rs` — MCP tool surface this CLI mirrors.
