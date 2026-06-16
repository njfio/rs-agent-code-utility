# Installation

`rts` ships the daemon, the MCP server, an optional human CLI, and a benchmark harness:

- **`rts-mcp`** — the agent-facing MCP server. This is the binary you
  wire into Claude Code / Cursor / Cline / Aider / Continue.
- **`rts-daemon`** — the workspace-pinned indexer. **You do not start
  this by hand**; `rts-mcp` auto-spawns it on first connect.
- **`rts`** — optional human CLI (`rts find`, `rts grep`, `rts callers`,
  `rts read`, …) for driving the daemon from the terminal. Not required
  for agent use.
- **`rts-bench`** — operator-only benchmark harness. Not required for
  agent use.

## System requirements

| platform | status |
|---|---|
| macOS arm64 (Apple Silicon) | supported |
| macOS x86_64 | supported |
| Linux x86_64 | supported |
| Linux aarch64 | supported |
| Windows | v1.1 — currently unsupported (no peer-cred boundary, no `XDG_RUNTIME_DIR` equivalent) |

Build dependencies:

- Rust **1.85+** (the workspace declares `rust-version = "1.85"` and
  edition 2024).
- A C toolchain for the tree-sitter grammar build scripts (`cc`,
  `make`, `git`).

## Build from source

```sh
git clone https://github.com/njfio/rust-treesitter-agent-code-utility.git
cd rust-treesitter-agent-code-utility
cargo build --workspace --release
```

Outputs at `target/release/rts-mcp`, `target/release/rts-daemon`,
`target/release/rts-bench`. The two binaries you'll point your agent
at are `rts-mcp` (always) and `rts-daemon` (only via `RTS_DAEMON_BIN`
when you want to pin a different version than the sibling of
`rts-mcp`).

**Prebuilt binaries** (no Rust toolchain) ship with each release for
macOS arm64 and Linux x86_64/arm64:

```sh
VERSION=0.7.0 TARGET=aarch64-apple-darwin   # or x86_64-unknown-linux-gnu / aarch64-unknown-linux-gnu
curl -fsSL "https://github.com/njfio/rs-agent-code-utility/releases/download/v${VERSION}/rts-${VERSION}-${TARGET}.tar.gz" | tar -xz
sudo install "rts-${VERSION}-${TARGET}"/{rts-daemon,rts-mcp,rts-bench,rts} /usr/local/bin/
```

(macOS browser downloads need `xattr -dr com.apple.quarantine "rts-${VERSION}-${TARGET}/"` before first run; the `curl | tar` path above is unaffected.)

## Smoke test the build

```sh
target/release/rts-mcp --help
target/release/rts-daemon --help    # (no flags; this just confirms the binary runs)
target/release/rts-bench task list
```

## Wiring into Claude Code

The canonical client. The `--workspace` flag tells `rts-mcp` which
directory to mount; default is `$PWD`.

```sh
# From the directory you want to index:
claude mcp add rts -- /path/to/target/release/rts-mcp --workspace "$PWD"
```

Or via the project-scoped `.mcp.json`:

```json
{
  "mcpServers": {
    "rts": {
      "command": "/path/to/target/release/rts-mcp",
      "args": ["--workspace", "."],
      "env": {
        "RTS_LOG": "rts_mcp=info,warn"
      }
    }
  }
}
```

`RTS_LOG` accepts the standard `tracing_subscriber` env-filter syntax
(`rts_mcp=debug,rts_daemon=info` for more detail). All logs go to
stderr; stdout is reserved for JSON-RPC frames.

## Wiring into Cursor

`~/.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "rts": {
      "command": "/path/to/target/release/rts-mcp",
      "args": ["--workspace", "${workspaceFolder}"]
    }
  }
}
```

## Wiring into Cline

Add to the Cline settings (`mcpServers` block). Cline is documented
but not formally smoke-tested for this release.

```json
{
  "mcpServers": {
    "rts": {
      "command": "/path/to/target/release/rts-mcp",
      "args": ["--workspace", "."],
      "disabled": false,
      "autoApprove": []
    }
  }
}
```

## Wiring into Aider

Aider's MCP support uses the standard `mcpServers` block in
`~/.config/aider/mcp.json` or `./.aider/mcp.json`:

```json
{
  "mcpServers": {
    "rts": {
      "command": "/path/to/target/release/rts-mcp",
      "args": ["--workspace", "."]
    }
  }
}
```

## Wiring into Continue

`~/.continue/config.yaml` or workspace `.continue/config.yaml`:

```yaml
mcpServers:
  - name: rts
    command: /path/to/target/release/rts-mcp
    args:
      - --workspace
      - .
```

## Verifying the install

After wiring `rts-mcp` into your agent, ask the agent to list the
tools. You should see four:

- `outline_workspace`
- `find_symbol`
- `read_symbol`
- `read_range`

If `outline_workspace` is missing, the rmcp handshake is failing —
check the agent's MCP log for the `initialize` response. If
`outline_workspace` returns `INDEX_NOT_READY` when invoked, that is
expected for the current alpha; the body lands with the P8 PageRank
slice.

A more direct smoke test:

```sh
echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"smoke","version":"0"}}}' \
  | target/release/rts-mcp --workspace . \
  | head -1
```

You should see a JSON response with
`"serverInfo":{"name":"rts-mcp",…}` on stdout, and tracing output on
stderr.

## Logs and troubleshooting

| symptom | check |
|---|---|
| Agent says "tool not available" | Confirm `rts-mcp --help` runs and exits 0 from the agent's shell environment. Workspace paths in MCP configs are resolved by the agent, not by `rts-mcp`. |
| Agent reports `INDEX_NOT_READY` for `find_symbol` | The writer hasn't finished its initial walk. Wait a few hundred ms; retry. On very large workspaces (>100k files) the walk can take seconds. |
| Agent reports `OUT_OF_ROOT` | Workspace-relative paths only. `rts-mcp` resolves your `--workspace` argument; paths outside that root are refused. |
| Agent reports `WORKSPACE_VANISHED` | The daemon is pinned to a different workspace. v0.2 supports one daemon per host; either point `rts-mcp` at the existing pinned workspace, or kill the daemon and let it auto-respawn for the new path. |
| `rts-mcp` exits immediately | Run it manually with `RTS_LOG=debug`; look for `XDG_RUNTIME_DIR` errors (Linux), `HOME` errors (macOS), or socket-permission errors. |

The daemon's stderr also goes to your agent's MCP log when it's
auto-spawned. To inspect the daemon directly, set `RTS_LOG=debug` in
the agent's MCP config and watch the log pane.

## Killing a stuck daemon

The daemon auto-shuts down after 10 minutes idle (`RTS_IDLE_SHUTDOWN_SECS`
overrides). To force-kill:

```sh
pkill -TERM -f rts-daemon
# Optionally clear the socket if you want a clean re-spawn:
rm -f "$HOME/Library/Caches/rts/default.sock"        # macOS
rm -f "$XDG_RUNTIME_DIR/rts/default.sock"            # Linux
```

The daemon's `flock`-based PID file is authoritative; stale sockets
without a live process are cleaned up at next bind.

## Verifying your install

After running any of the per-agent install snippets above, run
`rts-bench doctor` to verify the install end-to-end:

```sh
rts-bench doctor
```

Doctor inspects five surfaces in a single sub-second run:

1. **`binary`** — `rts-daemon` and `rts-mcp` on `$PATH`, version-drift
   detection between them.
2. **`daemon`** — per-workspace socket probe; one round-trip to the
   daemon's `Daemon.Stats v2` RPC (gracefully degrades on pre-v2
   daemons).
3. **`mcp_registration`** — rts MCP entry presence across Claude Code,
   Cursor, Continue, Aider, and Cline; cross-scope drift detection
   (e.g. Claude Code user-scope and project-scope registering different
   binaries).
4. **`hook`** — `.claude/hooks/rts-nudge.sh` presence, executability,
   version-marker match.
5. **`workspace_index`** — pinned-workspace path match against `$PWD`,
   cold-walk completion timestamp, index generation, file count.

Each row is `[OK]`, `[WARN]`, or `[FAIL]`; every WARN/FAIL row carries
a copy-pasteable one-line fix on the next line. Exit codes are a
public contract — `0` means healthy (any WARNs allowed), `1` means at
least one FAIL row, `2` means doctor itself failed.

For machine-readable output (e.g. for an agent-bench preflight),
`rts-bench doctor --output json` produces a versioned JSON document
per the schema in [`doctor-schema.md`](doctor-schema.md).

```sh
# Exit-code-driven CI gate:
rts-bench doctor || { echo "rts install is broken — see output above"; exit 1; }

# Just check whether all 5 host detectors found rts:
rts-bench doctor --output json \
  | jq '.sections[] | select(.name=="mcp_registration") | .rows[] | select(.kind=="fail")'
```

`NO_COLOR=1` (or `--no-color`) disables ANSI; useful in pipelines and
snapshot tests.

## Uninstalling

The build produces no installed files outside the cargo target dir.
To remove:

```sh
# Stop the daemon if it's running:
pkill -TERM -f rts-daemon

# Drop the on-disk index:
rm -rf "$XDG_STATE_HOME/rts"                         # Linux (defaults to ~/.local/state)
rm -rf "$HOME/Library/Caches/rts"                    # macOS (state + socket)

# Remove the agent's MCP registration. For Claude Code:
claude mcp remove rts

# Cargo artifacts (optional):
cargo clean
```

## See also

- [docs/protocol-v0.md](protocol-v0.md) — daemon ↔ MCP wire-protocol
  spec.
- [docs/doctor-schema.md](doctor-schema.md) — `rts-bench doctor`
  `--output json` schema and exit-code contract.
- [AGENTS.md](../AGENTS.md) — project structure + coding conventions.
- [CHANGELOG.md](../CHANGELOG.md) — per-alpha release notes.
