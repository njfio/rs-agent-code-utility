### `rts-mcp` — reconnect + remount + retry on daemon disconnect

**Surfaced by real MCP-path dogfood** (same session that caught the `find_callers` `scoped_identifier` gap fixed in #94). When the auto-spawned `rts-daemon` died mid-session — crash, `SIGTERM`, upgrade, or operator `kill` — `rts-mcp` kept writing JSON-RPC frames to the dead socket and returned `Broken pipe (os error 32)` to the agent forever. The only recovery was to restart the host app (Claude Code, Cursor, etc.), which is the wrong UX for a "persistent code graph" pitch.

#### Root cause

`DaemonClient` held a single `OwnedReadHalf` + `OwnedWriteHalf` for the lifetime of the MCP stdio session. There was no detection of socket death and no path to re-establish the connection. The auto-spawn logic in `socket::connect_with_auto_spawn` was only invoked once, at `main.rs` boot.

#### Fix

Three layered changes in `crates/rts-mcp`:

1. **`DaemonClient` learns to reconnect.** New fields `daemon_bin: PathBuf` and `workspace: PathBuf` are threaded through the constructor so the client can re-resolve the binary and per-workspace socket path. `pub async fn reconnect(&mut self)` re-runs `connect_with_auto_spawn` and swaps in fresh reader/writer halves. `next_id` is **not** reset — protocol-v0 §3.4 only requires uniqueness within a session and the daemon has fresh state anyway.

2. **`DaemonError::is_disconnect()` classifies transport failures.** Returns `true` only when `code == "INTERNAL_ERROR"` AND the message matches one of: `broken pipe`, `connection reset`, `daemon closed connection`, `connection refused`, `unexpected end of file`, `eof`. Legitimate daemon-emitted errors like `INDEX_NOT_READY` or `OUT_OF_ROOT` return `false` — we never reconnect on a working daemon's expected error path.

3. **`RtsServer::call_daemon` retries once on disconnect.** On the first `is_disconnect()` error: call `guard.reconnect()`, reset the `self.mounted` `AtomicBool` to `false` (so the lazy `Workspace.Mount` re-fires against the fresh daemon), and retry the original call. A second disconnect propagates the error rather than looping — repeated reconnects indicate a deeper problem (binary path wrong, daemon refusing to stay up) that should surface to the agent.

#### Verification

New `tests/mcp_round_trip.rs::mcp_reconnects_after_daemon_death`:

1. Spawn `rts-mcp` against a fixture workspace, complete one successful `find_symbol` call (auto-spawning the daemon).
2. Read the daemon's PID from the per-workspace lockfile at `<runtime_root>/ws-<16hex>.sock.pid` (first line of the two-line `<pid>\n<start_seconds>\n` format that `socket_path_for_workspace` writes).
3. `kill -9 <pid>` the daemon via a subprocess (`std::process::Command`; `rts-mcp` has `#![deny(unsafe_code)]` so `libc::kill` isn't available).
4. Issue another `find_symbol`. The retry path re-auto-spawns the daemon, re-mounts, and serves the call. Result: `passed in 1.67s`.

#### Out of scope (filed for follow-up)

- **Backoff on repeated reconnects.** Current logic is "retry once per call." A daemon that crashes every Mount would burn through respawns. Adding a per-session reconnect counter / exponential backoff is worth doing once we see it in practice — not before.
- **Surface reconnect events to the agent.** Today the retry is silent. An `eprintln!` to stderr (which the host app's stderr parser ignores per the P0.1 spike) would help operators correlate "huh, that one was slow" with "the daemon got OOM-killed and respawned."
