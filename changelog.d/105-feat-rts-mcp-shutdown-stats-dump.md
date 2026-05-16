### `rts-mcp` — auto-dump `Daemon.Stats` to stderr on session shutdown

Phase 2 of #104. The `Daemon.Stats` RPC made per-session call counts queryable; this PR makes them **automatic**. When the MCP stdio session ends (agent hangs up, host app closes, `Ctrl-D` on rts-mcp's stdin), `rts-mcp` issues one final `Daemon.Stats` query and pretty-prints the snapshot to stderr.

Example output at session end:

```
rts-mcp session stats:
  daemon-version: 0.5.7
  uptime-ms:      3782451
  total-calls:    89
  Index.Grep: 47
  Index.FindSymbol: 12
  Workspace.Mount: 1
  Daemon.Stats: 1
```

#### Why

Three rounds of *"am I regularly using rts?"* reflection produced three rounds of anecdote. #104 made the data **queryable**; this PR makes it **automatic**. Every session that ends naturally — including this one when the user closes Claude Code — leaves a data point on stderr. The next reflection round opens the host app's log pane instead of asking the agent.

The dominant cost of the prior "no telemetry" state wasn't ignorance — it was *friction*. Asking the agent "am I using rts?" requires the agent to remember to query stats; running `rts-bench query daemon-stats` requires the user to know the command exists. Neither happens in practice. Auto-dump closes both loops without anyone having to remember anything.

#### Output rules

- **Zero-count counters are silent.** A session that only issued `find_symbol` 5× emits one `Index.FindSymbol: 5` line, not a wall of `Index.Foo: 0` zeros. Keeps quiet sessions tight.
- **Sorted by count descending** (then method-name ascending for tiebreak). Most-called methods appear first.
- **`#`-free format** — single-line per counter, `Method: N` shape. Tracing-friendly if a future PR wants to switch from `eprintln!` to `tracing::info!`.
- **Pre-v0.5.7 daemon fallback.** Daemons that predate `Daemon.Stats` (no RPC handler) return `INVALID_PARAMS`; `rts-mcp` logs the failure at `debug!` and skips the dump. Old daemons don't get a scary warning on every shutdown.

#### Non-fatal

The dump is observational, not load-bearing. Any failure — daemon already crashed, socket already torn down, JSON decode error — surfaces as a single `tracing::debug!` and the shutdown continues. Observability should never block process exit.

#### Verification

New integration test `crates/rts-mcp/tests/mcp_round_trip.rs::rts_mcp_dumps_session_stats_to_stderr_on_shutdown`:

- Spawns `rts-mcp` with `stderr: Stdio::piped()` (not `null`).
- Completes the MCP handshake + one confirmed `find_symbol("hello")` call.
- Closes stdin → `service.waiting()` returns → shutdown dump fires.
- Reads stderr to EOF; asserts:
  - Contains `"rts-mcp session stats:"` header
  - Contains `daemon-version:`, `total-calls:` fields
  - Contains `Workspace.Mount: N`, `Index.FindSymbol: N`, `Daemon.Stats: N` lines (counters that were definitely advanced during the session)
  - Does NOT contain `Index.ImpactOf:` or `Index.Grep:` lines (zero-count, must be filtered)

End-to-end smoke against the rts repo:

```
$ printf '%s\n%s\n%s\n' \
    '{"jsonrpc":"2.0","id":1,"method":"initialize",…}' \
    '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
    '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"find_symbol",…}}' \
  | rts-mcp --workspace . 2>&1 1>/dev/null

rts-mcp session stats:
  daemon-version: 0.5.7
  uptime-ms:      17494
  total-calls:    3
  Daemon.Stats: 1
  Index.FindSymbol: 1
  Workspace.Mount: 1
```

Three calls: 1 lazy mount (triggered by `find_symbol`) + 1 `find_symbol` + 1 final `Daemon.Stats`. Exactly the documented shape.

Full suite: `cargo test --workspace --release` — **41 test binaries pass, 0 fail**.

#### Out of scope (filed for v0.5.8 follow-up)

- **Structured-log alternative.** Today the dump is `eprintln!` so it's always visible regardless of `RTS_LOG`. A future revision could switch to `tracing::info!` with structured fields once host-app log pipelines reliably filter on target/level — but the loud, always-on shape is the right default for now (the whole point is visibility).
- **Per-session snapshots vs daemon-cumulative.** The dump reflects the daemon process's running totals — multiple MCP sessions against the same long-lived daemon see accumulated counts. A per-session delta (subtract pre-session snapshot from post-session) would isolate this session's traffic. Useful for shared-daemon setups; not blocking for the typical single-user case.
