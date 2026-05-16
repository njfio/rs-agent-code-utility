### `Daemon.Stats` RPC + per-session call counters — measure dogfood, don't guess

Every reflection-on-dogfooding round of this project has been **anecdotal**: *"I think I used grep more than find_symbol."* No actual data. This PR adds the data.

#### What

- **`CallCounters` struct** in `DaemonState`, 18 `AtomicU64` fields — one per RPC the daemon dispatches (`Daemon.Ping`, `Daemon.Stats`, `Workspace.Mount/Status/Unmount`, `Session.Open/Close`, `Index.FindSymbol/FindCallers/ImpactOf/ReadRange/ReadSymbol/ReadSymbolAt/Outline/Grep`, plus `unknown_method` for wire-protocol mismatches).
- **Counter bumped in `methods::dispatch`** before each handler fires. One relaxed atomic increment per RPC; negligible overhead next to the rest of the dispatch path. **Errored calls count too** — they still represent agent intent, and the Stats surface should reflect them.
- **New `Daemon.Stats` RPC** returns a JSON snapshot with `uptime_ms`, daemon `version`, `total_calls`, and the per-method `calls` map. Wire shape:

```jsonc
{
  "uptime_ms":   12345,
  "version":     "0.5.7",
  "total_calls": 89,
  "calls": {
    "Index.FindSymbol":  3,
    "Index.Grep":        47,
    "Index.FindCallers": 0,
    "Workspace.Mount":   1,
    "Daemon.Stats":      2,
    // …all 18 methods including unknown_method
  }
}
```

- **New `rts-bench query daemon-stats` subcommand** + matching MCP tool (`mcp__rts__daemon_stats`) so the surface is reachable from both bash and MCP-aware agents.
- **`--output lines` rendering**: emits `# daemon-version`, `# uptime-ms`, `# total-calls` header lines (prefixed `#` so `grep -v ^#` strips them) followed by `Method: N` lines sorted by count descending, with method-name lex tiebreaker for reproducibility. Pipe-friendly:

```sh
# Show only methods that actually got called this session
rts-bench query --output lines daemon-stats | grep -v '^#' | awk -F: '$2+0 > 0'

# Watch usage drift over time
watch -n 5 'rts-bench query --output lines daemon-stats | grep Index'
```

#### Counter lifetime

Counters live in the daemon process — **not persisted across daemon restarts**. A daemon crash + auto-respawn, SIGTERM + new process, or version upgrade all reset every counter to zero. This is intentional: the counters describe *this daemon process's* served traffic. Persisting would conflate independent runs and make the "fresh start vs accumulated" distinction muddy. Cross-session aggregation should happen client-side from per-session snapshots.

A single long-lived daemon (the typical agent setup) accumulates counters across many `rts-bench query` / MCP-session invocations — they all share the daemon's socket. The first session sees a counter at 0; the 47th sees 47 (one per call from prior sessions, plus its own).

#### Why this matters

The agent (me) building rts has been claiming "I'm not using it" for three sessions running. Each claim has been anecdotal. With `Daemon.Stats` shipped, the next claim can be:

```
$ rts-bench query --output lines daemon-stats | head -8
# daemon-version: 0.5.7
# uptime-ms: 3782451
# total-calls: 89
Index.Grep: 47
Index.FindSymbol: 3
Workspace.Mount: 1
Daemon.Stats: 2
…
```

A real number, not a vibe. The question stops being unfalsifiable.

#### Verification

- **New integration test** `crates/rts-daemon/tests/daemon_stats_round_trip.rs::daemon_stats_counts_each_rpc`:
  - Asserts `Daemon.Ping` advertises the `daemon_stats` capability.
  - First `Daemon.Stats` call shows `Daemon.Ping: 1` + `Daemon.Stats: 1`, everything else 0.
  - Exercises `Workspace.Mount`, `Workspace.Status`, `Index.FindSymbol`, `Index.Grep` (×2) and verifies each counter advances by the expected amount.
  - Calls a deliberately-malformed `Index.NonExistentMethod` and verifies the `unknown_method` counter advances even though the call errors.
  - Asserts `total_calls` equals the sum of per-method counts (cross-check on the snapshot serialization).

- **End-to-end smoke** via `rts-bench query daemon-stats` against the rts repo itself — JSON output round-trips through MCP correctly, `--output lines` produces the documented shape, pipe composition works.

- **Full suite**: `cargo test --workspace --release` — **41 test binaries pass, 0 fail**.

#### Out of scope (filed for follow-up)

- **rts-mcp shutdown dump**: on stdio-EOF, rts-mcp could issue a final `Daemon.Stats` and log the snapshot to stderr. Closes the agent-session-end reflection loop without manual querying. ~15 LOC; deferred to keep this PR scoped.
- **Per-tool latency histograms**: counters say *how often* but not *how long*. A future `Daemon.Stats` extension with p50/p95/p99 per method would surface "find_symbol is fast but grep is slow on this workspace" without external bench runs.
- **Cumulative cross-session counters via persistence**: optional opt-in (env var?) that stores totals in META so a daemon restart preserves history. Would muddy the "this process's traffic" semantics, so deferred until a real use case emerges.
