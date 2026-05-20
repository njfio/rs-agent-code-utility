# `rts` anonymous opt-in telemetry

> [!IMPORTANT]
> Telemetry is **off by default**. Nothing is sent unless you
> explicitly run `rts telemetry enable`. This page describes what
> happens when you opt in.

## TL;DR

- **Default state:** OFF. No pings. No install-id on disk.
- **To opt in:** `rts telemetry enable`. Generates a random
  install-id, sets a flag, and the daemon's once-per-day ticker
  starts pinging the project's receiver.
- **To opt out:** `rts telemetry disable`. Deletes the install-id
  file. All pings stop immediately.
- **To audit:** `rts telemetry preview`. Prints the exact JSON that
  would be sent right now. Always works, opted in or not.

## Why this exists

`rts` ships with introspection (`Daemon.Stats`), but that's per-user.
The maintainers have no aggregate view of which methods agents use,
which error codes fire in the wild, or which language mixes show up
on real workspaces. Without that signal, every roadmap call is made
on n=1 (the author) plus n≤10 (the issue tracker).

Telemetry is the smallest channel that can answer those questions
**without** trading user trust. The bright lines below are
non-negotiable; the schema is frozen at `schema_version: 1` and
versioned for transparent evolution.

## Bright lines (the things `rts` will NEVER do)

1. **Telemetry is opt-in.** The default is OFF. There is no first-run
   prompt, no "we'll just try it" default. You explicitly enable.
2. **No paths, file contents, or symbol names ever leave your
   machine.** The payload is categorical and numeric only.
3. **No PII.** The `install_id` is a random UUID generated locally
   when you opt in. It is deleted by `rts telemetry disable`. The
   receiver hashes it with a rotating monthly salt, so even the
   receiver-side query engine can't track you across months.
4. **`rts telemetry preview` shows exactly what would be sent.** Byte-
   equivalent to the wire payload.
5. **`rts telemetry disable` deletes the install-id.** No further
   pings. Nothing tracking you remains on disk.
6. **The receiver code is open source.** See
   [`telemetry-receiver/`](../telemetry-receiver/). You can run your
   own (`RTS_TELEMETRY_ENDPOINT=https://your.receiver/v1/ingest`).
7. **A single nightly ping**, not per-method real-time. Failures are
   silent and never retried until the next scheduled tick.

## What gets sent

The complete wire schema (`schema_version: 1`):

```json
{
  "schema_version": 1,
  "install_id": "01HXXX...",
  "rts_version": "0.6.1",
  "os": "macos",
  "arch": "aarch64",
  "uptime_hours": 168,
  "languages_indexed": ["rust", "python"],
  "method_counts": {
    "Index.FindSymbol": 1234,
    "Index.Grep": 421,
    "Index.FindCallers": 89
  },
  "method_latency_p50_ms": { "Index.FindSymbol": 2, "Index.Grep": 38 },
  "method_latency_p99_ms": { "Index.FindSymbol": 8, "Index.Grep": 412 },
  "error_counts": {
    "INVALID_STRUCTURAL_QUERY": 7,
    "TIMEOUT": 1
  },
  "cache_hit_rate": 0.84,
  "cold_walk_ms_p50": 230,
  "workspace_size_bucket": "10k_to_100k"
}
```

Field by field, in plain English:

| Field | Meaning |
|---|---|
| `schema_version` | Always 1 today. Bumped when the wire shape changes. |
| `install_id` | Random UUID generated on first opt-in. Deleted on disable. |
| `rts_version` | The `rts` version that produced the ping. |
| `os` | One of `linux`, `macos`, `windows`. |
| `arch` | One of `aarch64`, `x86_64`. |
| `uptime_hours` | How long the daemon has been running. |
| `languages_indexed` | Subset of `rust`, `python`, `typescript`, `javascript`, `go`, `java`, `c`, `cpp`, `php`, `ruby`, `swift`, `csharp` that the daemon observed on disk. |
| `method_counts` | How many times each protocol method was invoked. Keys are from a fixed allowlist. |
| `method_latency_p50_ms` / `_p99_ms` | Latency percentiles per method (in milliseconds). |
| `error_counts` | How often each error code fired. Keys from a fixed allowlist. |
| `cache_hit_rate` | A single scalar in `[0, 1]`. Not per-request. |
| `cold_walk_ms_p50` | Median initial-walk duration. |
| `workspace_size_bucket` | One of `lt_1k`, `1k_to_10k`, `10k_to_100k`, `gt_100k`. We never send the exact file count. |

Notably **not** in the payload (and never will be):

- Paths, filenames, directory names.
- Symbol names, function names, variable names.
- File contents, query text, search patterns.
- Username, hostname, MAC address, IP address (the receiver sees your
  IP at the TCP layer but does not log it).
- Anything we'd describe as "code".

## How to enable

```sh
rts telemetry enable
```

This:

1. Generates a random UUIDv4 → `~/.config/rts/install_id`.
2. Writes `enabled = true` → `~/.config/rts/telemetry.toml`.
3. Starts the daemon's 24h ticker on the next daemon start (if your
   build supports it; see "Build flags" below).

You can verify with `rts telemetry status`:

```
telemetry: ENABLED
schema_version: 1
endpoint: https://telemetry.rts.dev/v1/ingest
install_id: 91a8c4...
last_ping_unix_ms: <never>
```

## How to opt out

```sh
rts telemetry disable
```

This:

1. **Deletes** `~/.config/rts/install_id` from disk.
2. Sets `enabled = false` in `~/.config/rts/telemetry.toml`.
3. Stops the daemon's ticker on the next tick (which is a no-op
   anyway when `enabled = false`).

After this, no pings are sent. The opt-out is local-only — there is
nothing to "unsubscribe from" on the receiver side, because the
receiver only ever saw a hashed, salt-rotated derivative of the
install-id that's already invalidated by the next monthly rotation.

## Retention & access

- **The receiver keeps pings for at most 90 days.** After that
  they're deleted.
- The `install_id` is hashed at ingest with a monthly-rotating salt.
  Within a single month, queries can identify "the same install"; the
  next month, the same client hashes to a different value, so longer-
  term cohort analysis isn't possible.
- **Project maintainers** can query aggregate stats from the
  receiver. There is no per-install drill-down — the data warehouse
  schema does not expose unfiltered `install_id_hash` to interactive
  queries; only roll-up views are queryable.

## Privacy concerns

If you have a privacy concern, please open an issue at
<https://github.com/njfio/rs-agent-code-utility/issues> with the label
`privacy`. We treat any report that the payload contains something
outside this documented schema as a release-blocking bug.

## Building from source: the `telemetry` feature

The HTTP send path is **feature-gated** at build time as well as
runtime, so the default `cargo build` of `rts-mcp` and `rts-daemon`
links zero HTTP code paths (matching the project's
"Dependency hygiene" rule in AGENTS.md). To compile telemetry support
into the binaries, build with:

```sh
cargo build --release --workspace --features telemetry
```

Release artifacts published via brew tap or GitHub Releases ship the
feature ON; if you compile from source, you control whether it's
linked.

## Self-hosting the receiver

If you'd rather route telemetry to your own infrastructure (corporate
fleet, air-gapped lab, regulated industry), set
`RTS_TELEMETRY_ENDPOINT` to your endpoint URL. The reference
implementation in [`telemetry-receiver/`](../telemetry-receiver/) is
a Cloudflare Workers handler; adapt to your environment.

## Auditing the implementation

The whole telemetry surface fits in three files:

- `crates/rts-mcp/src/telemetry.rs` — wire schema, payload builder,
  local opt-in state machine. **All bounded-enum filters live here.**
- `crates/rts-mcp/src/bin/rts.rs` (the `Telemetry` subcommand block)
  — CLI surface.
- `crates/rts-daemon/src/telemetry_ticker.rs` — daemon-side
  scheduler. Shells out to `rts telemetry flush`; does not link any
  HTTP client itself.

The gating tests in `crates/rts-mcp/tests/telemetry_privacy.rs`
mechanically verify each bright line.
