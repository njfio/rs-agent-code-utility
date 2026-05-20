### Anonymous opt-in telemetry (`rts telemetry`)

`rts` now ships **opt-in** telemetry — counters and latencies only, no
paths/content/symbol names — so the project can make roadmap calls
on aggregate signal instead of n=1. **Off by default.** Activate with
`rts telemetry enable`; the daemon's once-per-day ticker sends a
single anonymous JSON payload to the receiver and stops on
`rts telemetry disable` (which deletes the local install-id).

New CLI surface on the `rts` binary:

- `rts telemetry status` — current state, schema version, endpoint.
- `rts telemetry preview` — print the exact JSON the next ping would
  send (byte-equivalent to the wire payload). Auditable; works any
  time.
- `rts telemetry enable` / `rts telemetry disable` — toggle.
- `rts telemetry flush` — send now (requires `--features telemetry` at
  build time AND `enable` at runtime).

Schema is frozen at `schema_version: 1`; every map key is a static
`&'static str` from a bounded allowlist in
`crates/rts-mcp/src/telemetry.rs`. A schema golden-file test catches
drift.

HTTP support is feature-gated (`--features telemetry` on `rts-mcp`
and `rts-daemon`), so default workspace builds still link zero HTTP
code paths per AGENTS.md "Dependency hygiene". Reference receiver
implementation lives in-tree under `telemetry-receiver/`.

See [`docs/telemetry.md`](docs/telemetry.md) for the full
plain-English explanation of what gets sent, why, and how to opt out.
