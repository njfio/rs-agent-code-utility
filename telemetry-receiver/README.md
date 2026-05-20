# `telemetry-receiver/` — reference implementation

This directory holds the **reference** server-side implementation that
ingests `rts` telemetry pings. It's published in-tree so:

1. Users opting in can see exactly what happens to their payload after
   `rts telemetry flush` POSTs it.
2. Anyone wanting to self-host (air-gapped fleet, regulated industry,
   privacy-strict org) can deploy their own receiver and point clients
   at it via `RTS_TELEMETRY_ENDPOINT`.

> [!IMPORTANT]
> **This is reference code, not a deployable artifact.** It exists to
> demonstrate the receiver contract, not to be `git clone && deploy`.
> Production deployments should fork it, audit it, and add their own
> ops plumbing (secrets management, monitoring, rate limiting).

## What gets stored

Per `docs/telemetry.md`, the payload is **counters and latencies
only** — no paths, no content, no symbol names, no PII. The receiver
applies one additional defense-in-depth step:

- **`install_id` is hashed at ingest with a monthly-rotating salt.**
  After 30 days, the same client's `install_id` hashes to a different
  value. This means even the receiver-side query engine can't see a
  stable per-install timeline. Daily uniques are queryable; long-term
  cohorts are not.

## Retention policy

- **90 days max.** Pings older than 90 days are deleted by a
  scheduled job. The retention SQL is in `cleanup.sql`.
- **Aggregate queries only.** No "show me what install-id $X did".
  Even with the rotating salt, we don't expose per-install drill-down
  to the maintainer queries that produce the public roll-up reports.

## Reference handler

`ingest.ts` is a [Cloudflare Workers](https://developers.cloudflare.com/workers/)
handler that:

1. Validates the `schema_version` field (rejects unknown versions).
2. Validates that every map key is in the bounded-enum allowlist
   mirrored from `crates/rts-mcp/src/telemetry.rs`.
3. Hashes the `install_id` with the current monthly salt.
4. Inserts the row into a ClickHouse Cloud database.

This is the *minimum* set of guards. Real production deployments
should additionally:

- Rate-limit per source IP (Cloudflare's edge handles this).
- Drop payloads larger than 32 KiB (the legitimate maximum is ~4 KiB).
- Log only counts, never payload contents, in the receiver-side
  observability stack.

## Schema mirror

`schema.json` is the exact wire schema (`schema_version: 1`)
mirrored from the Rust client, in JSON Schema form. The receiver's
validator uses it. **Bumping `schema_version` requires updating
this file in lockstep** with the Rust struct in
`crates/rts-mcp/src/telemetry.rs`.

## Files

- `ingest.ts`            — Cloudflare Workers ingest handler
  (reference).
- `schema.json`          — JSON Schema mirror of `schema_version: 1`.
- `salt-rotation.md`     — operational doc explaining the
  monthly salt rotation.
- `cleanup.sql`          — 90-day retention cleanup SQL.
