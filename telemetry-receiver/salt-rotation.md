# Salt rotation policy

The receiver hashes every incoming `install_id` with a current salt
before storing it. The salt rotates monthly, so the same client's
`install_id_hash` differs across months — making long-term per-install
cohort analysis impossible even with full database access.

## Rotation cadence

- **First of each month, 00:00 UTC.**
- A cron-triggered Cloudflare Worker generates a new 32-byte salt
  (via `crypto.randomBytes`) and writes it to the
  `TELEMETRY_SALT_NEXT` secret. After a 24-hour overlap window where
  both old and new salts are accepted, the new salt is promoted to
  `TELEMETRY_SALT` and the old salt is deleted.

## Why rotate

Without rotation, a leak of the salt would let an attacker re-derive
the install-id from any historical hash. With monthly rotation, an
attacker would have to leak every monthly salt to back-fill the
timeline — a continuous breach signal rather than a single recoverable
leak.

This is layered with the 90-day retention cap (see `cleanup.sql`):
even with no salt rotation, no row lives long enough to outlast its
salt.

## Implementation note

The rotation cron is intentionally out of scope for `ingest.ts`. A
production deployment writes this as a separate Worker, scheduled via
the `[triggers.crons]` block of `wrangler.toml`. See Cloudflare's
[scheduled events docs](https://developers.cloudflare.com/workers/configuration/cron-triggers/)
for the binding shape.
