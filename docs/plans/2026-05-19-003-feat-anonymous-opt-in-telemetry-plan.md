---
title: Anonymous Opt-In Telemetry — counters and latencies only
type: feat
status: active
date: 2026-05-19
---

# Anonymous Opt-In Telemetry

## Overview

`Daemon.Stats` introspects the *self.* It tells one user, on one machine,
what their daemon is doing. **We have no aggregate view of what users
do.** Which methods are hot? Which error codes fire in the wild? What is
the language mix on real workspaces? What is the p99 latency we ship vs.
what we benchmarked? How many users are even running this thing?

This plan is the smallest, most privacy-respectful telemetry channel that
can answer those questions: **opt-in, anonymous, counters-and-latencies
only, no paths or content, well-documented, easy to disable**. Designed
under the assumption that *trust* is the load-bearing constraint and any
mis-step burns the entire project's credibility.

## Problem Statement / Motivation

We are making roadmap decisions blind:

- Is `Index.Grep` actually used more than `Index.FindSymbol`?
- How many users hit `INVALID_STRUCTURAL_QUERY` per week — is it a
  documentation bug or a UX bug?
- Are users on Rust/Python/Go workspaces, or are they primarily on
  Java/C# (the languages Plan 005 targets)? The brew-tap-vs-AST sequencing
  decision turns on this.
- Is the persisted cold-mount actually winning in the field? Local
  benchmarks say yes; reality might disagree.

Currently, the only signal is GitHub issues — biased toward the
problems-only-when-something-breaks population. Every product decision is
made on n=1 (the author) plus n≤10 (the issue tracker).

Telemetry is the highest *information-per-line-shipped* move available,
**if and only if it earns user trust**. If it doesn't, the cost is
catastrophic (lose the security-conscious early adopters).

## Proposed Solution

### Bright lines (non-negotiable)

These are the constraints that everything else is designed around:

1. **Opt-in, never opt-out.** Default is off. User must
   `rts telemetry enable` or set `RTS_TELEMETRY=1`. No "we'll just try
   it" defaults.
2. **No paths, no content, no symbol names.** Categorical and numeric
   only. No string fields except: enum-bounded values (language names,
   method names, error code names) and version strings.
3. **No PII or identifying info.** Anonymous install-id is a random UUID
   generated on first opt-in, stored locally, never linked to anything.
4. **Visible in transit.** A `rts telemetry preview` command shows
   exactly what the next ping will send. Users can audit.
5. **Easy off.** `rts telemetry disable` deletes the install-id and stops
   pinging. No tracking after opt-out.
6. **Open code.** The schema is in-tree; the receiver code is open
   source; the receiver retention policy is documented publicly.
7. **No real-time tracking.** Single nightly ping (or on-demand via
   `rts telemetry flush`); no per-method send.

### Data model (the entire wire schema)

```json
{
  "schema_version": 1,
  "install_id": "01HXXX...",         // random uuidv7, generated locally
  "rts_version": "0.6.1",
  "os": "macos",                      // enum: linux|macos|windows
  "arch": "aarch64",                  // enum: aarch64|x86_64
  "uptime_hours": 168,
  "languages_indexed": ["rust", "python"],  // enum subset
  "method_counts": {                  // bounded enum keys only
    "Index.FindSymbol": 1234,
    "Index.Grep": 421,
    "Index.FindCallers": 89
  },
  "method_latency_p50_ms": {
    "Index.FindSymbol": 2,
    "Index.Grep": 38
  },
  "method_latency_p99_ms": {
    "Index.FindSymbol": 8,
    "Index.Grep": 412
  },
  "error_counts": {                   // bounded enum: error code names
    "INVALID_STRUCTURAL_QUERY": 7,
    "TIMEOUT": 1
  },
  "cache_hit_rate": 0.84,
  "cold_walk_ms_p50": 230,
  "workspace_size_bucket": "10k-100k"  // enum bucket, not exact count
}
```

That's the complete wire format. Anything not in this schema is not sent.

### Receiver shape

Phase 1: simplest viable receiver.
- Static endpoint: `https://telemetry.rts.dev/v1/ingest` (TLS).
- Backend: serverless function (Cloudflare Workers / Vercel) writes to a
  managed columnar store (e.g., ClickHouse Cloud or Tinybird).
- No PII stored. install_id is hashed at ingest with a rotating salt so
  it's not stable across receiver-side queries.
- 90-day retention max.

### Client-side privacy controls

- `rts telemetry status` — shows current state (enabled/disabled),
  install-id, last ping time, schema version.
- `rts telemetry preview` — prints the JSON that would be sent right now.
- `rts telemetry enable` / `rts telemetry disable` — toggle.
- `rts telemetry flush` — send immediately and print confirmation.
- `RTS_TELEMETRY_ENDPOINT=...` env var — override endpoint (for
  air-gapped use or testing).

### When the ping fires

Daemon runs a background ticker (default: 24h cadence). On tick:
1. Check opt-in flag (config + env).
2. Sample current counters from `Daemon.Stats`.
3. Construct the payload (using **only** the bounded schema).
4. POST to endpoint with 5s timeout. Failure is silent and counters
   accrue until next tick.
5. Reset *delta* counters (we send deltas, not absolutes; cumulative
   would let the receiver back-compute install age, leaking signal).

## Technical Considerations

- **Bounded enums:** every map key is a static `&'static str` from a
  hardcoded set. Adding new keys is a code change visible in PRs. No
  user-controlled strings.
- **No DNS-leak via probe-then-decide:** the check for opt-in happens
  before any network call.
- **Network hygiene:** TLS-only. `User-Agent: rts-telemetry/<version>`.
  Single POST, no follow-up requests.
- **No cookies, no headers beyond UA + Content-Type.**
- **Failure modes:** network error, DNS failure, 5xx — all silent. We do
  NOT retry beyond next scheduled tick (no thundering-herd risk on outage
  recovery).
- **Receiver-side:** salt rotates monthly; old data is rebucketed.
  Receiver code MUST be open source (a `telemetry-receiver/` directory
  in-tree).

## System-Wide Impact

- **Interaction graph:** background ticker → opt-in check → snapshot
  Daemon.Stats → serialize schema → HTTP POST → done. Fully isolated from
  the request path. No effect on query latency.
- **Error propagation:** telemetry failures never affect daemon behavior.
  A failed POST logs at `trace` level only.
- **State lifecycle:** install-id is the only persisted state, written to
  `~/.config/rts/install_id` (XDG-respecting). Deleted by
  `telemetry disable`.
- **API surface parity:** the CLI exposes the telemetry controls. MCP
  agents can also call `Daemon.TelemetryStatus` / `Daemon.TelemetryEnable`
  if hosts want to surface this in their UI.
- **Integration test scenarios:**
  1. Daemon with telemetry disabled — confirm zero outbound connections
     (mock-network assertion).
  2. Daemon with telemetry enabled + endpoint override to a local mock —
     confirm payload matches schema and contains no out-of-enum strings.
  3. `rts telemetry preview` output is byte-equivalent to what
     `telemetry flush` sends.
  4. `rts telemetry disable` deletes the install-id file and stops
     subsequent pings.

## Acceptance Criteria

### Functional

- [ ] Daemon supports a background telemetry ticker, off by default.
- [ ] `rts telemetry {status,preview,enable,disable,flush}` subcommands
      implemented.
- [ ] Schema implemented and frozen at `schema_version: 1`; deviations
      from schema in code fail at compile time (enum-bounded keys).
- [ ] No path, content, symbol name, or user identifier appears anywhere
      in the payload.
- [ ] `RTS_TELEMETRY_ENDPOINT` env var override works.
- [ ] Receiver code lives in-tree at `telemetry-receiver/` (open source).
- [ ] Receiver retention policy documented in `docs/telemetry.md`.

### Privacy gates (these are gating requirements, not nice-to-haves)

- [ ] **First-run prompt does NOT exist.** Telemetry is silent unless
      explicitly enabled.
- [ ] No telemetry pings before opt-in. Verified by integration test.
- [ ] No telemetry pings after opt-out. Verified by integration test.
- [ ] `docs/telemetry.md` explains in plain English what is sent, why,
      how to disable, how long it's kept, who can see it.
- [ ] Privacy review by a non-author before ship (single trusted
      reviewer is sufficient; document in PR description).

### Quality Gates

- [ ] Schema golden-file test: any change to the wire format requires
      bumping `schema_version` and updating the golden file in the same
      commit.
- [ ] CHANGELOG entry calls out telemetry prominently.

## Success Metrics

- 90 days after ship: ≥100 opted-in installs (proves the value
  proposition is clear enough to opt in).
- Zero issues filed about telemetry violating its bright-line constraints.
- First roadmap decision made on telemetry data (vs. guessing) within 6
  months of ship.

## Dependencies & Risks

- **Risk: trust catastrophe.** Single biggest risk. If telemetry ships
  with any bug that leaks user paths, content, or identifying info, the
  project loses years of credibility. Mitigations:
  - Golden-file schema test (catches schema drift).
  - Privacy review by non-author.
  - Bounded enums for every map key (no user-controlled strings).
  - Integration test asserts no network activity when opted out.
- **Risk: receiver becomes unmaintained.** If we host telemetry, we own
  uptime. Mitigation: serverless receiver (no machine to babysit); failure
  is silent on client side.
- **Risk: opt-in friction means no data.** Predictable.
  Counter-strategy: lead the value proposition in docs ("here's what we
  learn and how it helps you").
- **Dependency:** the Human CLI (Plan 002 — 2026-05-19-002) — the
  `rts telemetry` subcommands need somewhere to live. Sequence after the
  CLI lands.
- **No new runtime dependencies beyond a TLS-capable HTTP client (likely
  `reqwest` minimal feature set or `ureq`).**

## Out of Scope (Non-Goals)

- **Crash reporting.** Telemetry is counters only; crashes are a separate
  workstream (Sentry integration would be a v0.7+ conversation).
- **Per-request tracing.** No per-request data ever.
- **Workspace fingerprinting** — we do not send any workspace identifier,
  not even a hash.
- **Feature flags / remote config.** Telemetry is one-way (client →
  server). The server cannot push config to the daemon.
- **Real-time dashboards for users.** `Daemon.Stats` is the local
  introspection surface; telemetry is the aggregate one.

## Resource Requirements

- ~3-4 days client-side.
- ~1-2 days receiver setup + retention plumbing.
- ~1 day docs/copy.
- 1 privacy reviewer (non-author) before ship.

## Sources & References

### Internal

- `Daemon.Stats` counters source: `crates/rts-daemon/src/methods/stats.rs`
- XDG config conventions used elsewhere: `crates/rts-bench/src/doctor/`
- Human CLI (dependency): `docs/plans/2026-05-19-002-feat-human-cli-subcommand-plan.md`

### External

- Mozilla Telemetry principles —
  <https://wiki.mozilla.org/Firefox/Data_Collection>
  (the gold standard for opt-in privacy-respecting telemetry)
- "No Color" standard parallel — <https://no-color.org/> — same spirit of
  user-controlled defaults
- Cloudflare Workers + ClickHouse — possible receiver stack
  <https://developers.cloudflare.com/workers/>
  <https://clickhouse.com/docs/en/cloud/get-started>

### Reference projects

- **rustup's telemetry** — pre-1.0 had telemetry; was removed in 2018 due
  to data-quality issues. Lessons: keep the schema small; sample
  representatively; bound retention.
- **homebrew's analytics** — opt-out (not opt-in). Burned credibility;
  do not repeat.
- **vscode telemetry** — too granular, lots of pushback. Do not repeat.
- **ripgrep, fd, bat** — zero telemetry. Default position for
  Rust CLI tools. Departing from it requires careful framing.
