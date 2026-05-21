### `rts-bench` real-repos: drop `Option` wrappings on latency / language fields

PR #123 shipped the real-repo regression bench against tokio / flask / gin, but five fields on `RepoMetrics` had to be `Option`-wrapped because `Daemon.Telemetry` was reachable on the daemon's JSON-RPC wire but not routed through the MCP tool list — only `daemon_stats` was. PR #124 added the `daemon_telemetry` MCP tool, unblocking those fields. This PR finishes the work.

#### What

In `crates/rts-bench/src/real_repos/mod.rs`:

- `languages_indexed: Option<Vec<String>>` → `Vec<String>`
- `find_symbol_latency_p50_ms: Option<u64>` → `u64`
- `find_symbol_latency_p99_ms: Option<u64>` → `u64`
- `grep_latency_p50_ms: Option<u64>` → `u64`
- `grep_latency_p99_ms: Option<u64>` → `u64`

`run_one_repo` now calls `daemon_telemetry` (via the MCP tool surface PR #124 added) and populates the five fields from the response. The cold-walk poll path also warms `Index.Grep` once before the telemetry read so the grep latency histogram has at least one sample to summarise.

`unresolved_refs_count` stays `Option<u64>` — the daemon doesn't yet expose a call-graph gap counter; a parallel follow-up adds that surface.

#### Diff machinery (`crates/rts-bench/src/real_repos/diff.rs`)

`TolerancePolicy` gains a `latency_p50_pct: f64` field alongside the existing `latency_p99_pct`. Both default to `50.0`. The compare grid now always emits rows for the four latency fields and the language set — they're no longer skipped on `None`.

Tolerance bands (unchanged for cold_walk_ms, memory_peak_rss_kb, symbol_count, files_indexed):

| metric                       | band     |
|------------------------------|----------|
| `languages_indexed`          | exact    |
| `find_symbol_latency_p50_ms` | ±50 %    |
| `find_symbol_latency_p99_ms` | ±50 %    |
| `grep_latency_p50_ms`        | ±50 %    |
| `grep_latency_p99_ms`        | ±50 %    |

±50 % is intentionally wide: a single warm-up sample on a CI runner is intrinsically noisy and the bench's purpose here is to catch order-of-magnitude regressions (a hot path going from microseconds to milliseconds), not tail-latency micro-drift.

#### Baseline

`.github/baselines/rts-bench-real-repos.json` has been regenerated to capture the now-mandatory fields. Cold-walk and RSS numbers shift slightly from the v0.5.5 baseline (different runner, fresh clones) but stay well within the existing ±25 % / ±15 % bands on a representative run.

#### Test guard

- `crates/rts-bench/src/real_repos/mod.rs::tests` — `report_roundtrips_through_json` now asserts the latency fields round-trip as bare `u64`. `unresolved_refs_omitted_when_none` replaces the old multi-field omission test (it's the only remaining `Option`). A new `latency_p50_does_not_exceed_p99` sanity test asserts the histogram-ordering invariant for both find_symbol and grep.
- `crates/rts-bench/src/real_repos/diff.rs::tests` — `latency_p50_within_band_passes` and `latency_p50_outside_band_regresses` cover the new always-on p50 row.

#### Out of scope

- `unresolved_refs_count` daemon-side surface (separate parallel follow-up).
- Adding new bench metrics — only the existing five `Option`-wrapped fields are dropped to their bare types.
- Changing the protocol or wire shapes — PR #124 already exposed `daemon_telemetry` through MCP; this PR only changes what `rts-bench` does with the response.

#### Post-deploy monitoring

The nightly real-repo bench workflow now gates on the four latency fields plus the language set. Healthy signal: green check on the scheduled run. Failure signal: a latency regression > 50 % triggers the workflow's existing failure path with the per-metric diff row indicating which `Index.*` method drifted.
