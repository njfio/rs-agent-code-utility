### Real-repo regression bench (`rts-bench real-repos`) — nightly CI fixture against tokio, flask, and gin

`rts-bench` gains a `real-repos` subcommand (`run` / `baseline` / `compare`) that clones a pinned set of representative OSS repos, indexes each with the rts daemon, captures core indexer metrics, and compares them against a committed baseline. A new nightly GitHub Actions workflow (`real-repo-bench.yml`) runs `compare` at 07:00 UTC and fails the run on any out-of-band metric. The maintainer regenerates the baseline (`rts-bench real-repos baseline …`) any time a daemon change deliberately moves a metric and commits the new `.github/baselines/rts-bench-real-repos.json` in the same PR.

#### Motivation

Two latent bugs in the 2026-05-19/20/21 multi-PR series surfaced only against real codebases:

- The `cancel_in_flight` test flake (fixed in PR #119) reproduced for two unrelated PR agents — #116 (AST-precise call edges) and #117 (MCP resilience). Synthetic single-test runs missed it; the full-workspace test run under contention caught it.
- The PHP `method_declaration` extractor gap (fixed in PR #118) passed every synthetic single-file unit test but failed PR #116's multi-file integration test against a real PHP fixture.

A small set of pinned real repos under a regression-gated metrics check would have surfaced both classes of bug the night they landed. v1 covers Rust (tokio @ 1.47.0), Python (flask @ 3.1.0), and Go (gin @ v1.10.0) — three repos, <2 min total index time on a CI runner.

#### What's gated

| metric                  | band       | rationale                                       |
|-------------------------|-----------|-------------------------------------------------|
| `symbol_count`          | exact     | off-by-one means an extractor changed behavior  |
| `files_indexed`         | exact     | a missed file = a filter or walker regression   |
| `cold_walk_ms`          | ±25 %     | cache-sensitive on cold runners                 |
| `memory_peak_rss_kb`    | ±15 %     | catches leaks; slack for jemalloc thermal noise |

Metrics that the daemon tracks but doesn't yet route through the MCP tool surface (per-method latencies, language set, unresolved-ref count) are recorded as `Option` fields with `TODO(post-G)` callouts; the diff machinery skips them cleanly until the wire path lands.

#### Scope notes

This PR adds the bench machinery and the workflow; it does **not** add any new daemon-side counters. It does **not** add per-PR gating (nightly + manual dispatch only). It does **not** add an issue-opener — regressions annotate the workflow run and fail the workflow, period. Each of those is a deliberate follow-up.
