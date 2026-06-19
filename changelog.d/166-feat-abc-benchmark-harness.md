### Feat: A/B/C benchmark harness extensions (verify-v0 P4, build-only)

Extends `agent-bench` from a 2-arm A/B into a 3-arm **A/B/C** benchmark that
separates the effect of rts *retrieval* tools from the *verify_\** tools. This
is BUILD-ONLY — every unit is unit-tested with mocks (`FakeAnthropicClient`,
`FakeBridge`, `FakeRunner`); ZERO live model/API calls and ZERO real daemon
dependencies in the suite. The live run is gated on the deferred PR-B infra.

- **Arm tool profiles** (`agent_bench/run.py`) — explicit allowlists
  `RETRIEVAL_TOOLS` (find_symbol, grep, read_symbol, read_symbol_at, read_range,
  outline_workspace, find_callers, impact_of) and `VERIFY_TOOLS` (verify_symbol,
  verify_signature, verify_import, verify_claims, verify_impact, verify_edit).
  `ArmConfig.tool_profile` ∈ {`baseline`, `retrieval`, `retrieval_verify`} drives
  `build_tool_list`, which intersects the bridge's live listing with the active
  allowlist — a future rts tool can never silently leak into an arm. Arm C
  ("retrieval_verify") appends a one-line `VERIFY_NUDGE` to its system prompt
  via `effective_system_prompt`. `include_rts_tools` is kept as a back-compat
  shim derived from the profile.

- **Statistics** (`agent_bench/report.py`) — per-tool breakdown
  (`tool_calls_by_name`, `verify_tools_total`) on `ArmAggregate`; a hand-rolled
  `mcnemar()` paired test (NO scipy: exact binomial two-sided for <25 discordant
  pairs, else continuity-corrected χ²(df=1) via `math.erfc`); and
  `multi_arm_comparison_json/markdown` rendering per-arm Wilson CIs, tokens,
  wall-clock, verify metrics, the per-tool breakdown, and the three McNemar
  deltas (B vs A, C vs B, C vs A). Schema-versioned `agent-bench/multi-arm/v1`.

- **Per-arm verify metrics** (`agent_bench/eval_verify.py`) — offline (no model)
  `evaluate_arm(trajectories, runner)` computes EVR (pass-verdict rate), BCIR
  (broken_caller/signature_break introduction rate), and SHR/IHR from the verify
  CLI hallucination output, mirroring `rts-bench`'s numerator/denominator/rate
  metric shape (rate `None` on empty denominator). SMR is approximated as `None`
  (the file-level `rts verify --json` surface lacks call-arity data). The
  `RtsVerifyRunner` Protocol is the test seam; the real `CliRtsVerifyRunner`
  shells out to `rts verify-edit` / `rts verify`.

- **CLI `estimate`** (`agent_bench/cli.py`) — `agent-bench estimate --tasks
  --seeds --arms --model --in-price --out-price` projects token + USD spend
  (`runs = tasks × seeds × arms`, priced per MTok) with NO API call. Price
  defaults to Sonnet list ($3 in / $15 out per MTok).

- **Smoke corpus** `agent-bench/corpus/swe-bench-lite-smoke.json` — 4 real
  SWE-bench_Lite instance ids with clearly-labelled placeholder statements for
  cheap wiring tests (not the full curated corpus).
