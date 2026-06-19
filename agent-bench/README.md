# agent-bench

**SWE-bench-lite A/B harness for the rts MCP surface.**

Measures whether the `rts` MCP tools and the PreToolUse nudge hook
(from #106) actually shift agent tool-use behavior on a representative
external workload, vs anecdotal *"I think I used grep more than
find_symbol."*

Lives outside the `rts-bench` Rust crate because it hits the Anthropic
API — and per `AGENTS.md:377-381`, daemon/MCP build trees stay
HTTP-free. CI asserts that invariant via `cargo tree`.

## What it does

For each task in a SWE-bench-lite subset, run the task through the
Anthropic API once per **arm**. The bench is **A/B/C**: three arms with
progressively wider rts tool surfaces, so we can separate the effect of
*retrieval* tools from the effect of the *verify_\** tools.

| Arm | Profile | Tools available |
|---|---|---|
| **A** (baseline) | `baseline` | `Bash`, `Read` |
| **B** (retrieval) | `retrieval` | `Bash`, `Read`, **+ rts RETRIEVAL tools** (`find_symbol`, `grep`, `read_symbol`, `read_symbol_at`, `read_range`, `outline_workspace`, `find_callers`, `impact_of`) |
| **C** (retrieval + verify) | `retrieval_verify` | Arm B's tools **+ the `verify_*` tools** (`verify_symbol`, `verify_signature`, `verify_import`, `verify_claims`, `verify_impact`, `verify_edit`) **+ a one-line verify nudge appended to the system prompt** |

The tool surface is an explicit allowlist per arm (`RETRIEVAL_TOOLS` /
`VERIFY_TOOLS` in `agent_bench/run.py`): a tool the bridge advertises
but the arm's profile does not allow is excluded, so a future rts tool
can never silently leak into an arm. Arm C is the only arm whose system
prompt differs — it appends `VERIFY_NUDGE` ("Before asserting a symbol
exists or changing a signature, verify it with the verify_\* tools.").

All arms run against the same:

- Pinned model snapshot ID (never `claude-sonnet-latest`)
- Identical system prompt (SHA-locked across arms)
- Identical retry / backoff policy
- Identical turn cap, token cap, temperature

The **only** difference is the tool surface. So any shift in agent
behavior is attributable to the surface change.

## Metrics

| Metric | Reported as | Status |
|---|---|---|
| **Tool-use ratio** | `count(mcp__rts__*) / count(all tool calls)` per arm, with Wilson-score 95 % CI | Primary (pre-registered) |
| **Task success rate** | Did the agent's patch make the failing tests pass? | Secondary; needs Docker eval (U2.10, deferred) |
| **Wall-clock latency** | Median + p95 of turn-to-completion per arm | Secondary descriptive |

Per the plan ([`docs/plans/2026-05-16-001-...`](../docs/plans/2026-05-16-001-feat-agent-habit-and-benchmark-plan.md))
and best-practices research, at **n = 30 tasks per arm** the
**tool-use ratio is the primary metric**; success + latency are
secondary descriptive. ~25-point delta needed for p<0.05 — results
are reported as **directional**, not significant.

### Statistics (A/B/C)

The reporter (`agent_bench/report.py`) renders a `multi_arm_comparison`
with per-arm success ± Wilson CI, tokens, wall-clock, a per-tool
breakdown (`tool_calls_by_name`), the per-arm verify-metric block, and
**McNemar paired deltas** for the three contrasts **B vs A**, **C vs B**,
**C vs A**. McNemar is implemented by hand (no scipy): the exact
binomial two-sided test for fewer than 25 discordant pairs, else the
continuity-corrected χ²(df=1) via `math.erfc`.

Per-arm edit-quality / hallucination metrics (EVR, BCIR, SHR, IHR; SMR
is approximated as `None` because the file-level `rts verify --json`
surface lacks call-arity data) are computed **offline** by
`agent_bench/eval_verify.py`, feeding each arm's patches through the
`rts verify-edit` / `rts verify` CLI via the `RtsVerifyRunner` boundary.

## Usage

```bash
# One-time: install deps via uv
cd agent-bench && uv sync --dev

# Project token + USD spend for a run BEFORE spending anything (no API
# call). Defaults: Sonnet pricing ($3 in / $15 out per MTok), 3 arms.
uv run agent-bench estimate --tasks 30 --seeds 1 --arms 3 \
    --model claude-sonnet-4-7-20260315
# Opus pricing:
uv run agent-bench estimate --tasks 30 --arms 3 --in-price 15 --out-price 75

# Run a dry-run against a 3-task smoke subset (no API key needed
# if --mock is passed; otherwise uses ANTHROPIC_API_KEY)
uv run agent-bench --mock --tasks smoke

# Full bench, Sonnet default, $100 budget cap:
ANTHROPIC_API_KEY=sk-ant-... uv run agent-bench \
    --tasks corpus/swe-bench-lite-v1.json \
    --model claude-sonnet-4-7-20260315 \
    --budget-usd 100

# Run with Opus for release-gate confidence (more expensive):
ANTHROPIC_API_KEY=sk-ant-... uv run agent-bench \
    --tasks corpus/swe-bench-lite-v1.json \
    --model claude-opus-4-7-20260315 \
    --budget-usd 400
```

## Output

```
bench-results/<version>/
├── control-summary.json     # machine-readable per-task results
├── control-summary.md       # human-readable aggregate
├── treatment-summary.json
├── treatment-summary.md
└── comparison.md            # side-by-side with deltas + Wilson CIs
```

The summary files are **committed to the repo** so the trend across
releases is part of the git history. Raw trajectories (per-task
turn-by-turn JSONL) are NOT committed (volume + privacy of any
embedded API outputs); they're written to `runs/<run-id>/` which is
gitignored.

> **Note:** `estimate` is build-only and makes ZERO API calls. The
> actual A/B/C model run — budget enforcement, per-task isolation,
> resume-from-checkpoint, Docker patch eval, and CI — ships with the
> deferred **PR-B** infrastructure. A cheap smoke corpus
> (`corpus/swe-bench-lite-smoke.json`, 4 real SWE-bench_Lite instance
> ids with placeholder statements) is included for wiring tests.

## What this does NOT do (yet)

- **Docker patch evaluation** — verifying that the agent's patch
  actually makes the failing tests pass. Requires x86_64 Linux (per
  SWE-bench's `swebench` harness requirements); deferred to U2.10.
- **Per-tool latency histograms** — `Daemon.Stats` doesn't surface
  these yet (filed in #104 follow-up).
- **CI nightly cadence** — per-release-tag only, gated on
  `.github/workflows/agent-bench.yml`.

## Architecture

```
agent-bench/
├── agent_bench/
│   ├── mcp_bridge.py   # spawn rts-mcp, JSON-RPC stdio, list_tools, call_tool
│   ├── run.py          # one task → two arms → trajectory
│   ├── isolation.py    # per-task tempdir + per-task daemon socket
│   ├── preflight.py    # cost estimate + budget caps + confound asserts
│   ├── report.py       # tool-use ratio + Wilson CI + Markdown summary
│   └── cli.py          # `agent-bench` entry point
├── corpus/
│   └── swe-bench-lite-v1.json   # curated 30-instance subset
├── prompts/
│   └── system.md       # SHA-locked across arms
└── tests/
    └── test_mcp_bridge.py   # integration test against real rts-mcp
```

See [`agent_bench/mcp_bridge.py`](agent_bench/mcp_bridge.py) — the
single load-bearing component is the bridge that lets Anthropic's
`messages.create(tools=[...])` accept the rts MCP tools alongside
Bash/Read. The bridge mirrors
[`crates/rts-bench/src/mcp_runner.rs`](../crates/rts-bench/src/mcp_runner.rs)
in Python; same JSON-RPC handshake, same `INDEX_NOT_READY` retry
budget, same lifecycle.

## Cost expectations

Per the [research](../docs/plans/2026-05-16-001-feat-agent-habit-and-benchmark-plan.md#risk-analysis--mitigation):

| Configuration | Estimate per full bench run (30 tasks × 2 arms) |
|---|---|
| Sonnet 4 | ~$50-100 |
| Opus 4 | ~$300+ |

Pre-flight estimates `n × mean_tokens × $/Mtok × 2 × 1.5_safety`
before any API call; hard ceiling aborts the run at 90 % consumed.
