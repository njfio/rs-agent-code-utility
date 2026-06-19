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

# Run the A/B/C bench. The PRE-FLIGHT budget gate computes the projected
# spend and ABORTS (nonzero exit) BEFORE constructing any client or
# making any API call if it exceeds --max-usd. A real run needs:
#   - ANTHROPIC_API_KEY in the environment
#   - git on PATH (to clone + checkout each task at base_commit)
#   - the rts-mcp / rts-daemon binaries (for the retrieval / verify arms)
ANTHROPIC_API_KEY=sk-ant-... uv run agent-bench run \
    --corpus corpus/swe-bench-lite-smoke.json \
    --arms baseline,retrieval,retrieval_verify \
    --seeds 1 \
    --model claude-sonnet-4-7-20260315 \
    --max-usd 100 \
    --out bench-results/ \
    [--resume] [--limit N]

# Re-render the reports from an existing run dir — NO API call. Reads the
# stored trajectory JSONs and re-aggregates.
uv run agent-bench report --runs bench-results/runs/<run-id>
```

`--max-usd` is a **hard pre-flight gate**: `run` calls `estimate_cost`
for `tasks × seeds × arms` and, if the projection exceeds the cap, prints
an `ABORT:` line and exits nonzero **before any Anthropic client is
constructed**. `--resume` skips any `(task, arm, seed)` tuple whose
trajectory file already exists on disk, so an interrupted run picks up
where it left off without re-paying for completed work.

## Output

```
<out>/runs/<run-id>/
├── raw/<arm>/<instance_id>__seed<seed>.json   # per-run ArmTrajectory.to_dict()
├── <arm>-summary.json                         # machine-readable per-arm
├── <arm>-summary.md                           # human-readable per-arm
├── comparison.json                            # A/B/C multi-arm payload
└── comparison.md                              # A/B/C side-by-side + McNemar
```

The trajectory file name encodes the `(instance_id, seed)` tuple so
`--resume` can detect completed runs and the reporter can re-aggregate
offline. The summary files can be **committed to the repo** so the trend
across releases lives in git history; raw trajectories are large and may
embed API output, so keep `runs/` gitignored if that's a concern.

> **Note:** `estimate` and `report` make ZERO API calls. `run` is
> **build-only** in this milestone: the harness runs **end-to-end with a
> fake client** (see `tests/test_cli_run.py`), and a real run is gated on
> a budget (`--max-usd`) plus the live infrastructure below. A cheap
> smoke corpus (`corpus/swe-bench-lite-smoke.json`, 4 real SWE-bench_Lite
> instance ids with placeholder statements) is included for wiring tests.

### What a REAL run needs

- `ANTHROPIC_API_KEY` in the environment (the agent loop hits the API).
- `git` on PATH — `GitRepoProvider` clones each task's repo and checks
  out `base_commit` into an isolated per-task tempdir.
- The `rts-mcp` / `rts-daemon` binaries for the `retrieval` /
  `retrieval_verify` arms (the `baseline` arm needs neither).
- **Docker + x86_64 + the `swebench` harness + multi-GB per-repo images**
  for *real* task success (FAIL_TO_PASS resolution via
  `eval_docker.evaluate_patches`). Without Docker results, success falls
  back to a `halt_reason == "submit"` **proxy**, labelled as such in the
  report.

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
│   ├── run.py          # one task → one arm → trajectory
│   ├── isolation.py    # per-task tempdir + per-task daemon socket (boundaries)
│   ├── corpus.py       # load Task records from JSON or a dataset id (boundary)
│   ├── eval_verify.py  # offline EVR/BCIR/SHR/IHR via the rts verify CLI boundary
│   ├── eval_docker.py  # swebench-in-Docker patch eval + success vectors (boundary)
│   ├── report.py       # tool-use ratio + Wilson CI + McNemar + Markdown
│   └── cli.py          # `agent-bench` entry point: estimate / run / report
├── corpus/
│   └── swe-bench-lite-smoke.json   # cheap smoke subset for wiring tests
└── tests/
    └── test_mcp_bridge.py   # integration test against real rts-mcp
```

Every external boundary is a `Protocol` injected into the code under
test, so the suite runs with **zero** real model / API / daemon / Docker
/ network:

| Boundary | Real implementation | Test fake |
|---|---|---|
| `run.AnthropicClient` | `anthropic.Anthropic` | `FakeAnthropicClient` |
| `isolation.RepoProvider` | `GitRepoProvider` (git clone + checkout) | `FakeRepoProvider` (fixture tree) |
| `isolation.DaemonHandle` | `RtsDaemonHandle` (spawn rts-daemon) | fake socket path |
| `corpus.CorpusLoader` | `HuggingFaceLoader` | `FakeLoader` (canned rows) |
| `eval_verify.RtsVerifyRunner` | `CliRtsVerifyRunner` (`rts verify`) | `FakeRunner` |
| `eval_docker.PatchEvalRunner` | swebench-in-Docker | `FakePatchEvalRunner` |

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
