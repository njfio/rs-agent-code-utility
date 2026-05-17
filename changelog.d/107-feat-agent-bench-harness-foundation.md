### `agent-bench/` — Phase 2 PR-A: SWE-bench-lite A/B harness foundation

Foundational scaffold for the agent-bench harness planned in [`docs/plans/2026-05-16-001-feat-agent-habit-and-benchmark-plan.md`](../docs/plans/2026-05-16-001-feat-agent-habit-and-benchmark-plan.md). Phase 2 of the agent-habit work that #106 (PreToolUse hook + project-local `.mcp.json`) opened.

**Why split Phase 2 across two PRs**: PR-A (this one) ships the harness skeleton + bridge + run loop + reporter + mock-API test suite — provable end-to-end without an Anthropic API key. PR-B will add per-task isolation, cost guardrails, resume-from-checkpoint, the curated 30-task SWE-bench-lite subset, the GitHub Actions workflow, and the first real-money baseline run. Splitting keeps each PR scoped to one concern per `AGENTS.md` Rule 24 and lets a contributor review the harness architecture independently of the bench-run plumbing.

#### What's in PR-A

New top-level **`agent-bench/`** directory (Python; **NOT** inside `rts-bench` Rust crate, because `AGENTS.md:377-381` forbids HTTP code paths in the daemon/MCP build trees — CI asserts this via `cargo tree`):

```
agent-bench/
├── pyproject.toml         # uv-managed; anthropic, datasets, tenacity, numpy, rich
├── .python-version        # 3.11 pinned
├── README.md              # what it does, how to use, cost expectations
├── agent_bench/
│   ├── mcp_bridge.py      # spawn rts-mcp, JSON-RPC stdio, list_tools, call_tool
│   ├── run.py             # one-task one-arm Anthropic agent loop
│   ├── report.py          # Wilson-CI tool-use ratio + Markdown comparison
│   └── cli.py             # entry point (PR-A surface: --status only)
└── tests/
    ├── test_mcp_bridge.py # 5 integration tests against real rts-mcp
    └── test_run_loop.py   # 23 unit/integration tests with FakeAnthropicClient
```

#### Key decisions

- **Raw Anthropic SDK + custom MCP-stdio bridge**, NOT the Anthropic Agent SDK. The Agent SDK abstracts the turn loop; agent-bench's *whole point* is precise per-turn measurement (tool counts, attribution by name prefix, retry policy, snapshot pinning). Owning the loop is the feature, not a workaround.
- **Bridge mirrors `crates/rts-bench/src/mcp_runner.rs`** in Python — same JSON-RPC handshake, same `INDEX_NOT_READY` retry budget (30 × 120ms), same lifecycle. Reusing a known-good shape avoids re-litigating already-decided protocol-v0 plumbing.
- **Confound asserts at `RunConfig` construction**: model must match `^claude-(sonnet|opus|haiku)-\d+-\d+-\d{8}$` (a pinned snapshot id; `claude-sonnet-latest` is silently invalid). System prompt SHA-locked across arms by the harness; temperature pinned (Sonnet 0.0, Opus omits — per litellm #26444).
- **Bash + Read + `submit_patch` in both arms**, plus `mcp__rts__*` only in treatment. The `submit_patch` shape is borrowed from mini-swe-agent: the agent ends the loop by calling it with a unified diff. The harness considers anything else as still-working.
- **Tool-use attribution via Anthropic message-log scan** (canonical per best-practices research), not `Daemon.Stats` deltas — the latter under-counts when the model re-reads cached results from earlier turns.
- **Wilson-score 95% CI for the primary metric** (tool-use ratio). At n=30 per arm, a Wilson delta needs ≈25pp to reach p<0.05 — results will be reported as **directional**, not significant. Pre-registered in the comparison.md template that PR-A's reporter emits.

#### Deferred to PR-B

| Unit | What it adds |
|---|---|
| U2.5 | Per-task isolation (per-task `rts-daemon` socket; hook activation per arm; tempdir-cloned repo at `base_commit`) |
| U2.6 | Pre-flight cost estimate + hard `--budget-usd` ceiling with abort-clean-on-overrun |
| U2.7 | Resume-from-checkpoint via `preds.json` (kill at task 27/60 → restart skips 1-26) |
| U2.9 | Curated 30-task SWE-bench-lite subset committed to `corpus/swe-bench-lite-v1.json` |
| U2.10 | Docker patch-validation eval (x86_64 Linux only; deferred per plan Risk #1) |
| U2.11 | `.github/workflows/agent-bench.yml` (workflow_dispatch + on-tag) |
| U2.12 | First baseline run + commit `bench-results/v0.5.8-baseline.{json,md}` |

#### Verification

```
$ cd agent-bench && uv sync --dev && uv run pytest
28 passed in 0.48s
```

Breakdown:
- **5 MCP-bridge integration tests** against real `rts-mcp` + `rts-daemon` release binaries: spawn lifecycle, `tools/list` schema conversion, `find_symbol` round-trip on a seeded workspace (cold mount in <200ms!), unknown-name graceful error, message-log attribution helper.
- **4 confound-assert tests**: pinned snapshot id required, `latest` aliases rejected, family-without-snapshot rejected, foreign model families rejected.
- **6 run-loop dispatch tests**: `submit_patch` ends loop, Bash dispatches locally + logs call, Read dispatches locally, turn-cap halt, no-tool-use halt, API error halt clean.
- **1 confound-data test**: every `messages.create` call receives the exact model / system / temperature from config (the SHA-lock check).
- **4 Wilson-CI math tests**: n=0 max-uncertainty, unanimous-low (0/30), unanimous-high (30/30), midpoint (15/30).
- **5 reporter aggregation tests**: per-backend counts, mixed-model rejection, comparison Markdown delta, file output paths, tool-use ratio at task level.
- **3 boundary tests**: treatment requires bridge, tool-use ratio with zero calls, ratio includes submit in per-traj denominator.

CLI works:
```
$ uv run agent-bench --status
agent-bench 0.1.0 — SWE-bench-lite A/B harness for the rts MCP surface
...
Shipped:
  ✓ U2.1 ... U2.8
Deferred to PR-B:
  ✗ U2.5 ... U2.12
```

No Rust changes; `cargo test -p rts-mcp --release` not re-run (PR-A doesn't touch any Rust code).

#### Out of scope (filed for follow-up, beyond PR-B)

- **Agent-bench live invocation in CI** — currently the `--status` command is the only safe surface; the real `run` subcommand only ships in PR-B alongside the cost guardrails.
- **Multi-model A/B/C** — PR-A's `RunConfig.model` is a single string; running e.g. Sonnet 4 + Opus 4 + Haiku 4 in the same bench is a future shape.
- **External-corpus selection beyond SWE-bench-lite** — researcher-quality benchmarks like SWE-bench-verified or LiveBench. Bigger commitment + bigger spend; revisit after PR-B's baseline.

#### One observation worth noting

Phase 2's harness ended up materially smaller than the plan estimated (~3-5 person-days for the whole phase). That's because U2.3's bridge could mirror `crates/rts-bench/src/mcp_runner.rs` line-for-line in Python (per plan's "Patterns to follow"), and U2.8's reporter is a couple hundred LOC of Wilson-CI math + Markdown templating. The deferred PR-B units (per-task isolation + cost guardrails + Docker eval + CI) are where the real complexity lives — that estimate stands.
