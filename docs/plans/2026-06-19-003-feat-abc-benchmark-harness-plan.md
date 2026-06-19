---
title: "feat: A/B/C verification benchmark harness (verify-v0 P4, build-only)"
type: feat
status: draft
date: 2026-06-19
origin: docs/plans/2026-06-18-001-feat-verification-anti-hallucination-layer-plan.md
---

# feat: A/B/C verification benchmark harness (verify-v0 P4)

**Goal:** Make `agent-bench` able to run the paired **A/B/C** benchmark — A (baseline: bash+read), B (rts *retrieval* tools), C (retrieval **+** the `verify_*` tools wired into the loop) — and report task success + tokens + the SHR/SMR/IHR/BCIR/EVR metrics per arm with statistical rigor (mean±95% CI, McNemar paired test). **This plan is BUILD-ONLY**: it ships the harness extensions + tests with NO live model calls; the actual benchmark run is a separate, budget-gated step (see Cost).

## Why build-only
P4's headline is *measured numbers*, which require real model API runs over SWE-bench-lite (and Docker patch eval). That spends real budget and depends on infra the harness still defers (the corpus, per-task isolation, Docker eval — agent-bench PR-B). So this plan lands the pieces that make an eventual run produce the *correct A/B/C comparison*, all unit-tested against the existing `FakeAnthropicClient`/pytest mocks, and reports a cost estimate so the run can be authorized deliberately.

## Grounding (from exploration)
agent-bench (Python, PR-A shipped): `run.py` (`run_one_arm`, `ArmConfig{arm, include_rts_tools}`, `build_tool_list` ~267), `mcp_bridge.py` (`list_tools` returns ALL rts tools — verify_* included), `report.py` (`ArmAggregate`, `aggregate_arm`, `wilson_ci`, `arm_summary_*`/`comparison_markdown`), `tests/` (`FakeAnthropicClient`, 28 mock tests). **Gaps:** Arm B can't be retrieval-only (no tool profile); no per-tool breakdown; no McNemar; no per-arm verify-metric collection; corpus/Docker eval/cost-cap deferred (PR-B).

---

## Implementation Units (all build-only, pytest-mocked)

### U1 — Arm tool profiles (make A/B/C distinct)
**Files:** `agent_bench/run.py` (`ArmConfig`, `build_tool_list`), `tests/test_run_loop.py`.

Replace the boolean `include_rts_tools` with a **tool profile** so the three arms expose genuinely different surfaces:
- `ToolProfile.Baseline` → bash + read + submit_patch only (Arm A).
- `ToolProfile.Retrieval` → + the rts **retrieval** tools only: `find_symbol`, `grep`, `read_symbol`, `read_symbol_at`, `read_range`, `outline_workspace`, `find_callers`, `impact_of` (Arm B).
- `ToolProfile.RetrievalVerify` → Retrieval **+** the verify tools: `verify_symbol`, `verify_signature`, `verify_import`, `verify_claims`, `verify_impact`, `verify_edit` (Arm C).

`build_tool_list` filters `bridge.list_tools()` by the profile's allowlist (an explicit frozenset of `mcp__rts__*` names, so a newly-added rts tool can't silently leak into an arm). Keep `include_rts_tools` as a derived shim for back-compat if cheap. Arm C also gets a **verify nudge** appended to its system prompt ("before asserting a symbol exists or editing a signature, verify it") so "verify wired into the loop" is real, not just tool availability. **Tests:** each profile yields exactly its tool set; an unknown rts tool name is excluded from Baseline/Retrieval; Arm C's system prompt carries the verify nudge.

### U2 — Statistics: per-tool breakdown, McNemar, 3-arm comparison
**Files:** `agent_bench/report.py`, `tests/test_report.py` (or extend `test_run_loop.py`).

- **Per-tool breakdown:** `ArmAggregate.tool_calls_by_name: dict[str,int]` + `verify_tools_total`, computed in `aggregate_arm` from `ToolCall.name`/`backend`. Surfaces "did arm C actually *use* verify_*".
- **McNemar paired test** (pure, no scipy dep — implement the exact/continuity-corrected formula): `mcnemar(a_success: list[bool], b_success: list[bool]) -> {b01, b10, statistic, p_value}` over the **paired per-task** success vectors. Use the continuity-corrected χ² for discordant counts ≥ ~25, exact binomial otherwise; document the rule. Return p=1.0 when no discordant pairs.
- **3-arm comparison report:** generalize `comparison_markdown` to A/B/C — per-arm success-rate ± Wilson CI, tokens/$/wall-clock, the per-arm verify-metric block (from U3), and the paired McNemar deltas (B vs A, C vs B, C vs A). Schema-versioned JSON + markdown.
- **Tests:** McNemar against hand-computed fixtures (discordant 10/0 → significant; 5/5 → p=1; 0/0 → p=1; a known textbook 2×2); per-tool breakdown counts; the 3-arm report renders all arms + deltas.

### U3 — Per-arm verify-metric collection (`eval_verify.py`)
**Files:** new `agent_bench/eval_verify.py`, `tests/test_eval_verify.py`.

Post-run (offline, no model), feed each arm's produced code through the rts verify surface to compute the §5 metrics PER ARM:
- From each `ArmTrajectory.final_patch` (+ the touched files' post-edit content), call `rts verify-edit --json` → **EVR** (verdict `pass`) and **BCIR** (≥1 `broken_caller`/`signature_break`).
- Extract the patch's symbol/import references (reuse `rts-bench verify`'s pipeline via the CLI, or `rts verify --json` on the post-edit files) → **SHR / IHR / SMR** per arm.
- Aggregate with honest denominators (exclude `indeterminate`), mirroring `rts-bench`'s `HallucinationReport` conventions.
Define a thin `RtsVerifyRunner` boundary (invokes the `rts`/`rts-bench` CLI) so tests inject a **fake runner** with canned JSON — no daemon, no model. **Tests:** a trajectory with a known breaking patch → EVR 0, BCIR 1; a clean patch → EVR 1, BCIR 0; SHR from canned not_found counts; empty/`None` patch handled.

### U4 — Wiring + a tiny pinned smoke corpus + docs
**Files:** `agent_bench/cli.py` (wire `report` over an arms list incl. C; a `--dry-run`/`--estimate` cost mode that needs no API), `corpus/swe-bench-lite-smoke.json` (3–5 hand-pinned public SWE-bench-lite instance ids — for a cheap smoke run, not the full set), `agent-bench/README.md` + root changelog.

- A **pre-flight cost estimate** (`agent_bench estimate --tasks N --seeds S --arms 3 --model <id>`) prints projected tokens + $ from the per-task token model — **no API call**. This is the gate the user reads before authorizing a run.
- Document the run procedure + that A/B/C requires the deferred PR-B infra (corpus, isolation, Docker eval) to produce task-success numbers; the harness + metrics + stats are ready now.

---

## Cost estimate (for the eventual run — NOT spent by this plan)
Per task per arm (SWE-bench-lite, 20-turn cap, rts arms use less context): ~30–120k input + 8–20k output tokens. For **3 arms**:
- **Pilot** (N=30 tasks, S=1 seed, Sonnet 4.x): ~270 task-runs ≈ **$30–60**.
- **Publishable** (N=300, S=3, Sonnet): ~2,700 runs ≈ **$1,000–1,800**.
- Opus ≈ 4–5× the above.
- The post-run verify-metric pass (U3) is offline CLI work — negligible $ (no model).
A pre-flight `estimate` (U4) prints the figure for the exact run before any spend.

## Acceptance criteria
- Three distinct arm profiles; A/B/C tool surfaces verified by tests; Arm C carries the verify nudge.
- McNemar implemented + tested against hand-computed fixtures; per-tool breakdown + 3-arm comparison render.
- `eval_verify` computes per-arm EVR/BCIR/SHR/IHR/SMR from trajectories via an injectable runner; tested with fakes.
- `agent_bench estimate` prints a token/$ projection with no API call.
- `uv run pytest` green; **zero live model calls in the test suite.**

## Deferred (needs budget / infra, NOT this plan)
- The actual benchmark RUN + the published numbers (budget-gated).
- The full curated SWE-bench-lite corpus, per-task isolation, Docker patch eval, CI cadence (agent-bench PR-B / U2.5–U2.12).

## Requirements trace
| Spec § | Covered by |
| :-- | :-- |
| §7 arms A/B/C | U1 (tool profiles) |
| §7 metrics per arm (success/tokens + SHR/SMR/IHR/BCIR/EVR) | U2 (success/tokens/breakdown) + U3 (verify metrics) |
| §7 statistical rigor (CI, McNemar) | U2 |
| §7 the RUN + headline numbers | DEFERRED (budget-gated; `estimate` gates it) |
