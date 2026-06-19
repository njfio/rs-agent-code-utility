"""Reporter — converts per-task ArmTrajectory records into the
agent-bench's two output artifacts:

  bench-results/<version>/<arm>-summary.json   (machine-readable)
  bench-results/<version>/<arm>-summary.md     (human-readable)

Plus a `comparison.md` that puts the two arms side-by-side with
deltas + Wilson-score CIs for the primary metric (tool-use ratio).

Why Wilson-score and not normal-approximation: at n ≤ 50 the
normal CI for a proportion gets the bounds wrong (can go negative
or above 1.0 near the extremes). Wilson is bounded and well-defined
for small n. Per best-practices research: "at n=30, tool-use-ratio
should be reported with Wilson CI; results are directional, not
significant" (origin: brainstorm Decision #6).

This module has no Anthropic API surface — pure data → format.
"""

from __future__ import annotations

import json
import math
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .mcp_bridge import RTS_TOOL_PREFIX
from .run import ArmTrajectory, count_tool_uses_by_backend


@dataclass
class WilsonCI:
    """Wilson-score 95% CI for a binomial proportion."""

    p: float  # point estimate
    lo: float  # lower bound
    hi: float  # upper bound
    n: int  # sample size

    def fmt(self) -> str:
        """Compact `p% [lo%, hi%] n=N` for Markdown tables."""
        return f"{self.p * 100:.1f}% [{self.lo * 100:.1f}, {self.hi * 100:.1f}] n={self.n}"


def wilson_ci(successes: int, n: int, z: float = 1.96) -> WilsonCI:
    """Wilson-score interval for `successes` out of `n`. z=1.96 → 95%.

    Per https://en.wikipedia.org/wiki/Binomial_proportion_confidence_interval#Wilson_score_interval

    At n=0 returns (0, 0, 1) — the maximally uncertain interval — so
    the reporter doesn't crash on an arm with zero tool calls.
    """
    if n == 0:
        return WilsonCI(p=0.0, lo=0.0, hi=1.0, n=0)

    phat = successes / n
    denominator = 1 + z**2 / n
    center = (phat + z**2 / (2 * n)) / denominator
    half = (z * math.sqrt(phat * (1 - phat) / n + z**2 / (4 * n**2))) / denominator
    return WilsonCI(p=phat, lo=max(0.0, center - half), hi=min(1.0, center + half), n=n)


# --- McNemar paired test ------------------------------------------
#
# McNemar's test compares two paired binary classifiers (here: two arms
# run on the SAME tasks, success=True/False per task). Only the
# DISCORDANT pairs matter:
#   b01 = a fail, b pass   (b "fixed" what a got wrong)
#   b10 = a pass, b fail   (b "broke" what a got right)
# Concordant pairs (both pass / both fail) carry no signal.
#
# Method selection (documented threshold):
#   - b01+b10 == 0          → no discordant pairs, p = 1.0, method "none"
#   - b01+b10 <  25         → EXACT binomial two-sided test (n small;
#                             the chi-square approximation is unreliable)
#   - b01+b10 >= 25         → continuity-corrected chi-square
#                             (Edwards' correction), df=1
# We implement everything by hand (no scipy): the exact tail via the
# binomial PMF summed directly, and the chi-square df=1 survival
# function via math.erfc (chi2 df=1 == squared standard normal, so
# P(X > x) = erfc(sqrt(x/2))).

EXACT_MCNEMAR_THRESHOLD = 25


def _binom_two_sided_p(k: int, n: int) -> float:
    """Two-sided exact binomial p for k successes in n trials at p=0.5.

    Sums the tail at the more-extreme-or-equal side and doubles it,
    clamped to 1.0 — the standard two-sided exact McNemar p when the
    null is symmetric (p=0.5). Computed by summing the binomial PMF
    directly; no scipy.
    """
    if n == 0:
        return 1.0
    # Distance of k from the mean n/2; sum both tails at >= that distance.
    kk = min(k, n - k)

    def pmf(i: int) -> float:
        return math.comb(n, i) * (0.5**n)

    tail = sum(pmf(i) for i in range(kk + 1))
    return min(1.0, 2.0 * tail)


def _chi2_df1_sf(x: float) -> float:
    """Survival function P(X > x) for a chi-square with df=1.

    A chi-square(df=1) variate is the square of a standard normal, so
    P(X > x) = P(|Z| > sqrt(x)) = erfc(sqrt(x/2)). Pure stdlib.
    """
    if x <= 0:
        return 1.0
    return math.erfc(math.sqrt(x / 2.0))


def mcnemar(a: list[bool], b: list[bool]) -> dict[str, Any]:
    """McNemar paired test over two arms' per-task success vectors.

    `a` and `b` are equal-length lists of booleans (True = task
    succeeded for that arm). Returns the discordant counts, the test
    statistic, the two-sided p-value, and which method produced it.
    Symmetric in (a, b): swapping the arguments swaps b01/b10 but
    leaves the p-value unchanged.
    """
    if len(a) != len(b):
        raise ValueError(
            f"mcnemar: a and b must be the same length (got {len(a)} vs {len(b)})"
        )
    b01 = sum(1 for ai, bi in zip(a, b, strict=True) if (not ai) and bi)  # a fail, b pass
    b10 = sum(1 for ai, bi in zip(a, b, strict=True) if ai and (not bi))  # a pass, b fail
    n = b01 + b10

    if n == 0:
        return {"b01": 0, "b10": 0, "statistic": 0.0, "p_value": 1.0, "method": "none"}

    if n < EXACT_MCNEMAR_THRESHOLD:
        p = _binom_two_sided_p(min(b01, b10), n)
        return {
            "b01": b01,
            "b10": b10,
            "statistic": float(min(b01, b10)),
            "p_value": p,
            "method": "exact",
        }

    chi2 = (abs(b01 - b10) - 1) ** 2 / n
    return {
        "b01": b01,
        "b10": b10,
        "statistic": chi2,
        "p_value": _chi2_df1_sf(chi2),
        "method": "chi2_corrected",
    }


@dataclass
class ArmAggregate:
    """One arm's roll-up across all tasks."""

    arm: str
    model: str
    n_tasks: int
    n_completed: int  # halt_reason == "submit"
    n_turncap: int
    n_tokencap: int
    n_error: int

    total_tool_calls: int
    rts_tool_calls: int
    bash_tool_calls: int
    read_tool_calls: int
    submit_tool_calls: int

    # Wall-clock per task: median + p95 (in seconds).
    median_wall_clock_s: float
    p95_wall_clock_s: float

    total_input_tokens: int
    total_output_tokens: int

    # Per-tool breakdown, keyed by bare tool name (rts prefix stripped;
    # local Bash/Read/submit_patch kept as-is). Summed across all tasks.
    tool_calls_by_name: dict[str, int] = field(default_factory=dict)
    # Total verify_* tool calls (names starting with "verify_").
    verify_tools_total: int = 0

    def tool_use_ratio_ci(self) -> WilsonCI:
        """Tool-use ratio = rts_mcp / (all tool calls).

        Excludes `submit_patch` (always 0 or 1, not relevant to the
        "which search tool did the agent use?" question we're
        measuring).
        """
        searchable = self.total_tool_calls - self.submit_tool_calls
        return wilson_ci(self.rts_tool_calls, searchable)

    def success_rate_ci(self) -> WilsonCI:
        """Task success rate. Currently 'agent emitted submit_patch';
        Docker-verified success deferred to U2.10."""
        return wilson_ci(self.n_completed, self.n_tasks)


def aggregate_arm(arm: str, trajectories: list[ArmTrajectory]) -> ArmAggregate:
    """Roll up per-task trajectories into one arm-level summary."""
    if not trajectories:
        raise ValueError(f"aggregate_arm({arm!r}) given empty trajectories")

    model_set = {t.model for t in trajectories}
    if len(model_set) > 1:
        raise ValueError(
            f"trajectories span multiple model snapshots: {model_set}. "
            "Confound control: all tasks in one arm must use the same snapshot id."
        )
    model = next(iter(model_set))

    n_tasks = len(trajectories)
    n_completed = sum(1 for t in trajectories if t.halt_reason == "submit")
    n_turncap = sum(1 for t in trajectories if t.halt_reason == "turn_cap")
    n_tokencap = sum(1 for t in trajectories if t.halt_reason == "token_cap")
    n_error = sum(
        1
        for t in trajectories
        if t.halt_reason.startswith("api_error") or t.halt_reason == "no_patch"
    )

    total_tc = 0
    rts_tc = bash_tc = read_tc = submit_tc = 0
    by_name: dict[str, int] = {}
    verify_total = 0
    for traj in trajectories:
        c = count_tool_uses_by_backend(traj)
        total_tc += sum(c.values())
        rts_tc += c.get("rts_mcp", 0)
        bash_tc += c.get("bash", 0)
        read_tc += c.get("read", 0)
        submit_tc += c.get("submit", 0)
        # Per-tool breakdown: strip the rts prefix so verify_* /
        # find_symbol show up by bare name; verify_total counts the
        # anti-hallucination tools.
        for tc in traj.tool_calls:
            bare = (
                tc.name[len(RTS_TOOL_PREFIX):]
                if tc.name.startswith(RTS_TOOL_PREFIX)
                else tc.name
            )
            by_name[bare] = by_name.get(bare, 0) + 1
            if bare.startswith("verify_"):
                verify_total += 1

    wall_times = sorted(t.wall_clock_s for t in trajectories)
    median = wall_times[len(wall_times) // 2] if wall_times else 0.0
    p95 = wall_times[min(len(wall_times) - 1, int(len(wall_times) * 0.95))] if wall_times else 0.0

    return ArmAggregate(
        arm=arm,
        model=model,
        n_tasks=n_tasks,
        n_completed=n_completed,
        n_turncap=n_turncap,
        n_tokencap=n_tokencap,
        n_error=n_error,
        total_tool_calls=total_tc,
        rts_tool_calls=rts_tc,
        bash_tool_calls=bash_tc,
        read_tool_calls=read_tc,
        submit_tool_calls=submit_tc,
        median_wall_clock_s=median,
        p95_wall_clock_s=p95,
        total_input_tokens=sum(t.input_tokens for t in trajectories),
        total_output_tokens=sum(t.output_tokens for t in trajectories),
        tool_calls_by_name=by_name,
        verify_tools_total=verify_total,
    )


# --- Serialization ----------------------------------------------------


def arm_summary_json(agg: ArmAggregate) -> dict[str, Any]:
    """Machine-readable arm summary. Schema-versioned so future
    formats can be parsed alongside historical ones."""
    tur = agg.tool_use_ratio_ci()
    suc = agg.success_rate_ci()
    return {
        "schema": "agent-bench/v1",
        "arm": agg.arm,
        "model": agg.model,
        "tasks": {
            "n": agg.n_tasks,
            "completed": agg.n_completed,
            "turn_cap_hit": agg.n_turncap,
            "token_cap_hit": agg.n_tokencap,
            "errored": agg.n_error,
        },
        "tool_calls": {
            "total": agg.total_tool_calls,
            "rts_mcp": agg.rts_tool_calls,
            "bash": agg.bash_tool_calls,
            "read": agg.read_tool_calls,
            "submit": agg.submit_tool_calls,
        },
        "metrics": {
            "tool_use_ratio": {
                "point": tur.p,
                "ci_low": tur.lo,
                "ci_high": tur.hi,
                "n": tur.n,
                "note": "Wilson-score 95% CI. Primary metric.",
            },
            "task_success_rate": {
                "point": suc.p,
                "ci_low": suc.lo,
                "ci_high": suc.hi,
                "n": suc.n,
                "note": (
                    "Currently 'agent emitted submit_patch'. "
                    "Docker-verified success deferred to U2.10."
                ),
            },
            "wall_clock_s": {
                "median": agg.median_wall_clock_s,
                "p95": agg.p95_wall_clock_s,
            },
        },
        "tokens": {
            "input": agg.total_input_tokens,
            "output": agg.total_output_tokens,
        },
    }


def arm_summary_markdown(agg: ArmAggregate) -> str:
    """Human-readable arm summary."""
    tur = agg.tool_use_ratio_ci()
    suc = agg.success_rate_ci()
    lines = [
        f"# agent-bench arm summary — {agg.arm}",
        "",
        f"- **Model**: `{agg.model}`",
        f"- **Tasks**: {agg.n_tasks} ({agg.n_completed} completed, "
        f"{agg.n_turncap} turn-cap, {agg.n_tokencap} token-cap, {agg.n_error} errored)",
        "",
        "## Primary metric — tool-use ratio",
        "",
        f"**{tur.fmt()}**",
        "",
        f"Of {agg.total_tool_calls - agg.submit_tool_calls} non-submit tool calls "
        f"across {agg.n_tasks} tasks:",
        "",
        f"- `mcp__rts__*`: {agg.rts_tool_calls}",
        f"- `Bash`: {agg.bash_tool_calls}",
        f"- `Read`: {agg.read_tool_calls}",
        "",
        "## Secondary descriptive",
        "",
        f"- **Task success rate** (submit_patch emitted): {suc.fmt()}",
        f"- **Wall-clock per task**: median {agg.median_wall_clock_s:.1f}s, "
        f"p95 {agg.p95_wall_clock_s:.1f}s",
        f"- **Tokens**: {agg.total_input_tokens:,} input, "
        f"{agg.total_output_tokens:,} output",
        "",
    ]
    return "\n".join(lines)


def comparison_markdown(
    control: ArmAggregate,
    treatment: ArmAggregate,
) -> str:
    """Side-by-side control vs treatment with deltas + CIs."""
    c_tur = control.tool_use_ratio_ci()
    t_tur = treatment.tool_use_ratio_ci()
    c_suc = control.success_rate_ci()
    t_suc = treatment.success_rate_ci()

    delta_tur = (t_tur.p - c_tur.p) * 100  # pp
    delta_suc = (t_suc.p - c_suc.p) * 100  # pp

    lines = [
        "# agent-bench A/B comparison",
        "",
        f"- **Model**: `{control.model}` (both arms — confound asserted)",
        f"- **Tasks**: {control.n_tasks}",
        "",
        "## Tool-use ratio (primary; Wilson 95% CI)",
        "",
        "| Arm       | rts/total       | Ratio                      |",
        "|-----------|-----------------|----------------------------|",
        f"| control   | {control.rts_tool_calls}/"
        f"{control.total_tool_calls - control.submit_tool_calls} "
        f"| {c_tur.fmt()} |",
        f"| treatment | {treatment.rts_tool_calls}/"
        f"{treatment.total_tool_calls - treatment.submit_tool_calls} "
        f"| {t_tur.fmt()} |",
        "",
        f"**Delta**: {delta_tur:+.1f}pp",
        "",
        "> At n=30 per arm, a Wilson-score CI delta needs ≈25pp to be "
        "statistically significant. Smaller deltas are directional — "
        "useful for trend-tracking across releases, not for declaring "
        "the hook 'works'.",
        "",
        "## Task success (secondary descriptive — Docker eval deferred)",
        "",
        "| Arm       | completed     | Ratio        |",
        "|-----------|---------------|--------------|",
        f"| control   | {control.n_completed}/{control.n_tasks} "
        f"| {c_suc.fmt()} |",
        f"| treatment | {treatment.n_completed}/{treatment.n_tasks} "
        f"| {t_suc.fmt()} |",
        "",
        f"**Delta**: {delta_suc:+.1f}pp",
        "",
        "## Wall-clock per task",
        "",
        "| Arm       | median   | p95    |",
        "|-----------|----------|--------|",
        f"| control   | {control.median_wall_clock_s:.1f}s "
        f"| {control.p95_wall_clock_s:.1f}s |",
        f"| treatment | {treatment.median_wall_clock_s:.1f}s "
        f"| {treatment.p95_wall_clock_s:.1f}s |",
        "",
        "## Token spend",
        "",
        "| Arm       | input         | output       |",
        "|-----------|---------------|--------------|",
        f"| control   | {control.total_input_tokens:,} "
        f"| {control.total_output_tokens:,} |",
        f"| treatment | {treatment.total_input_tokens:,} "
        f"| {treatment.total_output_tokens:,} |",
        "",
    ]
    return "\n".join(lines)


# --- 3-arm (A/B/C) comparison -------------------------------------

MULTI_ARM_SCHEMA = "agent-bench/multi-arm/v1"

# The three paired contrasts we always render for an A/B/C bench.
_MULTI_ARM_DELTAS = ("B_vs_A", "C_vs_B", "C_vs_A")


def multi_arm_comparison_json(
    aggregates: list[ArmAggregate],
    paired_success: dict[str, tuple[list[bool], list[bool]]],
    verify_metrics: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    """Schema-versioned A/B/C comparison payload.

    - `aggregates`: per-arm rollups (any order).
    - `paired_success`: maps each contrast key in {"B_vs_A","C_vs_B",
      "C_vs_A"} to a `(a_success, b_success)` tuple of equal-length
      per-task booleans (the McNemar inputs).
    - `verify_metrics`: maps arm name → that arm's verify-metric block
      (from `eval_verify.evaluate_arm`); attached per arm.
    """
    arms_payload: list[dict[str, Any]] = []
    arms_by_name: dict[str, dict[str, Any]] = {}
    for agg in aggregates:
        tur = agg.tool_use_ratio_ci()
        suc = agg.success_rate_ci()
        entry = {
            "arm": agg.arm,
            "model": agg.model,
            "n_tasks": agg.n_tasks,
            "success_rate": {
                "point": suc.p,
                "ci_low": suc.lo,
                "ci_high": suc.hi,
                "n": suc.n,
            },
            "tool_use_ratio": {
                "point": tur.p,
                "ci_low": tur.lo,
                "ci_high": tur.hi,
                "n": tur.n,
            },
            "tokens": {
                "input": agg.total_input_tokens,
                "output": agg.total_output_tokens,
            },
            "wall_clock_s": {
                "median": agg.median_wall_clock_s,
                "p95": agg.p95_wall_clock_s,
            },
            "tool_calls_by_name": dict(sorted(agg.tool_calls_by_name.items())),
            "verify_tools_total": agg.verify_tools_total,
            "verify_metrics": verify_metrics.get(agg.arm, {}),
        }
        arms_payload.append(entry)
        arms_by_name[agg.arm] = entry

    mcnemar_block: dict[str, Any] = {}
    for key in _MULTI_ARM_DELTAS:
        if key not in paired_success:
            continue
        av, bv = paired_success[key]
        mcnemar_block[key] = mcnemar(av, bv)

    return {
        "schema": MULTI_ARM_SCHEMA,
        "arms": arms_payload,
        "arms_by_name": arms_by_name,
        "mcnemar": mcnemar_block,
    }


def multi_arm_comparison_markdown(
    aggregates: list[ArmAggregate],
    paired_success: dict[str, tuple[list[bool], list[bool]]],
    verify_metrics: dict[str, dict[str, Any]],
) -> str:
    """Human-readable A/B/C comparison."""
    payload = multi_arm_comparison_json(aggregates, paired_success, verify_metrics)
    lines = [
        "# agent-bench A/B/C comparison",
        "",
        "## Per-arm summary (Wilson 95% CI)",
        "",
        "| Arm | Success | Tool-use ratio | Verify calls | Tokens (in/out) | Wall median/p95 |",
        "|-----|---------|----------------|--------------|-----------------|-----------------|",
    ]
    for arm in payload["arms"]:
        suc = arm["success_rate"]
        tur = arm["tool_use_ratio"]
        lines.append(
            f"| {arm['arm']} "
            f"| {suc['point'] * 100:.1f}% [{suc['ci_low'] * 100:.1f}, {suc['ci_high'] * 100:.1f}] "
            f"| {tur['point'] * 100:.1f}% [{tur['ci_low'] * 100:.1f}, {tur['ci_high'] * 100:.1f}] "
            f"| {arm['verify_tools_total']} "
            f"| {arm['tokens']['input']:,}/{arm['tokens']['output']:,} "
            f"| {arm['wall_clock_s']['median']:.1f}s/{arm['wall_clock_s']['p95']:.1f}s |"
        )

    lines += [
        "",
        "## Verify metrics (per arm)",
        "",
    ]
    for arm in payload["arms"]:
        vm = arm["verify_metrics"] or {}
        lines.append(f"- **{arm['arm']}**: {vm if vm else '(none)'}")

    lines += [
        "",
        "## Per-tool breakdown",
        "",
    ]
    for arm in payload["arms"]:
        breakdown = arm["tool_calls_by_name"]
        rendered = ", ".join(f"{k}={v}" for k, v in breakdown.items()) or "(none)"
        lines.append(f"- **{arm['arm']}**: {rendered}")

    lines += [
        "",
        "## McNemar deltas (paired task success)",
        "",
        "| Contrast | b01 (a✗→b✓) | b10 (a✓→b✗) | statistic | p-value | method |",
        "|----------|-------------|-------------|-----------|---------|--------|",
    ]
    for key in _MULTI_ARM_DELTAS:
        m = payload["mcnemar"].get(key)
        if m is None:
            continue
        lines.append(
            f"| {key} | {m['b01']} | {m['b10']} "
            f"| {m['statistic']:.3f} | {m['p_value']:.4f} | {m['method']} |"
        )
    lines.append("")
    return "\n".join(lines)


# --- Filesystem ---------------------------------------------------


def write_arm_outputs(
    output_dir: Path,
    arm: str,
    trajectories: list[ArmTrajectory],
) -> ArmAggregate:
    """Aggregate + write both JSON and Markdown for one arm.

    Also dumps each trajectory's full message log to
    `output_dir/raw/<arm>/<task_id>.json` so the reporter can be
    re-run on stored data without re-paying API costs.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    raw_dir = output_dir / "raw" / arm
    raw_dir.mkdir(parents=True, exist_ok=True)
    for traj in trajectories:
        (raw_dir / f"{traj.task_id}.json").write_text(
            json.dumps(traj.to_dict(), indent=2)
        )

    agg = aggregate_arm(arm, trajectories)
    (output_dir / f"{arm}-summary.json").write_text(
        json.dumps(arm_summary_json(agg), indent=2)
    )
    (output_dir / f"{arm}-summary.md").write_text(arm_summary_markdown(agg))
    return agg


def write_comparison(
    output_dir: Path,
    control: ArmAggregate,
    treatment: ArmAggregate,
) -> Path:
    """Write the side-by-side comparison Markdown. Returns its path."""
    path = output_dir / "comparison.md"
    path.write_text(comparison_markdown(control, treatment))
    return path
