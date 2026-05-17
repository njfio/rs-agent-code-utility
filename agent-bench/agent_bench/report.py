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
from dataclasses import dataclass
from pathlib import Path
from typing import Any

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
    for traj in trajectories:
        c = count_tool_uses_by_backend(traj)
        total_tc += sum(c.values())
        rts_tc += c.get("rts_mcp", 0)
        bash_tc += c.get("bash", 0)
        read_tc += c.get("read", 0)
        submit_tc += c.get("submit", 0)

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
