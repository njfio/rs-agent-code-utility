"""Tests for the A/B/C statistics layer (verify-v0 P4 U2).

Covers:
  - per-tool breakdown + verify_tools_total in ArmAggregate
  - the hand-rolled McNemar paired test (exact + corrected, no scipy)
  - the 3-arm comparison report (per-arm CIs + 3 McNemar deltas)

No Anthropic API, no daemon.
"""

from __future__ import annotations

from agent_bench.report import (
    aggregate_arm,
    mcnemar,
    multi_arm_comparison_json,
    multi_arm_comparison_markdown,
)
from agent_bench.run import ArmTrajectory, ToolCall

PINNED_MODEL = "claude-sonnet-4-7-20260315"


def _traj(
    arm: str,
    *,
    names: list[str] | None = None,
    halt_reason: str = "submit",
    task_id: str = "t",
) -> ArmTrajectory:
    traj = ArmTrajectory(task_id=task_id, arm=arm, model=PINNED_MODEL)
    for n in names or []:
        backend = "rts_mcp" if n.startswith("mcp__rts__") else "bash"
        traj.tool_calls.append(
            ToolCall(turn=1, name=n, arguments={}, backend=backend, elapsed_s=0.01)
        )
    traj.halt_reason = halt_reason
    return traj


# --- McNemar -------------------------------------------------------


class TestMcNemar:
    def test_no_discordant_pairs_returns_p1(self) -> None:
        # All pairs concordant: both pass or both fail.
        a = [True, True, False, False]
        b = [True, True, False, False]
        r = mcnemar(a, b)
        assert r["b01"] == 0 and r["b10"] == 0
        assert r["p_value"] == 1.0
        assert r["method"] == "none"

    def test_strongly_discordant_10_0_is_significant(self) -> None:
        # b fixes 10 that a failed, breaks 0: exact two-sided p tiny.
        a = [False] * 10
        b = [True] * 10
        r = mcnemar(a, b)
        assert r["b01"] == 10  # a fail, b pass
        assert r["b10"] == 0
        assert r["method"] == "exact"
        # Exact two-sided p for (10,0), n=10, p=0.5 = 2 * 0.5^10 = 1/512.
        assert abs(r["p_value"] - (2 * 0.5**10)) < 1e-12
        assert r["p_value"] < 0.05

    def test_balanced_5_5_is_p1(self) -> None:
        a = [False] * 5 + [True] * 5
        b = [True] * 5 + [False] * 5
        r = mcnemar(a, b)
        assert r["b01"] == 5 and r["b10"] == 5
        assert r["method"] == "exact"
        assert r["p_value"] == 1.0  # symmetric → max p

    def test_textbook_exact_b01_1_b10_12(self) -> None:
        # Discordant (1, 12), n=13 < 25 → exact binomial two-sided.
        # k=min=1, n=13: two-sided p = 2 * sum_{i=0}^{1} C(13,i) 0.5^13
        #   = 2 * (1 + 13) / 8192 = 28/8192 = 0.00341796875
        a = [False] + [True] * 12
        b = [True] + [False] * 12
        r = mcnemar(a, b)
        assert r["b01"] == 1 and r["b10"] == 12
        assert r["method"] == "exact"
        assert abs(r["p_value"] - 28 / 8192) < 1e-12

    def test_large_discordant_uses_corrected_chi2(self) -> None:
        # n = b01+b10 = 40 ≥ 25 → continuity-corrected chi-square.
        a = [False] * 30 + [True] * 10
        b = [True] * 30 + [False] * 10
        r = mcnemar(a, b)
        assert r["b01"] == 30 and r["b10"] == 10
        assert r["method"] == "chi2_corrected"
        # chi2 = (|30-10|-1)^2 / 40 = 361/40 = 9.025
        assert abs(r["statistic"] - 9.025) < 1e-9
        # p < 0.05 for chi2 ~9.0 on df=1.
        assert r["p_value"] < 0.05

    def test_symmetry_p_a_b_equals_p_b_a(self) -> None:
        a = [False] + [True] * 12 + [False] * 5
        b = [True] + [False] * 12 + [False] * 5
        assert abs(mcnemar(a, b)["p_value"] - mcnemar(b, a)["p_value"]) < 1e-12
        # Also for the corrected branch.
        a2 = [False] * 30 + [True] * 10 + [True] * 3
        b2 = [True] * 30 + [False] * 10 + [True] * 3
        assert abs(mcnemar(a2, b2)["p_value"] - mcnemar(b2, a2)["p_value"]) < 1e-12

    def test_length_mismatch_raises(self) -> None:
        import pytest

        with pytest.raises(ValueError, match="length"):
            mcnemar([True], [True, False])


# --- Per-tool breakdown -------------------------------------------


class TestPerToolBreakdown:
    def test_counts_by_bare_name(self) -> None:
        trajs = [
            _traj(
                "C",
                names=[
                    "mcp__rts__find_symbol",
                    "mcp__rts__find_symbol",
                    "mcp__rts__verify_symbol",
                    "Bash",
                ],
                task_id="a",
            ),
            _traj(
                "C",
                names=["mcp__rts__verify_edit", "mcp__rts__grep"],
                task_id="b",
            ),
        ]
        agg = aggregate_arm("C", trajs)
        assert agg.tool_calls_by_name["find_symbol"] == 2
        assert agg.tool_calls_by_name["verify_symbol"] == 1
        assert agg.tool_calls_by_name["verify_edit"] == 1
        assert agg.tool_calls_by_name["grep"] == 1
        assert agg.tool_calls_by_name["Bash"] == 1
        # verify_* total = verify_symbol + verify_edit = 2
        assert agg.verify_tools_total == 2

    def test_zero_verify_when_none(self) -> None:
        agg = aggregate_arm("A", [_traj("A", names=["Bash", "Bash"])])
        assert agg.verify_tools_total == 0


# --- 3-arm comparison ----------------------------------------------


def _arm(name: str, *, n: int, completed: int) -> object:
    trajs = []
    for i in range(n):
        hr = "submit" if i < completed else "turn_cap"
        trajs.append(
            _traj(name, names=["mcp__rts__find_symbol", "Bash"], halt_reason=hr, task_id=f"{name}-{i}")
        )
    return aggregate_arm(name, trajs)


class TestMultiArmComparison:
    def test_json_includes_three_arms_and_three_deltas(self) -> None:
        a = _arm("A", n=6, completed=2)
        b = _arm("B", n=6, completed=4)
        c = _arm("C", n=6, completed=5)
        paired = {
            "B_vs_A": ([True, False] * 3, [True, True] * 3),
            "C_vs_B": ([True, True] * 3, [True, True] * 3),
            "C_vs_A": ([True, False] * 3, [True, True] * 3),
        }
        verify_metrics = {
            "A": {"evr": None},
            "B": {"evr": None},
            "C": {"evr": 0.8},
        }
        out = multi_arm_comparison_json([a, b, c], paired, verify_metrics)
        assert out["schema"].startswith("agent-bench/")
        assert {arm["arm"] for arm in out["arms"]} == {"A", "B", "C"}
        assert set(out["mcnemar"]) == {"B_vs_A", "C_vs_B", "C_vs_A"}
        for key in ("B_vs_A", "C_vs_B", "C_vs_A"):
            assert "p_value" in out["mcnemar"][key]
        # per-arm verify metric block present
        assert out["arms_by_name"]["C"]["verify_metrics"]["evr"] == 0.8

    def test_markdown_renders_all_arms_and_deltas(self) -> None:
        a = _arm("A", n=4, completed=1)
        b = _arm("B", n=4, completed=2)
        c = _arm("C", n=4, completed=3)
        paired = {
            "B_vs_A": ([False, False, True, True], [True, True, True, True]),
            "C_vs_B": ([True, True, True, True], [True, True, True, True]),
            "C_vs_A": ([False, False, True, True], [True, True, True, True]),
        }
        md = multi_arm_comparison_markdown(
            [a, b, c], paired, {"A": {}, "B": {}, "C": {}}
        )
        assert "A" in md and "B" in md and "C" in md
        assert "McNemar" in md
        assert "B_vs_A" in md or "B vs A" in md
