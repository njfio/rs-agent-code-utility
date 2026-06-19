"""Tests for the CLI `estimate` projection (verify-v0 P4 U4).

Pure math — projects tokens + USD from a per-task token model and the
CLI args. NO API call. The `estimate_cost` function is the unit under
test; the argparse wiring is smoke-checked via `main`.
"""

from __future__ import annotations

import pytest

from agent_bench.cli import estimate_cost, main


class TestEstimateCost:
    def test_basic_projection(self) -> None:
        # 2 tasks × 2 seeds × 3 arms = 12 runs.
        # Per run: in_tokens=10_000, out_tokens=2_000 (defaults).
        # input cost  = 12 * 10_000  * 3.0  / 1e6 = 0.36
        # output cost = 12 *  2_000  * 15.0 / 1e6 = 0.36
        est = estimate_cost(
            tasks=2,
            seeds=2,
            arms=3,
            in_per_run=10_000,
            out_per_run=2_000,
            in_price=3.0,
            out_price=15.0,
        )
        assert est["runs"] == 12
        assert est["input_tokens"] == 120_000
        assert est["output_tokens"] == 24_000
        assert abs(est["input_usd"] - 0.36) < 1e-9
        assert abs(est["output_usd"] - 0.36) < 1e-9
        assert abs(est["total_usd"] - 0.72) < 1e-9

    def test_scales_with_arms_and_seeds(self) -> None:
        one = estimate_cost(tasks=30, seeds=1, arms=1, in_price=3.0, out_price=15.0)
        three = estimate_cost(tasks=30, seeds=1, arms=3, in_price=3.0, out_price=15.0)
        assert abs(three["total_usd"] - 3 * one["total_usd"]) < 1e-6
        assert three["runs"] == 90

    def test_zero_tasks_is_zero(self) -> None:
        est = estimate_cost(tasks=0, seeds=2, arms=3)
        assert est["runs"] == 0
        assert est["total_usd"] == 0.0


class TestEstimateCli:
    def test_estimate_subcommand_runs_without_api(self, capsys: pytest.CaptureFixture) -> None:
        rc = main(
            [
                "estimate",
                "--tasks",
                "30",
                "--seeds",
                "1",
                "--arms",
                "3",
                "--model",
                "claude-sonnet-4-7-20260315",
            ]
        )
        assert rc == 0
        out = capsys.readouterr().out
        assert "Projected" in out or "projection" in out.lower()
        assert "$" in out
        assert "90" in out  # 30 * 1 * 3 runs

    def test_estimate_respects_price_overrides(
        self, capsys: pytest.CaptureFixture
    ) -> None:
        rc = main(
            [
                "estimate",
                "--tasks",
                "1",
                "--seeds",
                "1",
                "--arms",
                "1",
                "--in-price",
                "0",
                "--out-price",
                "0",
            ]
        )
        assert rc == 0
        out = capsys.readouterr().out
        assert "$0.00" in out
