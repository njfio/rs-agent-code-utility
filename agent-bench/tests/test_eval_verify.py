"""Tests for per-arm verify-metric collection (verify-v0 P4 U3).

`eval_verify.evaluate_arm` feeds each trajectory's final patch through
the rts verify CLI boundary (RtsVerifyRunner) and rolls up EVR / BCIR /
SHR / IHR / SMR per arm. The boundary is a Protocol so tests inject a
FakeRunner with canned JSON — NO daemon, NO subprocess, NO API.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from agent_bench.eval_verify import evaluate_arm
from agent_bench.run import ArmTrajectory

PINNED_MODEL = "claude-sonnet-4-7-20260315"


def _traj(patch: str | None, task_id: str = "t") -> ArmTrajectory:
    traj = ArmTrajectory(task_id=task_id, arm="C", model=PINNED_MODEL)
    traj.final_patch = patch
    traj.halt_reason = "submit" if patch else "no_patch"
    return traj


@dataclass
class FakeRunner:
    """Canned RtsVerifyRunner. Maps a patch string → verify_edit JSON,
    and a file path → verify_file JSON. Records calls for assertions."""

    edit_responses: dict[str, dict[str, Any]] = field(default_factory=dict)
    file_responses: dict[str, dict[str, Any]] = field(default_factory=dict)
    default_edit: dict[str, Any] = field(
        default_factory=lambda: {"verdict": "pass", "findings": []}
    )
    edit_calls: list[list[dict]] = field(default_factory=list)
    file_calls: list[tuple[str, str]] = field(default_factory=list)

    def verify_edit(self, edits: list[dict]) -> dict:
        self.edit_calls.append(edits)
        key = edits[0].get("content", "") if edits else ""
        return self.edit_responses.get(key, self.default_edit)

    def verify_file(self, path: str, content: str) -> dict:
        self.file_calls.append((path, content))
        return self.file_responses.get(path, {"hallucinations": []})


class TestEVRandBCIR:
    def test_clean_patch_evr1_bcir0(self) -> None:
        runner = FakeRunner(
            edit_responses={"clean": {"verdict": "pass", "findings": []}}
        )
        # The patch content the runner keys on is the patch string itself
        # (the impl wraps the patch into a single edit dict {content: patch}).
        trajs = [_traj("clean")]
        out = evaluate_arm(trajs, runner)
        assert out["evr"]["numerator"] == 1
        assert out["evr"]["denominator"] == 1
        assert out["evr"]["rate"] == 1.0
        assert out["bcir"]["numerator"] == 0
        assert out["bcir"]["rate"] == 0.0

    def test_fail_with_broken_caller_evr0_bcir1(self) -> None:
        runner = FakeRunner(
            edit_responses={
                "bad": {
                    "verdict": "fail",
                    "findings": [{"kind": "broken_caller", "symbol": "foo"}],
                }
            }
        )
        out = evaluate_arm([_traj("bad")], runner)
        assert out["evr"]["numerator"] == 0
        assert out["evr"]["rate"] == 0.0
        assert out["bcir"]["numerator"] == 1
        assert out["bcir"]["rate"] == 1.0

    def test_signature_break_counts_for_bcir(self) -> None:
        runner = FakeRunner(
            edit_responses={
                "sig": {
                    "verdict": "warn",
                    "findings": [{"kind": "signature_break"}],
                }
            }
        )
        out = evaluate_arm([_traj("sig")], runner)
        # warn verdict → not a pass → EVR numerator 0.
        assert out["evr"]["numerator"] == 0
        assert out["bcir"]["numerator"] == 1

    def test_mixed_arm_rates(self) -> None:
        runner = FakeRunner(
            edit_responses={
                "p1": {"verdict": "pass", "findings": []},
                "p2": {"verdict": "pass", "findings": []},
                "p3": {
                    "verdict": "fail",
                    "findings": [{"kind": "broken_caller"}],
                },
            }
        )
        trajs = [_traj("p1", "a"), _traj("p2", "b"), _traj("p3", "c")]
        out = evaluate_arm(trajs, runner)
        assert out["evr"]["numerator"] == 2 and out["evr"]["denominator"] == 3
        assert abs(out["evr"]["rate"] - 2 / 3) < 1e-9
        assert out["bcir"]["numerator"] == 1 and out["bcir"]["denominator"] == 3


class TestEmptyPatchHandling:
    def test_none_patch_is_skipped_from_denominator(self) -> None:
        runner = FakeRunner()
        trajs = [_traj("clean", "a"), _traj(None, "b"), _traj("", "c")]
        out = evaluate_arm(trajs, runner)
        # Only the one real patch counts toward EVR/BCIR denominators.
        assert out["evr"]["denominator"] == 1
        assert out["bcir"]["denominator"] == 1
        assert out["skipped_empty_patches"] == 2

    def test_all_empty_yields_none_rate(self) -> None:
        out = evaluate_arm([_traj(None), _traj("")], FakeRunner())
        assert out["evr"]["denominator"] == 0
        assert out["evr"]["rate"] is None
        assert out["bcir"]["rate"] is None


class TestHallucinationMetrics:
    def test_shr_from_verify_file_not_found(self) -> None:
        # verify_edit reports which files it touched; verify_file then
        # returns hallucination refs per file.
        runner = FakeRunner(
            edit_responses={
                "withfile": {
                    "verdict": "pass",
                    "findings": [],
                    "files": ["src/lib.rs"],
                }
            },
            file_responses={
                "src/lib.rs": {
                    "hallucinations": [
                        {"name": "ghost_fn", "kind": "symbol", "resolution": "not_found"},
                        {"name": "real_fn", "kind": "symbol", "resolution": "exact"},
                        {"name": "use foo::bar", "kind": "import", "resolution": "not_found"},
                    ]
                }
            },
        )
        out = evaluate_arm([_traj("withfile")], runner)
        # SHR: 1 not_found / (1 not_found + 1 exact) decidable symbols = 1/2
        assert out["shr"]["numerator"] == 1
        assert out["shr"]["denominator"] == 2
        assert abs(out["shr"]["rate"] - 0.5) < 1e-9
        # IHR: 1 not_found import / 1 decidable = 1.0
        assert out["ihr"]["numerator"] == 1
        assert out["ihr"]["denominator"] == 1
        assert out["ihr"]["rate"] == 1.0

    def test_smr_approximated_as_none(self) -> None:
        # SMR is documented as approximated (call-arity unavailable from
        # the CLI surface) — denominator 0, rate None.
        runner = FakeRunner(
            edit_responses={"x": {"verdict": "pass", "findings": [], "files": []}}
        )
        out = evaluate_arm([_traj("x")], runner)
        assert out["smr"]["denominator"] == 0
        assert out["smr"]["rate"] is None
