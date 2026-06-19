"""Tests for Docker patch evaluation + success vectors (U4).

`evaluate_patches` runs each trajectory's final patch through the
`PatchEvalRunner` boundary (real = swebench-in-Docker FAIL_TO_PASS; test
= a `FakePatchEvalRunner` with canned resolutions). `task_success_vector`
turns a result map into a per-task success vector — or, when no Docker
results exist, falls back to a `halt_reason == "submit"` PROXY flagged
`proxy=True`.

NO Docker, NO swebench, NO network in this suite.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from agent_bench.eval_docker import (
    PatchEvalRunner,
    evaluate_patches,
    task_success_vector,
)
from agent_bench.run import ArmTrajectory

PINNED_MODEL = "claude-sonnet-4-7-20260315"


def _traj(task_id: str, patch: str | None, halt: str = "submit") -> ArmTrajectory:
    t = ArmTrajectory(task_id=task_id, arm="A", model=PINNED_MODEL)
    t.final_patch = patch
    t.halt_reason = halt
    return t


@dataclass
class FakePatchEvalRunner:
    """Canned PatchEvalRunner. Maps instance_id → resolved bool."""

    resolved: dict[str, bool] = field(default_factory=dict)
    calls: list[str] = field(default_factory=list)

    def evaluate(self, instance_id: str, patch: str) -> dict:
        self.calls.append(instance_id)
        return {"instance_id": instance_id, "resolved": self.resolved.get(instance_id, False)}


class TestEvaluatePatches:
    def test_fake_runner_drives_resolution_map(self) -> None:
        trajs = [_traj("a", "patch-a"), _traj("b", "patch-b")]
        runner = FakePatchEvalRunner(resolved={"a": True, "b": False})
        results = evaluate_patches(trajs, runner)
        assert results["a"]["resolved"] is True
        assert results["b"]["resolved"] is False
        assert runner.calls == ["a", "b"]

    def test_empty_patch_is_unresolved_without_calling_runner(self) -> None:
        trajs = [_traj("a", None, halt="no_patch")]
        runner = FakePatchEvalRunner(resolved={"a": True})
        results = evaluate_patches(trajs, runner)
        # No patch → cannot resolve; runner not invoked for it.
        assert results["a"]["resolved"] is False
        assert runner.calls == []


class TestSuccessVector:
    def test_real_results_drive_success_no_proxy(self) -> None:
        trajs = [_traj("a", "p"), _traj("b", "p"), _traj("c", "p")]
        results = {
            "a": {"resolved": True},
            "b": {"resolved": False},
            "c": {"resolved": True},
        }
        vec, proxy = task_success_vector(trajs, results)
        assert vec == [True, False, True]
        assert proxy is False

    def test_none_results_fall_back_to_submit_proxy(self) -> None:
        trajs = [
            _traj("a", "p", halt="submit"),
            _traj("b", None, halt="no_patch"),
            _traj("c", "p", halt="turn_cap"),
        ]
        vec, proxy = task_success_vector(trajs, None)
        # Proxy: success iff halt_reason == "submit".
        assert vec == [True, False, False]
        assert proxy is True

    def test_proxy_flag_labels_the_vector(self) -> None:
        trajs = [_traj("a", "p", halt="submit")]
        _, proxy_real = task_success_vector(trajs, {"a": {"resolved": True}})
        _, proxy_fallback = task_success_vector(trajs, None)
        assert proxy_real is False
        assert proxy_fallback is True


def test_patch_eval_runner_protocol_importable() -> None:
    assert PatchEvalRunner is not None
