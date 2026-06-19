"""Docker patch evaluation + the task-success notion (U4).

Real success = "did the agent's patch make the failing tests pass?",
which SWE-bench answers by applying the patch in a per-instance Docker
image and checking the `FAIL_TO_PASS` set. That path needs **Docker +
x86_64 + the `swebench` harness + multi-GB per-repo images**, so it is
reached ONLY through the `PatchEvalRunner` boundary (a Protocol). Tests
inject a `FakePatchEvalRunner` with canned resolutions — NO Docker, NO
swebench, NO network in the suite.

`task_success_vector` turns the result map into a per-task boolean
vector for the success-rate ± Wilson CI and the McNemar contrasts. When
no Docker results exist (the common build-only / CI-light case), it
falls back to a PROXY: success iff `halt_reason == "submit"`, flagged
`proxy=True` so the reporter can label the number as a proxy rather than
a real resolution.
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

from .run import ArmTrajectory


@runtime_checkable
class PatchEvalRunner(Protocol):
    """Boundary over swebench-in-Docker patch evaluation.

    `evaluate(instance_id, patch)` applies `patch` to the instance's
    base image, runs the test suite, and returns a result dict with at
    least `{"resolved": bool}` (True iff the FAIL_TO_PASS set now passes
    and PASS_TO_PASS did not regress).

    Real implementation drives the `swebench` harness (Docker, x86_64,
    multi-GB images). The test fake returns canned resolutions.
    """

    def evaluate(self, instance_id: str, patch: str) -> dict: ...


def evaluate_patches(
    trajectories: list[ArmTrajectory],
    runner: PatchEvalRunner,
) -> dict[str, dict[str, Any]]:
    """Evaluate each trajectory's final patch via the runner boundary.

    Returns a map `instance_id -> result dict`. A trajectory with no
    final patch is recorded `{"resolved": False}` WITHOUT invoking the
    runner (nothing to apply — Docker is expensive, so skip it).
    """
    results: dict[str, dict[str, Any]] = {}
    for traj in trajectories:
        patch = traj.final_patch
        if not patch:
            results[traj.task_id] = {"instance_id": traj.task_id, "resolved": False}
            continue
        results[traj.task_id] = runner.evaluate(traj.task_id, patch)
    return results


def task_success_vector(
    trajectories: list[ArmTrajectory],
    results: dict[str, dict[str, Any]] | None,
) -> tuple[list[bool], bool]:
    """Per-task success vector + a `proxy` flag.

    - `results` given (real Docker eval): success[i] = results[task]'s
      `resolved`, missing instances treated as unresolved. `proxy=False`.
    - `results` None: PROXY fallback — success[i] = (halt_reason ==
      "submit"). `proxy=True` so the caller labels it as a proxy.

    The vector is aligned to `trajectories` order, so it pairs directly
    with another arm's vector for McNemar.
    """
    if results is None:
        return ([t.halt_reason == "submit" for t in trajectories], True)
    vec = [bool(results.get(t.task_id, {}).get("resolved", False)) for t in trajectories]
    return (vec, False)
