"""Tests for the `run` + `report` CLI subcommands (U3).

The `run` command: load corpus → PRE-FLIGHT budget gate → per
(task, arm, seed) prepare_task + run_one_arm → write trajectory JSON →
aggregate + verify + render reports. The `report` command re-renders
from existing JSONs with NO client/API.

Everything injectable is faked: FakeAnthropicClient (via client_factory),
FakeRepoProvider, fake daemon, RtsVerifyRunner fake, and a fixed run_id.
ZERO real API / daemon / Docker / network.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from agent_bench.cli import (
    _is_complete_trajectory,
    _render_reports,
    report_command,
    run_command,
)
from agent_bench.run import Task
from tests.conftest import FakeAnthropicClient, FakeMessageResponse

PINNED_MODEL = "claude-sonnet-4-7-20260315"


# --- Fakes --------------------------------------------------------


@dataclass
class FakeRepoProvider:
    tree: dict[str, str] = field(default_factory=lambda: {"README.md": "hi\n"})

    def materialize(self, task: Task, dest: Path) -> None:
        dest.mkdir(parents=True, exist_ok=True)
        for name, content in self.tree.items():
            (dest / name).write_text(content)


@dataclass
class FakeDaemon:
    socket_path: str = "/tmp/fake.sock"

    def start(self, workdir: Path) -> str:
        return self.socket_path

    def stop(self) -> None:
        pass


@dataclass
class FakeVerifyRunner:
    def verify_edit(self, edits: list[dict]) -> dict:
        return {"verdict": "pass", "findings": [], "files": []}

    def verify_file(self, path: str, content: str) -> dict:
        return {"hallucinations": []}


def _submit_client() -> FakeAnthropicClient:
    """A client that immediately submits a patch (one turn)."""
    return FakeAnthropicClient(
        [
            FakeMessageResponse(
                content=[
                    {
                        "type": "tool_use",
                        "id": "t1",
                        "name": "submit_patch",
                        "input": {"patch": "--- a\n+++ b\n@@\n-x\n+y\n"},
                    }
                ]
            )
        ]
    )


@dataclass
class FakeBridge:
    """Minimal McpBridge double — advertises the retrieval tools so
    build_tool_list can compose them, but the agent script never calls
    one (it submits a patch immediately)."""

    closed: int = 0

    def list_tools(self):
        from agent_bench.mcp_bridge import McpToolSchema

        return [
            McpToolSchema(name="find_symbol", description="d", input_schema={"type": "object"}),
            McpToolSchema(name="grep", description="d", input_schema={"type": "object"}),
        ]

    def close(self) -> None:
        self.closed += 1


def _bridge_factory(arm, workspace):
    # Baseline needs no bridge; rts arms get a fake bridge over the workspace.
    if arm == "baseline":
        return None
    return FakeBridge()


def _bridge_factory_none(arm, workspace):
    # Baseline-only paths: no bridge ever needed.
    return None


def _write_corpus(tmp_path: Path, n: int = 2) -> Path:
    rows = [
        {
            "instance_id": f"acme__widget-{i}",
            "repo": "acme/widget",
            "base_commit": "0" * 40,
            "problem_statement": f"Fix bug {i}.",
            "gold_patch": "",
        }
        for i in range(n)
    ]
    p = tmp_path / "corpus.json"
    p.write_text(json.dumps({"name": "test-corpus", "tasks": rows}))
    return p


def _make_args(**overrides):
    import argparse

    ns = argparse.Namespace(
        corpus=None,
        arms="baseline",
        seeds=1,
        model=PINNED_MODEL,
        max_usd=1000.0,
        out=None,
        resume=False,
        limit=None,
    )
    for k, v in overrides.items():
        setattr(ns, k, v)
    return ns


# --- Budget gate --------------------------------------------------


class TestBudgetGate:
    def test_max_usd_zero_aborts_before_any_client_call(
        self, tmp_path: Path, capsys: pytest.CaptureFixture
    ) -> None:
        corpus = _write_corpus(tmp_path, n=2)
        out = tmp_path / "out"
        called = {"made_client": False}

        def boom_factory(model: str):
            called["made_client"] = True
            return _submit_client()

        rc = run_command(
            _make_args(corpus=str(corpus), arms="baseline", out=str(out), max_usd=0.0),
            client_factory=boom_factory,
            repo_provider=FakeRepoProvider(),
            daemon_factory=lambda arm: None,
            bridge_factory=_bridge_factory_none,
            verify_runner=FakeVerifyRunner(),
            run_id="run-test",
        )
        assert rc != 0
        # No client was ever constructed.
        assert called["made_client"] is False
        # No trajectory files were written.
        assert not (out / "runs").exists()
        captured = capsys.readouterr()
        err = (captured.out + captured.err).lower()
        assert "budget" in err or "max-usd" in err or "abort" in err


# --- Happy path: trajectories + report ----------------------------


class TestRunWritesTrajectoriesAndReport:
    def test_two_tasks_two_arms_one_seed(self, tmp_path: Path) -> None:
        corpus = _write_corpus(tmp_path, n=2)
        out = tmp_path / "out"

        rc = run_command(
            _make_args(
                corpus=str(corpus),
                arms="baseline,retrieval",
                seeds=1,
                out=str(out),
                max_usd=1000.0,
            ),
            client_factory=lambda model: _submit_client(),
            repo_provider=FakeRepoProvider(),
            daemon_factory=lambda arm: (FakeDaemon() if arm != "baseline" else None),
            bridge_factory=_bridge_factory,
            verify_runner=FakeVerifyRunner(),
            run_id="run-test",
        )
        assert rc == 0
        raw = out / "runs" / "run-test" / "raw"
        baseline_files = sorted((raw / "baseline").glob("*.json"))
        retrieval_files = sorted((raw / "retrieval").glob("*.json"))
        # 2 tasks × 1 seed per arm = 2 files per arm, 4 total.
        assert len(baseline_files) == 2
        assert len(retrieval_files) == 2
        # File naming carries instance + seed.
        names = {p.name for p in baseline_files}
        assert "acme__widget-0__seed0.json" in names
        # Trajectory JSON is run.ArmTrajectory.to_dict() shape.
        body = json.loads(baseline_files[0].read_text())
        assert body["arm"] == "baseline"
        assert body["halt_reason"] == "submit"
        # A multi-arm report was rendered.
        run_dir = out / "runs" / "run-test"
        assert (run_dir / "comparison.json").is_file() or (
            run_dir / "comparison.md"
        ).is_file()


# --- Resume -------------------------------------------------------


class TestResume:
    def test_resume_skips_completed_tuples(self, tmp_path: Path) -> None:
        corpus = _write_corpus(tmp_path, n=2)
        out = tmp_path / "out"
        raw = out / "runs" / "run-test" / "raw" / "baseline"
        raw.mkdir(parents=True)
        # Pre-seed one completed tuple's trajectory file.
        existing = {
            "task_id": "acme__widget-0",
            "arm": "baseline",
            "model": PINNED_MODEL,
            "messages": [],
            "tool_calls": [],
            "final_patch": "preexisting",
            "halt_reason": "submit",
            "wall_clock_s": 0.0,
            "input_tokens": 0,
            "output_tokens": 0,
        }
        (raw / "acme__widget-0__seed0.json").write_text(json.dumps(existing))

        client_calls = {"n": 0}

        def counting_factory(model: str):
            client_calls["n"] += 1
            return _submit_client()

        rc = run_command(
            _make_args(
                corpus=str(corpus),
                arms="baseline",
                seeds=1,
                out=str(out),
                resume=True,
            ),
            client_factory=counting_factory,
            repo_provider=FakeRepoProvider(),
            daemon_factory=lambda arm: None,
            bridge_factory=_bridge_factory_none,
            verify_runner=FakeVerifyRunner(),
            run_id="run-test",
        )
        assert rc == 0
        # Only the missing task (widget-1) ran → exactly one client built.
        assert client_calls["n"] == 1
        # The pre-existing file is untouched.
        body = json.loads((raw / "acme__widget-0__seed0.json").read_text())
        assert body["final_patch"] == "preexisting"

    def test_resume_reruns_corrupt_trajectory(self, tmp_path: Path) -> None:
        # A truncated/half-written trajectory must NOT be trusted as complete.
        corpus = _write_corpus(tmp_path, n=1)
        out = tmp_path / "out"
        raw = out / "runs" / "run-test" / "raw" / "baseline"
        raw.mkdir(parents=True)
        (raw / "acme__widget-0__seed0.json").write_text('{"task_id": "acme__widget-0"')  # truncated

        client_calls = {"n": 0}

        def counting_factory(model: str):
            client_calls["n"] += 1
            return _submit_client()

        rc = run_command(
            _make_args(
                corpus=str(corpus), arms="baseline", seeds=1, out=str(out), resume=True
            ),
            client_factory=counting_factory,
            repo_provider=FakeRepoProvider(),
            daemon_factory=lambda arm: None,
            bridge_factory=_bridge_factory_none,
            verify_runner=FakeVerifyRunner(),
            run_id="run-test",
        )
        assert rc == 0
        # The corrupt file was re-run (not skipped) → client built once.
        assert client_calls["n"] == 1
        # And overwritten with a valid trajectory.
        json.loads((raw / "acme__widget-0__seed0.json").read_text())


# --- report subcommand (offline) ----------------------------------


class TestReportOffline:
    def test_report_rerenders_from_existing_jsons(self, tmp_path: Path) -> None:
        # First do a run to produce trajectories.
        corpus = _write_corpus(tmp_path, n=2)
        out = tmp_path / "out"
        run_command(
            _make_args(
                corpus=str(corpus),
                arms="baseline,retrieval",
                out=str(out),
            ),
            client_factory=lambda model: _submit_client(),
            repo_provider=FakeRepoProvider(),
            daemon_factory=lambda arm: None,
            bridge_factory=_bridge_factory,
            verify_runner=FakeVerifyRunner(),
            run_id="run-test",
        )
        run_dir = out / "runs" / "run-test"
        # Remove rendered reports to prove report re-creates them.
        for f in run_dir.glob("comparison.*"):
            f.unlink()

        import argparse

        rc = report_command(
            argparse.Namespace(runs=str(run_dir)),
            verify_runner=FakeVerifyRunner(),
        )
        assert rc == 0
        assert (run_dir / "comparison.md").is_file() or (
            run_dir / "comparison.json"
        ).is_file()
        # Success is the submit proxy (no Docker eval), so the comparison MUST
        # be labelled proxy — a reader can't mistake it for real resolved.
        cj = json.loads((run_dir / "comparison.json").read_text())
        assert cj["success_proxy"] is True
        assert "PROXY" in (run_dir / "comparison.md").read_text()


# --- Fix 2: resume validates schema + identity --------------------


def _full_record(
    *, task_id: str, arm: str, model: str, halt_reason: str = "submit"
) -> dict:
    return {
        "task_id": task_id,
        "arm": arm,
        "model": model,
        "messages": [],
        "tool_calls": [],
        "final_patch": "p",
        "halt_reason": halt_reason,
        "wall_clock_s": 0.0,
        "input_tokens": 0,
        "output_tokens": 0,
    }


class TestIsCompleteTrajectory:
    def test_bare_object_is_incomplete(self, tmp_path: Path) -> None:
        p = tmp_path / "t.json"
        p.write_text("{}")
        assert _is_complete_trajectory(
            p, task_id="x", arm="baseline", model=PINNED_MODEL
        ) is False

    def test_partial_object_is_incomplete(self, tmp_path: Path) -> None:
        p = tmp_path / "t.json"
        p.write_text(json.dumps({"task_id": "x"}))
        assert _is_complete_trajectory(
            p, task_id="x", arm="baseline", model=PINNED_MODEL
        ) is False

    def test_wrong_arm_is_incomplete(self, tmp_path: Path) -> None:
        p = tmp_path / "t.json"
        p.write_text(json.dumps(_full_record(task_id="x", arm="retrieval", model=PINNED_MODEL)))
        # Same schema but the arm doesn't match → re-run.
        assert _is_complete_trajectory(
            p, task_id="x", arm="baseline", model=PINNED_MODEL
        ) is False

    def test_wrong_model_is_incomplete(self, tmp_path: Path) -> None:
        p = tmp_path / "t.json"
        p.write_text(json.dumps(_full_record(task_id="x", arm="baseline", model="claude-opus-4-7-20260101")))
        assert _is_complete_trajectory(
            p, task_id="x", arm="baseline", model=PINNED_MODEL
        ) is False

    def test_full_matching_record_is_complete(self, tmp_path: Path) -> None:
        p = tmp_path / "t.json"
        p.write_text(json.dumps(_full_record(task_id="x", arm="baseline", model=PINNED_MODEL)))
        assert _is_complete_trajectory(
            p, task_id="x", arm="baseline", model=PINNED_MODEL
        ) is True


class TestResumeIdentity:
    def test_resume_reruns_mismatched_model_record(self, tmp_path: Path) -> None:
        # A complete-looking file left over from a DIFFERENT model must be
        # re-run, not skipped (it would aggregate stale data).
        corpus = _write_corpus(tmp_path, n=1)
        out = tmp_path / "out"
        raw = out / "runs" / "run-test" / "raw" / "baseline"
        raw.mkdir(parents=True)
        stale = _full_record(
            task_id="acme__widget-0",
            arm="baseline",
            model="claude-opus-4-7-20260101",
        )
        (raw / "acme__widget-0__seed0.json").write_text(json.dumps(stale))

        client_calls = {"n": 0}

        def counting_factory(model: str):
            client_calls["n"] += 1
            return _submit_client()

        rc = run_command(
            _make_args(
                corpus=str(corpus), arms="baseline", seeds=1, out=str(out), resume=True
            ),
            client_factory=counting_factory,
            repo_provider=FakeRepoProvider(),
            daemon_factory=lambda arm: None,
            bridge_factory=_bridge_factory_none,
            verify_runner=FakeVerifyRunner(),
            run_id="run-test",
        )
        assert rc == 0
        # Mismatched-model file was re-run.
        assert client_calls["n"] == 1
        body = json.loads((raw / "acme__widget-0__seed0.json").read_text())
        assert body["model"] == PINNED_MODEL


# --- Fix 3: McNemar pairs by task identity, not vector length -----


def _seed_raw(raw_dir: Path, instance_id: str, seed: int, arm: str, *, submit: bool) -> None:
    raw_dir.mkdir(parents=True, exist_ok=True)
    rec = _full_record(
        task_id=instance_id,
        arm=arm,
        model=PINNED_MODEL,
        halt_reason="submit" if submit else "no_patch",
    )
    (raw_dir / f"{instance_id}__seed{seed}.json").write_text(json.dumps(rec))


class TestMcNemarPairsByIdentity:
    def test_disjoint_task_ids_are_not_spuriously_paired(self, tmp_path: Path) -> None:
        # Two arms, same COUNT (2 each) but DISJOINT task ids. Length-based
        # pairing would emit a bogus contrast; identity pairing must skip it
        # (empty intersection).
        run_dir = tmp_path / "runs" / "r"
        a = run_dir / "raw" / "baseline"
        b = run_dir / "raw" / "retrieval"
        _seed_raw(a, "acme__widget-0", 0, "baseline", submit=True)
        _seed_raw(a, "acme__widget-1", 0, "baseline", submit=True)
        _seed_raw(b, "acme__gadget-0", 0, "retrieval", submit=False)
        _seed_raw(b, "acme__gadget-1", 0, "retrieval", submit=False)

        _render_reports(run_dir, ["baseline", "retrieval"], FakeVerifyRunner())

        cj = json.loads((run_dir / "comparison.json").read_text())
        # No shared task ids → no B_vs_A contrast at all.
        assert "B_vs_A" not in cj["mcnemar"]

    def test_same_ids_different_file_order_pair_by_id(self, tmp_path: Path) -> None:
        # Both arms ran the same two tasks. Arm A: widget-0 submit,
        # widget-1 no-submit. Arm B: BOTH submit. Identity pairing must
        # match widget-0↔widget-0 and widget-1↔widget-1 regardless of the
        # (sorted) filename order.
        run_dir = tmp_path / "runs" / "r"
        a = run_dir / "raw" / "baseline"
        b = run_dir / "raw" / "retrieval"
        _seed_raw(a, "acme__widget-0", 0, "baseline", submit=True)
        _seed_raw(a, "acme__widget-1", 0, "baseline", submit=False)
        _seed_raw(b, "acme__widget-0", 0, "retrieval", submit=True)
        _seed_raw(b, "acme__widget-1", 0, "retrieval", submit=True)

        _render_reports(run_dir, ["baseline", "retrieval"], FakeVerifyRunner())

        cj = json.loads((run_dir / "comparison.json").read_text())
        assert "B_vs_A" in cj["mcnemar"]
        block = cj["mcnemar"]["B_vs_A"]
        # Contrast is (A=baseline, B=retrieval). widget-0: A=T,B=T
        # (concordant). widget-1: A=F,B=T → b01 (a fail, b pass) = 1, b10 = 0.
        # If the tasks were mispaired by order this would be wrong.
        assert block["b01"] == 1
        assert block["b10"] == 0

    def test_partial_overlap_pairs_only_intersection(self, tmp_path: Path) -> None:
        # Arm A ran widget-0,1; arm B ran widget-1,2 (resume with a missing
        # file). Only widget-1 is shared → contrast over exactly 1 pair.
        run_dir = tmp_path / "runs" / "r"
        a = run_dir / "raw" / "baseline"
        b = run_dir / "raw" / "retrieval"
        _seed_raw(a, "acme__widget-0", 0, "baseline", submit=True)
        _seed_raw(a, "acme__widget-1", 0, "baseline", submit=True)
        _seed_raw(b, "acme__widget-1", 0, "retrieval", submit=True)
        _seed_raw(b, "acme__widget-2", 0, "retrieval", submit=True)

        _render_reports(run_dir, ["baseline", "retrieval"], FakeVerifyRunner())

        cj = json.loads((run_dir / "comparison.json").read_text())
        # Only widget-1 is shared, and it's T/T → concordant (b01=b10=0).
        # The contrast is emitted (intersection non-empty) over that 1 pair.
        block = cj["mcnemar"]["B_vs_A"]
        assert block["b01"] == 0 and block["b10"] == 0
