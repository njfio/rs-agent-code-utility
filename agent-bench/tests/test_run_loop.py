"""Tests for the agent run loop and reporter.

Uses FakeAnthropicClient so we don't spend API credits validating
dispatch logic. The mcp_bridge integration test (test_mcp_bridge.py)
already covers the real-MCP path; this file is about the loop
shape, confound asserts, attribution counts, and the reporter's
Wilson-CI math.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from agent_bench.report import (
    aggregate_arm,
    comparison_markdown,
    wilson_ci,
    write_arm_outputs,
    write_comparison,
)
from agent_bench.run import (
    ArmConfig,
    ArmTrajectory,
    RunConfig,
    Task,
    run_one_arm,
    tool_use_ratio,
)
from tests.conftest import FakeAnthropicClient, FakeMessageResponse

PINNED_MODEL = "claude-sonnet-4-7-20260315"


# --- RunConfig confound assertions --------------------------------


class TestRunConfigConfounds:
    """Confound controls fire at config-construction time."""

    def test_pinned_snapshot_id_accepted(self) -> None:
        RunConfig(model=PINNED_MODEL, system_prompt="x")  # no raise

    def test_latest_alias_rejected(self) -> None:
        with pytest.raises(ValueError, match="pinned snapshot id"):
            RunConfig(model="claude-sonnet-latest", system_prompt="x")

    def test_bare_family_rejected(self) -> None:
        with pytest.raises(ValueError, match="pinned snapshot id"):
            RunConfig(model="claude-sonnet-4", system_prompt="x")

    def test_unrecognized_family_rejected(self) -> None:
        with pytest.raises(ValueError, match="pinned snapshot id"):
            RunConfig(model="gpt-4-turbo-20240409", system_prompt="x")


# --- Helpers ------------------------------------------------------


def make_task(tmp_path: Path, *, repo_files: dict[str, str] | None = None) -> Task:
    """Build a Task fixture with a tempdir repo_dir and optional files."""
    repo_dir = tmp_path / "task_repo"
    repo_dir.mkdir()
    for name, content in (repo_files or {}).items():
        (repo_dir / name).write_text(content)
    return Task(
        instance_id="test/inst-1",
        repo="test/repo",
        base_commit="0" * 40,
        problem_statement="Fix the broken thing.",
        repo_dir=repo_dir,
    )


# --- Loop dispatch ------------------------------------------------


class TestRunOneArm:
    def test_submit_patch_halts_loop_with_patch_recorded(self, tmp_path: Path) -> None:
        client = FakeAnthropicClient(
            [
                FakeMessageResponse(
                    content=[
                        {"type": "text", "text": "Here is my fix."},
                        {
                            "type": "tool_use",
                            "id": "t1",
                            "name": "submit_patch",
                            "input": {"patch": "--- a\n+++ b\n@@\n-x\n+y\n"},
                        },
                    ]
                )
            ]
        )
        traj = run_one_arm(
            client=client,
            task=make_task(tmp_path),
            arm=ArmConfig(arm="control", include_rts_tools=False),
            config=RunConfig(model=PINNED_MODEL, system_prompt="be helpful"),
        )
        assert traj.halt_reason == "submit"
        assert traj.final_patch is not None and traj.final_patch.startswith("--- a")
        assert len(traj.tool_calls) == 1
        assert traj.tool_calls[0].backend == "submit"

    def test_bash_dispatches_locally_and_logs_call(self, tmp_path: Path) -> None:
        """Bash tool_use lands in `_run_bash` and the call is attributed."""
        task = make_task(tmp_path, repo_files={"hello.txt": "hi\n"})
        client = FakeAnthropicClient(
            [
                FakeMessageResponse(
                    content=[
                        {
                            "type": "tool_use",
                            "id": "t1",
                            "name": "Bash",
                            "input": {"command": "ls"},
                        },
                    ]
                ),
                FakeMessageResponse(
                    content=[
                        {
                            "type": "tool_use",
                            "id": "t2",
                            "name": "submit_patch",
                            "input": {"patch": "ok"},
                        },
                    ]
                ),
            ]
        )
        traj = run_one_arm(
            client=client,
            task=task,
            arm=ArmConfig(arm="control", include_rts_tools=False),
            config=RunConfig(model=PINNED_MODEL, system_prompt="x"),
        )
        # The Bash + submit calls each got logged.
        backends = [tc.backend for tc in traj.tool_calls]
        assert backends == ["bash", "submit"]
        # The model saw the tool_result for the bash call in turn 2.
        # The second client.create() call's `messages` list must end
        # with a tool_result user message.
        turn2 = client.calls[1]["messages"][-1]
        assert turn2["role"] == "user"
        assert isinstance(turn2["content"], list)
        assert turn2["content"][0]["type"] == "tool_result"
        # hello.txt should appear in the bash output.
        result_text = turn2["content"][0]["content"][0]["text"]
        assert "hello.txt" in result_text

    def test_read_dispatches_locally(self, tmp_path: Path) -> None:
        task = make_task(tmp_path, repo_files={"a.txt": "alpha\nbeta\n"})
        client = FakeAnthropicClient(
            [
                FakeMessageResponse(
                    content=[
                        {
                            "type": "tool_use",
                            "id": "t1",
                            "name": "Read",
                            "input": {"file_path": "a.txt"},
                        },
                    ]
                ),
                FakeMessageResponse(
                    content=[
                        {
                            "type": "tool_use",
                            "id": "t2",
                            "name": "submit_patch",
                            "input": {"patch": "ok"},
                        },
                    ]
                ),
            ]
        )
        traj = run_one_arm(
            client=client,
            task=task,
            arm=ArmConfig(arm="control", include_rts_tools=False),
            config=RunConfig(model=PINNED_MODEL, system_prompt="x"),
        )
        assert [tc.backend for tc in traj.tool_calls] == ["read", "submit"]
        # Verify the content reached the model.
        turn2_result = client.calls[1]["messages"][-1]["content"][0]["content"][0]["text"]
        assert "alpha" in turn2_result and "beta" in turn2_result

    def test_turn_cap_halts_with_reason(self, tmp_path: Path) -> None:
        """Agent that loops without submitting hits the turn cap."""
        # Script: every turn, the agent issues a `Bash` call that
        # doesn't submit. Loop should halt at max_turns=3.
        script = [
            FakeMessageResponse(
                content=[
                    {
                        "type": "tool_use",
                        "id": f"t{i}",
                        "name": "Bash",
                        "input": {"command": "true"},
                    },
                ]
            )
            for i in range(3)
        ]
        client = FakeAnthropicClient(script)
        traj = run_one_arm(
            client=client,
            task=make_task(tmp_path),
            arm=ArmConfig(arm="control", include_rts_tools=False),
            config=RunConfig(
                model=PINNED_MODEL, system_prompt="x", max_turns=3
            ),
        )
        assert traj.halt_reason == "turn_cap"
        assert traj.final_patch is None
        assert len(traj.tool_calls) == 3

    def test_no_tool_use_halts_with_no_patch(self, tmp_path: Path) -> None:
        """Agent that just emits text (no tool calls) halts immediately."""
        client = FakeAnthropicClient(
            [
                FakeMessageResponse(
                    content=[{"type": "text", "text": "I don't know how."}]
                )
            ]
        )
        traj = run_one_arm(
            client=client,
            task=make_task(tmp_path),
            arm=ArmConfig(arm="control", include_rts_tools=False),
            config=RunConfig(model=PINNED_MODEL, system_prompt="x"),
        )
        assert traj.halt_reason == "no_patch"

    def test_api_error_halted_cleanly(self, tmp_path: Path) -> None:
        """When the SDK raises, the loop records `api_error: ...`
        instead of bubbling."""

        class BoomClient:
            def create(self, **_: object) -> object:
                raise RuntimeError("rate-limited")

        traj = run_one_arm(
            client=BoomClient(),
            task=make_task(tmp_path),
            arm=ArmConfig(arm="control", include_rts_tools=False),
            config=RunConfig(model=PINNED_MODEL, system_prompt="x"),
        )
        assert traj.halt_reason.startswith("api_error")
        assert "rate-limited" in traj.halt_reason

    def test_treatment_arm_requires_bridge(self, tmp_path: Path) -> None:
        """Calling run_one_arm with include_rts_tools=True but no
        bridge is a programming error — fail loudly."""
        client = FakeAnthropicClient(
            [FakeMessageResponse(content=[])]
        )
        with pytest.raises(ValueError, match="requires an MCP bridge"):
            run_one_arm(
                client=client,
                task=make_task(tmp_path),
                arm=ArmConfig(arm="treatment", include_rts_tools=True),
                config=RunConfig(model=PINNED_MODEL, system_prompt="x"),
                bridge=None,
            )


# --- Confound: same prompt/model/temperature across arms ----------


def test_messages_create_kwargs_match_config(tmp_path: Path) -> None:
    """The loop must hand the configured model/temperature/system to
    every messages.create call, unmodified."""
    client = FakeAnthropicClient(
        [
            FakeMessageResponse(
                content=[
                    {
                        "type": "tool_use",
                        "id": "t1",
                        "name": "submit_patch",
                        "input": {"patch": "x"},
                    }
                ]
            )
        ]
    )
    config = RunConfig(
        model=PINNED_MODEL,
        system_prompt="EXACT-PROMPT-SHA",
        temperature=0.0,
    )
    run_one_arm(
        client=client,
        task=make_task(tmp_path),
        arm=ArmConfig(arm="control", include_rts_tools=False),
        config=config,
    )
    assert client.calls[0]["model"] == PINNED_MODEL
    assert client.calls[0]["system"] == "EXACT-PROMPT-SHA"
    assert client.calls[0]["temperature"] == 0.0


# --- Reporter: Wilson CI math -------------------------------------


class TestWilsonCI:
    def test_zero_n_returns_max_uncertainty(self) -> None:
        ci = wilson_ci(0, 0)
        assert ci.p == 0.0
        assert ci.lo == 0.0
        assert ci.hi == 1.0

    def test_unanimous_low(self) -> None:
        """0/30 successes: point is 0, CI lower bound is 0, upper is small."""
        ci = wilson_ci(0, 30)
        assert ci.p == 0.0
        assert ci.lo == 0.0
        assert 0.05 < ci.hi < 0.20  # ~0.11 for Wilson

    def test_unanimous_high(self) -> None:
        ci = wilson_ci(30, 30)
        assert ci.p == 1.0
        assert ci.lo > 0.80
        assert ci.hi == 1.0

    def test_midpoint(self) -> None:
        """15/30 = 50%. CI should straddle that."""
        ci = wilson_ci(15, 30)
        assert ci.p == 0.5
        assert ci.lo < 0.5 < ci.hi
        # Sanity: width is reasonable at n=30.
        assert (ci.hi - ci.lo) < 0.40


# --- Reporter: aggregation + formatting ---------------------------


_TRAJ_COUNTER = 0


def _fake_trajectory(
    arm: str,
    *,
    rts: int = 0,
    bash: int = 0,
    read: int = 0,
    submit: bool = True,
    halt_reason: str = "submit",
    wall_clock_s: float = 1.0,
    task_id: str | None = None,
) -> ArmTrajectory:
    from agent_bench.run import ToolCall

    global _TRAJ_COUNTER
    _TRAJ_COUNTER += 1
    tid = task_id or f"task-{arm}-{_TRAJ_COUNTER:04d}"
    traj = ArmTrajectory(
        task_id=tid,
        arm=arm,
        model=PINNED_MODEL,
    )
    for _ in range(rts):
        traj.tool_calls.append(
            ToolCall(turn=1, name="mcp__rts__find_symbol", arguments={},
                     backend="rts_mcp", elapsed_s=0.01)
        )
    for _ in range(bash):
        traj.tool_calls.append(
            ToolCall(turn=1, name="Bash", arguments={},
                     backend="bash", elapsed_s=0.01)
        )
    for _ in range(read):
        traj.tool_calls.append(
            ToolCall(turn=1, name="Read", arguments={},
                     backend="read", elapsed_s=0.01)
        )
    if submit:
        traj.tool_calls.append(
            ToolCall(turn=2, name="submit_patch", arguments={},
                     backend="submit", elapsed_s=0.01)
        )
        traj.final_patch = "fake"
    traj.halt_reason = halt_reason
    traj.wall_clock_s = wall_clock_s
    traj.input_tokens = 1000
    traj.output_tokens = 500
    return traj


def test_aggregate_counts_per_backend() -> None:
    trajs = [
        _fake_trajectory("control", bash=5, read=2),
        _fake_trajectory("control", bash=3, read=1),
    ]
    agg = aggregate_arm("control", trajs)
    assert agg.n_tasks == 2
    assert agg.n_completed == 2
    assert agg.bash_tool_calls == 8
    assert agg.read_tool_calls == 3
    assert agg.rts_tool_calls == 0
    assert agg.submit_tool_calls == 2  # one per traj
    # Tool-use ratio: rts/searchable = 0/(8+3+0) = 0%.
    ci = agg.tool_use_ratio_ci()
    assert ci.p == 0.0
    assert ci.n == 11


def test_aggregate_rejects_mixed_model_snapshots() -> None:
    """A bench arm that ran some tasks on Sonnet and some on Opus
    is invalid — the harness must catch that before aggregation."""
    a = _fake_trajectory("control", bash=1)
    b = _fake_trajectory("control", bash=1)
    b.model = "claude-opus-4-7-20260315"  # contaminate
    with pytest.raises(ValueError, match="model snapshots"):
        aggregate_arm("control", [a, b])


def test_comparison_markdown_shows_delta(tmp_path: Path) -> None:
    """A treatment arm with all rts vs a control arm with all bash
    produces a +100pp delta in the comparison."""
    control_trajs = [_fake_trajectory("control", bash=10) for _ in range(5)]
    treatment_trajs = [_fake_trajectory("treatment", rts=10) for _ in range(5)]
    control_agg = aggregate_arm("control", control_trajs)
    treatment_agg = aggregate_arm("treatment", treatment_trajs)
    md = comparison_markdown(control_agg, treatment_agg)
    assert "Delta**: +100.0pp" in md or "Delta**: +100pp" in md
    assert "control" in md and "treatment" in md


def test_write_arm_outputs_creates_files(tmp_path: Path) -> None:
    trajs = [_fake_trajectory("control", bash=3, read=1) for _ in range(2)]
    agg = write_arm_outputs(tmp_path, "control", trajs)
    assert (tmp_path / "control-summary.json").is_file()
    assert (tmp_path / "control-summary.md").is_file()
    # Raw trajectories also dumped.
    raw_files = list((tmp_path / "raw" / "control").glob("*.json"))
    assert len(raw_files) == 2
    # And aggregate is returned.
    assert agg.n_tasks == 2


def test_write_comparison_creates_file(tmp_path: Path) -> None:
    c = aggregate_arm(
        "control", [_fake_trajectory("control", bash=5) for _ in range(3)]
    )
    t = aggregate_arm(
        "treatment",
        [_fake_trajectory("treatment", rts=3, bash=2) for _ in range(3)],
    )
    path = write_comparison(tmp_path, c, t)
    assert path.is_file()
    text = path.read_text()
    assert "Delta" in text
    assert PINNED_MODEL in text


# --- Tool-use ratio helper ----------------------------------------


def test_tool_use_ratio_zero_when_no_calls() -> None:
    traj = _fake_trajectory("control", submit=False)
    assert tool_use_ratio(traj) == 0.0


def test_tool_use_ratio_includes_submit_in_denominator() -> None:
    """submit is a tool call but doesn't count toward the rts ratio
    at the reporter level. Per-traj `tool_use_ratio` is a quick
    smoke check; the reporter-side `tool_use_ratio_ci` is the
    authoritative number (excludes submit)."""
    traj = _fake_trajectory("treatment", rts=1, bash=1, submit=True)
    # 1 rts / (1 rts + 1 bash + 1 submit) = 0.333 (per-traj)
    assert abs(tool_use_ratio(traj) - 0.333) < 0.01
