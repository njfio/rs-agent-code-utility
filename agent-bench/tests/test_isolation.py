"""Tests for per-task isolation (U1).

`prepare_task` is a context manager that materializes a task's repo at
`base_commit` (via the RepoProvider boundary) into a guaranteed-cleaned
tempdir, and — for arms that need rts tools — spins up a per-task daemon
(via the DaemonHandle boundary) on a private socket.

Both boundaries are Protocols so tests inject fakes: NO git clone, NO
daemon spawn, NO network, NO Docker.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import pytest

from agent_bench.isolation import (
    DaemonHandle,
    RepoProvider,
    TaskWorkspace,
    prepare_task,
)
from agent_bench.run import Task

PINNED_MODEL = "claude-sonnet-4-7-20260315"


def _task(tmp_path: Path) -> Task:
    return Task(
        instance_id="acme__widget-42",
        repo="acme/widget",
        base_commit="0" * 40,
        problem_statement="Fix the widget.",
        repo_dir=tmp_path / "unused",  # overwritten by prepare_task
    )


@dataclass
class FakeRepoProvider:
    """Writes a canned fixture tree instead of cloning a real repo."""

    tree: dict[str, str] = field(default_factory=lambda: {"README.md": "hi\n"})
    calls: list[tuple[str, str, str]] = field(default_factory=list)

    def materialize(self, task: Task, dest: Path) -> None:
        self.calls.append((task.repo, task.base_commit, str(dest)))
        dest.mkdir(parents=True, exist_ok=True)
        for name, content in self.tree.items():
            p = dest / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content)


@dataclass
class FakeDaemonHandle:
    """Hands back a fake socket path instead of spawning rts-daemon."""

    socket_path: str = "/tmp/fake-rts.sock"
    started: list[Path] = field(default_factory=list)
    stopped: int = 0

    def start(self, workdir: Path) -> str:
        self.started.append(workdir)
        return self.socket_path

    def stop(self) -> None:
        self.stopped += 1


class TestPrepareTask:
    def test_repo_materialized_at_base_commit(self, tmp_path: Path) -> None:
        provider = FakeRepoProvider(tree={"src/lib.py": "x = 1\n"})
        task = _task(tmp_path)
        with prepare_task(task, tmp_path / "work", repo_provider=provider) as ws:
            assert isinstance(ws, TaskWorkspace)
            assert ws.repo_dir.is_dir()
            assert (ws.repo_dir / "src" / "lib.py").read_text() == "x = 1\n"
            # The provider saw the right repo + commit.
            assert provider.calls[0][0] == "acme/widget"
            assert provider.calls[0][1] == "0" * 40

    def test_baseline_needs_no_daemon(self, tmp_path: Path) -> None:
        provider = FakeRepoProvider()
        task = _task(tmp_path)
        with prepare_task(task, tmp_path / "work", repo_provider=provider) as ws:
            assert ws.socket is None

    def test_rts_arm_gets_a_socket(self, tmp_path: Path) -> None:
        provider = FakeRepoProvider()
        daemon = FakeDaemonHandle(socket_path="/tmp/task.sock")
        task = _task(tmp_path)
        with prepare_task(
            task, tmp_path / "work", repo_provider=provider, daemon=daemon
        ) as ws:
            assert ws.socket == "/tmp/task.sock"
            assert daemon.started  # daemon was started against the repo workdir
        # Cleaned up on exit.
        assert daemon.stopped == 1

    def test_cleanup_on_exception(self, tmp_path: Path) -> None:
        provider = FakeRepoProvider()
        daemon = FakeDaemonHandle()
        task = _task(tmp_path)
        captured: list[Path] = []
        with pytest.raises(RuntimeError, match="boom"), prepare_task(
            task, tmp_path / "work", repo_provider=provider, daemon=daemon
        ) as ws:
            captured.append(ws.repo_dir)
            assert ws.repo_dir.is_dir()
            raise RuntimeError("boom")
        # Tempdir removed even though the body raised.
        assert not captured[0].exists()
        # Daemon stopped even on exception.
        assert daemon.stopped == 1

    def test_tempdir_removed_on_normal_exit(self, tmp_path: Path) -> None:
        provider = FakeRepoProvider()
        task = _task(tmp_path)
        seen: list[Path] = []
        with prepare_task(task, tmp_path / "work", repo_provider=provider) as ws:
            seen.append(ws.repo_dir)
        assert not seen[0].exists()


def test_protocols_are_importable() -> None:
    # RepoProvider + DaemonHandle are the injectable boundaries.
    assert hasattr(RepoProvider, "materialize") or RepoProvider is not None
    assert hasattr(DaemonHandle, "start") or DaemonHandle is not None
