"""Per-task isolation — materialize a repo + (optionally) a private daemon.

Each (task, arm, seed) run gets its own scratch workspace so concurrent
runs can't corrupt one another and so a task's edits never leak into the
next. `prepare_task` is a context manager that:

  1. Creates a guaranteed-cleaned tempdir under `workdir`.
  2. Materializes the task's repo at `base_commit` via the `RepoProvider`
     boundary (real = git clone + checkout; test = a fixture tree).
  3. For arms that need rts tools, starts a per-task daemon on a PRIVATE
     socket via the `DaemonHandle` boundary (real = spawn rts-daemon;
     test = a fake socket path). Baseline arms pass `daemon=None` and get
     `socket=None`.

The tempdir is removed on `__exit__` — including on exception — and any
daemon is stopped. Both boundaries are Protocols so the whole module is
unit-testable with NO git, NO daemon, NO network, NO Docker.
"""

from __future__ import annotations

import shutil
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, runtime_checkable

from .run import Task


@runtime_checkable
class RepoProvider(Protocol):
    """Boundary that puts a task's repo at `base_commit` into `dest`.

    Real implementation clones the repo and checks out `base_commit`;
    the test `FakeRepoProvider` writes a canned fixture tree. `dest` is a
    fresh directory owned by `prepare_task`.
    """

    def materialize(self, task: Task, dest: Path) -> None: ...


@runtime_checkable
class DaemonHandle(Protocol):
    """Boundary over a per-task rts-daemon on a private socket.

    `start(workdir)` brings up a daemon scoped to `workdir` and returns
    its socket path; `stop()` tears it down. Real implementation spawns
    `rts-daemon`; the test fake returns a canned socket path. A handle is
    single-use per `prepare_task` (started once, stopped once).
    """

    def start(self, workdir: Path) -> str: ...

    def stop(self) -> None: ...


@dataclass
class TaskWorkspace:
    """A prepared, isolated workspace for one task run.

    `repo_dir` is the materialized repo at `base_commit`. `socket` is the
    private daemon socket path when a daemon was started (rts arms), else
    `None` (baseline).
    """

    task: Task
    repo_dir: Path
    socket: str | None = None


# --- Real implementations -----------------------------------------
#
# These shell out to git / rts-daemon and are used only in real runs;
# tests never touch them (they inject fakes). Importing this module
# spawns nothing.


class GitRepoProvider:
    """Real `RepoProvider`: `git clone` + `git checkout <base_commit>`.

    `repo` is rendered into a clone URL via `url_template` (default the
    public GitHub https form). Shallow-history is avoided because
    `base_commit` may be deep; a full clone is the safe default.
    """

    def __init__(self, url_template: str = "https://github.com/{repo}.git") -> None:
        self._url_template = url_template

    def materialize(self, task: Task, dest: Path) -> None:
        import subprocess

        url = self._url_template.format(repo=task.repo)
        dest.mkdir(parents=True, exist_ok=True)
        subprocess.run(["git", "clone", url, str(dest)], check=True)
        subprocess.run(
            ["git", "checkout", task.base_commit], cwd=str(dest), check=True
        )


class RtsDaemonHandle:
    """Real `DaemonHandle`: spawn `rts-daemon` on a private unix socket.

    The socket lives inside the task workdir so it is removed with the
    tempdir. `stop()` terminates the process. Used only in real runs.
    """

    def __init__(self, rts_daemon_bin: str = "rts-daemon") -> None:
        self._bin = rts_daemon_bin
        self._proc = None

    def start(self, workdir: Path) -> str:
        import subprocess

        socket_path = str(workdir / ".rts-daemon.sock")
        self._proc = subprocess.Popen(  # noqa: S603 — real-run only
            [self._bin, "--socket", socket_path, "--workspace", str(workdir)],
        )
        return socket_path

    def stop(self) -> None:
        if self._proc is not None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=10)
            except Exception:  # noqa: BLE001 — best-effort teardown
                self._proc.kill()
            self._proc = None


# --- The context manager ------------------------------------------


@contextmanager
def prepare_task(
    task: Task,
    workdir: Path,
    *,
    repo_provider: RepoProvider,
    daemon: DaemonHandle | None = None,
) -> Iterator[TaskWorkspace]:
    """Materialize an isolated workspace for one task run.

    Creates a scratch tempdir under `workdir`, materializes the repo via
    `repo_provider`, and — when `daemon` is given — starts a per-task
    daemon on a private socket. Yields a `TaskWorkspace`. The tempdir is
    ALWAYS removed and any daemon ALWAYS stopped on exit, including when
    the body raises.
    """
    workdir.mkdir(parents=True, exist_ok=True)
    scratch = Path(
        tempfile.mkdtemp(prefix=f"{task.instance_id.replace('/', '_')}__", dir=str(workdir))
    )
    repo_dir = scratch / "repo"
    started_daemon = False
    try:
        repo_provider.materialize(task, repo_dir)
        socket: str | None = None
        if daemon is not None:
            socket = daemon.start(repo_dir)
            started_daemon = True
        yield TaskWorkspace(task=task, repo_dir=repo_dir, socket=socket)
    finally:
        if started_daemon and daemon is not None:
            daemon.stop()
        shutil.rmtree(scratch, ignore_errors=True)
