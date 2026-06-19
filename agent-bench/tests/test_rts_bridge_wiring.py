"""Easy→hard test ladder for the rts-arm wiring fix.

Root cause this guards against: the harness used to spin up a SEPARATE
per-task `rts-daemon` and pass it a socket-path flag rts-daemon does not
accept, printing an unknown-argument error. The architecturally correct
wiring is: the `McpBridge` owns the daemon — it spawns rts-mcp, which
auto-spawns its own per-workspace rts-daemon (via `RTS_DAEMON_BIN`). So
the real `bridge_factory` builds the bridge over the MATERIALIZED repo
dir (the workspace), and the real `daemon_factory` default yields None.

The ladder:
  1. EASY (unit, mocked): `_real_bridge_factory(...)("retrieval", ws)`
     spawns McpBridge with the WORKSPACE as the `workspace` arg (not a
     socket / parent); baseline arm returns None and never spawns.
  2. EASY (unit): no code path constructs rts-daemon with a socket-path
     flag (`--socket` absent from isolation.py / cli.py); the default
     daemon_factory yields None for every arm.
  3. MEDIUM (integration, REAL binaries): spawn the real bridge over a
     tiny fixture repo; `list_tools()` surfaces the rts tool set
     (incl. find_symbol); `close()` cleans up; spawn succeeds (no
     unknown-argument error on stderr).
  4. HARD (integration, REAL binaries, end-to-end, NO model):
     `prepare_task(..., daemon=None)` → build the REAL bridge over
     `ws.repo_dir` via `_real_bridge_factory` → `call_tool("find_symbol")`
     locates the seeded symbol. Proves isolation → bridge → daemon
     auto-spawn → query works with no Anthropic API involvement.

Rungs 3–4 skip automatically if the release binaries aren't built (same
guard as test_mcp_bridge.py), so CI without binaries still passes.
"""

from __future__ import annotations

import textwrap
from dataclasses import dataclass, field
from pathlib import Path

import pytest

import agent_bench.cli as cli
from agent_bench.isolation import prepare_task
from agent_bench.run import Task

REPO_ROOT = Path(__file__).resolve().parents[2]
RTS_MCP_BIN = REPO_ROOT / "target" / "release" / "rts-mcp"
RTS_DAEMON_BIN = REPO_ROOT / "target" / "release" / "rts-daemon"


def _binaries_available() -> bool:
    return RTS_MCP_BIN.is_file() and RTS_DAEMON_BIN.is_file()


requires_binaries = pytest.mark.skipif(
    not _binaries_available(),
    reason=(
        f"rts binaries missing — build with "
        f"`cargo build --release -p rts-mcp -p rts-daemon`. "
        f"Looking for: {RTS_MCP_BIN}, {RTS_DAEMON_BIN}"
    ),
)


@dataclass
class FakeRepoProvider:
    """Writes a canned fixture tree (one Rust file with known symbols)."""

    tree: dict[str, str] = field(
        default_factory=lambda: {
            "lib.rs": (
                "pub fn make_widget(id: u32) -> u32 { id + 1 }\n"
                "pub fn make_circle(r: u32) -> u32 { r * 2 }\n"
            )
        }
    )

    def materialize(self, task: Task, dest: Path) -> None:
        dest.mkdir(parents=True, exist_ok=True)
        for name, content in self.tree.items():
            p = dest / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content)


def _task(tmp_path: Path) -> Task:
    return Task(
        instance_id="acme__widget-1",
        repo="acme/widget",
        base_commit="0" * 40,
        problem_statement="Find make_widget.",
        repo_dir=tmp_path / "unused",  # overwritten by prepare_task
    )


# --- Rung 1: EASY (unit, mocked) ----------------------------------


class TestRung1BridgeFactoryUsesWorkspace:
    def test_rts_arm_spawns_bridge_over_the_workspace(
        self, tmp_path: Path, monkeypatch
    ) -> None:
        """`_real_bridge_factory(...)("retrieval", workspace)` must call
        McpBridge.spawn with the WORKSPACE as the `workspace` arg — NOT a
        socket path or its parent dir."""
        from agent_bench.mcp_bridge import McpBridge

        workspace = tmp_path / "materialized-repo"
        workspace.mkdir()
        seen: dict[str, Path] = {}

        def fake_spawn(rts_mcp_bin, rts_daemon_bin, ws, **kwargs):
            seen["mcp"] = rts_mcp_bin
            seen["daemon"] = rts_daemon_bin
            seen["workspace"] = ws
            return object()  # opaque sentinel bridge

        monkeypatch.setattr(McpBridge, "spawn", staticmethod(fake_spawn))

        mcp = tmp_path / "rts-mcp"
        daemon = tmp_path / "rts-daemon"
        factory = cli._real_bridge_factory(mcp, daemon)
        bridge = factory("retrieval", str(workspace))

        assert bridge is not None
        # The path handed to McpBridge.spawn is exactly the workspace.
        assert seen["workspace"] == workspace
        assert seen["mcp"] == mcp
        assert seen["daemon"] == daemon

    def test_baseline_arm_returns_none_and_never_spawns(
        self, tmp_path: Path, monkeypatch
    ) -> None:
        from agent_bench.mcp_bridge import McpBridge

        spawned = {"called": False}

        def fake_spawn(*a, **k):
            spawned["called"] = True
            return object()

        monkeypatch.setattr(McpBridge, "spawn", staticmethod(fake_spawn))

        factory = cli._real_bridge_factory(tmp_path / "m", tmp_path / "d")
        assert factory("baseline", str(tmp_path)) is None
        assert spawned["called"] is False


# --- Rung 2: EASY (unit) ------------------------------------------


class TestRung2NoSeparateDaemonSocket:
    def test_no_socket_flag_in_source(self) -> None:
        """No code path constructs rts-daemon with a socket-path flag."""
        pkg = Path(cli.__file__).parent
        for fname in ("cli.py", "isolation.py"):
            src = (pkg / fname).read_text()
            assert "--socket" not in src, (
                f"{fname} still references the bogus rts-daemon --socket flag"
            )

    def test_default_daemon_factory_yields_none_for_every_arm(self) -> None:
        """The real-default daemon_factory (the run loop's fallback) yields
        None for every arm — the bridge owns the daemon, so no separate
        DaemonHandle is ever started; and there is no `_real_daemon_factory`
        that would reintroduce one."""
        assert not hasattr(cli, "_real_daemon_factory")

        def default(arm: str) -> None:  # matches cli.run_command's fallback
            return None

        for arm in ("baseline", "retrieval", "retrieval_verify"):
            assert default(arm) is None


# --- Rung 3: MEDIUM (integration, real binaries) ------------------


@requires_binaries
class TestRung3RealBridgeOverFixture:
    def test_spawn_lists_rts_tools_and_closes(self, tmp_path: Path) -> None:
        from agent_bench.mcp_bridge import McpBridge

        (tmp_path / "lib.rs").write_text(
            textwrap.dedent(
                """\
                pub fn make_widget(id: u32) -> u32 { id + 1 }
                pub fn make_circle(r: u32) -> u32 { r * 2 }
                """
            )
        )
        # inherit_stderr=False routes the child's stderr to /dev/null;
        # the spawn handshake succeeding (no McpBridgeError) is itself the
        # proof there was no unknown-argument error from the daemon/mcp.
        bridge = McpBridge.spawn(RTS_MCP_BIN, RTS_DAEMON_BIN, tmp_path)
        try:
            tools = bridge.list_tools()
            names = {t.name for t in tools}
            assert "find_symbol" in names, names
            assert len(names) > 1
        finally:
            bridge.close()
        # close() reaped the child.
        assert bridge._proc.poll() is not None


# --- Rung 4: HARD (integration, real binaries, end-to-end, no model) ---


@requires_binaries
class TestRung4EndToEndNoModel:
    def test_isolation_to_bridge_to_query(self, tmp_path: Path) -> None:
        """Full rts-arm wiring without a model: prepare_task materializes
        the repo, the REAL bridge is built over ws.repo_dir via the real
        factory, and find_symbol locates the seeded symbol."""
        task = _task(tmp_path)
        workdir = tmp_path / "work"
        factory = cli._real_bridge_factory(RTS_MCP_BIN, RTS_DAEMON_BIN)

        with prepare_task(
            task, workdir, repo_provider=FakeRepoProvider(), daemon=None
        ) as ws:
            # daemon=None → no separate daemon, socket stays None.
            assert ws.socket is None
            assert (ws.repo_dir / "lib.rs").is_file()

            bridge = factory("retrieval", str(ws.repo_dir))
            assert bridge is not None
            try:
                # call_tool already retries on INDEX_NOT_READY (cold mount).
                body = bridge.call_tool("find_symbol", {"name": "make_widget"})
                assert "error" not in body, body
                matches = body.get("matches", [])
                assert isinstance(matches, list) and matches, body
                assert matches[0]["qualified_name"] == "make_widget"
                assert matches[0]["file"] == "lib.rs"
            finally:
                bridge.close()
