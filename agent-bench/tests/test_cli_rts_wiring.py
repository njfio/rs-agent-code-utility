"""Fix 1 (P1): rts-arm bridge/daemon wiring + fail-fast BEFORE any spend.

A real `run` with a non-baseline arm needs an MCP bridge + per-task
daemon. When no `bridge_factory` is injected (a real invocation, not a
test) the CLI wires the REAL bridge/daemon over the built binaries — but
if those binaries are missing it must FAIL FAST: print a clear error and
return nonzero BEFORE constructing any client or running any arm, so no
baseline API call is ever spent.

ZERO real API / daemon / Docker / network — the only thing exercised here
is the pre-flight gate (binaries are absent on the test host) and the
injected-fake path (which never wires the real bridge).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

import pytest

import agent_bench.cli as cli
from agent_bench.cli import run_command
from agent_bench.run import Task
from tests.conftest import FakeAnthropicClient, FakeMessageResponse

PINNED_MODEL = "claude-sonnet-4-7-20260315"


@dataclass
class FakeRepoProvider:
    tree: dict[str, str] = field(default_factory=lambda: {"README.md": "hi\n"})

    def materialize(self, task: Task, dest: Path) -> None:
        dest.mkdir(parents=True, exist_ok=True)
        for name, content in self.tree.items():
            (dest / name).write_text(content)


@dataclass
class FakeVerifyRunner:
    def verify_edit(self, edits: list[dict]) -> dict:
        return {"verdict": "pass", "findings": [], "files": []}

    def verify_file(self, path: str, content: str) -> dict:
        return {"hallucinations": []}


@dataclass
class _FakeBridge:
    """Minimal McpBridge double — advertises retrieval tools; never called."""

    closed: int = 0

    def list_tools(self):
        from agent_bench.mcp_bridge import McpToolSchema

        return [
            McpToolSchema(name="find_symbol", description="d", input_schema={"type": "object"}),
            McpToolSchema(name="grep", description="d", input_schema={"type": "object"}),
        ]

    def close(self) -> None:
        self.closed += 1


def _submit_client() -> FakeAnthropicClient:
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


class TestRtsArmFailFast:
    def test_missing_binaries_fail_fast_before_any_spend(
        self, tmp_path: Path, capsys: pytest.CaptureFixture, monkeypatch
    ) -> None:
        # Force the binary discovery to report "missing" so the test is
        # deterministic regardless of whether the host has built rts.
        monkeypatch.setattr(cli, "_discover_rts_binaries", lambda: None)

        corpus = _write_corpus(tmp_path, n=2)
        out = tmp_path / "out"
        called = {"made_client": False}

        def boom_factory(model: str):
            called["made_client"] = True
            return _submit_client()

        rc = run_command(
            _make_args(corpus=str(corpus), arms="baseline,retrieval", out=str(out)),
            client_factory=boom_factory,
            repo_provider=FakeRepoProvider(),
            # NOTE: no bridge_factory injected → real-wiring path → fail-fast.
            verify_runner=FakeVerifyRunner(),
            run_id="run-test",
        )
        assert rc != 0
        # Fail-fast happened BEFORE any client was constructed (no spend).
        assert called["made_client"] is False
        # No trajectory files written.
        assert not (out / "runs").exists()
        err = (capsys.readouterr().err).lower()
        assert "rts-mcp" in err and "rts-daemon" in err
        assert "no api call made" in err

    def test_baseline_only_does_not_require_binaries(
        self, tmp_path: Path, monkeypatch
    ) -> None:
        # Even with no binaries and no bridge_factory, a baseline-only run
        # must proceed: baseline needs no bridge.
        monkeypatch.setattr(cli, "_discover_rts_binaries", lambda: None)

        corpus = _write_corpus(tmp_path, n=1)
        out = tmp_path / "out"
        rc = run_command(
            _make_args(corpus=str(corpus), arms="baseline", out=str(out)),
            client_factory=lambda model: _submit_client(),
            repo_provider=FakeRepoProvider(),
            verify_runner=FakeVerifyRunner(),
            run_id="run-test",
        )
        assert rc == 0
        raw = out / "runs" / "run-test" / "raw" / "baseline"
        assert len(sorted(raw.glob("*.json"))) == 1

    def test_present_binaries_wire_real_bridge_factory(
        self, tmp_path: Path, monkeypatch
    ) -> None:
        # When the binaries are "present", the real bridge factory is wired
        # (constructed) WITHOUT spawning anything: we stub the factory
        # builder and the run loop so nothing real executes. There is NO
        # separate daemon factory anymore — the bridge owns the daemon.
        fake_mcp = tmp_path / "rts-mcp"
        fake_daemon = tmp_path / "rts-daemon"
        fake_mcp.write_text("")
        fake_daemon.write_text("")
        monkeypatch.setattr(
            cli, "_discover_rts_binaries", lambda: (fake_mcp, fake_daemon)
        )

        seen = {"bridge_built": False}

        def fake_bridge_builder(mcp, daemon):
            seen["bridge_built"] = (mcp, daemon)

            def make(arm, workspace):
                if arm == "baseline":
                    return None
                return _FakeBridge()  # rts arm: a fake (no real subprocess)

            return make

        monkeypatch.setattr(cli, "_real_bridge_factory", fake_bridge_builder)
        # No _real_daemon_factory exists; assert that absence explicitly so
        # this test fails if the redundant daemon path is ever reintroduced.
        assert not hasattr(cli, "_real_daemon_factory")

        corpus = _write_corpus(tmp_path, n=1)
        out = tmp_path / "out"
        rc = run_command(
            _make_args(corpus=str(corpus), arms="baseline,retrieval", out=str(out)),
            client_factory=lambda model: _submit_client(),
            repo_provider=FakeRepoProvider(),
            verify_runner=FakeVerifyRunner(),
            run_id="run-test",
        )
        assert rc == 0
        # The real bridge factory was wired from the discovered binaries.
        assert seen["bridge_built"] == (fake_mcp, fake_daemon)
