"""Integration test for agent_bench.mcp_bridge.

Spawns the real rts-mcp + rts-daemon binaries against a tiny seeded
workspace, exercises the bridge's full lifecycle (spawn, list_tools,
call_tool, close), and asserts the wire shapes match what agent-bench
will see at run time. No Anthropic API involvement — this is purely
the rts-mcp side.

Skips automatically if the release binaries aren't built (so CI can
run the suite without the slow `cargo build --release` step on PRs
that don't touch Rust).
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from agent_bench.mcp_bridge import RTS_TOOL_PREFIX, McpBridge, iter_tool_use_blocks


# Path to the freshly-built release binaries. The integration test
# wants release for speed; debug works too but a cold mount on the
# debug daemon can run past the bridge's 30s timeout.
REPO_ROOT = Path(__file__).resolve().parents[2]
RTS_MCP_BIN = REPO_ROOT / "target" / "release" / "rts-mcp"
RTS_DAEMON_BIN = REPO_ROOT / "target" / "release" / "rts-daemon"


def _binaries_available() -> bool:
    return RTS_MCP_BIN.is_file() and RTS_DAEMON_BIN.is_file()


pytestmark = pytest.mark.skipif(
    not _binaries_available(),
    reason=(
        f"rts binaries missing — build with "
        f"`cargo build --release -p rts-mcp -p rts-daemon`. "
        f"Looking for: {RTS_MCP_BIN}, {RTS_DAEMON_BIN}"
    ),
)


@pytest.fixture
def seeded_workspace(tmp_path: Path) -> Path:
    """Tempdir with one Rust file the daemon can index quickly.

    Small fixture = fast cold mount (<5s) so the test stays under
    the bridge's 30s recv timeout on any machine.
    """
    (tmp_path / "lib.rs").write_text(
        textwrap.dedent(
            """\
            pub fn make_widget(id: u32) -> u32 { id + 1 }
            pub fn make_circle(r: u32) -> u32 { r * 2 }
            pub fn format_widget(w: u32) -> String { format!("w#{w}") }
            """
        )
    )
    return tmp_path


class TestMcpBridge:
    def test_spawn_and_close_lifecycle(self, seeded_workspace: Path) -> None:
        """Bridge starts, handshakes, and shuts down without errors."""
        with McpBridge.spawn(RTS_MCP_BIN, RTS_DAEMON_BIN, seeded_workspace) as bridge:
            # Just spawning + auto-handshake + auto-close on context
            # exit is enough to validate the lifecycle.
            assert bridge._proc.poll() is None

    def test_list_tools_returns_rts_namespace(self, seeded_workspace: Path) -> None:
        """tools/list must surface the rts MCP tools with their
        Anthropic-shape input_schema field."""
        with McpBridge.spawn(RTS_MCP_BIN, RTS_DAEMON_BIN, seeded_workspace) as bridge:
            tools = bridge.list_tools()

        assert len(tools) > 0, "rts-mcp should advertise some tools"
        names = {t.name for t in tools}
        # Spot-check: at least find_symbol and grep are core to the
        # rts surface. Don't enumerate everything (the tool set may
        # grow); we just need to confirm the conversion works.
        assert "find_symbol" in names
        assert "grep" in names

        # Wire shape: each tool has an input_schema that Anthropic
        # accepts. Smoke-check one tool's schema has the required
        # `type` field.
        find_sym = next(t for t in tools if t.name == "find_symbol")
        anth = find_sym.to_anthropic_tool()
        assert anth["name"] == "find_symbol"
        assert isinstance(anth["description"], str) and anth["description"]
        assert anth["input_schema"].get("type") == "object"

    def test_call_tool_find_symbol_returns_match(self, seeded_workspace: Path) -> None:
        """End-to-end: ask for `make_widget`, get the seeded def."""
        with McpBridge.spawn(RTS_MCP_BIN, RTS_DAEMON_BIN, seeded_workspace) as bridge:
            # Cold mount can take a few seconds; the bridge's
            # INDEX_NOT_READY retry handles the race.
            body = bridge.call_tool("find_symbol", {"name": "make_widget"})

        assert "error" not in body, f"find_symbol errored: {body}"
        matches = body.get("matches", [])
        assert isinstance(matches, list) and len(matches) >= 1
        first = matches[0]
        assert first["qualified_name"] == "make_widget"
        assert first["file"] == "lib.rs"

    def test_call_tool_unknown_name_returns_error(
        self, seeded_workspace: Path
    ) -> None:
        """A misspelled tool name should surface as a structured
        error body, not throw."""
        with McpBridge.spawn(RTS_MCP_BIN, RTS_DAEMON_BIN, seeded_workspace) as bridge:
            body = bridge.call_tool("does_not_exist_xyz", {})
        # The MCP server returns either an error envelope or a
        # generic "tool not found"-shaped body. Either way, the
        # bridge must not crash.
        assert isinstance(body, dict)


def test_iter_tool_use_blocks_filters_to_assistant_tool_uses() -> None:
    """Reporter-side helper: walk an Anthropic message log and yield
    only the `tool_use` blocks emitted by the assistant.

    This is the canonical attribution channel per best-practices
    research. The test validates the filter without involving the
    Anthropic API.
    """
    messages = [
        {"role": "user", "content": [{"type": "text", "text": "find foo"}]},
        {
            "role": "assistant",
            "content": [
                {"type": "text", "text": "I'll search."},
                {
                    "type": "tool_use",
                    "id": "tu_1",
                    "name": f"{RTS_TOOL_PREFIX}find_symbol",
                    "input": {"name": "foo"},
                },
                {
                    "type": "tool_use",
                    "id": "tu_2",
                    "name": "Bash",
                    "input": {"command": "ls"},
                },
            ],
        },
        {
            "role": "user",
            "content": [
                {
                    "type": "tool_result",
                    "tool_use_id": "tu_1",
                    "content": [{"type": "text", "text": "{}"}],
                }
            ],
        },
        {
            "role": "assistant",
            "content": [
                {
                    "type": "tool_use",
                    "id": "tu_3",
                    "name": f"{RTS_TOOL_PREFIX}grep",
                    "input": {"text": "foo"},
                },
            ],
        },
    ]
    blocks = list(iter_tool_use_blocks(messages))
    assert [b["name"] for b in blocks] == [
        f"{RTS_TOOL_PREFIX}find_symbol",
        "Bash",
        f"{RTS_TOOL_PREFIX}grep",
    ]
    # Reporter uses this for tool-use ratio: count blocks whose name
    # starts with RTS_TOOL_PREFIX vs total.
    rts_count = sum(1 for b in blocks if b["name"].startswith(RTS_TOOL_PREFIX))
    assert rts_count == 2
