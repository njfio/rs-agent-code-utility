"""Tests for the A/B/C arm tool profiles (verify-v0 P4 U1).

Each arm exposes a different rts tool surface:
  - baseline          → no rts tools (just Bash/Read/submit_patch)
  - retrieval         → RETRIEVAL_TOOLS only
  - retrieval_verify  → RETRIEVAL_TOOLS ∪ VERIFY_TOOLS, + a verify nudge

Uses a FakeBridge that lists ALL rts tools (including an unknown
`mcp__rts__future_tool`) so we can assert the allowlist filters
correctly — a future tool must never silently leak into an arm.
No Anthropic API, no real daemon involved.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import pytest

from agent_bench.mcp_bridge import RTS_TOOL_PREFIX, McpToolSchema
from agent_bench.run import (
    RETRIEVAL_TOOLS,
    VERIFY_NUDGE,
    VERIFY_TOOLS,
    ArmConfig,
    build_tool_list,
    effective_system_prompt,
)


@dataclass
class FakeBridge:
    """Stands in for McpBridge.list_tools(); lists every rts tool.

    Includes an unknown `future_tool` to prove the allowlist excludes
    tools that aren't part of any declared profile.
    """

    extra: list[str] | None = None

    def list_tools(self) -> list[McpToolSchema]:
        names = sorted(RETRIEVAL_TOOLS | VERIFY_TOOLS | {"future_tool"})
        if self.extra:
            names = sorted(set(names) | set(self.extra))
        return [
            McpToolSchema(
                name=n,
                description=f"rts tool {n}",
                input_schema={"type": "object"},
            )
            for n in names
        ]


def _rts_names(tools: list[dict[str, Any]]) -> set[str]:
    """Bare rts tool names present in a built tool list."""
    return {
        t["name"][len(RTS_TOOL_PREFIX):]
        for t in tools
        if t["name"].startswith(RTS_TOOL_PREFIX)
    }


def _local_names(tools: list[dict[str, Any]]) -> set[str]:
    return {t["name"] for t in tools if not t["name"].startswith(RTS_TOOL_PREFIX)}


class TestArmProfiles:
    def test_baseline_spawns_no_rts_tools(self) -> None:
        arm = ArmConfig(arm="A", tool_profile="baseline")
        tools = build_tool_list(arm, FakeBridge())
        assert _rts_names(tools) == set()
        # Local tools always present.
        assert _local_names(tools) == {"Bash", "Read", "submit_patch"}

    def test_baseline_works_without_bridge(self) -> None:
        arm = ArmConfig(arm="A", tool_profile="baseline")
        tools = build_tool_list(arm, None)
        assert _rts_names(tools) == set()

    def test_retrieval_yields_exactly_retrieval_tools(self) -> None:
        arm = ArmConfig(arm="B", tool_profile="retrieval")
        tools = build_tool_list(arm, FakeBridge())
        assert _rts_names(tools) == set(RETRIEVAL_TOOLS)
        # future_tool and verify tools excluded.
        assert "future_tool" not in _rts_names(tools)
        assert _rts_names(tools).isdisjoint(VERIFY_TOOLS)

    def test_retrieval_verify_yields_retrieval_plus_verify(self) -> None:
        arm = ArmConfig(arm="C", tool_profile="retrieval_verify")
        tools = build_tool_list(arm, FakeBridge())
        assert _rts_names(tools) == set(RETRIEVAL_TOOLS) | set(VERIFY_TOOLS)
        assert "future_tool" not in _rts_names(tools)

    def test_unknown_tool_never_leaks_into_any_profile(self) -> None:
        bridge = FakeBridge(extra=["another_unknown"])
        for profile in ("retrieval", "retrieval_verify"):
            arm = ArmConfig(arm="x", tool_profile=profile)
            names = _rts_names(build_tool_list(arm, bridge))
            assert "future_tool" not in names
            assert "another_unknown" not in names

    def test_non_baseline_requires_bridge(self) -> None:
        arm = ArmConfig(arm="B", tool_profile="retrieval")
        with pytest.raises(ValueError, match="requires an MCP bridge"):
            build_tool_list(arm, None)


class TestVerifyNudge:
    def test_arm_c_prompt_gets_nudge_appended(self) -> None:
        arm = ArmConfig(arm="C", tool_profile="retrieval_verify")
        prompt = effective_system_prompt("base prompt body", arm)
        assert "base prompt body" in prompt
        assert VERIFY_NUDGE in prompt
        assert "verify_" in prompt

    def test_baseline_and_retrieval_prompts_unchanged(self) -> None:
        for profile in ("baseline", "retrieval"):
            arm = ArmConfig(arm="x", tool_profile=profile)
            assert effective_system_prompt("base", arm) == "base"


class TestBackCompatShim:
    """`include_rts_tools` stays a working derived property so any
    older caller keeps functioning."""

    def test_baseline_profile_has_include_rts_false(self) -> None:
        assert ArmConfig(arm="A", tool_profile="baseline").include_rts_tools is False

    def test_retrieval_profiles_have_include_rts_true(self) -> None:
        assert ArmConfig(arm="B", tool_profile="retrieval").include_rts_tools is True
        assert (
            ArmConfig(arm="C", tool_profile="retrieval_verify").include_rts_tools is True
        )

    def test_construct_from_include_rts_tools_back_compat(self) -> None:
        """Old call sites passing include_rts_tools= still work."""
        a = ArmConfig(arm="control", include_rts_tools=False)
        assert a.tool_profile == "baseline"
        b = ArmConfig(arm="treatment", include_rts_tools=True)
        # Treatment historically meant ALL tools; map to retrieval_verify
        # (the widest surface) for back-compat.
        assert b.tool_profile == "retrieval_verify"
        assert b.include_rts_tools is True
