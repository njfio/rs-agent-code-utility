"""Shared pytest fixtures + the FakeAnthropicClient.

The fake client returns scripted message-create responses so we can
test the agent loop's dispatch logic without spending API credits.
Each test injects its own script — a list of (content_blocks,
usage) tuples — and asserts on the loop's resulting trajectory.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class FakeUsage:
    input_tokens: int = 100
    output_tokens: int = 100

    def model_dump(self) -> dict[str, int]:
        return {
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
        }


@dataclass
class FakeMessageResponse:
    content: list[dict[str, Any]]
    usage: FakeUsage = field(default_factory=FakeUsage)


class FakeAnthropicClient:
    """Test double for the Anthropic Messages API.

    The agent loop calls `client.create(...)`. We return responses
    from a pre-loaded script in order. If the script is exhausted
    before the loop halts, the test fails loudly (likely a turn-cap
    or no-patch terminator missing from the script).

    Usage:
        client = FakeAnthropicClient(script=[
            FakeMessageResponse(content=[
                {"type": "text", "text": "I'll search for it."},
                {"type": "tool_use", "id": "t1", "name": "Bash",
                 "input": {"command": "ls"}},
            ]),
            FakeMessageResponse(content=[
                {"type": "tool_use", "id": "t2", "name": "submit_patch",
                 "input": {"patch": "fake diff"}},
            ]),
        ])
        # The loop will consume two turns: the first issues a Bash
        # call, the second submits a patch and ends.
    """

    def __init__(self, script: list[FakeMessageResponse]) -> None:
        self._script = list(script)
        self._calls: list[dict[str, Any]] = []  # for assertions

    @property
    def calls(self) -> list[dict[str, Any]]:
        return self._calls

    def create(
        self,
        *,
        model: str,
        system: str,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
        max_tokens: int,
        temperature: float | None,
    ) -> FakeMessageResponse:
        # Log the call so tests can introspect what the loop sent.
        self._calls.append(
            {
                "model": model,
                "system": system,
                "messages": [dict(m) for m in messages],
                "tools": [dict(t) for t in tools],
                "max_tokens": max_tokens,
                "temperature": temperature,
            }
        )
        if not self._script:
            raise AssertionError(
                "FakeAnthropicClient: script exhausted. The agent loop "
                "made more turns than scripted. Add a terminating "
                "submit_patch / no-tool_use response to the script, "
                "or raise the test's expected turn count."
            )
        return self._script.pop(0)
