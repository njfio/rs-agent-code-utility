"""The agent run loop — one task, one arm, one trajectory.

Owns the Anthropic API conversation, dispatches `tool_use` blocks to
the right backend (Bash/Read locally, `mcp__rts__*` via the bridge),
and logs every tool call for attribution. Single-threaded per task.

Why we hand-roll instead of using Agent SDK: precise control over
turn counting, tool-use logging, retry policy, and snapshot pinning
is the whole *point* of an A/B benchmark. Agent SDK abstracts the
loop and obscures the measurements.

The loop is also `mock`-aware: tests inject a `FakeAnthropicClient`
that returns scripted messages so we can validate the dispatch logic
without spending Anthropic API credits. Real runs pass the actual
`anthropic.Anthropic` client.
"""

from __future__ import annotations

import json
import re
import subprocess
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from .mcp_bridge import RTS_TOOL_PREFIX, McpBridge


# Built-in tool schemas the agent sees in BOTH arms.
# We surface Bash + Read so the agent has a baseline shell-shaped
# toolkit comparable to typical SWE-bench harnesses.
BASH_TOOL_SCHEMA: dict[str, Any] = {
    "name": "Bash",
    "description": (
        "Run a shell command in the task's working directory. "
        "Use for builds, tests, file edits, and any system "
        "operation. STDOUT and STDERR are returned together; "
        "exit code is in the response."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "command": {"type": "string", "description": "Shell command to run"},
        },
        "required": ["command"],
    },
}

READ_TOOL_SCHEMA: dict[str, Any] = {
    "name": "Read",
    "description": (
        "Read a file's contents. Use when you know the exact path. "
        "Returns the full file as text."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "file_path": {"type": "string", "description": "Absolute or task-relative path"},
        },
        "required": ["file_path"],
    },
}

SUBMIT_PATCH_TOOL_SCHEMA: dict[str, Any] = {
    "name": "submit_patch",
    "description": (
        "Submit the final unified-diff patch that resolves the task. "
        "Calling this ends the agent loop. Patch must be a valid "
        "`git diff`-shaped string."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "patch": {"type": "string", "description": "Unified diff (git diff format)"},
        },
        "required": ["patch"],
    },
}


# Bounds that prevent a runaway loop or budget incident. Mirrors
# mini-swe-agent defaults adapted to our A/B context.
DEFAULT_MAX_TURNS = 20
DEFAULT_MAX_INPUT_TOKENS = 200_000  # ≈ Sonnet's effective context
DEFAULT_TOOL_OUTPUT_TRUNCATE_BYTES = 10_000  # per call, into the message


@dataclass(frozen=True)
class Task:
    """SWE-bench-lite (or equivalent) task record."""

    instance_id: str
    repo: str
    base_commit: str
    problem_statement: str
    # Path to a working copy of the repo at base_commit. Populated by
    # the per-task isolation module before run_one_arm is called.
    repo_dir: Path
    # Optional gold patch — only used for Docker eval (deferred to
    # U2.10). The agent never sees this.
    gold_patch: str = ""


@dataclass
class ArmConfig:
    """The deltas that differentiate control from treatment.

    Holding the rest of the loop config fixed across arms is the
    primary confound control. The harness asserts on these.
    """

    arm: str  # "control" or "treatment"
    include_rts_tools: bool  # treatment: True; control: False


@dataclass
class RunConfig:
    """Per-task config; identical across arms within a task."""

    model: str  # full snapshot id (e.g. claude-sonnet-4-7-20260315)
    system_prompt: str
    max_turns: int = DEFAULT_MAX_TURNS
    max_input_tokens: int = DEFAULT_MAX_INPUT_TOKENS
    tool_output_truncate_bytes: int = DEFAULT_TOOL_OUTPUT_TRUNCATE_BYTES
    # Sonnet accepts temperature=0; Opus 4.7 rejects it (per
    # litellm #26444). Set to None to omit.
    temperature: float | None = 0.0

    def __post_init__(self) -> None:
        # Confound control: refuse non-pinned model names. A bench
        # against "claude-sonnet-latest" silently drifts as Anthropic
        # ships new snapshots.
        if not re.match(r"^claude-(sonnet|opus|haiku)-\d+-\d+-\d{8}$", self.model):
            raise ValueError(
                f"Model must be a pinned snapshot id (got {self.model!r}). "
                "Use e.g. claude-sonnet-4-7-20260315, not claude-sonnet-latest."
            )


@dataclass
class ToolCall:
    """One agent → tool dispatch. Used for attribution + post-run report."""

    turn: int
    name: str
    arguments: dict[str, Any]
    backend: str  # "bash" | "read" | "rts_mcp" | "submit" | "unknown"
    elapsed_s: float
    error: str | None = None


@dataclass
class ArmTrajectory:
    """Full record of one (task, arm) run."""

    task_id: str
    arm: str
    model: str
    messages: list[dict[str, Any]] = field(default_factory=list)
    tool_calls: list[ToolCall] = field(default_factory=list)
    final_patch: str | None = None
    halt_reason: str = ""  # "submit" | "turn_cap" | "token_cap" | "error" | "no_patch"
    wall_clock_s: float = 0.0
    # Best-effort token totals, summed across all messages.create calls.
    input_tokens: int = 0
    output_tokens: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id,
            "arm": self.arm,
            "model": self.model,
            "messages": self.messages,
            "tool_calls": [
                {
                    "turn": tc.turn,
                    "name": tc.name,
                    "arguments": tc.arguments,
                    "backend": tc.backend,
                    "elapsed_s": tc.elapsed_s,
                    "error": tc.error,
                }
                for tc in self.tool_calls
            ],
            "final_patch": self.final_patch,
            "halt_reason": self.halt_reason,
            "wall_clock_s": self.wall_clock_s,
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
        }


# --- Anthropic client protocol -----------------------------------
#
# We type the client as a Protocol so tests can inject a fake. The
# real anthropic.Anthropic satisfies this shape; the FakeClient in
# tests/conftest.py also does.


class AnthropicClient(Protocol):
    def create(
        self,
        *,
        model: str,
        system: str,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
        max_tokens: int,
        temperature: float | None,
    ) -> Any: ...


# --- Tool dispatch ------------------------------------------------


def _truncate(s: str, max_bytes: int) -> str:
    """Truncate a tool's stdout/stderr to fit the model context budget.

    UTF-8 safe — slices on the byte boundary and adds a marker.
    """
    encoded = s.encode("utf-8")
    if len(encoded) <= max_bytes:
        return s
    return encoded[:max_bytes].decode("utf-8", errors="ignore") + "\n…[output truncated]"


def _run_bash(command: str, cwd: Path, truncate_bytes: int) -> tuple[str, bool]:
    """Execute a shell command in cwd. Returns (combined_output, is_error)."""
    try:
        proc = subprocess.run(
            command,
            shell=True,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=120,
        )
    except subprocess.TimeoutExpired:
        return ("[bash] timed out after 120s", True)
    combined = (proc.stdout or "") + (proc.stderr or "")
    if proc.returncode != 0:
        combined += f"\n[exit {proc.returncode}]"
    return (_truncate(combined, truncate_bytes), proc.returncode != 0)


def _read_file(file_path: str, cwd: Path, truncate_bytes: int) -> tuple[str, bool]:
    """Read a file relative to cwd. Returns (content_or_error, is_error)."""
    target = Path(file_path)
    if not target.is_absolute():
        target = cwd / target
    try:
        text = target.read_text(encoding="utf-8")
        return (_truncate(text, truncate_bytes), False)
    except FileNotFoundError:
        return (f"[read] file not found: {target}", True)
    except PermissionError:
        return (f"[read] permission denied: {target}", True)
    except UnicodeDecodeError:
        return (f"[read] binary file (not UTF-8): {target}", True)


# --- Tool list construction ---------------------------------------


def build_tool_list(
    arm: ArmConfig,
    bridge: McpBridge | None,
) -> list[dict[str, Any]]:
    """Compose the Anthropic `tools=[...]` list for an arm.

    Both arms get Bash + Read + submit_patch. Treatment also gets the
    rts MCP tools (queried live from the bridge so the schema stays
    in sync with whatever rts-mcp advertises).
    """
    tools: list[dict[str, Any]] = [
        BASH_TOOL_SCHEMA,
        READ_TOOL_SCHEMA,
        SUBMIT_PATCH_TOOL_SCHEMA,
    ]
    if arm.include_rts_tools:
        if bridge is None:
            raise ValueError("treatment arm requires an MCP bridge")
        for t in bridge.list_tools():
            tools.append(
                {
                    "name": f"{RTS_TOOL_PREFIX}{t.name}",
                    "description": t.description,
                    "input_schema": t.input_schema,
                }
            )
    return tools


# --- The loop -----------------------------------------------------


def _ensure_dict(o: Any) -> dict[str, Any]:
    """Normalize Anthropic message blocks (BaseModel or dict) to dict.

    The real anthropic SDK returns pydantic BaseModel instances;
    tests inject plain dicts. Loop code uses dict-shaped access so
    we coerce here.
    """
    if isinstance(o, dict):
        return o
    if hasattr(o, "model_dump"):
        return o.model_dump()  # pydantic v2
    if hasattr(o, "dict"):
        return o.dict()  # pydantic v1
    return dict(o.__dict__)


def run_one_arm(
    client: AnthropicClient,
    task: Task,
    arm: ArmConfig,
    config: RunConfig,
    *,
    bridge: McpBridge | None = None,
) -> ArmTrajectory:
    """Drive one (task, arm) end-to-end.

    The model sees the task's `problem_statement` as the first user
    message, plus the available tools. It alternates between assistant
    responses (which may contain `tool_use` blocks) and our injected
    tool-result user messages until:
      - it calls `submit_patch` (success path)
      - it hits the turn or token cap (truncated)
      - it errors out (network, etc.)

    Returns an `ArmTrajectory` with every tool call logged for
    attribution.
    """
    import time as _time

    started = _time.perf_counter()

    traj = ArmTrajectory(task_id=task.instance_id, arm=arm.arm, model=config.model)

    tools = build_tool_list(arm, bridge)
    messages: list[dict[str, Any]] = [
        {"role": "user", "content": task.problem_statement},
    ]

    for turn in range(1, config.max_turns + 1):
        # Token check (best-effort): if cumulative input tokens
        # exceed cap, halt. Caller can re-run with a fresh task.
        if traj.input_tokens > config.max_input_tokens:
            traj.halt_reason = "token_cap"
            break

        try:
            resp = client.create(
                model=config.model,
                system=config.system_prompt,
                messages=messages,
                tools=tools,
                max_tokens=4096,
                temperature=config.temperature,
            )
        except Exception as e:  # noqa: BLE001 — we want everything
            traj.halt_reason = f"api_error: {type(e).__name__}: {e}"
            break

        # Token accounting. Real SDK exposes resp.usage; mocks supply
        # the same shape.
        usage = _ensure_dict(getattr(resp, "usage", {}) or {})
        traj.input_tokens += int(usage.get("input_tokens", 0) or 0)
        traj.output_tokens += int(usage.get("output_tokens", 0) or 0)

        # Normalize the assistant message into a dict the trajectory
        # can store + we can iterate.
        assistant_msg = {
            "role": "assistant",
            "content": [_ensure_dict(b) for b in getattr(resp, "content", [])],
        }
        messages.append(assistant_msg)
        traj.messages = messages.copy()

        # Walk the assistant content. Dispatch any tool_use blocks;
        # collect tool_results into one user message at the end.
        tool_results: list[dict[str, Any]] = []
        submitted_patch: str | None = None

        for block in assistant_msg["content"]:
            if block.get("type") != "tool_use":
                continue

            name = block.get("name", "")
            args = block.get("input", {}) or {}
            tool_use_id = block.get("id", "")
            call_started = _time.perf_counter()
            backend = "unknown"
            err: str | None = None
            result_text: str
            is_error = False

            if name == "Bash":
                backend = "bash"
                command = str(args.get("command", ""))
                result_text, is_error = _run_bash(
                    command, task.repo_dir, config.tool_output_truncate_bytes
                )
            elif name == "Read":
                backend = "read"
                file_path = str(args.get("file_path", ""))
                result_text, is_error = _read_file(
                    file_path, task.repo_dir, config.tool_output_truncate_bytes
                )
            elif name == "submit_patch":
                backend = "submit"
                submitted_patch = str(args.get("patch", ""))
                result_text = "[patch submitted; ending loop]"
            elif name.startswith(RTS_TOOL_PREFIX):
                backend = "rts_mcp"
                if bridge is None:
                    err = "treatment-arm bug: rts tool used but no bridge"
                    result_text = err
                    is_error = True
                else:
                    rts_name = name[len(RTS_TOOL_PREFIX):]
                    body = bridge.call_tool(rts_name, args)
                    if isinstance(body, dict) and "error" in body:
                        is_error = True
                        result_text = json.dumps(body["error"])
                        err = body["error"].get("code", "rts_error")
                    else:
                        result_text = _truncate(
                            json.dumps(body), config.tool_output_truncate_bytes
                        )
            else:
                backend = "unknown"
                result_text = f"[unknown tool: {name}]"
                is_error = True
                err = "unknown_tool"

            traj.tool_calls.append(
                ToolCall(
                    turn=turn,
                    name=name,
                    arguments=args,
                    backend=backend,
                    elapsed_s=_time.perf_counter() - call_started,
                    error=err,
                )
            )

            tool_results.append(
                {
                    "type": "tool_result",
                    "tool_use_id": tool_use_id,
                    "content": [{"type": "text", "text": result_text}],
                    "is_error": is_error,
                }
            )

        # Halt if patch was submitted.
        if submitted_patch is not None:
            traj.final_patch = submitted_patch
            traj.halt_reason = "submit"
            break

        # If the assistant didn't use any tools, it's likely done
        # (or stuck). Halt; the loop has nothing else to do.
        if not tool_results:
            traj.halt_reason = "no_patch"
            break

        messages.append({"role": "user", "content": tool_results})
        traj.messages = messages.copy()
    else:
        # Loop finished without a break — turn cap reached.
        traj.halt_reason = "turn_cap"

    traj.wall_clock_s = _time.perf_counter() - started
    return traj


# --- Convenience: tool-use attribution helpers --------------------


def count_tool_uses_by_backend(traj: ArmTrajectory) -> dict[str, int]:
    """Aggregate ToolCall counts per backend, for reporter use."""
    counts: dict[str, int] = {}
    for tc in traj.tool_calls:
        counts[tc.backend] = counts.get(tc.backend, 0) + 1
    return counts


def tool_use_ratio(traj: ArmTrajectory) -> float:
    """Primary metric: fraction of tool calls that were rts MCP.

    Returns 0.0 when no tool calls were made — distinguishes
    "agent didn't try" from "agent tried bash only." Caller
    decides how to interpret.
    """
    counts = count_tool_uses_by_backend(traj)
    rts = counts.get("rts_mcp", 0)
    total = sum(counts.values())
    if total == 0:
        return 0.0
    return rts / total


def iter_messages_tool_uses(
    messages: Iterable[dict[str, Any]],
) -> Iterable[dict[str, Any]]:
    """Reporter-shape iterator yielding `tool_use` blocks from a
    serialized message log.

    Convenience for consumers that load trajectory.json from disk —
    they get the canonical Anthropic-message-log scan that
    `mcp_bridge.iter_tool_use_blocks` exposes for live traj.
    """
    for m in messages:
        if m.get("role") != "assistant":
            continue
        for block in m.get("content", []):
            if isinstance(block, dict) and block.get("type") == "tool_use":
                yield block
