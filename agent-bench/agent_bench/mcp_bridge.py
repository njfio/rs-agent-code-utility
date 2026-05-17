"""Python MCP-stdio bridge for the rts MCP server.

Mirrors `crates/rts-bench/src/mcp_runner.rs` (the Rust harness for
rts-bench's own integration tests) but in Python so the agent-bench
loop can register rts tools alongside Anthropic's `tools=[...]` list
without writing a Rust binding for the SWE-bench task harness.

Why we can't use the Anthropic SDK directly for this:
  - The SDK's `messages.create(tools=...)` accepts tool *schemas* the
    model can call. When the model emits a `tool_use` block, the SDK
    surfaces it to *us* — we must execute the tool and feed the
    result back via a `tool_result` block.
  - For Bash / Read tools we execute locally. For `mcp__rts__*` tools
    we delegate to a running rts-mcp subprocess via the protocol-v0
    stdio JSON-RPC frame (the same one Claude Code itself speaks).
  - This bridge owns the subprocess lifecycle + the JSON-RPC plumbing.

Why NOT the Anthropic Agent SDK's native `mcp_servers` support:
  - Agent SDK abstracts the turn loop. The whole point of agent-bench
    is precise per-turn measurement (tool counts, attribution by
    name prefix, retry policy, snapshot pinning). Owning the loop
    is the feature, not a workaround.
"""

from __future__ import annotations

import json
import os
import subprocess
import threading
import time
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any


# Anthropic tool-block names that mean "delegate to the rts MCP server".
# Used elsewhere in the harness to attribute tool calls to rts vs bash.
RTS_TOOL_PREFIX = "mcp__rts__"


@dataclass
class McpToolSchema:
    """Mirror of an Anthropic tool schema, converted from MCP's
    `tools/list` reply.

    Anthropic expects: {name, description, input_schema}.
    MCP returns:       {name, description, inputSchema}.
    (camelCase vs snake_case is the only delta; we normalize.)
    """

    name: str
    description: str
    input_schema: dict[str, Any]

    def to_anthropic_tool(self) -> dict[str, Any]:
        """Shape Anthropic's `messages.create(tools=[...])` accepts."""
        return {
            "name": self.name,
            "description": self.description,
            "input_schema": self.input_schema,
        }


class McpBridgeError(Exception):
    """Any failure interacting with the rts-mcp subprocess.

    Distinct from network / API errors so the agent loop can decide
    whether to retry (transient daemon hiccup) or abort the run
    (rts-mcp binary missing).
    """


class McpBridge:
    """One rts-mcp subprocess; one stdio connection; one workspace.

    Lifecycle:
        bridge = McpBridge.spawn(rts_mcp_bin, rts_daemon_bin, workspace)
        tools  = bridge.list_tools()
        result = bridge.call_tool("mcp__rts__find_symbol", {"name": "X"})
        bridge.close()

    All `mcp__rts__*` MCP tool names are exposed as-is via list_tools()
    — the bridge does NOT prepend or rewrite the prefix. (The prefix
    is part of how Anthropic-style tool registration distinguishes
    MCP-namespaced tools from local Bash/Read.)

    Thread-safety: NOT thread-safe. One bridge per agent task; the
    agent loop is single-threaded per task.
    """

    def __init__(
        self,
        process: subprocess.Popen[bytes],
        recv_timeout_s: float = 30.0,
    ) -> None:
        self._proc = process
        self._next_id = 1
        self._recv_timeout_s = recv_timeout_s
        # Mirror the rts-mcp shell-out: a single line per JSON-RPC frame.
        # stdin/stdout are bytes streams; we encode/decode UTF-8 ourselves.

    # --- spawning ---------------------------------------------------

    @classmethod
    def spawn(
        cls,
        rts_mcp_bin: Path,
        rts_daemon_bin: Path,
        workspace: Path,
        *,
        recv_timeout_s: float = 30.0,
        inherit_stderr: bool = False,
        extra_env: dict[str, str] | None = None,
    ) -> McpBridge:
        """Spawn an rts-mcp subprocess for a specific workspace.

        Mirrors `crates/rts-bench/src/mcp_runner.rs::McpSession::spawn`:
        opens stdin/stdout pipes, routes stderr to /dev/null (or
        inherit on debug), sets RTS_DAEMON_BIN so the auto-spawn can
        find the daemon, then performs the MCP handshake.

        Per-task isolation: each task gets its own bridge (=> its own
        rts-mcp process) with its own per-workspace socket. Two
        concurrent bridges against different workspaces don't share
        any daemon state.
        """
        if not rts_mcp_bin.is_file():
            raise McpBridgeError(f"rts-mcp binary not found: {rts_mcp_bin}")
        if not rts_daemon_bin.is_file():
            raise McpBridgeError(f"rts-daemon binary not found: {rts_daemon_bin}")
        if not workspace.is_dir():
            raise McpBridgeError(f"workspace is not a directory: {workspace}")

        env = os.environ.copy()
        env["RTS_DAEMON_BIN"] = str(rts_daemon_bin)
        env["RTS_LOG"] = env.get("RTS_LOG", "warn")
        if extra_env:
            env.update(extra_env)

        stderr_target = None if inherit_stderr else subprocess.DEVNULL

        proc = subprocess.Popen(
            [str(rts_mcp_bin), "--workspace", str(workspace)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=stderr_target,
            env=env,
            cwd=str(workspace),
        )
        if proc.stdin is None or proc.stdout is None:
            raise McpBridgeError("rts-mcp stdin/stdout not piped")

        bridge = cls(proc, recv_timeout_s=recv_timeout_s)
        try:
            bridge._handshake()
        except Exception:
            bridge.close()
            raise
        return bridge

    # --- JSON-RPC plumbing ------------------------------------------

    def _alloc_id(self) -> str:
        # protocol-v0 §3.4: ids are stringified u64 (uniqueness only
        # required within the session).
        sid = str(self._next_id)
        self._next_id += 1
        return sid

    def _send(self, frame: dict[str, Any]) -> None:
        if self._proc.stdin is None:
            raise McpBridgeError("stdin closed")
        line = json.dumps(frame, separators=(",", ":")) + "\n"
        try:
            self._proc.stdin.write(line.encode("utf-8"))
            self._proc.stdin.flush()
        except BrokenPipeError as e:
            raise McpBridgeError("rts-mcp closed stdin (process died?)") from e

    def _recv(self) -> dict[str, Any]:
        """Read one newline-terminated JSON frame from rts-mcp's stdout.

        Blocking with a soft timeout: we use a watchdog thread to
        SIGTERM the child if the read doesn't return in time. The
        plain `readline()` on the subprocess pipe doesn't take a
        timeout argument; this is the workaround.
        """
        if self._proc.stdout is None:
            raise McpBridgeError("stdout closed")

        result: dict[str, Any] = {}
        error: list[Exception] = []

        def reader() -> None:
            try:
                line = self._proc.stdout.readline()  # type: ignore[union-attr]
                if not line:
                    error.append(McpBridgeError("rts-mcp closed stdout"))
                    return
                result.update(json.loads(line.decode("utf-8")))
            except Exception as e:
                error.append(e)

        t = threading.Thread(target=reader, daemon=True)
        t.start()
        t.join(timeout=self._recv_timeout_s)
        if t.is_alive():
            # Watchdog: kill the child so the loop doesn't hang.
            self._proc.terminate()
            raise McpBridgeError(
                f"no rts-mcp response after {self._recv_timeout_s}s "
                "(daemon may be cold-mounting; raise recv_timeout_s)"
            )
        if error:
            raise error[0]
        return result

    def _handshake(self) -> None:
        """MCP initialize + initialized notification.

        Same shape as `mcp_runner.rs::handshake` — the server sends
        back its capabilities; we don't strictly need them for the
        bridge to work, but we read one frame so the channel is
        drained before the first tool call.
        """
        init = {
            "jsonrpc": "2.0",
            "id": self._alloc_id(),
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {
                    "name": "agent-bench",
                    "version": "0.1.0",
                },
            },
        }
        self._send(init)
        _ = self._recv()
        # MCP requires a notification (no id, no response).
        self._send(
            {
                "jsonrpc": "2.0",
                "method": "notifications/initialized",
                "params": {},
            }
        )

    # --- public surface ---------------------------------------------

    def list_tools(self) -> list[McpToolSchema]:
        """Return the rts MCP server's tool schemas, Anthropic-shape.

        Returns the empty list rather than raising on malformed
        responses — a benchmark that can't list tools should report
        the failure as part of its run metadata, not crash.
        """
        self._send(
            {
                "jsonrpc": "2.0",
                "id": self._alloc_id(),
                "method": "tools/list",
                "params": {},
            }
        )
        resp = self._recv()
        tools = resp.get("result", {}).get("tools", [])
        out: list[McpToolSchema] = []
        for t in tools:
            name = t.get("name")
            if not name:
                continue
            out.append(
                McpToolSchema(
                    name=name,
                    description=t.get("description", ""),
                    input_schema=t.get("inputSchema", {"type": "object"}),
                )
            )
        return out

    def call_tool(
        self,
        name: str,
        arguments: dict[str, Any],
        *,
        max_retries: int = 30,
        retry_delay_s: float = 0.12,
    ) -> dict[str, Any]:
        """Send tools/call with INDEX_NOT_READY retry.

        Mirrors `mcp_runner.rs::tools_call`: retry-on-not-ready up to
        max_retries × retry_delay_s. The writer is asynchronous; on
        cold mount the first few tool calls can land before commit
        and return INDEX_NOT_READY. 30 × 120ms = 3.6s budget — enough
        for any conceivable per-task workspace.

        Returns the raw daemon-shape response body (the JSON inside
        Anthropic's `content[0].text`). Wraps daemon-side errors as
        `{"error": {"code": ..., "message": ...}}` so the caller can
        feed errors back to the agent as `tool_result.is_error=true`.
        """
        last_err: dict[str, Any] | None = None
        for _ in range(max_retries + 1):
            self._send(
                {
                    "jsonrpc": "2.0",
                    "id": self._alloc_id(),
                    "method": "tools/call",
                    "params": {"name": name, "arguments": arguments},
                }
            )
            resp = self._recv()
            content = resp.get("result", {}).get("content", [])
            is_error = bool(resp.get("result", {}).get("isError", False))
            # rts MCP server packs the daemon response as one text
            # content block: {"type":"text", "text":"<json...>"}.
            if not content:
                return {"error": {"code": "INTERNAL_ERROR", "message": "empty content"}}
            text = content[0].get("text", "")
            try:
                body = json.loads(text)
            except json.JSONDecodeError:
                # Daemon returned non-JSON text. Surface as-is.
                return {"raw": text, "is_error": is_error}

            if is_error and isinstance(body, dict) and body.get("error", {}).get(
                "code"
            ) == "INDEX_NOT_READY":
                last_err = body
                time.sleep(retry_delay_s)
                continue
            return body
        # All retries exhausted with INDEX_NOT_READY.
        return last_err or {"error": {"code": "INDEX_NOT_READY", "message": "retries exhausted"}}

    def close(self) -> None:
        """Clean shutdown: close stdin so rts-mcp exits naturally,
        then reap the child with a 5s grace period before SIGKILL."""
        if self._proc.poll() is not None:
            return  # already exited
        try:
            if self._proc.stdin is not None:
                self._proc.stdin.close()
        except BrokenPipeError:
            pass
        try:
            self._proc.wait(timeout=5.0)
        except subprocess.TimeoutExpired:
            self._proc.kill()
            self._proc.wait(timeout=2.0)

    def __enter__(self) -> McpBridge:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


def iter_tool_use_blocks(messages: list[dict[str, Any]]) -> Iterator[dict[str, Any]]:
    """Walk an Anthropic message log and yield every `tool_use` block.

    Used by the reporter to count `mcp__rts__*` calls vs Bash/Read.
    Per best-practices research: scanning the API message log is the
    canonical attribution channel — `Daemon.Stats` deltas under-count
    when the model re-reads cached results.
    """
    for msg in messages:
        if msg.get("role") != "assistant":
            continue
        content = msg.get("content", [])
        for block in content:
            if isinstance(block, dict) and block.get("type") == "tool_use":
                yield block
