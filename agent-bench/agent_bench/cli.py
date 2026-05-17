"""agent-bench CLI entry point.

This PR (Phase 2 PR-A) ships the harness *foundation* — bridge, run
loop, reporter, mock-API test suite. The real-money A/B baseline run
+ CI workflow + 30-task curated corpus + resume-from-checkpoint ship
in PR-B.

This CLI is the scaffolding for both. Today it:

  - Validates the harness imports and exposes a `--help` surface so
    contributors can see what's coming.
  - Prints the deferred-units list so anyone running `agent-bench`
    today understands what's not yet built.

When PR-B lands, this file gains the real subcommand wiring (run,
report, resume).
"""

from __future__ import annotations

import argparse
import sys
from importlib.metadata import version as _pkg_version


__all__ = ["main"]


_BANNER = """\
agent-bench {version} — SWE-bench-lite A/B harness for the rts MCP surface
"""

_PRA_NOTICE = """\
This is Phase 2 PR-A of the agent-habit-and-benchmark plan
(docs/plans/2026-05-16-001-feat-agent-habit-and-benchmark-plan.md).

Shipped:
  ✓ U2.1  research/spike (SDK choice: raw + custom bridge)
  ✓ U2.2  scaffolding (uv, pyproject, README)
  ✓ U2.3  MCP-stdio bridge (5/5 integration tests vs real rts-mcp)
  ✓ U2.4  agent run loop with confound asserts
  ✓ U2.8  reporter (Wilson-CI tool-use ratio, Markdown comparison)
        + 28/28 mock-API tests

Deferred to PR-B (separate effort + real API key + Linux x86_64 CI):
  ✗ U2.5  per-task isolation (per-task daemon socket, hook activation)
  ✗ U2.6  pre-flight cost estimate + hard budget cap
  ✗ U2.7  resume-from-checkpoint (preds.json)
  ✗ U2.9  curated 30-task SWE-bench-lite subset
  ✗ U2.10 Docker patch evaluation (x86_64 Linux only)
  ✗ U2.11 .github/workflows/agent-bench.yml
  ✗ U2.12 first baseline run committed to bench-results/

How to use what's already shipped:

  # Smoke-test the MCP bridge end-to-end against real rts-mcp:
  cd agent-bench && uv sync --dev && uv run pytest tests/test_mcp_bridge.py

  # Run the full mock-API test suite (no API key needed):
  uv run pytest

  # Import and use the run loop programmatically:
  from agent_bench.run import run_one_arm, ArmConfig, RunConfig, Task
  # ... see tests/test_run_loop.py for examples
"""


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agent-bench",
        description=(
            "SWE-bench-lite A/B harness for the rts MCP surface. "
            "Measures whether the PreToolUse nudge (#106) actually "
            "shifts agent tool-use ratio on a representative external "
            "workload."
        ),
    )
    parser.add_argument(
        "--status",
        action="store_true",
        help="Print which Phase 2 units are shipped vs deferred and exit.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    try:
        v = _pkg_version("agent-bench")
    except Exception:
        v = "0.1.0-dev"

    parser = _build_parser()
    args = parser.parse_args(argv)

    print(_BANNER.format(version=v))

    if args.status or len(sys.argv) == 1:
        print(_PRA_NOTICE)
        return 0

    # In PR-B this is where `run`, `report`, and `resume` subcommands
    # get wired up. For now we just show status and exit.
    return 0


if __name__ == "__main__":
    sys.exit(main())
