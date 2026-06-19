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

__all__ = ["main", "estimate_cost"]


# Default per-task-run token model. A "run" is one (task, seed, arm)
# trajectory. These are deliberately conservative point estimates drawn
# from typical SWE-bench-lite agent loops (~15-turn trajectories with a
# growing context). Override at the call site as real data arrives.
DEFAULT_IN_TOKENS_PER_RUN = 120_000
DEFAULT_OUT_TOKENS_PER_RUN = 8_000

# Default per-MTok USD prices. Sonnet list pricing as of writing
# ($3 in / $15 out per million tokens). Override with --in-price /
# --out-price for Opus ($15 / $75) or future snapshots.
DEFAULT_IN_PRICE_USD = 3.0
DEFAULT_OUT_PRICE_USD = 15.0


def estimate_cost(
    *,
    tasks: int,
    seeds: int = 1,
    arms: int = 3,
    in_per_run: int = DEFAULT_IN_TOKENS_PER_RUN,
    out_per_run: int = DEFAULT_OUT_TOKENS_PER_RUN,
    in_price: float = DEFAULT_IN_PRICE_USD,
    out_price: float = DEFAULT_OUT_PRICE_USD,
) -> dict[str, float | int]:
    """Project token + USD spend for a full bench run. NO API call.

    A "run" is one (task, seed, arm) trajectory:
        runs = tasks * seeds * arms
    Token totals scale linearly with runs; USD is priced per MTok:
        input_usd  = input_tokens  * in_price  / 1e6
        output_usd = output_tokens * out_price / 1e6
    """
    runs = tasks * seeds * arms
    input_tokens = runs * in_per_run
    output_tokens = runs * out_per_run
    input_usd = input_tokens * in_price / 1_000_000
    output_usd = output_tokens * out_price / 1_000_000
    return {
        "runs": runs,
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "input_usd": input_usd,
        "output_usd": output_usd,
        "total_usd": input_usd + output_usd,
    }


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

    sub = parser.add_subparsers(dest="command")
    est = sub.add_parser(
        "estimate",
        help="Project token + USD spend for a bench run (no API call).",
    )
    est.add_argument("--tasks", type=int, default=30, help="Number of corpus tasks.")
    est.add_argument("--seeds", type=int, default=1, help="Repeats per (task, arm).")
    est.add_argument(
        "--arms", type=int, default=3, help="Number of arms (A/B/C = 3)."
    )
    est.add_argument(
        "--model",
        default="claude-sonnet-4-7-20260315",
        help="Pinned snapshot id (labels the projection; not called).",
    )
    est.add_argument(
        "--in-price",
        type=float,
        default=DEFAULT_IN_PRICE_USD,
        help=f"Input price USD/MTok (default {DEFAULT_IN_PRICE_USD}; Opus ~15).",
    )
    est.add_argument(
        "--out-price",
        type=float,
        default=DEFAULT_OUT_PRICE_USD,
        help=f"Output price USD/MTok (default {DEFAULT_OUT_PRICE_USD}; Opus ~75).",
    )
    return parser


def _run_estimate(args: argparse.Namespace) -> int:
    est = estimate_cost(
        tasks=args.tasks,
        seeds=args.seeds,
        arms=args.arms,
        in_price=args.in_price,
        out_price=args.out_price,
    )
    print("Projected bench-run cost (no API call made):")
    print(f"  model        : {args.model}")
    print(
        f"  runs         : {est['runs']:,} "
        f"({args.tasks} tasks × {args.seeds} seeds × {args.arms} arms)"
    )
    print(
        f"  input tokens : {est['input_tokens']:,}  "
        f"@ ${args.in_price}/MTok = ${est['input_usd']:.2f}"
    )
    print(
        f"  output tokens: {est['output_tokens']:,}  "
        f"@ ${args.out_price}/MTok = ${est['output_usd']:.2f}"
    )
    print(f"  TOTAL        : ${est['total_usd']:.2f}")
    print(
        "\nNote: per-run token model is a conservative point estimate "
        "(see agent_bench.cli.DEFAULT_*); a hard budget cap + the live "
        "run land with the deferred PR-B infra."
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    try:
        v = _pkg_version("agent-bench")
    except Exception:
        v = "0.1.0-dev"

    parser = _build_parser()
    args = parser.parse_args(argv)

    if getattr(args, "command", None) == "estimate":
        return _run_estimate(args)

    print(_BANNER.format(version=v))

    if args.status or argv is None or len(argv) == 0:
        print(_PRA_NOTICE)
        return 0

    # In PR-B this is where `run`, `report`, and `resume` subcommands
    # get wired up. For now we just show status and exit.
    return 0


if __name__ == "__main__":
    sys.exit(main())
