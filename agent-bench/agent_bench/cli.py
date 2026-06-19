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
import json
import sys
from collections.abc import Callable
from importlib.metadata import version as _pkg_version
from pathlib import Path
from typing import Any

__all__ = ["main", "estimate_cost", "run_command", "report_command"]


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


# --- run / report subcommands ------------------------------------
#
# `run` orchestrates: corpus load → PRE-FLIGHT budget gate → per
# (task, arm, seed) isolation + run_one_arm → trajectory JSON → reports.
# Every external boundary (Anthropic client, git, daemon, MCP bridge,
# verify CLI) is injected so the whole command is unit-testable with
# fakes and a fixed run_id. `report` re-renders from stored JSONs with
# NO client/API.

# Default system prompt for the agent loop. SHA-locked across arms (the
# only per-arm delta is Arm C's verify nudge, applied inside run.py).
_DEFAULT_SYSTEM_PROMPT = (
    "You are a software engineer fixing a bug in a repository. "
    "Investigate the codebase, make a minimal correct change, and call "
    "submit_patch with a unified diff once you are confident."
)

# Each arm name maps to its run.ArmConfig tool profile.
_ARM_PROFILES = {
    "baseline": "baseline",
    "retrieval": "retrieval",
    "retrieval_verify": "retrieval_verify",
}


def _real_client_factory(model: str) -> Any:
    """Construct the real anthropic.Anthropic client (real runs only).

    Imported lazily so the test suite — which injects a fake — never
    needs the SDK configured or an API key present.
    """
    import anthropic

    return _AnthropicAdapter(anthropic.Anthropic())


class _AnthropicAdapter:
    """Adapt anthropic.Anthropic to the run-loop's `create(...)` shape."""

    def __init__(self, client: Any) -> None:
        self._client = client

    def create(self, **kwargs: Any) -> Any:
        return self._client.messages.create(**kwargs)


def _trajectory_filename(instance_id: str, seed: int) -> str:
    return f"{instance_id}__seed{seed}.json"


def _load_trajectories(raw_dir: Path) -> list[Any]:
    """Reconstruct ArmTrajectory objects from stored raw JSON files."""
    from agent_bench.run import ArmTrajectory, ToolCall

    trajs: list[Any] = []
    for path in sorted(raw_dir.glob("*.json")):
        body = json.loads(path.read_text())
        traj = ArmTrajectory(
            task_id=body["task_id"],
            arm=body["arm"],
            model=body["model"],
            messages=body.get("messages", []),
            final_patch=body.get("final_patch"),
            halt_reason=body.get("halt_reason", ""),
            wall_clock_s=body.get("wall_clock_s", 0.0),
            input_tokens=body.get("input_tokens", 0),
            output_tokens=body.get("output_tokens", 0),
        )
        for tc in body.get("tool_calls", []):
            traj.tool_calls.append(
                ToolCall(
                    turn=tc["turn"],
                    name=tc["name"],
                    arguments=tc.get("arguments", {}),
                    backend=tc["backend"],
                    elapsed_s=tc.get("elapsed_s", 0.0),
                    error=tc.get("error"),
                )
            )
        trajs.append(traj)
    return trajs


def _render_reports(
    run_dir: Path,
    arms: list[str],
    verify_runner: Any,
) -> None:
    """Aggregate stored trajectories per arm + render the multi-arm
    comparison + per-arm summaries. NO client/API."""
    from agent_bench.eval_docker import task_success_vector
    from agent_bench.eval_verify import evaluate_arm
    from agent_bench.report import (
        aggregate_arm,
        arm_summary_json,
        arm_summary_markdown,
        multi_arm_comparison_json,
        multi_arm_comparison_markdown,
    )

    raw_root = run_dir / "raw"
    aggregates = []
    verify_metrics: dict[str, dict[str, Any]] = {}
    success_by_arm: dict[str, list[bool]] = {}

    for arm in arms:
        raw_dir = raw_root / arm
        if not raw_dir.is_dir():
            continue
        trajs = _load_trajectories(raw_dir)
        if not trajs:
            continue
        agg = aggregate_arm(arm, trajs)
        aggregates.append(agg)
        # Per-arm summaries.
        (run_dir / f"{arm}-summary.json").write_text(
            json.dumps(arm_summary_json(agg), indent=2)
        )
        (run_dir / f"{arm}-summary.md").write_text(arm_summary_markdown(agg))
        # Verify metrics (offline).
        verify_metrics[arm] = evaluate_arm(trajs, verify_runner)
        # Success vector — proxy (submit) when no Docker results present.
        vec, _proxy = task_success_vector(trajs, None)
        success_by_arm[arm] = vec

    # McNemar paired contrasts (proxy-labelled). Only emit a contrast when
    # both arms ran the SAME tasks (equal-length vectors).
    paired: dict[str, tuple[list[bool], list[bool]]] = {}
    contrasts = {
        "B_vs_A": ("baseline", "retrieval"),
        "C_vs_B": ("retrieval", "retrieval_verify"),
        "C_vs_A": ("baseline", "retrieval_verify"),
    }
    for key, (a_arm, b_arm) in contrasts.items():
        av = success_by_arm.get(a_arm)
        bv = success_by_arm.get(b_arm)
        if av is not None and bv is not None and len(av) == len(bv):
            paired[key] = (av, bv)

    (run_dir / "comparison.json").write_text(
        json.dumps(
            multi_arm_comparison_json(aggregates, paired, verify_metrics), indent=2
        )
    )
    (run_dir / "comparison.md").write_text(
        multi_arm_comparison_markdown(aggregates, paired, verify_metrics)
    )


def run_command(
    args: argparse.Namespace,
    *,
    client_factory: Callable[[str], Any] | None = None,
    repo_provider: Any = None,
    daemon_factory: Callable[[str], Any] | None = None,
    bridge_factory: Callable[[str, str | None], Any] | None = None,
    verify_runner: Any = None,
    run_id: str | None = None,
) -> int:
    """Execute a full A/B/C bench run from parsed CLI args.

    Boundaries are injected (defaults wire the real implementations):
      - `client_factory(model)` → an Anthropic-shaped client.
      - `repo_provider` → isolation.RepoProvider (git in real runs).
      - `daemon_factory(arm)` → isolation.DaemonHandle or None (baseline).
      - `bridge_factory(arm, socket)` → mcp_bridge.McpBridge or None.
      - `verify_runner` → eval_verify.RtsVerifyRunner.
      - `run_id` → deterministic id (tests pin it).

    Steps: (1) load corpus; (2) PRE-FLIGHT budget gate — if projected USD
    exceeds --max-usd, print + return nonzero BEFORE constructing any
    client / making any call; (3) per (task, arm, seed) prepare_task →
    run_one_arm → write trajectory JSON; (4) --resume skips tuples whose
    file exists; (5) aggregate + verify + render reports.
    """
    from agent_bench.corpus import load_corpus
    from agent_bench.isolation import prepare_task
    from agent_bench.run import ArmConfig, RunConfig, run_one_arm

    arms = [a.strip() for a in str(args.arms).split(",") if a.strip()]
    for arm in arms:
        if arm not in _ARM_PROFILES:
            print(f"error: unknown arm {arm!r}; expected {sorted(_ARM_PROFILES)}", file=sys.stderr)
            return 2

    tasks = load_corpus(args.corpus, limit=args.limit)
    if not tasks:
        print("error: corpus is empty", file=sys.stderr)
        return 2

    seeds = list(range(args.seeds))

    # (2) PRE-FLIGHT budget gate — BEFORE any client is constructed.
    est = estimate_cost(
        tasks=len(tasks),
        seeds=len(seeds),
        arms=len(arms),
    )
    if est["total_usd"] > args.max_usd:
        print(
            f"ABORT: projected spend ${est['total_usd']:.2f} exceeds "
            f"--max-usd ${args.max_usd:.2f} "
            f"({est['runs']} runs = {len(tasks)} tasks × {len(seeds)} seeds "
            f"× {len(arms)} arms). No client constructed; no API call made.",
            file=sys.stderr,
        )
        return 1

    out_root = Path(args.out)
    rid = run_id or _new_run_id()
    run_dir = out_root / "runs" / rid

    client_factory = client_factory or _real_client_factory
    daemon_factory = daemon_factory or (lambda arm: None)
    repo_provider = repo_provider or _real_repo_provider()
    verify_runner = verify_runner or _real_verify_runner()

    workdir = run_dir / "work"

    for arm in arms:
        profile = _ARM_PROFILES[arm]
        arm_cfg = ArmConfig(arm=arm, tool_profile=profile)
        raw_dir = run_dir / "raw" / arm
        raw_dir.mkdir(parents=True, exist_ok=True)
        for task in tasks:
            for seed in seeds:
                out_file = raw_dir / _trajectory_filename(task.instance_id, seed)
                # (4) resume: skip tuples whose trajectory file exists.
                if args.resume and out_file.exists():
                    continue

                config = RunConfig(model=args.model, system_prompt=_DEFAULT_SYSTEM_PROMPT)
                daemon = daemon_factory(arm)
                with prepare_task(
                    task, workdir, repo_provider=repo_provider, daemon=daemon
                ) as ws:
                    materialized = _with_repo_dir(task, ws.repo_dir)
                    bridge = (
                        bridge_factory(arm, ws.socket) if bridge_factory is not None else None
                    )
                    client = client_factory(args.model)
                    try:
                        traj = run_one_arm(
                            client=client,
                            task=materialized,
                            arm=arm_cfg,
                            config=config,
                            bridge=bridge,
                        )
                    finally:
                        if bridge is not None and hasattr(bridge, "close"):
                            bridge.close()
                out_file.write_text(json.dumps(traj.to_dict(), indent=2))

    # (5) aggregate + verify + render reports.
    _render_reports(run_dir, arms, verify_runner)
    print(f"run complete: {run_dir}")
    return 0


def report_command(
    args: argparse.Namespace,
    *,
    verify_runner: Any = None,
) -> int:
    """Re-render reports from an existing run dir's stored trajectories.

    NO client / NO API. Discovers arms from the `raw/` subdirectories.
    """
    run_dir = Path(args.runs)
    raw_root = run_dir / "raw"
    if not raw_root.is_dir():
        print(f"error: no raw/ trajectories under {run_dir}", file=sys.stderr)
        return 2
    arms = sorted(p.name for p in raw_root.iterdir() if p.is_dir())
    # Order canonically (baseline, retrieval, retrieval_verify) when present.
    order = ["baseline", "retrieval", "retrieval_verify"]
    arms = [a for a in order if a in arms] + [a for a in arms if a not in order]
    verify_runner = verify_runner or _real_verify_runner()
    _render_reports(run_dir, arms, verify_runner)
    print(f"report rendered: {run_dir}")
    return 0


def _with_repo_dir(task: Any, repo_dir: Path) -> Any:
    """Return a copy of `task` with `repo_dir` pointed at the workspace."""
    from dataclasses import replace

    return replace(task, repo_dir=repo_dir)


def _new_run_id() -> str:
    import datetime

    return datetime.datetime.now().strftime("%Y%m%d-%H%M%S")


def _real_repo_provider() -> Any:
    from agent_bench.isolation import GitRepoProvider

    return GitRepoProvider()


def _real_verify_runner() -> Any:
    from agent_bench.eval_verify import CliRtsVerifyRunner

    return CliRtsVerifyRunner()


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

    run_p = sub.add_parser(
        "run",
        help="Run the A/B/C bench (budget-gated; needs ANTHROPIC_API_KEY).",
    )
    run_p.add_argument("--corpus", required=True, help="Path to a JSON corpus file.")
    run_p.add_argument(
        "--arms",
        default="baseline,retrieval,retrieval_verify",
        help="CSV of arm names (baseline,retrieval,retrieval_verify).",
    )
    run_p.add_argument("--seeds", type=int, default=1, help="Repeats per (task, arm).")
    run_p.add_argument(
        "--model",
        default="claude-sonnet-4-7-20260315",
        help="Pinned snapshot id (e.g. claude-sonnet-4-7-20260315).",
    )
    run_p.add_argument(
        "--max-usd",
        type=float,
        required=True,
        dest="max_usd",
        help="Hard budget cap. Run ABORTS before any API call if exceeded.",
    )
    run_p.add_argument("--out", required=True, help="Output directory root.")
    run_p.add_argument(
        "--resume",
        action="store_true",
        help="Skip (task, arm, seed) tuples whose trajectory file exists.",
    )
    run_p.add_argument(
        "--limit", type=int, default=None, help="Truncate corpus to first N tasks."
    )

    rep_p = sub.add_parser(
        "report",
        help="Re-render reports from an existing run dir (no API call).",
    )
    rep_p.add_argument("--runs", required=True, help="Path to a runs/<run_id> dir.")
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

    if getattr(args, "command", None) == "run":
        return run_command(args)

    if getattr(args, "command", None) == "report":
        return report_command(args)

    print(_BANNER.format(version=v))

    if args.status or argv is None or len(argv) == 0:
        print(_PRA_NOTICE)
        return 0

    # In PR-B this is where `run`, `report`, and `resume` subcommands
    # get wired up. For now we just show status and exit.
    return 0


if __name__ == "__main__":
    sys.exit(main())
