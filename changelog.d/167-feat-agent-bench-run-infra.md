### Feat: agent-bench run infrastructure (build-only)

Wires `agent-bench` from a collection of units into an end-to-end harness that
runs a full A/B/C bench from a single `agent-bench run` command. This is
BUILD-ONLY — the harness runs **end-to-end with a fake client** (see
`tests/test_cli_run.py`) and every external boundary is a `Protocol` injected
with a test fake; there is ZERO real model/API/daemon/Docker/network in the
suite. A real run is gated on a budget cap (`--max-usd`) plus live infra
(ANTHROPIC_API_KEY + git + Docker/x86_64).

- **Per-task isolation** (`agent_bench/isolation.py`) — `prepare_task(task,
  workdir, *, repo_provider, daemon=None)` is a context manager yielding a
  `TaskWorkspace` (`repo_dir`, plus `socket` when a daemon is started). The repo
  is materialized at `base_commit` via the `RepoProvider` boundary
  (`GitRepoProvider` = clone + checkout; tests write a fixture tree). rts arms
  get a private per-task daemon socket via the `DaemonHandle` boundary
  (`RtsDaemonHandle` spawns rts-daemon; tests return a fake socket); baseline
  arms pass `daemon=None` and get `socket=None`. The scratch tempdir is removed
  and any daemon stopped on exit — **including on exception**.

- **Corpus loading** (`agent_bench/corpus.py`) — `load_corpus(source, *,
  limit=None, loader=None)` loads `Task` records from a checked-in JSON corpus or
  from a dataset id behind the `CorpusLoader` boundary (`HuggingFaceLoader` real;
  tests inject a fake — no network). Required fields are validated with a clear
  `ValueError`; `limit` truncates deterministically (first N in order); the
  corpus version rides on the returned list as `.corpus_version`.

- **`run` + `report` CLI** (`agent_bench/cli.py`) — `agent-bench run --corpus
  --arms --seeds --model --max-usd --out [--resume] [--limit N]`. (1) loads the
  corpus; (2) **PRE-FLIGHT budget gate**: computes `estimate_cost` and, if the
  projection exceeds `--max-usd`, prints an `ABORT:` line and exits nonzero
  **before any client is constructed / any API call is made**; (3) per
  `(task, arm, seed)`: `prepare_task` → `run_one_arm` → writes the trajectory
  `to_dict()` JSON to `<out>/runs/<run_id>/raw/<arm>/<instance_id>__seed<seed>.json`;
  (4) `--resume` skips tuples whose trajectory file already exists; (5)
  aggregates per arm + `eval_verify.evaluate_arm` + renders
  `multi_arm_comparison_*` and per-arm summaries. `agent-bench report --runs
  <dir>` re-renders from existing JSONs with NO client/API. The client, repo
  provider, daemon, MCP bridge, verify runner, and `run_id` are all injectable
  for deterministic offline tests.

- **Docker patch eval + success notion** (`agent_bench/eval_docker.py`) —
  `evaluate_patches(trajectories, runner)` behind the `PatchEvalRunner` Protocol
  (real = swebench-in-Docker FAIL_TO_PASS; tests inject canned resolutions).
  `task_success_vector(trajectories, results)` maps real results → success =
  resolved, or — when `results is None` — falls back to a `halt_reason ==
  "submit"` **proxy** flagged `proxy=True`. This success notion feeds the
  success-rate ± Wilson CI and the McNemar vectors (real when present, proxy
  otherwise, labelled). The real path requires Docker + x86_64 + the `swebench`
  harness + multi-GB per-repo images.

All boundaries (`AnthropicClient`, `RepoProvider`, `DaemonHandle`,
`CorpusLoader`, `RtsVerifyRunner`, `PatchEvalRunner`) have a documented real
implementation and a test fake; the full suite stays offline.
