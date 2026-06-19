---
title: "feat: agent-bench run infrastructure (PR-B, build-only)"
type: feat
status: draft
date: 2026-06-19
origin: docs/plans/2026-06-19-003-feat-abc-benchmark-harness-plan.md
---

# feat: agent-bench run infrastructure (PR-B)

**Goal:** Make the A/B/C benchmark actually *runnable end-to-end* — `agent_bench run` over a corpus × arms × seeds → trajectories → 3-arm report + per-arm verify metrics → optional Docker patch eval — so the only thing standing between here and headline numbers is (a) a real API key + budget and (b) Docker. BUILD-ONLY: every test uses the existing `FakeAnthropicClient` and injectable fakes for git/daemon/Docker; **no real model, daemon, or Docker in the test suite.**

## Grounding
P4 already shipped arm profiles (A/B/C), `eval_verify`, the McNemar/3-arm report, and `estimate`. `run_one_arm` (run.py:416) executes one arm against a `Task` with a `repo_dir`. Still missing (agent-bench U2.5–U2.10): per-task isolation (build the `repo_dir` + a daemon), the corpus loader, the `run`/`report` CLI wiring, a hard cost cap, resume, and Docker patch eval. cli.py is a scaffold + the `estimate` subcommand.

## Implementation Units (build-only, pytest-mocked)

### U1 — Per-task isolation (`isolation.py`)
`prepare_task(task, workdir) -> TaskWorkspace`: materialize the task's repo at `base_commit` into an isolated dir (git clone/worktree + checkout, OR copy a provided fixture), and (for the rts arms) spawn a per-task `rts-daemon` over it on a private socket; yield the workspace; tear everything down. Define a `RepoProvider` boundary (real = git; tests = a `FakeRepoProvider` that lays down a fixture tree) and a `DaemonHandle` boundary (real = spawn; tests = fake) so the unit tests need neither network nor a daemon. Context-manager API (`with prepare_task(...) as ws:`), guaranteed cleanup on error. Tests: a fixture repo is materialized at the right commit; cleanup removes the tempdir even on exception; the rts arms get a socket path, baseline doesn't.

### U2 — Corpus loader (`corpus.py`)
`load_corpus(path_or_name, limit=None) -> list[Task]`: load tasks from a checked-in JSON (the `swe-bench-lite-smoke.json` P4 added, plus a `swe-bench-lite-v1.json` curated set if available) OR a HuggingFace dataset id (behind a boundary so tests don't hit the network — inject a fake loader). Validate each task has the required fields; pin a `corpus_version`. Tests: loads the smoke JSON into `Task`s; `limit` truncates deterministically; a malformed entry raises a clear error; the HF path is exercised via a fake loader (no network).

### U3 — `run` + `report` CLI wiring + cost cap + resume
`agent_bench run --corpus <c> --arms a,b,c --seeds S --model <id> --max-usd <cap> --out <dir> [--resume]`:
- Pre-flight: compute the `estimate` (P4) and **hard-abort if it exceeds `--max-usd`** before any API call (the budget guardrail — U2.6).
- For each (task, arm, seed): `prepare_task` → `run_one_arm` (real `AnthropicClient` in prod; `FakeAnthropicClient` in tests) → persist the trajectory JSON under `--out/runs/<run-id>/raw/<arm>/<task>__<seed>.json`.
- **Resume** (U2.7): on `--resume`, skip (task, arm, seed) tuples whose trajectory JSON already exists; a `preds`/manifest records progress.
- After the runs: aggregate per arm, run `eval_verify` per arm, render the 3-arm report (`multi_arm_comparison_*`) + per-arm summaries to `--out`.
`agent_bench report --runs <dir>`: re-render the report from existing trajectories (no API). Tests (FakeAnthropicClient, fake isolation): a 2-task × 3-arm × 1-seed run produces 6 trajectory files + a 3-arm report; `--max-usd` below the estimate aborts with no client calls; `--resume` skips existing tuples; `report` re-renders without the client.

### U4 — Docker patch-eval boundary (`eval_docker.py`)
`evaluate_patches(trajectories, runner) -> dict[task_id, Resolved]`: behind a `PatchEvalRunner` boundary (real = shells to the `swebench` harness in Docker to check FAIL_TO_PASS; tests = `FakePatchEvalRunner` with canned resolved/unresolved). Wire per-task success into the report's success-rate ± Wilson CI and the McNemar paired vectors (replacing the `halt_reason=="submit"` proxy when real eval is available; fall back to the proxy + a clear "proxy success" label when Docker isn't configured). Document that the real path needs Docker + x86_64 Linux + the swebench package + pulled task images. Tests: fake runner → per-task resolved feeds success-rate + McNemar; absent runner → proxy success, clearly labelled.

### U5 — Docs + changelog
Update `agent-bench/README.md` (the run/report commands, the budget cap, what a real run needs: API key + Docker + the deferred image pulls) and a root changelog fragment. Note this is build-only: the harness runs end-to-end with a fake client; a real run is the budget+Docker-gated step.

## Acceptance criteria
- `agent_bench run` executes A/B/C over a corpus end-to-end with `FakeAnthropicClient`, producing trajectories + a 3-arm report + per-arm verify metrics.
- `--max-usd` aborts before any client call when the estimate exceeds the cap.
- `--resume` skips completed tuples; `report` re-renders offline.
- Isolation/corpus/Docker-eval all behind injectable boundaries; **zero real model/daemon/Docker/network in tests**; `uv run pytest` green.

## Deferred (the actual run — C, budget+infra-gated)
- A real model run (needs an API key + budget; `--max-usd` + `estimate` gate it).
- Real Docker patch eval (needs Docker + x86_64 + multi-GB task images).
- The full curated 30-task corpus content + the first committed baseline result + the CI cadence (`agent-bench.yml`).

## Requirements trace
| agent-bench unit | Covered by |
| :-- | :-- |
| U2.5 isolation | U1 |
| U2.6 cost cap | U3 (`--max-usd` pre-flight abort) |
| U2.7 resume | U3 |
| U2.9 corpus | U2 (loader + smoke/pinned JSON) |
| U2.10 Docker eval | U4 (boundary; real path documented, gated) |
