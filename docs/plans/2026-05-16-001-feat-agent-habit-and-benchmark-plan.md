---
title: "feat: agent-habit PreToolUse hook + SWE-bench-lite agent-bench harness"
type: feat
status: active
date: 2026-05-16
origin: docs/brainstorms/2026-05-16-agent-habit-and-benchmark-requirements.md
---

# feat: agent-habit PreToolUse hook + SWE-bench-lite agent-bench harness

## Overview

Two paired interventions that close the *behavioral* half of the "are agents regularly using rts?" loop:

- **Phase 1 (#1)** — A project-local Claude Code `PreToolUse` hook that intercepts `Bash` calls containing `grep`/`rg`/`find` against the workspace and emits an informational nudge into the model's context (via `hookSpecificOutput.additionalContext`), plus a `.mcp.json` that pins the rts MCP tools as `alwaysLoad: true` so they're first-class in the prompt rather than deferred behind `ToolSearch`.

- **Phase 2 (#10)** — A SWE-bench-lite A/B agent-bench harness in a new top-level `agent-bench/` Python directory (kept outside the HTTP-free `rts-bench` crate). Runs ~30 SWE-bench-lite tasks twice — control (Bash-only) vs treatment (Bash + rts MCP + hook) — against a pinned Claude Sonnet snapshot, with Opus opt-in for release-gate runs. Measures **tool-use ratio** (primary), task success rate (secondary descriptive), and wall-clock latency (secondary descriptive). Per-release-tag cadence.

Two separate PRs (per `AGENTS.md` "one concern per PR"), Phase 1 first because Phase 2's treatment arm depends on Phase 1 being live.

## Problem Statement

The product has been asked *"are you regularly using it?"* six times in a single multi-day session. Each round produced the same answer — no — with the agent (the same one shipping rts) reaching for `Bash grep` and `Read` ~95% of the time despite three rounds of feature work (#102 lines mode, #104 `Daemon.Stats`, #105 auto-dump) explicitly designed to surface the gap.

Telemetry observes the gap. It doesn't close it. The remaining work is **behavioral**, not technical, and the loop won't close from feature-shipping alone. We need:

1. A nudge that fires at the moment of bypass (Phase 1), to shift the habit.
2. A measurement that's *external to the product*, so we can tell whether the habit shift actually happened across a representative agent workload (Phase 2).

See origin: `docs/brainstorms/2026-05-16-agent-habit-and-benchmark-requirements.md`.

## Proposed Solution

### Phase 1 — Behavioral nudge

A bash script at `.claude/hooks/rts-nudge.sh` registered via `.claude/settings.json`'s `hooks.PreToolUse[]` block, matched to `Bash` tool calls with an `if: "Bash(rg *|grep *|egrep *|fgrep *|find *)"` filter to skip the fork cost on non-search bash commands. The script:

1. Reads the hook payload from stdin (JSON: `tool_name`, `tool_input.command`, `cwd`, …).
2. Bails fast if `RTS_HOOK_DISABLED=1` is set in the environment.
3. Tokenizes the command and walks pipeline segments (split on `|`, `;`, `&&`, `||`, `$(…)`).
4. For each `grep|rg|egrep|fgrep|find` token, resolves its non-flag args via `realpath -m` and checks if any resolves inside `$CLAUDE_PROJECT_DIR`.
5. Cached daemon-health probe (60s mtime gate, file under `${XDG_RUNTIME_DIR:-/tmp}/rts-up.$PPID`) — bails silently if the rts daemon isn't running.
6. Emits a JSON envelope on stdout with `permissionDecision: "allow"` and an `additionalContext` string that maps the detected pattern to its rts equivalent (per the R2 table in the brainstorm). The nudge is **visible to the model on the next turn**, not blocking.

The companion `.mcp.json` at repo root (project-scoped per `claude mcp add -s project`) pins the rts server with `"alwaysLoad": true`, eliminating the `ToolSearch` round-trip. Requires Claude Code ≥ v2.1.121.

### Phase 2 — A/B agent-bench

A new top-level `agent-bench/` directory (Python, `uv`-managed venv). Sibling to `crates/`. Kept **out of `rts-bench`** because the harness must call the Anthropic API and `AGENTS.md:377-381` forbids HTTP in the daemon/MCP build trees.

Harness skeleton: fork/inline mini-swe-agent's run loop (Princeton/Stanford, ~100 LOC, scores 74% on SWE-bench-verified, MIT-licensed). Provides cost limits, step limits, resume-from-checkpoint via `preds.json`, and trajectory JSONL storage out of the box.

For each task, the harness:

1. Loads the SWE-bench-lite instance from HuggingFace (`princeton-nlp/SWE-bench_Lite`).
2. Spawns **two** agent runs in sequence (sequential to keep rate-limit accounting clean):
   - **Control arm**: Anthropic `messages.create(tools=[bash_tool, read_tool])`, no rts MCP. System prompt + task identical to treatment.
   - **Treatment arm**: same plus the rts MCP toolset (`mcp__rts__*`) bridged via a custom MCP-stdio adapter — Anthropic Python SDK doesn't include one, so the harness spawns rts-mcp per task and translates `tool_use` blocks to/from the local stdio process. Per-task isolated `rts-daemon` (socket at `$TMPDIR/rts-$instance_id.sock`) prevents cross-task counter pollution.
3. Logs every `content_block.type == "tool_use"` from the API response message log. **This is the canonical attribution channel** — `Daemon.Stats` deltas under-count (model may re-use cached results) and bash-wrapper logs miss native MCP calls.
4. Stores per-arm trajectory + final patch in `runs/<run-id>/<instance-id>/<arm>.jsonl`.
5. After all tasks complete, computes:
   - **Tool-use ratio** per arm: `count(mcp__rts__*) / count(all tool calls)`. Reported with Wilson-score 95% CI.
   - **Task success rate** per arm: did the patch make `FAIL_TO_PASS` tests pass? Requires Docker eval — see Risk #1.
   - **Wall-clock latency** per arm: median + p95 turn-to-completion.
6. Writes `bench-results/<version>-<arm>.json` + a human-readable Markdown summary.

Cadence: **per release tag**, not nightly. New workflow `.github/workflows/agent-bench.yml` triggers on `push: tags: v*` with `workflow_dispatch` for ad-hoc runs. Sonnet by default (~$50-100/run estimate); Opus opt-in via workflow input (~$300+/run).

## Technical Approach

### Architecture

```text
Phase 1 — Behavioral nudge

   Claude Code agent
        │
        │ Bash(rg 'foo' crates/)        ← intercepted
        ▼
   ┌──────────────────────────────────────────┐
   │ .claude/settings.json hooks.PreToolUse[] │
   │   matcher: "Bash"                        │
   │   if:      "Bash(rg *|grep *|find *)"    │  ← pre-fork filter
   └──────────────────────────────────────────┘
        │ JSON on stdin
        ▼
   ┌──────────────────────────────────────────┐
   │ .claude/hooks/rts-nudge.sh               │
   │   1. RTS_HOOK_DISABLED check             │
   │   2. tokenize cmd                        │
   │   3. realpath -m args vs $PROJECT_DIR    │
   │   4. cached daemon-health probe (60s)    │
   │   5. emit hookSpecificOutput.additional… │  ← visible nudge
   └──────────────────────────────────────────┘
        │ JSON on stdout
        ▼
   Claude Code → Bash actually runs → model sees additionalContext next turn


Phase 2 — A/B agent-bench

   agent-bench/run.py
        │
        ├── load task from princeton-nlp/SWE-bench_Lite
        │
        ├── CONTROL ARM:    Anthropic SDK → bash + read tools
        │
        └── TREATMENT ARM:
              │
              ├── spawn fresh rts-daemon @ $TMPDIR/rts-$id.sock
              ├── spawn fresh rts-mcp connected to that daemon
              ├── activate hook (CLAUDE_PROJECT_DIR=...)
              ├── MCP-stdio bridge: tool_use → rts-mcp → tool_result
              └── Anthropic SDK → bash + read + mcp__rts__* tools
        │
        ▼
   trajectory.jsonl + patch.diff per (instance, arm)
        │
        ▼
   aggregate → JSON + Markdown summary → bench-results/<version>.{json,md}
```

### Implementation Units

Each unit lists Goal, Files, Approach, Patterns to follow, Verification, and Execution note. Execution-note guidance: pragmatic for hook + harness scaffolding; test-first for the few units whose correctness is hard to eyeball (path-detection logic, MCP-bridge JSON-RPC plumbing).

---

#### Phase 1 — PreToolUse hook + MCP eager-load

**U1.1 — Hook contract spike (research / verification)**
- **Goal**: Confirm `PreToolUse` JSON contract on the local Claude Code install matches the documented schema. Verify `additionalContext` actually surfaces to the model next turn (vs only debug log).
- **Files**: Throwaway `.claude/hooks/spike.sh` echoing fixed JSON; deleted before commit.
- **Approach**: Manually trigger a Bash call with the spike hook active. Inspect the agent's next response to confirm the `additionalContext` string appeared. Verify Claude Code version ≥ 2.1.121 for `alwaysLoad` support.
- **Verification**: agent's response visibly references the spike's nudge text. Claude Code version printed and recorded in the plan's "Dependencies" section before commit.
- **Execution note**: spike-then-discard. Not committed.

**U1.2 — `rts-nudge.sh` bash implementation**
- **Goal**: Pure-bash hook script. Sub-20ms p95 latency per Bash call (warm path), correct command parsing, workspace-path detection, daemon-health caching, nudge emission.
- **Files**: `.claude/hooks/rts-nudge.sh` (new).
- **Approach**:
  - Shebang `#!/usr/bin/env bash`, set `-euo pipefail` for safety.
  - Read entire stdin into a variable; parse with `jq -r` for `tool_name`, `tool_input.command`, `cwd`.
  - Early bail (exit 0 with empty stdout) if `RTS_HOOK_DISABLED=1` or `tool_name != Bash`.
  - Tokenize command: strip single-quoted strings, split on `|;&&||$()`, walk segments for `grep|rg|egrep|fgrep|find` head.
  - For each match, resolve non-flag args via `realpath -m` and check `[[ $resolved == "$CLAUDE_PROJECT_DIR"/* ]]`.
  - Cached daemon-health probe: `find "$probe_file" -mmin -1 -print -quit 2>/dev/null` to gate; if stale, check `pgrep rts-daemon || socket-stat`; `touch` the probe file.
  - Emit JSON via printf (avoid `jq` for the output to keep latency tight on hot path).
- **Patterns to follow**: `scripts/build-changelog.sh` for the bash quoting/error style. AGENTS.md §"Use the `rts` index, not `grep`" table at `AGENTS.md:184-191` for the mapping verbatim.
- **Verification**: invoking the script with synthetic stdin returns expected JSON; latency budget verified via `time` measurement on 100 invocations.
- **Execution note**: test-first for the command-parsing function (synthetic inputs → expected pattern matches). Pragmatic for the JSON wrapping.

**U1.3 — Wire `.claude/settings.json` hooks block**
- **Goal**: Register the hook so Claude Code fires it on Bash calls.
- **Files**: `.claude/settings.json` (new — there is no `settings.json` yet, only `settings.local.json`).
- **Approach**: Create `.claude/settings.json` (committed; project-scoped) with:
  ```json
  {
    "hooks": {
      "PreToolUse": [
        {
          "matcher": "Bash",
          "if": "Bash(rg *|grep *|egrep *|fgrep *|find *)",
          "hooks": [{ "type": "command", "command": ".claude/hooks/rts-nudge.sh", "timeout": 5 }]
        }
      ]
    }
  }
  ```
  Pre-fork filter via `if` is the single biggest latency win — the script doesn't even run when the bash command is something like `cargo build`.
- **Patterns to follow**: official Claude Code hook reference (`code.claude.com/docs/en/hooks`). Distinct from `.claude/settings.local.json` which stays user-private.
- **Verification**: spike from U1.1 still fires after the registration change. Confirm `cargo build` invocations do NOT trigger the hook (verify by adding a debug `>> /tmp/hook.log` line, running once, and removing).
- **Execution note**: pragmatic.

**U1.4 — Wire `.mcp.json` with `alwaysLoad: true`**
- **Goal**: Promote rts MCP tools out of the deferred surface so the agent sees them in the top-of-prompt tool list every session.
- **Files**: `.mcp.json` at repo root (new).
- **Approach**:
  ```json
  {
    "mcpServers": {
      "rts": {
        "type": "stdio",
        "command": "rts-mcp",
        "args": ["--workspace", "${workspaceFolder}"],
        "env": { "RTS_DAEMON_BIN": "rts-daemon" },
        "alwaysLoad": true
      }
    }
  }
  ```
  `${workspaceFolder}` is Claude Code's documented placeholder; if not supported, fall back to a relative path documented in the `agent-bench/README.md`. Verify during U1.1 spike.
- **Patterns to follow**: existing user-scoped registration (`claude mcp add -s user rts -- /path/to/rts-mcp …`) from `docs/install.md:61`. Project scope is the additive committed variant.
- **Verification**: a fresh Claude Code session in this repo lists `mcp__rts__find_symbol` etc. in `/help`'s tool surface WITHOUT having called `ToolSearch`.
- **Execution note**: pragmatic; the spike already verified the mechanism.

**U1.5 — Hook unit + integration tests**
- **Goal**: Lock the hook's behavior with executable assertions. Catch regressions before they hit users.
- **Files**:
  - `.claude/hooks/tests/rts-nudge.bats` (new) — bats-style test harness in pure bash (no Python startup cost in CI).
  - Or `.github/workflows/hook-test.yml` standalone if we'd rather use a `bash -c` test runner.
- **Approach**: Each test invokes the hook with a fixture JSON on stdin, captures stdout, asserts substring presence/absence. Cases:
  - `rg 'foo' crates/` (workspace path) → nudge present, mentions `mcp__rts__grep`.
  - `rg 'fn foo'` → nudge mentions `mcp__rts__find_symbol --name foo`.
  - `find . -name '*.rs'` → nudge mentions `mcp__rts__outline_workspace`.
  - `cargo build` → matcher's `if` filters this out at registration level; hook script not invoked. Asserted by writing a debug marker to `/tmp` and verifying absence.
  - `rg 'foo' /tmp/notes` (out-of-workspace) → no nudge.
  - `RTS_HOOK_DISABLED=1 rg 'foo' crates/` → no nudge.
  - rts daemon not running → silent (no nudge, no error to stderr).
- **Patterns to follow**: `crates/rts-bench/tests/query_cli.rs` for the "spawn process, capture stdout, assert" shape, adapted to bash.
- **Verification**: all assertions pass. Latency-budget assertion (`time` measurement over 100 iterations < 20ms p95) included as a separate test marked slow.
- **Execution note**: test-first.

**U1.6 — Update `AGENTS.md`**
- **Goal**: Document the hook + eager-load so the *next* agent that opens this repo learns about them by reading AGENTS.md at session start.
- **Files**: `AGENTS.md` — extend the "Use the `rts` index, not `grep` / `rg`" section (around line 174).
- **Approach**: Add a subsection "Active behavior nudges (v0.5.8+)" noting: PreToolUse hook is registered project-locally and nudges Bash grep/rg/find. Set `RTS_HOOK_DISABLED=1` to opt out. The rts MCP tools are eager-loaded via `.mcp.json` so `ToolSearch` is no longer required.
- **Patterns to follow**: the existing #102 cheatsheet section style (table + brief prose).
- **Verification**: AGENTS.md still scans cleanly; no broken links; new section follows existing structure.
- **Execution note**: pragmatic.

**U1.7 — Changelog fragment + PR**
- **Goal**: Ship Phase 1 as one PR per AGENTS.md Rule 24.
- **Files**: `changelog.d/xxx-feat-pretooluse-hook-and-eager-load.md` (rename to `<PR-number>-…` after PR opens).
- **Approach**: Follow the #93 fragments workflow. Sections: header, motivator (what + why), implementation summary, verification (test count, latency measurement), out-of-scope (user-global hook variant, additional command patterns).
- **Verification**: `cargo test --workspace --release` passes (no Rust changes but ensure no regression); fragment renders cleanly when concatenated.

---

#### Phase 2 — SWE-bench-lite A/B agent-bench harness

**U2.1 — Harness scaffold spike (research / verification)**
- **Goal**: Validate end-to-end on ONE SWE-bench-lite task before building the full harness. Measure cold + warm task cost on real hardware.
- **Files**: `agent-bench/spike.py` — throwaway, deleted before final PR.
- **Approach**:
  - Install `uv`, create venv, `uv pip install anthropic datasets swebench`.
  - Load a single SWE-bench-lite task via `datasets.load_dataset("princeton-nlp/SWE-bench_Lite", split="test")[0]`.
  - Invoke `anthropic.messages.create(model="claude-sonnet-4-...", tools=[bash_tool], messages=[…])` in a loop until the agent emits a patch or hits a turn cap.
  - Record: total tokens, $ cost, wall-clock, did-the-agent-converge.
  - Repeat with `mcp__rts__*` tools registered (path (a) — harness-mediated stdio bridge to rts-mcp).
- **Verification**: at least one task completes end-to-end; cost recorded; bridge plumbing works.
- **Deferred-to-research notes**:
  - **Docker eval feasibility on macOS arm64.** Docs say x86_64-only. Either run eval on GH Actions ubuntu-latest, OR scope v1 to skip patch validation entirely (just measure tool-use ratio + latency, defer success-rate to a follow-up that adds Docker eval on Linux CI).
  - **Anthropic Agent SDK vs raw SDK + custom bridge.** Agent SDK has native `mcp_servers` (stdio-aware) — likely far less custom code than the raw SDK + bridge path. Decide during spike: which gives cleaner harness code at acceptable lock-in?
- **Execution note**: characterization-first — measure before committing to architecture.

**U2.2 — `agent-bench/` scaffolding**
- **Goal**: New top-level dir, Python project, dependencies pinned.
- **Files**:
  - `agent-bench/pyproject.toml` (uv-compatible)
  - `agent-bench/agent_bench/__init__.py`
  - `agent-bench/README.md`
  - `agent-bench/.python-version` (3.11 or 3.12 — pin)
- **Approach**: `uv init`; pin `anthropic`, `datasets`, `tenacity` (retry/backoff), `pydantic` (config), `rich` (output). Decide on Agent SDK vs raw SDK based on U2.1 outcome. Document the choice in README's "Architecture" section.
- **Patterns to follow**: nothing in this repo; greenfield Python project. Match `mini-swe-agent`'s shape if we use it as the skeleton.
- **Verification**: `uv sync` succeeds; `python -m agent_bench --help` prints usage.
- **Execution note**: pragmatic.

**U2.3 — MCP-stdio bridge (only if U2.1 selects raw SDK)**
- **Goal**: A Python class that wraps an rts-mcp subprocess and exposes `list_tools()` + `call_tool(name, args) -> result` for the agent loop.
- **Files**: `agent-bench/agent_bench/mcp_bridge.py`
- **Approach**:
  - Spawn `rts-mcp --workspace <task_repo>` as a child process with stdin/stdout pipes (mirror `crates/rts-bench/src/mcp_runner.rs`'s pattern — adapt the JSON-RPC handshake to Python).
  - On `list_tools()`, send `tools/list` and return the response.
  - On `call_tool()`, send `tools/call` with retry on `INDEX_NOT_READY`. Bound to 30 retries × 120ms (match the Rust runner's budget).
  - Implement `close()` that closes stdin and reaps the child within a 5s timeout.
- **Patterns to follow**: `crates/rts-bench/src/mcp_runner.rs:64-244`. Same handshake, same retry shape.
- **Verification**: unit test against a real rts-mcp subprocess; assert `find_symbol` returns the expected matches on a tiny fixture workspace.
- **Execution note**: test-first; the JSON-RPC plumbing is exactly the kind of code where eyeballing is unreliable.

**U2.4 — Agent run loop (control + treatment)**
- **Goal**: Run one task through one arm, producing a trajectory + patch.
- **Files**: `agent-bench/agent_bench/run.py`
- **Approach**:
  - Identical system prompt across arms (load from `agent-bench/prompts/system.md`).
  - Identical model snapshot ID — full snapshot e.g. `claude-sonnet-4-7-20260315`, never `claude-sonnet-latest`. Note Opus 4.7 rejects `temperature` per litellm #26444; adapt config.
  - Same retry policy (`tenacity` exponential w/ jitter, honor `Retry-After`, max 5 attempts).
  - Same turn cap (20 turns) and same token budget per task (200K input total).
  - On each turn: send messages; receive `tool_use` blocks; for each block, dispatch:
    - `Bash`/`Read` → handler executes locally in a sandbox (per-task tempdir, chdir to task's repo checkout).
    - `mcp__rts__*` (treatment only) → bridge.call_tool().
  - Collect every `tool_use.name` into the trajectory log.
  - Stop conditions: turn cap, token budget exhausted, agent emits a patch via a designated `submit_patch(diff)` tool, or `cost_limit_usd` ceiling hit.
- **Patterns to follow**: `mini-swe-agent`'s run loop. Mirror its checkpoint shape (`preds.json`).
- **Verification**: dry-run against 3 tasks (cherry-picked from the curated subset), assert both arms produce trajectory files and at least one tool_use of the expected category.
- **Execution note**: test-first for the trajectory log structure; pragmatic for the orchestration glue.

**U2.5 — Per-task isolation**
- **Goal**: No cross-task contamination via rts-daemon state, no socket collisions on parallel runs.
- **Files**: `agent-bench/agent_bench/isolation.py`
- **Approach**: Per task: fresh tempdir, fresh checkout of the task's `base_commit`, fresh rts-daemon on `$TMPDIR/rts-$instance_id.sock` (override `XDG_RUNTIME_DIR` or pass `--socket`), torn down after the task. Activates the hook by setting `CLAUDE_PROJECT_DIR=<task_repo>` and copying the project's `.claude/settings.json` + `.mcp.json` if needed.
- **Patterns to follow**: `crates/rts-daemon/tests/per_workspace_sockets.rs` for the per-workspace socket pattern.
- **Verification**: two parallel task runs don't collide; each task's `Daemon.Stats` reflects only its own traffic.
- **Execution note**: test-first; this is exactly the kind of code where leaked state silently corrupts results.

**U2.6 — Confound controls & pre-flight cost estimate**
- **Goal**: Make the experiment scientifically defensible at n=30. Don't waste $ on runs we couldn't believe.
- **Files**: `agent-bench/agent_bench/preflight.py`, `agent-bench/agent_bench/confounds.py`
- **Approach**:
  - Pre-flight: estimate `n_tasks × mean_tokens_per_task × $/Mtok × 2_arms × 1.5_safety`. Abort if estimate exceeds `--budget-usd`. Print estimate + actual after each task so the user sees burn rate.
  - Hard ceiling check: after every task, sum cumulative `usage.input_tokens + usage.output_tokens × price`. Abort cleanly (write partial results) when 90% of budget consumed.
  - Confound asserts at boot: model is a full snapshot ID; both arms have identical system prompt SHA; task ordering is deterministic (sorted by `instance_id`); temperature, top_p, retry policy identical.
- **Verification**: a deliberately-broken config (e.g. `claude-sonnet-latest` instead of full ID) fails the boot assertion with a clear error.
- **Execution note**: test-first.

**U2.7 — Resume-from-checkpoint**
- **Goal**: A crash at task 27/60 doesn't burn the prior 26 tasks' $.
- **Files**: extend `agent-bench/agent_bench/run.py`.
- **Approach**: Per `mini-swe-agent`'s pattern, write `runs/<run-id>/preds.json` after every completed (task, arm). On startup, if `preds.json` exists, skip already-completed (task, arm) pairs. Idempotency key = `(instance_id, arm, model_snapshot_id)`.
- **Verification**: kill the harness mid-task; restart; observe it skips completed pairs and resumes.
- **Execution note**: test-first; the only way to verify resume is to run it.

**U2.8 — Reporter + statistics**
- **Goal**: Convert per-task trajectories into a human-readable + machine-readable summary.
- **Files**: `agent-bench/agent_bench/report.py`
- **Approach**:
  - Tool-use ratio per arm: `count(content_block.type == "tool_use" AND name.startswith("mcp__rts__")) / count(content_block.type == "tool_use")`. Per-arm Wilson-score 95% CI.
  - Task success rate per arm: deferred to U2.10 (Docker eval).
  - Wall-clock latency per arm: median + p95 of turn-to-completion times, per arm.
  - Output:
    - `bench-results/<version>/<arm>-summary.json` — machine-readable, schema-versioned (`schema: "agent-bench/v1"`).
    - `bench-results/<version>/<arm>-summary.md` — human-readable; one bullet per metric, embedded CI table.
- **Patterns to follow**: `crates/rts-bench/src/semantic.rs::build_report` shape.
- **Verification**: synthetic trajectories produce expected ratio + CI.
- **Execution note**: test-first for the statistics math; pragmatic for the formatting.

**U2.9 — Initial 30-task curated subset**
- **Goal**: A reproducible, committed-to-repo subset that the bench runs against by default.
- **Files**: `agent-bench/corpus/swe-bench-lite-v1.json`
- **Approach**: Filter SWE-bench-lite to tasks where the issue text mentions navigation/code-structure work (function names, file paths). Sample 30 across the 11 repos for diversity. Commit the `instance_id` list; the harness loads task content live from HuggingFace at run time.
- **Verification**: harness loads exactly 30 tasks, all valid `instance_id`s.
- **Execution note**: pragmatic; selection criteria documented in the corpus file's leading comment.

**U2.10 — Docker eval (v2, post-merge)**
- **Goal**: Verify patches actually fix the failing tests (the lagging-indicator success metric).
- **Files**: `agent-bench/agent_bench/eval.py`
- **Approach**: Wrap `python -m swebench.harness.run_evaluation --dataset_name princeton-nlp/SWE-bench_Lite --predictions_path preds.json --max_workers 8 --run_id <run-id>`. Linux x86_64 only — gate behind `--with-eval` flag and a runtime OS check. Default v1: skip eval, report tool-use + latency only.
- **Verification**: on a Linux CI runner, one task's gold patch evaluates to "passing"; one deliberately-broken patch evaluates to "failing".
- **Execution note**: **DEFERRED to a follow-up PR.** Doesn't block the first agent-bench landing; tool-use ratio is the primary metric (per origin: "pre-register tool-use ratio as primary; success/latency as secondary descriptive").

**U2.11 — `.github/workflows/agent-bench.yml`**
- **Goal**: CI-triggerable bench, on tag push + manual dispatch.
- **Files**: `.github/workflows/agent-bench.yml`
- **Approach**: ubuntu-latest runner (x86_64, supports Docker for U2.10 follow-up); install uv + python; `uv sync` in `agent-bench/`; run on a small subset (10 tasks) for tag pushes, full 30 for manual dispatch. Anthropic API key from secret. Budget cap as workflow input.
- **Verification**: dry-run via `act` (or GH Actions debug rerun) succeeds end-to-end on the 10-task path with mocked API.
- **Execution note**: pragmatic. Real-API verification happens when this workflow is invoked for the first time post-merge.

**U2.12 — Documentation + first baseline run**
- **Goal**: Ship a real first data point so #S1 is satisfied on day 1.
- **Files**: `agent-bench/README.md`, `bench-results/v0.5.7-baseline.{json,md}` (the baseline run output, committed).
- **Approach**: Author the README (what the bench measures, how to run, how to read results). Run the 30-task subset once (Sonnet, budget cap ~$100), commit the results. Link from the main `README.md`.
- **Verification**: README explains the harness to a stranger; the baseline result file exists and shows non-zero counts in both arms.
- **Execution note**: pragmatic.

**U2.13 — Changelog fragment + PR**
- **Goal**: Ship Phase 2 as a separate PR.
- **Files**: `changelog.d/xxx-feat-agent-bench-harness.md`.
- **Approach**: Sections: motivator (closes the meta-loop), what (Python harness in new top-level dir, mini-swe-agent skeleton, A/B with confound controls), verification (cargo test passes, baseline run results committed, Wilson CI on tool-use ratio), out-of-scope (Docker eval, larger task subsets, statistical-significance thresholds).
- **Verification**: `cargo test --workspace --release` passes (no Rust changes, but the workflow's lefthook + CI must remain green).

## Alternative Approaches Considered

### Phase 1 alternatives

- **Hard-block `Bash grep` on workspace paths.** Rejected per origin (Scope Boundaries §"Not in scope: hard enforcement"). Combative agent workflow; breaks edge cases like grep on `target/`, vendored deps, multi-line scripts.
- **Python hook instead of bash.** Rejected. Python startup (~300-500ms) blows the per-Bash-call latency budget; bash startup is ~10-50ms.
- **User-global hook from day one.** Rejected per origin. Project-local is the experiment; promotion is a separate decision after we trust the local-only version.

### Phase 2 alternatives

- **Curated rts-favoring task corpus.** Rejected per origin Decision #1 — grading our own homework. SWE-bench-lite is external and reproducible.
- **Before/after instead of A/B.** Rejected. Sonnet snapshot drift between "before" and "after" contaminates the signal. Same model running both arms in the same window is the only confound-controlled shape.
- **Static capability check only (no real LLM).** Rejected per origin (the dismissed brainstorm option). Cheap, doesn't answer "do agents actually use it?" — which is the entire point.
- **Build the harness inside `rts-bench` crate.** Rejected — `AGENTS.md:377-381` forbids HTTP in the daemon/MCP build trees and CI asserts via `cargo tree`. The Anthropic SDK + reqwest would violate this. Top-level Python dir keeps the crate clean.
- **Anthropic API MCP-connector beta.** Rejected — HTTP/SSE only; our rts-mcp is stdio. Forces harness-mediated bridging (path (a) from research).

## System-Wide Impact

### Interaction Graph

**Phase 1**: agent issues Bash call → Claude Code's tool runtime → matched `Bash` hook → `if` filter → if pass, fork bash → `rts-nudge.sh` → reads stdin JSON → checks env opt-out → tokenizes command → realpath args → cached daemon-health probe → maps pattern → emits `hookSpecificOutput.additionalContext` JSON → Claude Code → injects into next-turn context. Latency budget per call: <20ms p95, <5ms p50 warm.

**Phase 2**: harness loads task → spawns rts-daemon@unique-socket + rts-mcp (treatment only) → orchestrates Anthropic message loop → per-turn `tool_use` blocks dispatch to either Bash sandbox or MCP bridge → trajectory log captures every tool name → on task complete, write checkpoint → next task. Per-task isolation via per-task tempdir + per-task socket prevents counter pollution.

### Error & Failure Propagation

- **Phase 1**: hook errors must NEVER block the Bash call. `set -e` plus `trap` to `exit 0` on any error. JSON parse failure → silent exit (no nudge, no harm). daemon health probe fails → silent exit.
- **Phase 2**: per-task failures are isolated — a crashed task's checkpoint records `status: "failed"` and the harness moves on. Cost-cap breach aborts the whole run cleanly (writes partial results, exits non-zero so CI catches it). API `429`s honor `Retry-After`; `5xx`s retry up to 5×. Anthropic `messages.create` timeout = 10min default; per-task timeout (15min wall-clock) supersedes.

### State Lifecycle Risks

- **Phase 1**: hook writes the health-probe file to `${XDG_RUNTIME_DIR:-/tmp}/rts-up.$PPID`. Stale entries after a daemon crash → 60s mtime gate auto-recovers on next probe. No persistent state.
- **Phase 2**: `preds.json` checkpoint is append-only per (task, arm). A torn write on crash → harness validates JSON on resume; rolls back to last-known-good. Per-task tempdirs are cleaned up on success; left in place on failure for post-mortem. The `bench-results/<version>/` outputs are committed to repo; the `runs/<run-id>/` raw trajectories are NOT committed (in `.gitignore`).

### API Surface Parity

- **No protocol-v0 wire-shape change.** Phase 1 is config-only; Phase 2 only consumes existing MCP tools.
- **No new MCP tools.** All existing tools work; the harness exercises `mcp__rts__find_symbol`, `mcp__rts__grep`, `mcp__rts__find_callers` most heavily.
- **No daemon side changes.** Phase 2 leverages `Daemon.Stats` for cross-checking but doesn't add fields.

### Integration Test Scenarios

1. **Phase 1 — hook nudge under realistic Bash heredoc**: agent issues `bash -c 'rg "foo" crates/ && echo done'` (sub-shell). Verify the hook detects `rg crates/` as in-workspace and emits the nudge.
2. **Phase 1 — non-workspace grep stays silent**: agent issues `grep -r 'foo' /tmp/notes/`. Verify no nudge.
3. **Phase 1 — `RTS_HOOK_DISABLED=1` env propagation**: `make my-target` invokes a sub-make that issues `grep`. Verify env propagates and hook is silent.
4. **Phase 2 — A/B clean isolation**: two parallel-running tasks have their own daemon sockets and don't see each other's counters via `Daemon.Stats`.
5. **Phase 2 — cost-cap trip**: configure budget=$0.01, run, verify clean abort after 1-2 tasks with partial results written.

## Acceptance Criteria

### Functional Requirements

- [ ] **AC1 (Phase 1):** Hook fires on `Bash` tool calls matching the `grep|rg|egrep|fgrep|find` pattern. Nudge text contains the equivalent `mcp__rts__*` tool name + at least one example arg.
- [ ] **AC2 (Phase 1):** Hook is silent (no stdout, exit 0) for Bash calls NOT matching the pattern (verified for `cargo build`, `git status`, `cat foo`).
- [ ] **AC3 (Phase 1):** `RTS_HOOK_DISABLED=1` opt-out works.
- [ ] **AC4 (Phase 1):** Hook latency p95 < 20ms warm path, measured on 100 invocations.
- [ ] **AC5 (Phase 1):** `.mcp.json` with `alwaysLoad: true` results in `mcp__rts__*` tools appearing in the top-of-prompt tool list without an explicit `ToolSearch` call. Verified by inspecting the deferred-tools listing in a fresh session.
- [ ] **AC6 (Phase 2):** `agent-bench run --tasks corpus/swe-bench-lite-v1.json` completes 30 tasks × 2 arms end-to-end on a Linux x86_64 CI runner within $100 (Sonnet) and 4 hours wall-clock.
- [ ] **AC7 (Phase 2):** Final report includes per-arm tool-use ratio with Wilson-score 95% CI, per-arm wall-clock latency median + p95.
- [ ] **AC8 (Phase 2):** Resume-from-checkpoint works: kill harness at task 5/30, restart, verify it skips tasks 1-5 and resumes from 6.
- [ ] **AC9 (Phase 2):** Hard budget cap aborts cleanly with partial results written when 90% of `--budget-usd` is consumed.

### Non-Functional Requirements

- [ ] Hook script passes `shellcheck`.
- [ ] Python harness passes `ruff check` + `mypy --strict`.
- [ ] No new HTTP/network code paths in any `crates/*` member (verified by existing `cargo tree` CI gate).
- [ ] All existing `cargo test --workspace --release` tests pass.

### Quality Gates

- [ ] **Phase 1 test coverage**: every R2 pattern in the brainstorm is asserted in the hook test suite.
- [ ] **Phase 2 reproducibility**: re-running the harness with the same seed + same model snapshot ID + same task ordering yields identical tool-use counts within Sonnet's intrinsic nondeterminism (run twice; deltas reported in baseline `README`).
- [ ] **Documentation**: `agent-bench/README.md` explains how to read results to a reader who hasn't seen this plan.

## Success Metrics

- **S1 (closes the loop)**: After this pair ships, the next time the user asks *"are you regularly using it?"*, the answer cites (a) a number from the auto-dump (#105) AND (b) the tool-use ratio from the most recent baseline run.
- **S2 (treatment > control)**: Treatment-arm tool-use ratio for `mcp__rts__*` is measurably higher than control. Threshold not pre-committed (we don't know the baseline yet) — but treatment-arm ratio <10% means the hook + eager-load didn't shift behavior, and Phase 1 needs revisiting.
- **S3 (no task-success regression)**: Treatment-arm task success rate is **not worse** than control. Deferred to U2.10 (Docker eval); for v1, manual spot-check of 3 representative patches.
- **S4 (regression signal)**: Per-release-tag bench runs are committed to `bench-results/`; a treatment-arm ratio regression between releases triggers a follow-up investigation before the next tag.

## Dependencies & Prerequisites

- **Claude Code v2.1.121+** for `alwaysLoad` support. Confirmed during U1.1 spike.
- **Anthropic API access** with sufficient budget for ~600 LLM runs per release-gate bench. ~$50-100 Sonnet, ~$300+ Opus.
- **HuggingFace `datasets` library** for SWE-bench-lite loading.
- **mini-swe-agent** (or fork) as harness skeleton, OR Anthropic Agent SDK if U2.1 spike concludes that's cleaner.
- **Existing `crates/rts-bench/src/mcp_runner.rs`** as the reference shape for the Python MCP bridge.
- **#102 + #104 + #105 merged** (already done). The harness reads `Daemon.Stats` as a cross-check (not primary attribution) and the hook leverages the auto-dump's daemon-existence signal.

## Risk Analysis & Mitigation

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Docker x86_64 requirement blocks macOS local dev | High | Medium | Skip Docker eval in v1 (defer to U2.10 post-merge); CI runs on ubuntu-latest x86_64. Tool-use ratio is the primary metric and doesn't need Docker. |
| `alwaysLoad: true` doesn't actually promote tools in current Claude Code | Medium | High | U1.1 spike validates before committing. Fallback: AGENTS.md soft-load (already in place from #102) remains. |
| Hook latency exceeds budget on cold daemon-probe | Medium | Low | Cached probe (60s mtime gate). If still too slow, drop probe entirely and always nudge — users with rts not installed see a "consider installing rts" message instead, which is also a win. |
| Anthropic API costs balloon past estimate | Medium | High | Pre-flight cost estimate; hard budget cap; per-task token cap; turn cap; abort-on-90%-budget. |
| n=30 statistical power insufficient | High | Medium | Pre-register tool-use ratio as primary; report Wilson CI; call results directional, not significant. Per best-practices research, n=30 needs ~25-point delta for p<0.05 — set expectations accordingly. |
| MCP-stdio bridge complexity (raw SDK path) | Medium | Medium | U2.1 spike decides Agent SDK vs raw SDK. If raw SDK, mirror `crates/rts-bench/src/mcp_runner.rs` line-by-line — known-good pattern. |
| SWE-bench-lite task takes much longer than 5min on chosen hardware | Medium | Medium | U2.1 measures wall-clock empirically. If too slow, drop subset size to 15 tasks for v1. |
| Tool-use attribution miscounts | Low | High | Use Anthropic message-log scan (canonical per research). Cross-check vs `Daemon.Stats` deltas as a sanity check — if they disagree by >10%, investigate. |
| Hook breaks legitimate `Bash grep` for users who genuinely want raw grep | Medium | Low | Soft enforcement only. `RTS_HOOK_DISABLED=1` propagates across subshells. Document in AGENTS.md. |

## Resource Requirements

- **Phase 1**: ~1 person-day. Half-day spike (U1.1) + half-day implementation + testing. Bash + a small JSON schema update.
- **Phase 2**: ~3-5 person-days. Spike (U2.1, half-day) + scaffold + bridge + run loop + report + CI workflow + initial baseline run. Real-money cost: ~$100 for the baseline.
- **Total**: 4-6 person-days, two PRs, ~$100 ongoing per release-tag (Sonnet); $300+ on Opus runs.

## Future Considerations

- **Docker eval as a follow-up PR** (U2.10) — once the harness is shipping, adding patch-validation closes the success-rate metric.
- **User-global hook variant** — only after the project-local one is trusted (S2 satisfied across several release cycles).
- **Latency histograms in `Daemon.Stats`** (filed in #104 follow-up) would add a complementary metric: not just *how often* but *how slow*.
- **Public SWE-bench leaderboard entry** — once results are stable across 3+ releases, publishing a leaderboard entry alongside the README is a low-effort visibility multiplier.
- **Auto-tune the nudge text** — A/B variants of the `additionalContext` string (concise vs prescriptive vs example-heavy) to find the form that most-shifts behavior.

## Documentation Plan

- **`AGENTS.md`** — extend `## Tooling: use the rts index, not grep / rg` section with the active-nudge subsection (U1.6).
- **`agent-bench/README.md`** — new top-level doc explaining the harness, how to run, how to read results, cost expectations.
- **Main `README.md`** — link to `agent-bench/README.md` in the development/maintenance section.
- **`changelog.d/`** — two fragments (one per PR), following the #93 fragments workflow. Each fragment has motivator, what, why, verification, out-of-scope sections.
- **`docs/install.md`** — note `.mcp.json` project-scoped registration as an alternative to user-scoped `claude mcp add -s user`.

## Implementation-Time Unknowns (Deferred to execution)

These are intentional gaps for `ce:work` to resolve during implementation, not failures of the plan:

1. **Anthropic Agent SDK vs raw SDK + custom bridge.** U2.1 spike makes the call. Recommendation: Agent SDK if native `mcp_servers` with stdio support exists and is stable.
2. **Exact `${workspaceFolder}` placeholder in `.mcp.json`.** Verified during U1.1.
3. **Exact 30-task subset.** U2.9 makes the selection during execution; criteria already documented.
4. **Tool-use ratio threshold for S2.** Pre-baseline, we don't know it. After the first run, document the observed baseline in `bench-results/v0.5.7-baseline.md` and set a regression threshold (e.g. "treatment must not regress by >5pp") for future runs.
5. **Docker eval scheduling** (U2.10, deferred to follow-up PR).

## Sources & References

### Origin

- **Origin document**: [`docs/brainstorms/2026-05-16-agent-habit-and-benchmark-requirements.md`](../brainstorms/2026-05-16-agent-habit-and-benchmark-requirements.md) — Key decisions carried forward:
  - External corpus (SWE-bench-lite) over curated rts-favoring tasks
  - A/B over before/after (LLM-drift confound elimination)
  - Sonnet default, Opus opt-in for releases
  - Per-release cadence, not nightly
  - Hook is informational (`hookSpecificOutput.additionalContext`), never blocking
  - Project-local first; user-global only after trust is established
  - Tool-use ratio is the primary metric; success + latency are secondary descriptive

### Internal References

- `crates/rts-bench/src/mcp_runner.rs:64-244` — reference MCP-session driver (handshake, tools_call retry, close) for the Python bridge to mirror.
- `crates/rts-bench/src/semantic.rs::build_report` — reference pattern for corpus-driven JSON+Markdown reporting.
- `.github/workflows/ci.yml:65-85` — reference pattern for `--check-*` regression gates (we don't add to ci.yml but mirror the shape in `release.yml` / `agent-bench.yml`).
- `AGENTS.md:174-238` — the "Use the rts index, not grep" section the hook makes operational.
- `AGENTS.md:377-381` — HTTP-free invariant forcing the harness to live outside `rts-bench`.
- `changelog.d/README.md:18-37` — fragments workflow shape both PRs must follow.

### External References

- [Claude Code hooks reference](https://code.claude.com/docs/en/hooks) — `PreToolUse` JSON schema, exit codes, `hookSpecificOutput.additionalContext` semantics.
- [Claude Code MCP reference](https://code.claude.com/docs/en/mcp) — `alwaysLoad` per-server pin (v2.1.121+), `ENABLE_TOOL_SEARCH` env, scope precedence.
- [SWE-bench harness](https://github.com/SWE-bench/SWE-bench) — `swebench.harness.run_evaluation` canonical command, `predictions.json` shape.
- [SWE-bench Lite dataset](https://huggingface.co/datasets/princeton-nlp/SWE-bench_Lite) — 300 test instances, all Python, fields confirmed.
- [mini-SWE-agent](https://mini-swe-agent.com/latest/usage/swebench/) — harness skeleton with built-in cost/step limits, resume, trajectory storage.
- [Anthropic Python SDK](https://platform.claude.com/docs/en/api/sdks/python) — `messages.create(tools=…)`, retry/backoff config, `usage` fields for cost tracking.
- [Anthropic MCP connector](https://platform.claude.com/docs/en/docs/agents-and-tools/mcp-connector) — `mcp-client-2025-11-20` beta (HTTP/SSE only; not viable for our stdio rts-mcp).
- [Wilson score interval](https://en.wikipedia.org/wiki/Binomial_proportion_confidence_interval#Wilson_score_interval) — correct CI for proportions at small n.

### Related Work

- Internal PRs: [#102](https://github.com/njfio/rs-agent-code-utility/pull/102) (rts-bench `--output lines` + AGENTS.md cheatsheet), [#104](https://github.com/njfio/rs-agent-code-utility/pull/104) (`Daemon.Stats` RPC), [#105](https://github.com/njfio/rs-agent-code-utility/pull/105) (auto-dump on shutdown). All three set up the observability surface this plan operates on top of.
- External: [Princeton SWE-bench leaderboard](https://www.swebench.com/) — public reference results for sanity-checking our Sonnet baselines against community numbers.
