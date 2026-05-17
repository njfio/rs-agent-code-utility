---
date: 2026-05-16
topic: agent-habit-and-benchmark
---

# Closing the agent-habit loop: PreToolUse nudge + agent-bench harness

## Problem Frame

The product has been asked *"are you regularly using it?"* six times in a single multi-day session. Every round produced the same answer: **no**. Telemetry (#104), auto-dump (#105), and a `--output lines` CLI (#102) made the data **queryable** and **automatic**, but didn't change behavior. The agent (the same one building rts) continues to reach for `Bash grep` and `Read` over `mcp__rts__*` by default.

The remaining gap is **behavioral**, not technical:

- The rts MCP tools work, are correct, and produce strictly better output than `rg`.
- The agent (me) doesn't reach for them because (a) `mcp__rts__*` are deferred-loaded behind `ToolSearch` friction and (b) `Bash grep` is one keystroke of muscle memory.
- Telemetry observes the gap; it doesn't close it.

This brainstorm covers two interventions, designed to be shipped together:

1. **#1 — Habit-shift via Claude Code hook.** Nudge the agent away from `Bash grep` on workspace paths *and* eager-load the rts MCP tools so they're first-class in the prompt.
2. **#10 — Agent-bench harness.** Measure whether the habit actually shifts on canonical agent tasks. Create a regression signal for "agents bypassing rts" before the next round of *"are you using it?"* reflection.

#1 enables the habit shift. #10 verifies it.

## Requirements

### Behavioral intervention (#1)

- **R1.** A `PreToolUse` hook in `.claude/hooks/` intercepts every `Bash` tool call. When the command contains `grep`, `rg`, `egrep`, `fgrep`, or `find` AND targets a path inside the rts workspace, the hook prints a one-line **informational** nudge to stderr suggesting the equivalent `mcp__rts__*` tool. The hook MUST NOT block the Bash call.
- **R2.** The nudge maps common patterns:
  - `grep -rn 'NAME'` / `rg 'NAME'` → suggest `mcp__rts__find_symbol --pattern 'NAME'` or `mcp__rts__grep`.
  - `rg 'fn NAME'` / `rg '^class NAME'` / `rg 'def NAME'` → suggest `mcp__rts__find_symbol --name 'NAME'`.
  - `grep '.NAME('` (call-site search) → suggest `mcp__rts__find_callers --name 'NAME'`.
  - `find . -name '*.rs'` (file enumeration) → suggest `mcp__rts__outline_workspace`.
- **R3.** A project-local `.claude/settings.local.json` (or equivalent Claude Code config) eager-loads the `mcp__rts__*` tools so they appear in the default top-of-prompt tool list rather than the deferred surface. Eliminates the `ToolSearch` round-trip cost.
- **R4.** The hook honors an opt-out: setting `RTS_HOOK_DISABLED=1` (or similar) skips the nudge entirely, for sessions where the user genuinely wants raw `Bash grep` (e.g. searching outside the indexed workspace).
- **R5.** The nudge MUST be useful even for users who don't yet have rts installed — when the hook can't detect a running rts-daemon, it prints a single-line *"rts not running; nudge skipped"* at debug-level only, not on every Bash call.

### Benchmark intervention (#10)

- **R6.** An `agent-bench` harness runs a fixed external corpus of agent tasks against the rts MCP surface and reports a quantitative usage metric. The corpus source is **SWE-bench-lite** — a public, reproducible benchmark of ~300 real GitHub issues, comparable across research literature. Tasks must come from the public dataset, not be designed to favor rts.
- **R7.** Each task runs as an **A/B trial**:
  - **Control arm**: agent has access to `Bash` (grep, rg, find, Read) but the `mcp__rts__*` tools are not available.
  - **Treatment arm**: agent has both `Bash` and the full `mcp__rts__*` toolset, with the #1 hook + eager-load active.
- **R8.** The harness reports three metrics per task and aggregated:
  - **Tool-use ratio** — fraction of agent tool calls that were `mcp__rts__*` in the treatment arm.
  - **Task success rate** — binary: did the agent's final patch make the failing tests pass?
  - **Wall-clock latency** — time-to-completion per task.
- **R9.** Initial scope: a curated subset of ~30 SWE-bench-lite tasks, filtered to repos in rts-supported languages where the task likely requires code navigation (not pure config / docs edits). Full corpus runs come later.
- **R10.** Default model for routine runs: **Claude Sonnet**. **Claude Opus** is opt-in via a flag for release-gate runs.
- **R11.** Cadence: per-release-tag, not nightly. Each `vX.Y.Z` release pushes results to a long-form CHANGELOG entry; the user sees the trend across versions without expensive nightly runs.

## Success Criteria

- **S1.** After this pair lands, the *next* time the user asks *"are you regularly using it?"*, the agent answers with a number from the auto-dump (#105) AND points at the most recent agent-bench treatment-arm tool-use ratio. Neither answer requires interpretation or guessing.
- **S2.** The tool-use ratio in the treatment arm is **measurably higher** than control on the SWE-bench-lite subset. We don't pre-commit to a threshold (we don't know the baseline yet), but a treatment arm that uses rts for <10% of tool calls means the hook + eager-load didn't shift behavior, and #1 needs revisiting.
- **S3.** Task success rate in the treatment arm is **not worse** than control. If giving the agent rts makes it solve fewer tasks, that's a product-quality red flag, not a usage win.
- **S4.** A regression in #S2 or #S3 between releases triggers an investigation before the next tag — the harness IS the regression signal.

## Scope Boundaries

- **Not in scope: hard enforcement.** The hook is informational. It MUST NOT block `Bash grep`; the agent or human can always proceed. Hard blocks create combative agent workflows and edge-case breakage.
- **Not in scope: cross-repo rollout of the hook.** The hook lives in *this repo's* `.claude/hooks/`. A user-global version that fires in every workspace is a future consideration once we know the project-local one is good.
- **Not in scope: a custom benchmark.** We use SWE-bench-lite specifically because it's external and reproducible. Inventing our own would risk grading our own homework.
- **Not in scope: optimizing the agent's prompt to prefer rts.** Prompt engineering for the bench's agent is a confound — we want to measure whether the **tool surface plus the hook** changes behavior, holding the prompt constant across arms.
- **Not in scope: shipping the bench results publicly in this round.** Internal-only data first; once we trust the harness, the results can become a public release artifact (a la SWE-bench leaderboards).

## Key Decisions

- **External corpus over curated.** Trades realism for comparability — SWE-bench-lite has known baselines from prior research; our results are interpretable in context. A curated rts-favoring corpus would be cheaper but uninterpretable.
- **A/B over before/after.** Bench-on-rts and bench-on-no-rts run in the same time window; eliminates LLM-drift confounds (sonnet-4.5 in March vs sonnet-4.7 in May would otherwise contaminate the signal).
- **Sonnet default, Opus opt-in.** ~5× cost difference per task means routine bench cadence stays affordable. Release-gate runs can pay the Opus premium for higher-confidence numbers.
- **Per-release cadence, not nightly.** Nightly is expensive (~$90/Sonnet, $300+/Opus per run) and noisier than useful. Per-tag aligns with the existing release workflow.
- **Hook is informational, not blocking.** Soft enforcement is what we want — agents should learn the better tool, not feel chained to it.

## Dependencies / Assumptions

- **Anthropic API access** with budget for ~600 LLM runs per release-gate bench (~$90 Sonnet, $300+ Opus). Without this, #10 reduces to a static capability check (the dismissed option from the brainstorm).
- **SWE-bench-lite tasks targeting rts-supported languages.** A spot check of the dataset confirms a usable subset exists; the harness filters out pure-config / docs tasks before running.
- **Claude Code's PreToolUse hook surface.** The hook contract for `Bash` interception is stable in the current Claude Code release. Assumed; verifiable on a half-day spike.
- **#102 + #104 + #105 are merged.** The harness consumes `Daemon.Stats` deltas to attribute tool calls, and the hook's "rts not running" detection uses the rts-mcp version banner.

## Alternatives Considered

- **Full enforcement (block `Bash grep` on workspace paths).** Rejected — combative, breaks legitimate uses (searching outside the index, binary content, vendored deps), and forces an opt-out treadmill. Soft nudge accomplishes 80% of the behavior shift with 0% of the edge-case breakage.
- **User-global hook from day one.** Rejected — premature. The project-local version is the experiment; promotion happens after we trust it.
- **Curated rts-favoring task corpus.** Rejected per Decision #1 — we'd be grading our own homework. External corpus is the trust-building shape.
- **Nightly bench cadence.** Rejected per Decision #4 — cost prohibitive without a clear signal benefit. Per-tag is sufficient for release gating.

## Outstanding Questions

### Resolve Before Planning

*(none — the brainstorm closed all blocking product questions.)*

### Deferred to Planning

- **[Affects R3][Technical]** What exactly is the project-local Claude Code config to eager-load `mcp__rts__*`? The deferred-tool mechanism is internal to Claude Code; the `.claude/settings.local.json` knob may or may not exist. **Needs research** during planning — a brief spike to confirm the right knob (settings JSON, hook output, MCP-config field, etc.).
- **[Affects R6][Technical]** What's the SWE-bench-lite dataset's exact format and how do we drive the rts-aware agent against it? **Needs research** — likely a Python harness that hits the Anthropic API with the rts MCP tools registered + a fixed system prompt + the SWE-bench task definition.
- **[Affects R8][Technical]** How do we **attribute** tool calls to rts vs Bash in the harness? Three options: (a) post-run analyse the Anthropic message log for `tool_use` blocks, (b) intercept via the rts-mcp side via `Daemon.Stats` deltas, (c) wrap the Bash tool to log invocations. The choice affects observability fidelity and harness complexity.
- **[Affects R9][Technical]** Which exact 30 SWE-bench-lite tasks form the initial subset? Filter rule: repo language ∈ rts-supported set AND issue title/body suggests code-navigation work. Final list is a planning artifact.
- **[Affects R11][Needs research]** Where do bench results live for the long-term trend? Options: a `bench/` directory in the repo (committed), a separate `rts-bench-results` repo (avoids polluting main repo's git history), or external (datasette, simple-stats). Choose during planning.

## Next Steps

→ `/ce:plan` for structured implementation planning — both interventions can plan in parallel since they share no code paths (hook is `.claude/hooks/`-only; harness is a new `bench/` directory or sibling crate).
