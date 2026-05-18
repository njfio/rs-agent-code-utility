---
date: 2026-05-17
topic: what-else-after-phase-2-and-readme
focus: open-ended ("what else?")
---

# Ideation: What else? (round 9, post #94–#108)

## Codebase Context

**Project shape.** Rust 2024 / Cargo workspace, MSRV 1.85, resolver=3. Four crates: `rts-core` (tree-sitter wrapper, 12 grammars), `rts-daemon` (persistent per-workspace daemon, redb + notify), `rts-mcp` (rmcp 1.6 stdio bridge), `rts-bench` (operator CLI + bench harness). Sibling `agent-bench/` is a Python/uv SWE-bench-lite A/B harness landed in #107.

**Shipped in the last 14 PRs (#94–#108).** Reference-graph correctness on cold-walk (#100) + live-edit (#103) paths. Per-session call counters via `Daemon.Stats` (#104) and auto-dump on shutdown (#105). PreToolUse hook nudging Bash grep → `mcp__rts__grep` in Claude Code (#106). agent-bench harness foundation: bridge + run loop + Wilson-CI reporter, 28 mock-API tests pass (#107). README rewrite from 403-line maintenance doc to 142-line pitch + new `docs/development.md` and `docs/demo.md` (#108 open).

**What hasn't been addressed (the surface area for "what else?"):**

- **Distribution friction**: no `brew install rts`, no `cargo install rts`, no `npx` wrapper, no `claude mcp add` one-liner that auto-downloads the binary. First-run failures (daemon not running, MCP not registered, stale index) are silent.
- **Cross-agent reach**: the PreToolUse nudge only fires in Claude Code. Cursor / Continue / Aider / Cline are mentioned in README but get no nudge. Adoption ceiling = "users whose agent reaches for MCP AND that agent is Claude Code."
- **Multi-line `Index.Grep`**: regex is single-line; multi-line patterns still need `rg`.
- **Call-edge parity**: 6 of 12 indexed languages have regex-fallback call detection (Go/Java/PHP/Ruby/Swift/C#), not AST-precise.
- **Cold-mount cost**: ~6s on 100k LOC, paid per session.
- **Cross-session telemetry**: per-machine, per-session; no aggregation.
- **`archive/` clutter**: 30k LOC of dead pre-pivot AI/security/SARIF analyzers in the repo's first-impression file tree.
- **`docs/solutions/` doesn't exist**: every ideation/planning round restarts from zero institutional knowledge.
- **Hook is one-directional**: only nudges *toward* rts; doesn't surface when rts returned a low-confidence answer that should fall back to `rg`.
- **No "ask the index in English"**: every tool is structured; user must already know the surface.

**Past learnings.** `docs/solutions/` is empty (confirmed via learnings-researcher). No retrospective notes exist — every ideation round restarts from zero. Worth scaffolding alongside one of the survivors.

## Ranked Ideas

### 1. `rts doctor` — first-run health check

**Description:** A single CLI subcommand that diagnoses install state across all configured agents: binary version, daemon reachability, per-workspace daemon PIDs, MCP registration across Claude Code / Cursor / Continue / Aider / Cline, hook installation, index freshness. Prints a checklist with copy-pasteable one-line fixes.

**Rationale:** The #1 first-run failure pattern today is silent: daemon not running, MCP not registered to the right scope, stale index, wrong workspace. Users currently grep through the README to debug. This is the cheapest possible investment in adoption beyond *"users whose agent reaches for MCP."*

**Downsides:** Maintenance — each new agent host adds a config-detect path. Doesn't *create* new capability; it surfaces existing state.

**Confidence:** 90%
**Complexity:** Low
**Status:** Explored (brainstorm queued 2026-05-18)

### 2. agent-bench public leaderboard + Phase 2 PR-B baseline

**Description:** Promote the audited 6-language corpus + Wilson-CI A/B harness from #107 into a versioned, citeable benchmark with `agent-bench run`, a published JSON results schema, and the first real Sonnet baseline committed to `bench-results/`. The benchmark becomes its own product surface — agent vendors can submit runs against a stable, public baseline.

**Rationale:** Closes the 9-round *"are you regularly using it?"* loop with a number, not a vibe. Turns every future rts change into a measurable delta against a public baseline. The corpus across rust-log / ripgrep / chalk / cobra / gson / requests / dogfood-v3 is unique — no published benchmark has that shape today.

**Downsides:** Real API spend (~$50-100/run Sonnet, $300+ Opus). Maintaining a leaderboard is its own commitment; if external submissions don't come, it's a stale page.

**Confidence:** 75%
**Complexity:** Medium
**Status:** Unexplored

### 3. `Index.Grep` v2 — multiline regex + structural queries + within-symbol scope

**Description:** Three extensions to the same tool, shipped together:
- `(?s)` multiline regex over the indexed bytes
- new `Index.StructGrep` variant that takes a tree-sitter query and runs it over the parsed-tree cache (`@reference.call`-style structural search)
- `within_symbol: "fn_name"` filter on the existing literal grep, intersecting byte-range-of-def with the byte-range-of-match

Combines two raw ideas (P7 multi-line + structural; U4 symbol-scoped) into one coherent tool upgrade.

**Rationale:** Multi-line regex is the #1 reason agents bail from rts back to `rg` mid-session — known leak in the value proposition. Structural grep is the unique moat over `rg`: *"find every impl block containing an unsafe fn"* is a one-tool-call answer, not a grep-then-filter. Symbol-scoped grep makes refactor-shaped searches sub-second.

**Downsides:** Tree-sitter query string is a power-user API; needs good error messages on malformed queries. Multiline regex grows the DFA size cap; needs a budget.

**Confidence:** 85%
**Complexity:** Medium
**Status:** Explored (brainstorm queued 2026-05-18)

### 4. Persisted cold-mount index

**Description:** Serialize the post-cold-walk redb index snapshot to `~/.cache/rts/<workspace-hash>/` and rehydrate on subsequent daemon startup, re-parsing only files whose mtime/size changed. Invalidate on schema-version bump or tree-sitter grammar version change.

**Rationale:** Cold mount on 100k LOC takes ~6 s today and is paid every time the daemon goes idle (10 min default). Killing it makes *"open editor, ask question"* feel instant for the first query of a session — the only latency users perceive.

**Downsides:** Cache invalidation is the perennial hard problem. mtime races; multi-machine workspaces (network FS) need a fingerprint that survives clock skew.

**Confidence:** 80%
**Complexity:** Medium
**Status:** Explored (brainstorm queued 2026-05-18)

### 5. Universal agent autowire + generic PreToolUse policy engine

**Description:** Two paired changes:
- `rts install --agent all` detects installed coding agents (Claude Code, Cursor, Continue, Aider, Cline, Zed AI, Windsurf) and writes per-agent MCP config + system-prompt injection where each supports it
- Factor `.claude/hooks/rts-nudge.sh` into a tiny declarative tool-nudge engine driven by a TOML ruleset; rts becomes one rule among many

Combines two raw ideas (P3 + L3) — same problem at two layers.

**Rationale:** README promises Cursor / Continue / Aider / Cline support; only Claude Code has the active behavior nudge today. Each non-Claude agent is a silent loss. The generic policy engine lifts a pattern useful well beyond rts (don't grep `node_modules/`, prefer `rg` over plain grep, etc.).

**Downsides:** Each agent has a different injection surface — what the nudge looks like in Cursor's rules vs Aider's system prompt is real engineering, not translation. Risk of building a hook framework that's worse than each agent's native config.

**Confidence:** 70%
**Complexity:** Medium-High
**Status:** Unexplored

### 6. Refactor Preview as a first-class query

**Description:** A new read-only MCP tool `Index.RenamePreview(old, new)` returns the exact unified diff of every call site + def site that would change for a symbol rename, without touching disk. The daemon owns the textual edit semantics; the agent (or human) reviews the diff and decides whether to apply.

**Rationale:** Refactors are the agent's most error-prone op today (grep-and-sed across 12 languages with locale-dependent boundary handling). Making refactor preview a graph query reframes rts from *"retrieval"* to *"retrieval + safe-edit preview."* On 6 AST-precise languages this is high-confidence; on the regex-fallback 6 we'd need a confidence score per site.

**Downsides:** Boldest of the six — partially redefines what rts is. Agents may already do this through Edit/Write tools; the value is being *atomic + reviewable* per symbol, not per-file.

**Confidence:** 60%
**Complexity:** High
**Status:** Unexplored

## Rejection Summary

| # | Idea | Reason rejected |
|---|---|---|
| 1 | Blast Radius Heatmap | Overlaps `impact_of` which exposes BFS-with-rank already |
| 2 | Reverse-PageRank `UpstreamOf` | Adjacent to `impact_of`; small marginal value |
| 3 | Daemon-as-MCP-server (delete `rts-mcp`) | High-risk refactor; protocol-v0 boundary is load-bearing; zero user-facing win |
| 4 | One daemon, many workspaces | Superseded by federated-index (A2) as the bigger play; both deferred |
| 5 | Single `query` tool with intent routing | Speculative — agents call the right tool today; no evidence of the failure mode |
| 6 | Auto-generated changelog fragments | Too small for ideation (10-min commit-msg hook) |
| 7 | Continuous bench-on-save | Bench takes minutes, not seconds; wrong granularity for a watcher |
| 8 | Workspace-of-workspaces (federated index) | Big & important but deserves its own ideation round; not actionable now |
| 9 | `rts` pushes / subscriptions | Ahead of its time; MCP push channel + agent subscription model are immature |
| 10 | Shared anonymous corpus + learned ranker | Privacy + infra leap; needs dedicated brainstorm before ideation can scope it |
| 11 | Index everything non-code (OpenAPI / SQL / Protobuf) | Scope explosion; pick a single seam first |
| 12 | HTTP + curl-able CLI | Distribution amplifier but `rts-bench query` already exposes CLI; HTTP is bigger lift. **Honorable mention.** |
| 13 | Public `rts-protocol` crate | Premature — no external consumers yet |
| 14 | `tree-sitter-callgraph` query pack | Premature for same reason |
| 15 | `mcp-stdio` client libraries | One in-tree consumer doesn't justify lib extraction |
| 16 | `changelogd` standalone tool | Off-mission for rts |
| 17 | Decision-record schema for plans/brainstorms | Internal-only; useful but not a product improvement |
| 18 | `rts ask` (English query gateway) | The hook + nudge cover most of this need; needs evidence first |
| 19 | Bidirectional hook (low-confidence) | Useful but data-light; revisit after agent-bench gives empirical signal |
| 20 | Delete `archive/` | Too small for ideation (one-line PR); on the obvious-cleanup pile |
| 21 | Cross-session telemetry sink (`rts insights`) | Folds into #2 leaderboard |
| 22 | Symbol Diff Between Refs | Folds into Commit-aware temporal index; deferred |
| 23 | Dead-Code Frontier (standalone) | Folds into Symbol Profile API; weaker alone |
| 24 | Doc-Coverage Report (standalone) | Same |
| 25 | Multi-dim importance (standalone) | Folds into Symbol Profile API |
| 26 | Symbol Profile API (synthesized C2) | Close call; lower leverage than the 6 chosen |
| 27 | Commit-aware temporal index (synthesized C3) | Deferred; competes with the 6 for attention |
| 28 | `docs/solutions/` scaffold (standalone) | Belongs alongside whatever ship next, not its own line item |

## Session Log

- 2026-05-17: Initial ideation — 35 raw candidates from 5 sub-agents across distinct frames (pain/friction, unmet need, inversion/removal, assumption-breaking, leverage/compounding); 3 cross-cutting combinations synthesized; 6 survivors after adversarial filter. Frames preserved: pain (P), unmet (U), inversion (I), assumption (A), leverage (L); combinations (C). User context: 9th round of *"what else?"* in a multi-day session that shipped #94–#108.
- 2026-05-18: User selected three survivors for brainstorming: #1 (`rts doctor`), #3 (`Index.Grep` v2), #4 (Persisted cold-mount index). Brainstorm order: #1 first (lowest complexity, fastest to define), then #3 (largest value-prop win), then #4 (latency/UX). Each will produce its own `docs/brainstorms/2026-05-18-*-requirements.md`.
