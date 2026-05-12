---
date: 2026-05-10
topic: agentic-retrieval-mcp
---

# Agentic Retrieval MCP — v1 Requirements

## Problem Frame

Today this repo is a ~148k-LOC Rust library and CLI ("Agent Code Utility") that does broad code analysis and *calls* LLMs. The intended consumer of v1 is the opposite: **AI coding agents** (Claude Code, Cursor, Cline, Aider) that *call us*.

Those agents currently burn tokens and wall-clock time orienting themselves by reading whole files, running `rg`, and re-parsing the same code every turn. We can win by becoming the **token-aware retrieval layer** they wish existed: a fast, persistent, multi-language code index that returns precise, budget-shaped slices over MCP. Speed comes from a hot in-memory AST/symbol index in a background daemon; token reduction comes from returning exactly what was asked for (plus only the minimum graph closure needed to make it understandable), not whole files.

Getting there requires cutting ~70% of the current surface. Most of what is there today (wiki gen, outbound AI service layer, security analyzers, refactoring engines, ML/embeddings stack, AST transformation) does not serve this product and gets archived for v1.

## Requirements

- **R1. MCP-first surface.** The product is an MCP server. Every v1 capability is exposed as an MCP tool that an AI coding agent can call. A thin local CLI is allowed for debugging/inspection but is not the supported surface.

- **R2. Repo map / outline.** Tool that returns a token-budgeted, structured outline of the workspace — files, top-level symbols, sizes, language breakdown — so an agent can orient in one call without reading anything.

- **R3. Symbol lookup.** Tools to find a symbol's definition, find references to it, and fetch its signature. Multi-language, AST-precise, language-aware (not regex). Replaces the agent's "grep then read several files to find the real def" loop.

- **R4. Token-budgeted slice extraction.** Tool that returns the body of a named symbol (or an explicit range), excluding the rest of the file. Includes a **skeleton mode** that returns signatures only (no bodies) until the agent asks for a body.

- **R5. Tree-shaken context.** When returning a slice, walk the AST/symbol graph and include only the minimum surrounding declarations the agent needs to understand it (types it uses, imports it depends on). Exclude unrelated siblings in the same file by default.

- **R6. Session-aware dedup.** The server is aware of an MCP session id and refuses to re-send code it has already returned in that session. Instead it returns a short "see earlier reply X" marker. Requires a small per-session cache; bounded and TTL'd.

- **R7. Persistent daemon + on-disk index.** A background service watches the workspace for file changes, keeps the AST + symbol index hot in memory, and persists enough to disk that cold-start after a reboot is fast. The MCP server is a thin client to the daemon.

- **R8. Multi-language support at parity with today.** All currently supported languages (Rust, JavaScript, TypeScript, Python, C, C++, Go, Java, PHP, Ruby, Swift, Kotlin) remain supported in v1. No language gets dropped just because we're cutting features.

- **R9. Local-only by default.** No network egress in v1. The product runs entirely on the user's machine. The current outbound LLM service layer is removed.

- **R10. Respect repo ignore rules.** `.gitignore` and `.git/info/exclude` are honored by the indexer. Vendored / build-output directories are not indexed by default.

- **R11. Drop-in MCP install.** Provide a documented install path that gets the daemon + MCP server working in Claude Code and at least one of (Cursor, Cline, Aider) without manual surgery.

## Success Criteria

All four are v1 acceptance gates, measured on a representative 100k-LOC mixed-language workspace:

- **S1. Query latency.** p95 warm query < 10ms; p95 cold (just after daemon start, hot in-memory index built) < 100ms.
- **S2. Token reduction.** On a small benchmark suite of agent tasks (locate function, get implementation, find callers, summarize module), the agent answers the same task with **≥50% fewer input tokens** vs a baseline of `rg` + `read_file`.
- **S3. Index footprint.** Initial index build < 5s; on-disk index < 50MB; resident daemon RAM < 200MB.
- **S4. Agent compatibility.** Works end-to-end as an MCP server in Claude Code + at least one other agent client (Cursor / Cline / Aider), with documented install.

The benchmark harness for S1 and S2 ships as part of v1, so the gates are reproducible, not aspirational.

## Scope Boundaries

Out of scope for v1 (candidates for v2+):

- **Structured search** (semantic + lexical + raw tree-sitter pattern DSL exposed as a tool).
- **Code reasoning** (call graph, callers/callees, impact / blast radius, diff-aware structured changes between revisions).
- **Safe edits** (AST-aware rename, apply-patch primitives).
- **Outbound LLM analysis** (existing OpenAI/Anthropic/Gemini/Ollama provider layer is archived, not migrated).
- **Security analysis** (taint analysis, SQL/command injection detectors, OWASP, vulnerability DB — archived, becomes its own product if revived).
- **Refactoring / AST transformation engines** (archived; revisit only after v2 safe-edits work).
- **Wiki generation, fuzz testing, CI/CD integration, code-evolution, test-coverage, performance-benchmarking modules** — archived as not serving agent retrieval.
- **Embeddings / ML / intent-mapping** (candle, hf-hub, tokenizers) — archived; semantic search returns in v2 if needed.
- **Remote / multi-user / hosted deployment.** Local-only.

## Key Decisions

- **Consumer is AI coding agents, not humans.** All product trade-offs are decided in favor of the agent caller. The human CLI exists for our own debugging.
- **Ruthless surface cut.** Of the current ~148k LOC, the four buckets above are archived for v1 (moved out of the default build, not refactored or wrapped).
- **Hot daemon, not stateless CLI.** The "super fast" target is unreachable without a persistent in-memory index. We accept the lifecycle complexity (file watcher, daemon supervision, on-disk persistence).
- **Token reduction is graph-based, not LLM-based.** We do not summarize via an LLM. Reduction comes from precise slicing, skeleton mode, tree-shaken graph closure, and session dedup. This keeps the product offline, deterministic, and fast.
- **Benchmarks are required, not optional.** S1–S4 numbers are part of the deliverable. Without them, "fast" and "fewer tokens" are unfalsifiable.
- **No new languages in v1.** Reuse the existing 12-language adapter set; do not add or drop.

## Dependencies / Assumptions

- The existing tree-sitter parsers, `parser.rs` / `tree.rs` / `query.rs` / `languages/*`, `symbol_table.rs`, `semantic_graph.rs`, `semantic_context.rs`, `code_map.rs`, and the cache infra are the load-bearing core that survives the cut and gets reshaped around a daemon.
- The MCP protocol surface and at least one client (Claude Code) is stable enough to ship against.
- "Workspace" in v1 means one root directory at a time; multi-workspace is a follow-up question for planning, not a blocker.

## Alternatives Considered

- **"Preserve everything, expose existing analyzers as MCP tools."** Rejected — keeps 148k LOC alive, slower startup, fights the speed/focus goal, and most of the surface doesn't serve agent retrieval.
- **"Per-session in-memory only, no daemon."** Rejected — agents pay full cold-start cost every session on large repos, killing S1.
- **"On-disk index, no daemon (stateless server)."** Rejected — eliminates hot in-memory queries, p95 unlikely to hit 10ms.
- **"Two binaries (tiny agent core + keep existing CLI)."** Considered. Rejected for v1 because it doubles the maintenance bill while everything human-facing is already best done by an AI agent calling the MCP server anyway. Easy to revisit later.
- **"Token reduction via LLM summarization."** Rejected — re-introduces the outbound AI service layer we're cutting, breaks the local-only / offline / deterministic property, adds latency.

## Outstanding Questions

### Resolve Before Planning

(none — brainstorm is complete enough to plan against)

### Deferred to Planning

- [Affects R7][Needs research] On-disk index format and storage engine — sled vs redb vs sqlite vs a custom format. Trade-off is fsync cost vs query latency vs ecosystem maturity. Decide during planning with a small spike.
- [Affects R7][Technical] Daemon transport — Unix socket vs loopback TCP vs stdio-only MCP. Affects multi-client behavior and Windows support.
- [Affects R7][Technical] Daemon lifecycle — auto-spawn on first MCP connect, brew/systemd service, or "launch the daemon as a subprocess of the MCP server." Affects R11 (drop-in install).
- [Affects R7][Needs research] File watcher strategy — `notify` crate, debounce window, handling editor swap-files and large rebuilds without thrashing.
- [Affects R7][Technical] Incremental re-parse — use tree-sitter's incremental edit API on save vs full-file re-parse. Likely incremental, but verify cost on big files.
- [Affects R5][Needs research] Tree-shaken context algorithm — what counts as "minimum closure" per language? Closure depth, generics/macros, transitive types, language-specific (e.g., Python dynamic dispatch).
- [Affects R4][Technical] Skeleton-mode semantics per language — definition of "signature" differs in Rust (lifetimes, generics), Python (decorators, type hints), Java (annotations), TS (overloads). Needs a per-language adapter rule set.
- [Affects R6][Technical] Session id semantics for MCP — does the MCP client provide one, or do we synthesize and pin to the connection? Eviction policy and content-hash strategy.
- [Affects R10][Technical] Beyond `.gitignore`: do we honor `.codexignore`, `.cursorignore`, or a tool-specific `.rtsignore`? Decide during planning.
- [Affects S2][Needs research] Concrete benchmark task set for token reduction — pick 5–10 representative agent tasks, define the baseline (`rg` + `read_file` per task) precisely, agree on how tokens are counted.
- [Affects R1][Product] Final binary/product name and the human CLI surface (debug-only `rts inspect` style? or a `rts` doctor-style command?). Cosmetic but worth deciding before v1 ships.

## Next Steps

→ `/ce:plan` for structured implementation planning
