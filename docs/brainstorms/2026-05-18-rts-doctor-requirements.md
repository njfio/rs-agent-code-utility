---
date: 2026-05-18
topic: rts-doctor
---

# `rts doctor` — first-run health check

## Problem Frame

The #1 first-run failure pattern for rts is silent. A user installs the binary, registers the MCP server, opens their agent — and nothing visible happens. Possible silent failures:

- daemon binary missing from `$PATH`
- daemon not running (or running but pinned to a different workspace)
- MCP not registered to the right scope (user vs project vs local in Claude Code; analogous splits in Cursor/Continue)
- `.mcp.json` present but malformed or pointing at a stale binary
- PreToolUse hook (`.claude/hooks/rts-nudge.sh`) missing or non-executable
- index never finished cold-walk; `find_symbol` returns empty
- workspace path mismatch — daemon happily indexes the wrong directory

Today the user grep-debugs the README, tails the daemon log, runs `ps` and `lsof`, and eventually files an issue. Adoption ceiling = *"users patient enough to debug a silent install."*

`rts doctor` is the cheapest possible investment past that ceiling: one subcommand that names every install signal and prints a copy-pasteable fix for anything broken.

## Requirements

- **R1.** `rts-bench doctor` is a new subcommand on the existing `rts-bench` binary. Runs offline. No network calls.
- **R2.** Doctor is **read-only**. It never writes to a user config file, never restarts the daemon, never installs anything. Side-effect-free except for `stderr`/`stdout`.
- **R3.** Doctor reports two signal classes per run:
  - **Install state** — binary version, daemon binary on `$PATH`, MCP registration in each supported agent host, hook file present + executable.
  - **Workspace state** — for the workspace at `$PWD`: daemon PID (or "not running"), workspace path the daemon is pinned to, index generation, last-completed-cold-walk timestamp, file count indexed.
- **R4.** Doctor covers all 5 advertised agent hosts: Claude Code, Cursor, Continue, Aider, Cline. Claude Code / Cursor / Continue use **hard detection** (canonical config-file paths). Aider / Cline use **soft detection** (best-effort: look for known config locations and CLI invocation patterns). Soft-detection results are labelled `?` in the checklist and never fail the run on their own.
- **R5.** Default output is a **human checklist**, grouped by section, with one row per signal. Each row is `[OK]`, `[WARN]`, or `[FAIL]`. Every `WARN` and `FAIL` is followed on the next line by a copy-pasteable one-line fix command (or, when no single command suffices, a short fix description + a link to the relevant section of `docs/install.md`).
- **R6.** `rts-bench doctor --json` produces machine-readable output: a single JSON object with the same signals, designed for agent consumption and for future automation. Shape stable across patch releases; documented in `docs/protocol-v0.md` or a sibling `docs/doctor-schema.md`.
- **R7.** Exit code semantics:
  - `0` — no `FAIL` rows (any `WARN` rows allowed).
  - `1` — any `FAIL` row.
  - `2` — doctor itself failed (couldn't read its own binary, panicked, etc.).
- **R8.** Doctor's **own latency budget** is `<500 ms p95` on a healthy install (no daemon spawn, no cold walk). It probes the daemon over the existing protocol-v0 socket; it does not start a daemon to ask one question.
- **R9.** When the daemon is reachable, doctor uses one round-trip for workspace state. Choice of RPC (existing `Daemon.Stats` vs a new `Daemon.Ping`) is a planning-time decision (see Deferred questions). When the daemon is unreachable, doctor reports the install signals it can determine statically and flags the workspace section as `[WARN] daemon not running`.
- **R10.** Doctor's checklist is grouped into named sections so the JSON shape and the human shape carry the same structure. Sections: `binary`, `daemon`, `mcp_registration`, `hook`, `workspace_index`. Each section header is independently runnable for testing.

## Success Criteria

- **SC1.** A new user with a clean machine and a broken install (e.g., MCP not registered) runs `rts-bench doctor`, copies the suggested fix, runs it, re-runs doctor, and sees all `[OK]`. End-to-end without consulting the README.
- **SC2.** On a healthy install the human output fits in one terminal screen (~30 lines) and the run completes in under 500 ms p95.
- **SC3.** The `--json` output is consumed by at least one downstream surface within 30 days of doctor shipping (the obvious candidate is the agent-bench harness's preflight in `agent-bench/`).
- **SC4.** The README's *"Status"* section gains a single line: *"`rts-bench doctor` diagnoses install state across all five supported agents."*

## Scope Boundaries

- **Out of scope (v1):** `--fix` mode that applies recommended changes. Doctor is diagnostic-only in v1; `--fix` is a separate later proposal.
- **Out of scope (v1):** behavioral state. Per-method call counters, nudge-fire log, recent error rate. These live in `daemon-stats` (#104) and the auto-dump-on-shutdown (#105) and stay there.
- **Out of scope (v1):** cross-version drift detection. The known "Claude Code spawned a pre-#104 rts-mcp at session start" version-skew bug is a real signal class but stays a separate brainstorm.
- **Out of scope (v1):** network probes, telemetry upload, calling out to GitHub for the latest version. Offline-only.
- **Out of scope (v1):** subsuming `rts install`. Doctor diagnoses; an install subcommand (if it ever ships) is a separate brainstorm.
- **Out of scope (v1):** "deep" workspace audits — per-file parse error rates, per-language coverage, grammar version mismatches. Surface area too big for v1.

## Key Decisions

- **Read-only over diagnostic + opt-in `--fix`** — auto-fix touches user config files; risk/reward is wrong for v1 when the failure surface is still being mapped. Defer `--fix` until field data tells us which fixes are universally safe.
- **All 5 agent hosts at v1, with soft-detect labelling for Aider/Cline** — matches what the README advertises. Soft-detect is honest: doctor reports what it could and couldn't determine, rather than silently skipping.
- **Lean signal classes (install + workspace only)** — behavioral and version-drift signals are real but live in separate, already-shipped surfaces. Keeping doctor narrow makes the "all-OK" case unambiguous.
- **Human checklist + inline fix snippets as default; `--json` flag** — humans read the failure context inline with the suggested fix, agents consume `--json`. One subcommand, two audiences, neither one has to read the other's format.
- **Subcommand on `rts-bench`** — lowest packaging cost. A future thin `rts` binary that re-exports common subcommands is its own decision.
- **Exit `0` on `WARN`, `1` on `FAIL`** — lets CI gates differentiate "broken" from "imperfect."

## Dependencies / Assumptions

- Doctor reads (does not modify) `.mcp.json`, `~/.claude/settings.json`, `~/.cursor/`, `~/.continue/`, `.aider/`, `.cline/` — exact paths to be confirmed in planning.
- Doctor assumes the protocol-v0 Unix socket convention from `rts-daemon` for reachability probes.
- Soft-detect for Aider relies on `~/.aider.conf.yml` or `AIDER_CONFIG`; soft-detect for Cline relies on the VS Code extension's settings file location. Both are best-effort.
- Doctor depends on `Daemon.Stats` (or a new `Daemon.Ping`) being callable without a running mount. To confirm in planning.

## Outstanding Questions

### Resolve Before Planning

*(none — all product-level decisions are made)*

### Deferred to Planning

- **[Affects R3]** **[Technical]** What's the precise definition of "stale" for the index-freshness signal? Options: (a) `index_generation == git HEAD commit`, (b) "any unwatched file under workspace has mtime > last cold-walk", (c) a delta-LOC threshold. Likely (b) with explicit override.
- **[Affects R4]** **[Needs research]** Per-host config file paths and MCP-scope conventions for each of Claude Code (user/project/local), Cursor, Continue, Aider, Cline. Some are documented; some require reading each tool's source or community docs.
- **[Affects R9]** **[Technical]** Reachability probe: extend `Daemon.Stats` (cheap, already exists) or add a dedicated `Daemon.Ping`? Probe choice affects what we can report when the daemon is reachable but its workspace is wrong.
- **[Affects R3]** **[Technical]** Workspace-mismatch detection: how does doctor identify that the running daemon is pinned to a *different* workspace than `$PWD`? Daemon currently emits its pinned-workspace path in `Daemon.Stats`; confirm this is exposed.
- **[Affects R4]** **[Technical]** Claude Code MCP scope detection: rts may be registered in user/project/local scope. Doctor should report which scope and warn on multi-scope registration (the "two different rts versions wired up" foot-gun). Need to confirm the canonical lookup order.
- **[Affects R5]** **[Product]** All-OK output format: still print every row, or collapse to a one-line `All checks passed (12 OK).`? Trade-off: discoverability vs noise. Lean toward "print every row but compact."
- **[Affects R4]** **[Needs research]** Soft-detect criteria for Aider/Cline — what specifically counts as evidence that rts is wired up? File presence? CLI flag scan? Version pin in config? Document the criteria in planning so users know what doctor is and isn't checking.
- **[Affects R6]** **[Technical]** JSON schema versioning: is the doctor JSON considered part of protocol-v0 (versioned with the daemon protocol), part of a new doctor-schema-v0, or unversioned? Recommend its own schema so doctor can evolve without bumping the daemon protocol.

## Next Steps

→ Continue brainstorming idea #3 (`Index.Grep` v2) next, then idea #4 (Persisted cold-mount index), per the ideation queue. After all three brainstorms land, run `/ce:plan` on each in turn.
