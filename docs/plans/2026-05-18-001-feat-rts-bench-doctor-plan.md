---
title: "feat(rts-bench): rts-bench doctor — read-only first-run health check"
type: feat
status: active
date: 2026-05-18
origin: docs/brainstorms/2026-05-18-rts-doctor-requirements.md
---

# `rts-bench doctor` — read-only first-run health check

## Overview

Ship a new `rts-bench doctor` subcommand: a read-only diagnostic CLI that inspects rts install state across the user's machine and the current workspace, prints a sectioned OK/WARN/FAIL checklist with copy-pasteable one-line fixes for every failing row, and exposes the same data as machine-readable JSON for agent consumption.

The user-facing contract is one sentence: *"if `rts-bench doctor` returns 0, your install is healthy; if it returns 1, the rows tell you exactly what to fix."*

Doctor is **read-only**: it never writes to a user config file, never restarts the daemon, never installs anything. The diagnosis surface covers two signal classes — **install state** (binary version, daemon binary on PATH, MCP registration in 5 agent hosts, hook file present and executable) and **workspace state** (per-workspace daemon PID, pinned-workspace path, index generation, cold-walk completion timestamp, file count). Behavioral telemetry stays in `daemon-stats` (#104); version-drift detection stays out of scope.

This plan also addresses three prerequisite gaps surfaced during research:

1. `Daemon.Stats` does not currently expose the pinned workspace path, `index_generation`, or `cold_walk_completed_at_ms`. The plan extends `Daemon.Stats` additively, with a capability bump, before doctor's `workspace_index` section can be implemented in a single round-trip.
2. The brainstorm's `--json` flag conflicts with the existing `rts-bench query --output [json|lines]` convention. Doctor uses `--output [human|json]`.
3. Continue's config is YAML, not JSON; planning corrects this.

## Problem Statement / Motivation

The #1 first-run failure pattern for rts is silent. A user installs the binary, registers the MCP server, opens their agent, and nothing visible happens. Today the user grep-debugs the README, tails the daemon log, runs `ps` and `lsof`, and eventually files an issue. Adoption ceiling = *"users patient enough to debug a silent install."*

Doctor is the cheapest possible investment past that ceiling: one subcommand that names every install signal and prints a copy-pasteable fix for anything broken. It's grounded in two existing surfaces — the rts-bench CLI (the operator-facing binary) and `Daemon.Stats` (#104) — and surfaces what's already true on disk rather than introducing new state.

## Proposed Solution

A new `Doctor` clap subcommand on `rts-bench` runs five independent diagnostic sections in stable order — `binary`, `daemon`, `mcp_registration`, `hook`, `workspace_index` — each emitting OK/WARN/FAIL rows with inline fix snippets. The default output is a human checklist; `--output json` produces a machine-readable shape stable across patch releases (`schema_version: "doctor-v0"`, additive `capabilities: []` array mirroring protocol-v0).

The `daemon` section probes the workspace's per-workspace socket; on success, one round-trip to a v0.6+ `Daemon.Stats` (extended additively with `pinned_workspace_path`, `index_generation`, `cold_walk_completed_at_ms`) provides everything doctor needs for both `daemon` and `workspace_index`. Against a pre-v0.6 daemon, doctor degrades gracefully via the existing `Workspace.Status` RPC (two round-trips, with a `[WARN] daemon predates doctor — please upgrade` row).

Per-host MCP registration is detected from canonical config-file paths documented in `docs/install.md`:

| Host         | Detection class | Canonical path(s) |
|--------------|-----------------|-------------------|
| Claude Code  | Hard (multi-scope) | `~/.claude.json` (user), project `.mcp.json`, `~/.claude/settings.json` |
| Cursor       | Hard            | `~/.cursor/mcp.json` |
| Continue     | Hard            | `~/.continue/config.yaml`, project `./.continue/config.yaml` |
| Aider        | Soft            | `~/.config/aider/mcp.json`, `./.aider/mcp.json`, `~/.aider.conf.yml` |
| Cline        | Soft            | VS Code extension global state (path varies by OS); CLI-flag scan |

Hook detection inspects `.claude/hooks/rts-nudge.sh` for presence, executability, and a content-version marker so an out-of-date hook is `[WARN]`-distinguishable from missing.

## Technical Approach

### Module layout

A new `crates/rts-bench/src/doctor/` module tree, sibling of `latency.rs`/`footprint.rs`/`semantic.rs`/`corpus.rs`. The brainstorm's claim that doctor logic might be promotable to `rts-core` is rejected: `rts-core` is a pure parsing library with zero MCP/install-surface concepts. If `rts-mcp` or `rts-daemon` ever needs doctor's logic, extract then.

```
crates/rts-bench/src/doctor/
├── mod.rs              // Doctor entry; section dispatch; exit-code computation
├── report.rs           // RowKind (OK/WARN/FAIL); SectionReport; FixSnippet; section ordering
├── render_human.rs     // ANSI-aware (NO_COLOR), no wall-clock timestamps, snapshot-stable
├── render_json.rs      // schema_version + capabilities; serde shape locked at v0
├── binary_section.rs   // binary version, daemon binary on PATH, symlink resolution
├── daemon_section.rs   // per-workspace socket probe; Stats vs Workspace.Status fallback
├── workspace_section.rs// index_generation, cold-walk timestamp, file count, workspace mismatch
├── mcp_section.rs      // dispatches to per-host detectors below
├── hooks/
│   ├── mod.rs          // shared host trait + result types
│   ├── claude_code.rs  // user-scope, project-scope, settings.json hook block
│   ├── cursor.rs
│   ├── continue_.rs    // YAML, NOT JSON; serde_yaml
│   ├── aider.rs        // soft-detect
│   └── cline.rs        // soft-detect
└── nudge_hook.rs       // .claude/hooks/rts-nudge.sh presence + executability + version marker
```

### `Daemon.Stats` additive extension (prerequisite)

`crates/rts-daemon/src/methods/daemon.rs:140-151` currently returns:

```jsonc
{ "uptime_ms": u64, "version": str, "total_calls": u64, "calls": { ... } }
```

Extend to (additive — old clients ignore unknown fields):

```jsonc
{
  "uptime_ms": u64,
  "version": str,
  "total_calls": u64,
  "calls": { ... },
  // new in v0.6, gated on capability "daemon_stats_v2":
  "pinned_workspace_path": str,
  "workspace_id": str,
  "index_generation": u64,
  "cold_walk_completed_at_ms": u64 | null
}
```

Capability string `"daemon_stats_v2"` added to the list at `crates/rts-daemon/src/methods/daemon.rs:18-87`. Doctor advertises that it requires `daemon_stats_v2`; if the daemon doesn't, doctor calls `Workspace.Status` instead (two round-trips, with a `[WARN]` advising upgrade).

### Output rendering

Human renderer is **snapshot-stable**: no wall-clock timestamps in default output, deterministic section ordering, `NO_COLOR` env var honored, `--no-color` flag for explicit control, and ANSI only when stdout is a TTY (via `IsTerminal`). The current rts-bench has no color library; this plan adds `anstream = "0.6"` to `rts-bench/Cargo.toml` (already a transitive clap dep — promote to direct).

JSON renderer is **stable**: schema versioned with `schema_version: "doctor-v0"` and a top-level `capabilities: []` array. The schema is documented in a new `docs/doctor-schema.md`. Future additive fields require a new capability string, never a schema_version bump.

### Exit codes

Exit code is a documented public API. Reserved values:
- `0` — no FAIL rows (any WARN allowed)
- `1` — at least one FAIL row
- `2` — doctor itself failed (panic, unreadable own binary, JSON-serialization error)
- `>=3` — reserved for future use; CI gates must not depend on specific values above 2

Doctor-self-failure (exit 2) emits valid JSON to stdout when `--output json` is set, with a single `{schema_version, capabilities, error: {code, message}}` shape; otherwise plain message to stderr.

### Per-host detection

Each host detector implements a tiny trait:

```rust
pub trait HostDetector {
    fn host_name(&self) -> &'static str;
    fn detection_class(&self) -> DetectionClass; // Hard | Soft
    fn detect(&self, ctx: &Ctx) -> HostFinding;
}

pub struct HostFinding {
    rows: Vec<Row>,           // OK/WARN/FAIL per registration scope discovered
    rts_registered: Option<RegistrationDetail>,  // for cross-row analysis (multi-scope drift)
    skipped_reason: Option<String>,              // "not installed", "permission denied"
}
```

The trait pattern centralizes:
- multi-scope handling (Claude Code user vs project vs local — flagged when multiple register at different binaries/versions: WARN, not FAIL)
- malformed-config policy: serde parse error on a host config file is `[WARN] could not parse {path}: {reason}` (not FAIL) — doctor never fails the run because *another* tool's config is broken
- "not installed" policy: a host's config dir doesn't exist → row is `[?] {host} not detected` for soft hosts, omitted for hard hosts (configurable later if needed)

### System-Wide Impact

- **Interaction graph.** Doctor reads file systems (config files, hook file, binary on PATH) and talks to the daemon via the existing protocol-v0 socket. It opens no new sockets, writes no files. The only side-effects are stdout/stderr.
- **Error propagation.** Doctor's own errors (panic, malformed own JSON output) are exit `2` with a structured `error` envelope in JSON mode. Per-host parse errors are downgraded to WARN rows; host detection never aborts the run.
- **State lifecycle.** No persistent state introduced. The Daemon.Stats extension is additive; old clients keep working unchanged.
- **API surface parity.** The new `daemon_stats_v2` capability is announced in protocol-v0's capability list. `Workspace.Status` continues to expose the same fields it does today (unchanged).
- **Integration test scenarios.**
  - Daemon at v0.5.x (pre-`daemon_stats_v2`): doctor reports `[WARN] daemon predates daemon_stats_v2; using fallback path`.
  - Daemon present, workspace mismatch: `workspace_index` section reports `[FAIL] daemon pinned to {other_path}, doctor running in {pwd}`.
  - Cold-walk in progress: `[WARN] indexing in progress ({files_done}/{files_total})`.
  - Stale socket file (PID dead, file remains): `[FAIL] socket exists but daemon unreachable; remove {socket_path}` with the `rm -f` fix snippet.
  - Multi-scope MCP: Claude Code user-scope and project-scope both register rts at different binaries: `[WARN] multi-scope registration: user-scope=v0.5.6, project-scope=v0.5.5`.
  - Malformed `.mcp.json`: `[WARN] .mcp.json present but unparseable: expected `,` at line 12`.
  - `~/.cursor/mcp.json` missing entirely (Cursor not installed): row omitted (hard host).
  - Aider config not detected: `[?] aider not detected (soft detect)`.
  - Hook file present but `chmod -x`: `[WARN] hook not executable; run: chmod +x .claude/hooks/rts-nudge.sh`.
  - $PWD outside any workspace: `workspace_index` section emits one row `[WARN] no rts workspace at $PWD` and skips inner checks.
  - `--output json` with all OK: valid JSON to stdout, exit 0.
  - `--output json` on doctor-self-failure: valid JSON `{error: ...}` to stdout, exit 2.

## Implementation Units

Units are ordered by dependency. Each unit lists Goal, Files, Approach, Patterns to follow, Execution note, Test scenarios, Verification.

### U1 — `Daemon.Stats` v2 (additive extension + capability)

- **Goal.** Extend `Daemon.Stats` with `pinned_workspace_path`, `workspace_id`, `index_generation`, `cold_walk_completed_at_ms`; announce capability `"daemon_stats_v2"`.
- **Files.** `crates/rts-daemon/src/methods/daemon.rs` (response struct + capability list); `crates/rts-daemon/src/state.rs` (expose `pinned_workspace_path` and `cold_walk_completed_at_ms` on `MountedWorkspace`); `crates/rts-daemon/tests/wire_round_trip.rs` (add round-trip case for the new fields); `docs/protocol-v0.md` (document v2 fields under capability `daemon_stats_v2`).
- **Approach.** Add fields to the existing `StatsResponse` struct (or wrap in `#[serde(flatten)]`-able extension struct). `pinned_workspace_path` reads from `MountedWorkspace.canonical.path`. `index_generation` mirrors `Workspace.Status`'s value. `cold_walk_completed_at_ms` is set once when `progress.phase` transitions to `"ready"`; stored as `Option<u64>` on `MountedWorkspace`.
- **Patterns to follow.** `crates/rts-daemon/src/methods/workspace.rs:277,350,357` (where `index_generation` and `workspace_id` already surface); `crates/rts-daemon/src/methods/daemon.rs:18-87` (capability list pattern); the `#94`-era pattern for adding additive fields with capability gating.
- **Execution note.** Characterization-first: add a round-trip test that captures the existing `Daemon.Stats` shape *before* extending. Confirms backward compatibility by construction.
- **Test scenarios.**
  - Round-trip: v2 response deserializes into the v1 shape with v1 fields preserved.
  - Capability list includes `"daemon_stats_v2"`.
  - `cold_walk_completed_at_ms` is `None` until cold-walk completes; populated when `progress.phase == "ready"`.
- **Verification.** `cargo test -p rts-daemon` green; `docs/protocol-v0.md` updated; capability list grep returns the new string.

### U2 — Doctor scaffolding + clap subcommand

- **Goal.** New `Cmd::Doctor` variant with `--output [human|json]`, `--no-color`, exits 0/1/2 plumbed.
- **Files.** `crates/rts-bench/src/main.rs` (add `Doctor` variant on `enum Cmd`; dispatch to `doctor::run`); `crates/rts-bench/src/doctor/mod.rs` (new; `pub fn run(args) -> anyhow::Result<ExitCode>`); `crates/rts-bench/src/doctor/report.rs` (Row, RowKind, SectionReport, FixSnippet types).
- **Approach.** Mirror the `query` subcommand's clap derive style. `--output` uses a new `value_enum` `DoctorOutput { Human, Json }`. Top-level entry validates flags, dispatches to per-section detectors, aggregates `SectionReport`s, computes exit code by max-severity-row across all sections.
- **Patterns to follow.** `crates/rts-bench/src/main.rs:34-187` (clap derive style, `value_enum`); `crates/rts-bench/src/main.rs:427` (`anyhow::Result<()>` from main, explicit `std::process::exit(N)` for non-error exit codes); `AGENTS.md` (tracing to stderr via `RTS_BENCH_LOG`).
- **Execution note.** Test-first: write the smoke test (`doctor_runs_and_returns_zero_on_healthy_install`) before scaffolding so the dispatch wiring is exercised end-to-end.
- **Test scenarios.**
  - `cargo run -p rts-bench -- doctor --help` shows usage with the flag set.
  - `doctor --output json` produces parseable JSON with `schema_version` and `capabilities` even before any sections are implemented (empty section list valid).
  - Exit code is 0 on empty/all-OK and 1 when a section emits FAIL.
- **Verification.** `cargo test -p rts-bench` green; manual smoke run produces stable, snapshot-friendly output.

### U3 — Output rendering (human + JSON)

- **Goal.** `render_human` and `render_json` produce stable output. NO_COLOR honored. Snapshot-friendly.
- **Files.** `crates/rts-bench/src/doctor/render_human.rs`; `crates/rts-bench/src/doctor/render_json.rs`; `crates/rts-bench/Cargo.toml` (add direct `anstream = "0.6"` + `is-terminal = "0.4"` if not already transitively present).
- **Approach.** Human renderer formats rows as `[OK]`/`[WARN]`/`[FAIL]` with optional ANSI when TTY + NO_COLOR unset; fix snippets render on the next line indented `  → `. JSON renderer serializes a fixed `DoctorReport { schema_version: "doctor-v0", capabilities: Vec<&'static str>, sections: Vec<Section>, exit_class: "ok"|"warn"|"fail" }`. No wall-clock timestamps; cold-walk-completed-at is data and lives in `workspace_index` row payloads.
- **Patterns to follow.** Existing rts-bench output goes to stdout; logs to stderr (`main.rs:428-435`). Use `std::io::IsTerminal` for TTY detection. `serde_json::to_writer_pretty` for JSON.
- **Execution note.** Test-first: snapshot tests against fixture `SectionReport`s. Use `insta` or hand-rolled string-equality if `insta` isn't already a dev-dep.
- **Test scenarios.**
  - Snapshot of human output with one FAIL + one WARN row matches golden file byte-for-byte.
  - `NO_COLOR=1` strips ANSI even on a TTY.
  - JSON output validates against a small JSON Schema fixture committed in `tests/fixtures/doctor-schema-v0.json`.
- **Verification.** `cargo test -p rts-bench doctor::render` green; snapshot stability verified by running twice and diffing.

### U4 — `binary` section

- **Goal.** Reports doctor binary version + daemon/MCP binary discovery + symlink resolution.
- **Files.** `crates/rts-bench/src/doctor/binary_section.rs`.
- **Approach.** Doctor binary version from `env!("CARGO_PKG_VERSION")`. Probe `which rts-daemon` and `which rts-mcp` via `std::env::var_os("PATH")` + manual lookup (no shell-out — avoids the macOS `realpath -m` foot-gun from #106). Resolve symlinks with `std::fs::canonicalize`. If a found binary's `--version` differs from doctor's version, emit `[WARN] version drift: doctor=v0.6.0, daemon=v0.5.5`. Fix snippet: `cargo install --path crates/rts-daemon` or release-tarball curl line.
- **Patterns to follow.** `crates/rts-bench/src/main.rs` (uses `which` crate indirectly? — confirm during implementation; if not present, use std-only PATH walk). The learnings researcher's BSD-vs-GNU note: do path work in Rust, not via shelling out.
- **Execution note.** Pragmatic — small, leaf-node section. No test-first required.
- **Test scenarios.**
  - `rts-daemon` not on PATH: `[FAIL]` with install-from-release fix.
  - Version drift between doctor and daemon: `[WARN]`.
  - Symlinked binary resolves to a different version than what's on PATH: `[WARN]`.
- **Verification.** Hand-run against a clean checkout + against a `PATH=/usr/bin` empty test.

### U5 — `daemon` section

- **Goal.** Reachability probe via per-workspace socket; `Daemon.Stats v2` round-trip; fallback to `Workspace.Status` against pre-`daemon_stats_v2` daemons.
- **Files.** `crates/rts-bench/src/doctor/daemon_section.rs`.
- **Approach.** Compute the per-workspace socket path the same way `rts-mcp` does (need to confirm: `ws-<16hex>.sock` per `crates/rts-daemon/src/main.rs`). If socket file absent → `[WARN] daemon not running for this workspace` + fix snippet (`rts-daemon --workspace $PWD &`). If socket exists, attempt connect with 1 s timeout. Stale socket (connect refused, PID dead) → `[FAIL] stale socket at {path}` + fix (`rm -f {path}`). On successful handshake, call `Daemon.Stats`; if response carries v2 fields, proceed in one round-trip; else fall back to `Workspace.Status` for `index_generation` and emit a `[WARN] daemon predates daemon_stats_v2`.
- **Patterns to follow.** `crates/rts-bench/src/main.rs:1363-1412` (cold-gate poll loop — shows existing daemon-connect pattern); `crates/rts-daemon/src/methods/workspace.rs:117-137` (per-workspace state-dir resolution); `docs/protocol-v0.md` for framing.
- **Execution note.** Test-first: integration test that spawns a daemon, points doctor at it, asserts on the row set.
- **Test scenarios.**
  - Socket absent: WARN + bootstrap fix.
  - Socket present, connect refused: FAIL + rm fix.
  - Daemon v0.5.x (no `daemon_stats_v2`): WARN about version + fallback to `Workspace.Status` succeeds.
  - Daemon v0.6.x (has `daemon_stats_v2`): one round-trip, OK row.
- **Verification.** Integration test green; manual run against a real daemon shows expected rows.

### U6 — `workspace_index` section

- **Goal.** Per-workspace index health: pinned-workspace path matches `$PWD`, cold walk completed, `index_generation`, file count.
- **Files.** `crates/rts-bench/src/doctor/workspace_section.rs`.
- **Approach.** Reuse the Daemon.Stats / Workspace.Status data fetched in U5 (passed via `Ctx`). If `pinned_workspace_path` ≠ `canonicalize($PWD)`: `[FAIL] daemon pinned to {pinned}, doctor running in {pwd}` + fix (`rts-daemon --workspace $PWD`). If `cold_walk_completed_at_ms` is `None`: `[WARN] indexing in progress ({files_done}/{files_total})`. If `index_generation > 0` and no FAILs: `[OK] index generation {n}, {file_count} files`. `$PWD` outside any workspace (no `.git` ancestor + no marker): one row `[WARN] no rts workspace at $PWD` and skip the rest of the section.
- **Patterns to follow.** `crates/rts-bench/src/main.rs:844-873` (`detect_workspace_from`); the `--output lines` convention for line-based readable text.
- **Execution note.** Test-first: scenarios above each get a test fixture.
- **Test scenarios.** See above (workspace-mismatch, in-progress, OK, no-workspace).
- **Verification.** `cargo test -p rts-bench doctor::workspace_section` green.

### U7 — `mcp_registration` section + per-host detectors

- **Goal.** Detect rts MCP registration across all 5 hosts. Hard hosts emit OK/WARN/FAIL per registration scope. Soft hosts emit `[?]` or `[OK]`. Multi-scope drift in Claude Code is `[WARN]`.
- **Files.** `crates/rts-bench/src/doctor/mcp_section.rs`; `crates/rts-bench/src/doctor/hooks/{mod,claude_code,cursor,continue_,aider,cline}.rs`.
- **Approach.** `HostDetector` trait per the System-Wide Impact section. Each detector reads its host's canonical config path(s), parses (JSON/YAML/JSONC), checks for an rts MCP entry, validates that the entry's binary path exists and is executable, returns `HostFinding`. The `mcp_section` orchestrator runs all five in parallel (`rayon::join` or `std::thread::scope`), collects findings, runs the cross-scope drift check on Claude Code, and emits rows. Continue uses `serde_yaml` (NOT `serde_json`).
- **Patterns to follow.** `docs/install.md:60-144` (canonical per-host paths and config formats). Existing dependency on `serde_json` in workspace; add `serde_yaml = "0.9"` to `rts-bench/Cargo.toml`.
- **Execution note.** Test-first per host: fixture config files in `crates/rts-bench/tests/fixtures/doctor/{host}/` covering (registered correctly, malformed, missing, binary path stale).
- **Test scenarios.**
  - Each host: registered correctly → OK; missing config dir → row omitted (hard) or `[?]` (soft); malformed config → `[WARN] could not parse {path}`; rts entry present but binary path missing → `[FAIL] {host}: binary {path} not found` + fix.
  - Claude Code multi-scope drift: user-scope and project-scope register different binaries → `[WARN] multi-scope: user={v1}, project={v2}`.
  - Aider and Cline soft-detect when their conventions aren't found → `[?]`.
- **Verification.** `cargo test -p rts-bench doctor::hooks` green; fixture coverage matrix complete.

### U8 — `hook` section

- **Goal.** `.claude/hooks/rts-nudge.sh` presence, executability, version-marker match.
- **Files.** `crates/rts-bench/src/doctor/nudge_hook.rs`; `.claude/hooks/rts-nudge.sh` (add a `# version: 0.6.0` comment marker at the top — single-line change; existing hook must remain otherwise identical).
- **Approach.** Look for `<workspace>/.claude/hooks/rts-nudge.sh`. If absent → `[WARN] PreToolUse nudge hook not installed` + fix (`cp .claude/hooks/rts-nudge.sh.template ...` or one-line `curl`). If present but `!is_executable()` → `[WARN] hook not executable; chmod +x ...`. If present, executable, but version marker doesn't match doctor's binary version → `[WARN] hook is v{old}, doctor is v{new}; consider updating`.
- **Patterns to follow.** `.claude/hooks/rts-nudge.sh` lines 1-15 (existing comments and contract); use `std::os::unix::fs::PermissionsExt`.
- **Execution note.** Pragmatic; small.
- **Test scenarios.** Absent, present-non-exec, present-exec-out-of-date, present-exec-up-to-date.
- **Verification.** `cargo test -p rts-bench doctor::nudge_hook` green.

### U9 — Fix-snippet taxonomy + final wiring

- **Goal.** Every WARN/FAIL row has a fix snippet from a closed taxonomy (no ad-hoc strings). Section ordering normative. Doctor itself becomes panic-safe (exit 2 path tested).
- **Files.** `crates/rts-bench/src/doctor/report.rs` (extend `FixSnippet` to an enum); cross-references to U4–U8.
- **Approach.** `enum FixClass { InstallBinary, StartDaemon, RemoveStaleSocket, RegisterMcp { host: HostKind }, FixMcpBinaryPath, MakeHookExecutable, UpdateHook, MoveWorkspace, ReindexNeeded, FixYamlSyntax, ... }`. Each variant renders a one-line command + a short description. Doctor-self-failure (`catch_unwind` at the entry point) emits exit 2 with structured JSON when `--output json`.
- **Patterns to follow.** `anyhow::Context` for error chaining; the existing `exit(2)` precedent at `crates/rts-bench/src/main.rs:592`.
- **Execution note.** Test-first for the exit-2 path: simulate a panic in one section, assert exit code and JSON shape.
- **Test scenarios.**
  - Every FixClass variant has a rendered fix that's a runnable shell command (asserted via parse).
  - Section ordering is fixed: `binary`, `daemon`, `mcp_registration`, `hook`, `workspace_index`.
  - Panicking section → exit 2, JSON has `error` envelope, other sections still rendered.
- **Verification.** `cargo test -p rts-bench doctor::report` green; doctor's exit-code table matches the documented contract.

### U10 — `docs/doctor-schema.md`, changelog fragment, README/install.md cross-references

- **Goal.** Documentation surface complete. Schema is a public artifact.
- **Files.** `docs/doctor-schema.md` (new — the JSON schema for `--output json`, plus exit-code contract); `docs/install.md` (add a small "Verifying your install" section pointing at `rts-bench doctor`); `README.md` (one-line addition under "Status"); `changelog.d/<NNNN>-rts-bench-doctor.md` (per `AGENTS.md` v0.5.5+ convention).
- **Approach.** `docs/doctor-schema.md` documents `schema_version: "doctor-v0"`, the `capabilities[]` array, the per-section row shape, the exit-code contract (0/1/2 with reserved values ≥3), and the JSON envelope for self-failure. Mention the snapshot stability rules.
- **Patterns to follow.** `docs/protocol-v0.md` (capability list + per-method schema sections); the per-PR changelog.d/ fragment workflow (#93).
- **Execution note.** Pragmatic; pure docs.
- **Verification.** `mdformat` or equivalent passes; the cross-references resolve.

## Requirements Trace

| ID  | Requirement (from origin)                                                                                                | Satisfied by | Notes |
|-----|---------------------------------------------------------------------------------------------------------------------------|--------------|-------|
| R1  | `rts-bench doctor` subcommand, offline, no network                                                                        | U2           |       |
| R2  | Read-only; no writes to user config                                                                                       | U2 (enforced by design — no writer module exists) | |
| R3  | Two signal classes: install (binary, daemon path, MCP per host, hook) + workspace (PID, pinned path, index_gen, walk time, file count) | U4, U5, U6, U7, U8 | Pinned path requires U1 |
| R4  | All 5 hosts; Aider/Cline soft-detect                                                                                       | U7           | Detection class explicit per host |
| R5  | Human checklist with inline fix snippet per WARN/FAIL                                                                      | U3, U9       | Fix taxonomy in U9 |
| R6  | `--output json` machine-readable; shape stable                                                                            | U3, U10      | `--json` reconciled to `--output json` |
| R7  | Exit 0 (no FAIL), 1 (any FAIL), 2 (doctor itself failed)                                                                   | U2, U9       | Exit-class on report; panic-handler in U9 |
| R8  | Doctor latency <500 ms p95 on healthy install                                                                              | U5, U6       | One round-trip when U1 lands; verified by manual bench |
| R9  | Use one round-trip when daemon reachable; fall back when not                                                              | U1, U5       | Single round-trip requires U1 |
| R10 | Sections grouped: `binary`, `daemon`, `mcp_registration`, `hook`, `workspace_index`; each independently testable          | U2, U4–U8    | Ordering documented in U10 |

## Acceptance Criteria

### Functional

- [ ] **AC1.** `rts-bench doctor --help` shows the new subcommand with `--output [human|json]` and `--no-color` flags.
- [ ] **AC2.** On a healthy install with v0.6+ daemon running for `$PWD`, `rts-bench doctor` exits 0 and renders five sections (`binary`, `daemon`, `mcp_registration`, `hook`, `workspace_index`) in that order, all `[OK]`.
- [ ] **AC3.** With the daemon down, the `daemon` section emits `[WARN] daemon not running for this workspace` + a fix snippet that is itself runnable (`rts-daemon --workspace $PWD &`).
- [ ] **AC4.** With a stale socket (file exists, PID dead), the `daemon` section emits `[FAIL] stale socket` and exits 1.
- [ ] **AC5.** With the daemon pinned to a different workspace than `$PWD`, the `workspace_index` section emits `[FAIL] daemon pinned to {other}, doctor running in {pwd}` and exits 1.
- [ ] **AC6.** With Claude Code's user-scope and project-scope both registering rts at different binary paths, `mcp_registration` emits `[WARN] multi-scope registration`.
- [ ] **AC7.** With a malformed `.mcp.json`, `mcp_registration` emits `[WARN] could not parse {path}` and exits 0 (parse errors don't fail doctor).
- [ ] **AC8.** With the hook file missing, `hook` emits `[WARN]` + install fix snippet.
- [ ] **AC9.** With the hook present but `chmod -x`, `hook` emits `[WARN] not executable` + `chmod +x` fix snippet.
- [ ] **AC10.** `rts-bench doctor --output json` produces a JSON document with `schema_version: "doctor-v0"`, `capabilities: []`, `sections: [...]`, and `exit_class` ∈ `{"ok","warn","fail"}`; the JSON validates against a committed schema fixture.
- [ ] **AC11.** `NO_COLOR=1 rts-bench doctor` produces output free of ANSI codes; same applies for `--no-color`.
- [ ] **AC12.** Doctor's human output is byte-stable across two consecutive runs against the same state (no wall-clock timestamps).
- [ ] **AC13.** A simulated panic inside one section causes exit 2; with `--output json`, stdout is valid JSON with an `error` envelope and the remaining sections still render.
- [ ] **AC14.** Against a pre-`daemon_stats_v2` daemon, doctor falls back to `Workspace.Status` and adds `[WARN] daemon predates daemon_stats_v2`.

### Non-Functional

- [ ] **AC15.** Doctor latency on a healthy v0.6+ daemon is `<500 ms p95` on a 100k LOC workspace, measured via `rts-bench bench` or an ad-hoc shell loop. One round-trip only.
- [ ] **AC16.** No new transitive crate dependencies are added beyond `anstream`, `is-terminal`, and `serde_yaml`. Workspace `cargo tree` diff reviewed.

### Quality Gates

- [ ] **AC17.** `cargo test -p rts-bench` green; new tests cover every per-section scenario above.
- [ ] **AC18.** `cargo test -p rts-daemon` green; U1's round-trip test asserts both v1-style and v2-style responses.
- [ ] **AC19.** `cargo clippy --workspace --all-targets -- -D warnings` clean.
- [ ] **AC20.** `docs/doctor-schema.md` exists, links from `README.md` and `docs/install.md`, validates against the JSON fixture committed in `crates/rts-bench/tests/fixtures/doctor-schema-v0.json`.
- [ ] **AC21.** A new `changelog.d/<NNNN>-rts-bench-doctor.md` fragment lands with the PR.

## Success Metrics

- **First-week:** README's "Status" line gets a one-line `rts-bench doctor` mention; at least one closed issue in 30 days that links a doctor output as the diagnosis path (replacing the "paste your `cat .mcp.json`" exchange).
- **agent-bench preflight:** The harness (in `agent-bench/`) consumes `rts-bench doctor --output json` for preflight within 30 days; a failed preflight aborts a run instead of producing a wasted-API-cost trajectory.
- **Latency:** p95 of `rts-bench doctor` on the rts-core workspace (~50k LOC) under 250 ms, p99 under 500 ms, sampled over 20 runs.

## Dependencies & Risks

- **U1 must land before U5/U6 can satisfy R9's one-round-trip goal.** If U1 slips, U5/U6 ship with the fallback path active and `[WARN] daemon predates daemon_stats_v2` is the default row — acceptable degradation, but the latency target may not be met.
- **`docs/install.md` is the source of truth for per-host paths.** If `install.md` is wrong about Continue's YAML format or any other path, doctor will misdiagnose. The plan corrects Continue (YAML, not JSON); planning-time review of `install.md` for other drift is required before merging U7.
- **Multi-scope Claude Code registration is a real foot-gun.** Doctor surfaces it as WARN, not FAIL, because both registrations may be intentional (e.g., user-scope as a default + project-scope override). Validate the policy choice with one or two real installs before locking the row text.
- **VS Code extension state for Cline varies by OS and is undocumented in the canonical install.md path.** Soft-detect only; doctor never fails on Cline.
- **The hook version marker (U8) is a new contract.** Adding `# version: x.y.z` to `.claude/hooks/rts-nudge.sh` must not change the hook's runtime semantics. The hook's existing "exit 0 ALWAYS" contract is preserved.
- **`Daemon.Stats v2` capability gates real behavior.** A consumer that depends on `pinned_workspace_path` without checking `daemon_stats_v2` would crash on old daemons. Plan U1 + U5 ensures doctor checks the capability before reading the new fields.

## Scope Boundaries

The following are explicit non-goals for this PR:

- **No `--fix` mode.** Doctor never applies a recommended action. (Deferred — separate proposal once field data informs which fixes are universally safe.)
- **No behavioral telemetry in doctor.** Per-method call counts, nudge-fire log, recent error rate. Those live in `daemon-stats` (#104) and the auto-dump-on-shutdown (#105). Doctor's `daemon` section reports liveness/version only.
- **No version-drift detection across rts-mcp ↔ daemon ↔ binary-on-PATH beyond the binary-section level.** The #104 version-skew detection is acknowledged as a future enhancement; doctor's U4 catches the simple `rts-mcp on PATH is not the version doctor expects` case but doesn't probe the runtime MCP child process attached to Claude Code.
- **No Windows support.** Unix sockets only.
- **No `--section` flag** for running individual sections; all-or-nothing in v1.
- **No tooling to bootstrap `docs/solutions/`.** The learnings researcher recommended scaffolding it; do it in a separate small PR.

## Sources & References

- **Origin document:** [docs/brainstorms/2026-05-18-rts-doctor-requirements.md](../brainstorms/2026-05-18-rts-doctor-requirements.md). Carried-forward decisions:
  1. Read-only diagnostic (no `--fix`) — Key Decisions §1
  2. All 5 agent hosts at v1, Aider/Cline soft-detect — Key Decisions §2
  3. Install + workspace signal classes only — Key Decisions §3
  4. Human checklist with inline fix snippet; `--json` (reconciled to `--output json` per repo convention) — Key Decisions §4
  5. Subcommand on `rts-bench` — Key Decisions §5
  6. Exit 0/1/2 contract — R7
- **Research consolidations:**
  - `crates/rts-bench/src/main.rs:34-187` — clap derive pattern, `value_enum` for `--output`
  - `crates/rts-bench/src/main.rs:427` — `anyhow::Result` from main, explicit exit codes
  - `crates/rts-bench/src/main.rs:844-873` — `detect_workspace_from`
  - `crates/rts-bench/src/main.rs:1363-1412` — daemon cold-gate poll pattern
  - `crates/rts-daemon/src/methods/daemon.rs:140-151` — current `Daemon.Stats` shape (gap: missing pinned_workspace_path / index_generation / cold_walk_completed_at_ms)
  - `crates/rts-daemon/src/methods/daemon.rs:18-87` — capability list pattern
  - `crates/rts-daemon/src/methods/workspace.rs:117-137` — `state_dir_for` (XDG-aware path precedent)
  - `crates/rts-daemon/src/methods/workspace.rs:277,350,357` — `Workspace.Status` shape including `index_generation`
  - `crates/rts-daemon/src/state.rs:68` — `MountedWorkspace.canonical.path`
  - `docs/install.md:60-144` — per-host canonical paths (Continue is YAML, brainstorm guessed JSON)
  - `docs/protocol-v0.md:155-218` — capability negotiation pattern
  - `.claude/hooks/rts-nudge.sh:1-15` — existing hook contract
- **Related PRs:**
  - #104 (Daemon.Stats RPC + counters)
  - #105 (rts-mcp auto-dump on shutdown)
  - #106 (PreToolUse hook — BSD `realpath -m` foot-gun)
  - #107 (agent-bench harness — natural consumer of doctor JSON for preflight)

## Deferred to Implementation

These were marked as planning-time decisions in the brainstorm and resolved here:

- **All-OK output format (R5 outstanding):** Resolved — full row echo (every section, every row), no compact mode in v1. Snapshot stability requires consistent shape.
- **Index-staleness definition (R3 outstanding):** Resolved — there is no "stale index" signal in v1. Doctor reports `index_generation` and `cold_walk_completed_at_ms` as data; deciding whether they indicate staleness is left to the user. Cleaner separation of concerns; revisit if doctor's signal-to-noise demands a derived flag.
- **Soft-detect criteria for Aider/Cline (R4 outstanding):** Resolved — check for `~/.config/aider/mcp.json` and `~/.aider.conf.yml` for Aider; for Cline, check VS Code globalState path on each OS (best-effort, may return `[?]`).
- **Reachability probe (R9 outstanding):** Resolved — extend `Daemon.Stats` with v2 fields (U1) rather than adding a separate `Daemon.Ping`. Keeps the surface small.
- **Workspace-mismatch detection (R3 outstanding):** Resolved — compare `pinned_workspace_path` (from `Daemon.Stats v2`) against `canonicalize($PWD)`.
- **MCP scope detection for Claude Code (R4 outstanding):** Resolved — check user-scope (`~/.claude.json`), project-scope (`./.mcp.json`), and the settings.json hook block; emit `[WARN]` on multi-scope binary drift.
- **JSON schema versioning (R6 outstanding):** Resolved — `schema_version: "doctor-v0"` + additive `capabilities: []` array, documented in `docs/doctor-schema.md`.

## Post-Deploy Monitoring & Validation

- **What to monitor/search**
  - Logs: doctor produces nothing persistent — stdout/stderr only. Monitor: GitHub issues filtered by `doctor` keyword; agent-bench preflight failures in `bench-results/`.
- **Validation checks (queries/commands)**
  - `rts-bench doctor` (manual run on the dev workspace; expect all OK after install)
  - `rts-bench doctor --output json | jq '.schema_version, .exit_class'`
  - `cargo test -p rts-bench doctor && cargo test -p rts-daemon`
- **Expected healthy behavior**
  - Exit 0, all sections OK, latency under 500 ms.
- **Failure signal(s) / rollback trigger**
  - Reports of doctor itself panicking (exit 2 spike). Rollback: revert the PR; no schema migrations to undo.
- **Validation window & owner**
  - 7-day window post-merge; author monitors.

---

## Plan Status

- **Detail level:** MORE (standard plan)
- **SpecFlow:** complete (11 edge cases surfaced and incorporated into AC2–AC14)
- **Deepen:** not requested
- **Source decisions trace:** complete
- **Next:** `/ce:work` on this plan, or move to brainstorm #3's plan (`index-grep-v2-requirements.md`) next.
