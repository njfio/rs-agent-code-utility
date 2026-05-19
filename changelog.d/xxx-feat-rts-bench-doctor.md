### `rts-bench doctor` + `Daemon.Stats v2` — first-run health check, end the silent-install era

The #1 first-run failure pattern for rts has always been silent: daemon not running, MCP not registered to the right scope, stale index, hook missing, wrong workspace. Users grep through the README, tail the daemon log, and eventually file an issue. Adoption ceiling = *"users patient enough to debug a silent install."*

This PR ships the diagnostic surface that surfaces every failure mode with an inline copy-pasteable fix.

#### What

**New `rts-bench doctor` subcommand.** Five sections, normative order, snapshot-stable output:

```
$ rts-bench doctor
rts-bench doctor (schema=doctor-v0)

== binary ==
  [OK]   binary:doctor_version — rts-bench doctor v0.6.0
  [OK]   binary:rts_daemon — rts-daemon at /usr/local/bin/rts-daemon (v0.6.0)
  [OK]   binary:rts_mcp — rts-mcp at /usr/local/bin/rts-mcp (v0.6.0)

== daemon ==
  [OK]   daemon:reachable — daemon v0.6.0 reachable, uptime 12345 ms (daemon_stats_v2)

== mcp_registration ==
  [OK]   claude_code:user_scope — registered at ~/.claude.json
  [?]    aider — not detected (soft-detect)
  …

== hook ==
  [OK]   hook:installed_current — hook installed and current (v0.6.0)

== workspace_index ==
  [OK]   workspace_index:state — index generation 1247, 4218 files (cold walk completed)

exit class: ok
```

Three flags: `--output [human|json]` (default `human`; reconciled to the `rts-bench query` convention), `--no-color`, `--workspace <path>`.

**Exit-code contract (public API):**
- `0` — no FAIL rows (any WARN allowed)
- `1` — at least one FAIL row
- `2` — doctor itself failed (panic, JSON serialization error)
- `>=3` — reserved; CI gates MUST NOT depend on specific values

**Five sections, in order:**

1. **`binary`** — doctor's own version; `rts-daemon` / `rts-mcp` discovery on `$PATH`; symlink resolution via `std::fs::canonicalize`; version-drift detection across binaries. Manual `$PATH` walk (no `which` crate dep). No shell-outs to `realpath -m` (BSD/Linux foot-gun, cf. #106).
2. **`daemon`** — per-workspace socket probe; one round-trip to the new `Daemon.Stats v2`; graceful fallback to `Workspace.Status` on pre-v2 daemons; distinguishes "not running" (WARN + `rts-daemon --workspace $PWD &` fix) from "stale socket" (FAIL + `rm -f` fix).
3. **`mcp_registration`** — reads canonical config-file paths for all 5 supported agent hosts:

   | Host         | Class  | Paths probed |
   |--------------|--------|--------------|
   | Claude Code  | Hard   | `~/.claude.json` (user), project `.mcp.json`, settings.json hook block |
   | Cursor       | Hard   | `~/.cursor/mcp.json` |
   | Continue     | Hard   | `~/.continue/config.yaml` (YAML, not JSON — corrected from brainstorm) |
   | Aider        | Soft   | `~/.config/aider/mcp.json`, `<workspace>/.aider/mcp.json`, `~/.aider.conf.yml` |
   | Cline        | Soft   | VS Code extension global state (OS-specific paths) |

   Cross-scope drift detection for Claude Code: multiple scopes registering rts at different binaries → `[WARN] multi-scope drift`.
4. **`hook`** — `.claude/hooks/rts-nudge.sh` presence + executability + version-marker match. New `# version: <ver>` comment in the hook lets doctor flag drift between bundled and installed versions.
5. **`workspace_index`** — pinned-workspace path match (FAIL on mismatch with `move_workspace` fix), cold-walk completion (WARN on indexing-in-progress), index generation, file count.

**`--output json` produces a versioned schema** (`doctor-v0`) documented in [`docs/doctor-schema.md`](../docs/doctor-schema.md). Stable across patch releases; additive evolution via the top-level `capabilities[]` array. Pre-v1 consumers: the agent-bench harness's preflight (PR follow-up).

#### Prerequisite: `Daemon.Stats v2`

Doctor's `daemon` and `workspace_index` sections need workspace metadata the daemon didn't previously surface. PR adds:

- `pinned_workspace_path: str` — the canonical path the daemon is pinned to
- `workspace_id: str` — 32-char hex (blake3 truncation) workspace fingerprint
- `index_generation: u64` — bumps on every committed write
- `cold_walk_completed_at_ms: u64 | null` — Unix-epoch ms of the writer's `ColdWalkComplete` flush; `null` until cold walk completes

Backward compatible: pre-mount `Daemon.Stats` calls keep the v1 shape exactly. New capability `daemon_stats_v2` advertises the v2 fields; doctor degrades gracefully against old daemons.

#### Fix-snippet taxonomy

Every WARN/FAIL row may carry an inline `fix` block with a closed `class` taxonomy (10 variants: `install_binary`, `start_daemon`, `remove_stale_socket`, `register_mcp`, `fix_mcp_binary_path`, `make_hook_executable`, `update_hook`, `move_workspace`, `reindex_needed`, `fix_config_syntax`) and a copy-pasteable `command`. Renders as the next line in human mode, structured JSON object in machine mode.

#### Panic safety

The entire `doctor::run` body is wrapped in `catch_unwind`. A panic in any section yields exit `2` with a structured `error` envelope in JSON mode — doctor itself stays alive and reports.

#### Snapshot stability

No wall-clock timestamps in default output. ANSI gated by stdout-is-TTY + `NO_COLOR` env + `--no-color` flag. Section order normative. Row order within a section deterministic. Snapshot tests can diff against goldens.

#### Why this matters

A new user with a broken install today runs `rts` and sees nothing — no error, no hint. They grep the README, tail logs, eventually open an issue. With this PR, the new flow is:

```
$ rts-bench doctor
== mcp_registration ==
  [FAIL] claude_code:user_scope — rts not registered
    → claude mcp add rts -- $(which rts-mcp) --workspace "$PWD"
…
$ claude mcp add rts -- ...   # paste the fix
$ rts-bench doctor
…all OK.
```

One subcommand, one failure narrative, one fix. The agent-bench harness consumes the JSON output for preflight checks so failed installs abort *before* burning API credit on a doomed trajectory.

#### Verification

- Full plan: [`docs/plans/2026-05-18-001-feat-rts-bench-doctor-plan.md`](../docs/plans/2026-05-18-001-feat-rts-bench-doctor-plan.md)
- Origin brainstorm: [`docs/brainstorms/2026-05-18-rts-doctor-requirements.md`](../docs/brainstorms/2026-05-18-rts-doctor-requirements.md)
- Schema doc: [`docs/doctor-schema.md`](../docs/doctor-schema.md)
- New integration test: `crates/rts-daemon/tests/daemon_stats_v2_round_trip.rs` — asserts the v2 capability is advertised, v1 shape preserved pre-mount, v2 fields populate post-mount with sane values.
- Per-section unit tests across `crates/rts-bench/src/doctor/` cover every documented row outcome.
- End-to-end smoke on the rts workspace: doctor reports all-OK after `claude mcp add rts ...`.

#### Out of scope (filed for follow-up)

- **`--fix` mode** that applies recommended actions. Doctor is read-only in v1; auto-fix touches user config files and is the wrong shape for v1's "first install" mission.
- **Behavioral telemetry** (per-method call counts, nudge-fire log, recent error rate). Lives in `daemon-stats` (#104) and the auto-dump-on-shutdown (#105).
- **Cross-version drift detection** beyond the binary section. The known "Claude Code spawned a pre-#104 rts-mcp at session start" foot-gun is acknowledged but stays a separate brainstorm.
- **Windows support.** Unix sockets only.
- **`--section <name>` flag** for partial runs. All-or-nothing in v1.
