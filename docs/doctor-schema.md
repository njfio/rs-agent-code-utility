# `rts-bench doctor` — schema & exit-code contract

This document is the wire-shape contract for `rts-bench doctor`'s
`--output json` mode plus its documented exit-code semantics. It is
the consumer-facing surface for agent-bench preflights and any other
machine consumer of doctor's output.

The schema is versioned via the top-level `schema_version` field.
**v1 ships as `doctor-v0`**. Additive evolution happens via the
`capabilities[]` array; new fields advertise via new capability
strings, never a `schema_version` bump. Breaking-shape changes would
require a new `schema_version` (e.g. `doctor-v1`), which is not on the
roadmap.

## Exit-code contract

| Code | Meaning |
|------|---------|
| `0`  | No `FAIL` rows in any section. Any number of `WARN` or `INFO` rows is allowed. Doctor's install + workspace state is considered healthy enough to use rts. |
| `1`  | At least one `FAIL` row. User intervention required — the offending row's `fix.command` is a copy-pasteable starting point. |
| `2`  | Doctor itself failed (panic, JSON serialization error, I/O failure on its own binary). Stdout still emits a valid JSON envelope when `--output json` is set; stderr carries the failure message. |

**Reserved**: exit codes `>= 3` are reserved for future use. CI gates
that consume `rts-bench doctor` MUST NOT depend on specific exit codes
above `2`.

## Top-level shape (`doctor-v0`)

```jsonc
{
  "schema_version": "doctor-v0",
  "capabilities": ["sections_v0", "fix_snippets", "host_detection_5x"],
  "sections": [
    { "name": "binary",            "rows": [...], "partial_failures": [...] },
    { "name": "daemon",            "rows": [...], "partial_failures": [...] },
    { "name": "mcp_registration",  "rows": [...], "partial_failures": [...] },
    { "name": "hook",              "rows": [...], "partial_failures": [...] },
    { "name": "workspace_index",   "rows": [...], "partial_failures": [...] }
  ],
  "exit_class": "ok",   // "ok" | "warn" | "fail" | "self_error"
  "error": null         // present only when exit_class == "self_error"
}
```

### `schema_version: string`

Locked at `"doctor-v0"`. Future shape changes require a major bump.
Additive changes do NOT bump this field; they advertise via
`capabilities[]`.

### `capabilities: string[]`

Stable, ordered, growing-only set of feature flags. v1 ships with:

- `sections_v0` — the 5-section layout in the order documented above
- `fix_snippets` — each WARN/FAIL row may carry an inline `fix` block
- `host_detection_5x` — covers Claude Code, Cursor, Continue, Aider, Cline

Consumers branch on capability strings, not on doctor version numbers.

### `sections: Section[]`

Sections appear in this normative order in both human and JSON output:

1. `binary` — doctor's own version, rts-daemon / rts-mcp on PATH, symlink resolution, cross-binary version drift
2. `daemon` — per-workspace socket probe, `Daemon.Stats v2` round-trip, pre-v2 fallback
3. `mcp_registration` — rts MCP entry presence across Claude Code, Cursor, Continue, Aider, Cline; cross-scope drift
4. `hook` — `.claude/hooks/rts-nudge.sh` presence, executability, version-marker match
5. `workspace_index` — pinned-workspace path match, cold-walk completion, index generation, file count

### `exit_class: "ok" | "warn" | "fail" | "self_error"`

Derived from the max-severity row across all sections (`fail` > `warn`
> `ok`). `self_error` is set independently when doctor itself
panicked or failed to initialize.

### `error: string | null`

Set only when `exit_class == "self_error"`. Carries a freeform
human-readable description of the failure. Absent (or `null`)
otherwise.

## Section shape

```jsonc
{
  "name": "<section-name>",
  "rows": [Row, ...],
  "partial_failures": [PartialFailure, ...]
}
```

### `name: string`

One of the five normative names above. Order-stable across runs.

### `rows: Row[]`

The section's observable findings. Order is implementation-defined
but stable within a single doctor build.

### `partial_failures: PartialFailure[]`

Annotations for recoverable errors that didn't produce a row (e.g.
*"the Continue config exists but the YAML failed to parse"*).
Surfaced as `(partial: <label> — <message>)` lines in human output.
The field is omitted entirely when empty.

## Row shape

```jsonc
{
  "kind": "ok",        // "ok" | "warn" | "fail" | "info"
  "label": "section:check_name",
  "message": "human-readable summary",
  "fix": {             // optional; present on most WARN/FAIL rows
    "class": "install_binary",
    "command": "cargo install --path crates/rts-daemon",
    "description": "optional context (1-2 sentences)"
  }
}
```

### `kind: "ok" | "warn" | "fail" | "info"`

| Kind   | Human prefix | Affects exit code? |
|--------|--------------|--------------------|
| `ok`   | `[OK]`       | No — exit 0 |
| `warn` | `[WARN]`     | No — exit 0; surfaces an anomaly worth fixing |
| `fail` | `[FAIL]`     | Yes — exit 1 |
| `info` | `[?]`        | No — soft-detect "we looked but couldn't determine" |

### `label: string`

Stable identifier of the form `<section>:<check_name>` (e.g.
`binary:rts_daemon_on_path`, `daemon:reachable`,
`mcp_registration:claude_code:user_scope`). Used by snapshot tests
and by external tooling that wants to assert on specific checks.

### `message: string`

Human-readable summary. Stable across runs given the same input
state, so snapshot tests can diff against goldens.

### `fix: object | absent`

Optional. Present on most `warn` and `fail` rows when doctor has a
copy-pasteable recovery action. Absent on `ok` and `info` rows.

#### `fix.class: string`

Closed taxonomy. Current set (subject to additive extension):

- `install_binary` — rts binary missing from PATH or version mismatched
- `start_daemon` — daemon not running for this workspace
- `remove_stale_socket` — socket file present but no live daemon
- `register_mcp` — rts not registered with the named agent host
- `fix_mcp_binary_path` — MCP config references a missing/non-executable binary
- `make_hook_executable` — hook present but not executable
- `update_hook` — hook content marker is out of date
- `move_workspace` — daemon pinned to a different workspace than `$PWD`
- `reindex_needed` — index empty or stale; trigger a re-index
- `fix_config_syntax` — host config file present but unparseable

Consumers should treat unknown `class` values as opaque labels.

#### `fix.command: string`

A single shell-line that the user can paste verbatim.

#### `fix.description: string | absent`

Optional context (1-2 sentences) for when the command alone is
unclear. Absent when the command is self-explanatory.

## PartialFailure shape

```jsonc
{
  "label": "host:claude_code:user_scope",
  "message": "could not parse ~/.claude.json: expected `,` at line 12"
}
```

Surfaced under the section header in human output as
`(partial: <label> — <message>)`. Does not affect exit code.

## Self-error envelope

When `exit_class == "self_error"`, the response shape collapses to:

```jsonc
{
  "schema_version": "doctor-v0",
  "capabilities": [...],
  "sections": [],
  "exit_class": "self_error",
  "error": "panic in daemon_section: thread 'main' panicked at ..."
}
```

The `sections` array is empty (the panic-handler captures whatever
sections completed; v1 omits them for simplicity). The `error` field
carries the panic message or initialization error.

## Snapshot stability

Both human and JSON output are designed for snapshot testing:

- **No wall-clock timestamps** anywhere in the default output.
  `cold_walk_completed_at_ms` (when present in workspace_index rows)
  is *data*, not flake.
- **Section order is normative** (see above).
- **Row order within a section is stable** within a single doctor build.
- **ANSI is disabled** by default when stdout is not a TTY, when
  `NO_COLOR` is set, or when `--no-color` is passed.

## Backward compatibility

Doctor's response shape is purely additive going forward. Adding a
new field to a `Row`, a new section, a new `fix.class` variant, or a
new top-level field does NOT bump `schema_version`. A consumer that
ignores unknown fields (the standard JSON parser default) will keep
working across additive evolution.

Removing or renaming a field WOULD require a `schema_version` bump.
This is not planned.

## See also

- [`docs/install.md`](install.md) — per-agent install snippets
- [`docs/protocol-v0.md`](protocol-v0.md) — daemon/MCP wire protocol;
  `daemon_stats_v2` capability backs doctor's workspace_index section
- Plan: [`docs/plans/2026-05-18-001-feat-rts-bench-doctor-plan.md`](plans/2026-05-18-001-feat-rts-bench-doctor-plan.md)
- Origin brainstorm: [`docs/brainstorms/2026-05-18-rts-doctor-requirements.md`](brainstorms/2026-05-18-rts-doctor-requirements.md)
