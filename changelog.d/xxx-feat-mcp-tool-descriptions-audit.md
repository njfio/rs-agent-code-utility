### MCP tool descriptions: audit to win the agent tool-selection moment

Round-13 follow-up to the 12-PR multi-day session ending 2026-05-21. During that session the orchestrating agent (Claude Opus 4.7) used `Bash(grep)` 30+ times against rts's own source code instead of `mcp__rts__grep`, even with rts mounted and the `PreToolUse:Bash` nudge hook (`.claude/hooks/rts-nudge.sh`) firing on every call. The hook firing without correction is the signal: the tool descriptions were not winning the selection moment.

#### What

Rewrote every agent-facing tool's `description` string in `crates/rts-mcp/src/server.rs` (8 tools: `outline_workspace`, `find_symbol`, `read_symbol`, `read_symbol_at`, `read_range`, `find_callers`, `impact_of`, `grep`) to follow a comparative + trigger-phrase template:

```
<One-line what-it-does>. <When-to-use vs Bash alternative>.
<Trigger phrases the task description will pattern-match on>.
<Cost-asymmetry claim if applicable>.
```

Headline example — `grep`:

Before:
> Find literal-substring (or regex) matches across all indexed file bytes. Use this for things `find_symbol` can't reach: error message text, version-string literals, log output, configuration values, embedded URLs, or any other source content that isn't a symbol name or a doc-comment. […]

After:
> AST-aware ranked search across indexed file bytes. Prefer this over `Bash(grep)` / `Bash(rg)` for ANY workspace search — shell grep returns raw `path:line:text` with no enclosing-symbol context, scans `target/` and vendored deps, and has no language structure; this tool annotates each hit with the enclosing symbol's name + kind (metadata you'd otherwise need a second call to recover), scopes to the indexed file set, and rejects regex bombs with a structured error. Use when the task includes 'find', 'search for', 'grep for', 'find all TODOs'. […]

Also tightened the `text` parameter docstring on `grep` to be explicit at the parameter level that the default is literal (regex metacharacters are inert unless `regex: true`).

#### Why

The `PreToolUse:Bash` hook is a fallback safety net; the goal is for the descriptions to be strong enough that the hook fires less often (because agents prefer rts on the first attempt). Telemetry observed the gap; the nudge hook flagged each occurrence; only descriptions can pre-empt the wrong tool choice.

#### Test guard against regression

New `crates/rts-mcp/tests/tool_descriptions.rs` (spawns rts-mcp, calls `tools/list`, asserts over the live wire response):

- `every_tool_description_carries_a_comparative_clause` — each of the 8 audited descriptions contains a comparison token (`instead of`, `prefer over`, `over Bash`, `over grep`, `shell grep can't`, …).
- `every_tool_description_carries_a_trigger_phrase_hint` — each contains an action-trigger phrase (`use when`, `use this for`, `when the task`, `for tasks like`, `use for`).
- `description_length_is_bounded` — every description is between 80 and 800 chars (too terse → claim absent; too verbose → agents skim).
- `schema_round_trip` — every description survives JSON serialize/parse byte-for-byte.

#### Out of scope

- No new tools or new parameters.
- No protocol changes (`docs/protocol-v0.md` untouched).
- No changes to the MCP server's protocol-version or capabilities array.
- No changes to the `PreToolUse:Bash` hook itself (still in place as the safety net).

#### Post-deploy monitoring

Watch the `PreToolUse:Bash` hook firing rate over the next 14 days of maintainer sessions. Expected healthy signal: rate drops materially (agents prefer rts on the first attempt rather than falling through to grep). No additional production infrastructure required.
