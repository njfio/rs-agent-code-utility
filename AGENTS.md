# Repository Guidelines

This file is the canonical project-coding-standards reference. Treat it
as the source of truth when conventions diverge from anything you find
in the git history of pre-pivot artifacts.

AGENTS.md — 12-rule template
These rules apply to every task in this project unless explicitly overridden.
Bias: caution over speed on non-trivial work. Use judgment on trivial tasks.

Rule 1 — Think Before Coding
State assumptions explicitly. If uncertain, ask rather than guess.
Present multiple interpretations when ambiguity exists.
Push back when a simpler approach exists.
Stop when confused. Name what's unclear.

Rule 2 — Simplicity First
Minimum code that solves the problem. Nothing speculative.
No features beyond what was asked. No abstractions for single-use code.
Test: would a senior engineer say this is overcomplicated? If yes, simplify.

Rule 3 — Surgical Changes
Touch only what you must. Clean up only your own mess.
Don't "improve" adjacent code, comments, or formatting.
Don't refactor what isn't broken. Match existing style.

Rule 4 — Goal-Driven Execution
Define success criteria. Loop until verified.
Don't follow steps. Define success and iterate.
Strong success criteria let you loop independently.

Rule 5 — Use the Model Only for Judgment Calls
Use me for: classification, drafting, summarization, extraction.
Do NOT use me for: routing, retries, deterministic transforms.
If code can answer, code answers.

Rule 6 — Token Budgets Are Not Advisory
Per-task: 4,000 tokens. Per-session: 30,000 tokens.
If approaching budget, summarize and start fresh.
Surface the breach. Do not silently overrun.

Rule 7 — Surface Conflicts, Don't Average Them
If two patterns contradict, pick one (more recent / more tested).
Explain why. Flag the other for cleanup.
Don't blend conflicting patterns.

Rule 8 — Read Before You Write
Before adding code, read exports, immediate callers, shared utilities.
"Looks orthogonal" is dangerous. If unsure why code is structured a way, ask.

Rule 9 — Tests Verify Intent, Not Just Behavior
Tests must encode WHY behavior matters, not just WHAT it does.
A test that can't fail when business logic changes is wrong.

Rule 10 — Checkpoint After Every Significant Step
Summarize what was done, what's verified, what's left.
Don't continue from a state you can't describe back.
If you lose track, stop and restate.

Rule 11 — Match the Codebase's Conventions, Even If You Disagree
Conformance > taste inside the codebase.
If you genuinely think a convention is harmful, surface it. Don't fork silently.

Rule 12 — Fail Loud
"Completed" is wrong if anything was skipped silently.
"Tests pass" is wrong if any were skipped.
Default to surfacing uncertainty, not hiding it.

Git Workflow
Branches
main is always deployable. Never commit directly to it.

Branch from main for every change:

feat/<short-description> — new feature

fix/<short-description> — bug fix

docs/<short-description> — documentation only

refactor/<short-description> — code restructuring, no behavior change

test/<short-description> — adding or fixing tests

chore/<short-description> — maintenance (deps, config, tooling)

Keep branches short-lived. One feature or fix per branch.

Delete the branch after merging.

Commits
Follow Conventional Commits:

text
<type>(<optional-scope>): <imperative subject, ≤72 chars>

<optional body: what and WHY, not how>
Types: feat, fix, docs, style, refactor, test, chore

Rules:

Use imperative mood: "Add login endpoint" not "Added login endpoint"

Each commit is one logical, self-contained unit of work (atomic)

The build must not be broken by any individual commit

Never commit secrets, credentials, or machine-local paths

Use git add -p to stage selectively when a change touches multiple concerns

Examples:

text
feat(auth): add JWT refresh token endpoint
fix(api): handle null response from payment gateway
test(cart): add edge case for zero-quantity items
docs: update README with local dev setup steps
Pull Requests
Open a PR before merging any branch into main

PR title must follow the same Conventional Commits format as commit messages

Keep PRs small and focused — one concern per PR

PR description must include:

What — what changed and why

How to test — steps to verify the change manually or via tests

Checklist — tests pass, no secrets committed, lint clean

Require at least one reviewer approval before merging

Rebase onto main (or squash) before merge to keep history linear and clean

Delete the remote branch after merge

Tags & Releases
Tag releases on main using semantic versioning: v<MAJOR>.<MINOR>.<PATCH>

Annotated tags only: git tag -a v1.2.0 -m "Release v1.2.0"

Never move or delete tags that have been pushed

What Requires Approval Before Running
The agent must ask before executing any of the following:

git push (any branch)

git commit (if not in an explicitly approved auto-commit session)

git rebase, git merge, git reset --hard

Deleting branches locally or remotely

Installing or removing packages

Modifying CI/CD configuration

Never
Never force-push to main

Never commit directly to main or any protected branch

Never commit .env, secrets, API keys, or credentials

Never leave merge conflict markers (<<<<<<<) in committed code

Never rebase commits already pushed and shared with others


## Tooling: use the `rts` index, not `grep` / `rg`

This project ships its own indexer (`rts-daemon` + `rts-mcp`). You're
expected to use it. Reaching for shell `grep` / `rg` on workspace
sources is a **fallback**, not the default. The index is AST-precise
(no comment/string false positives), carries PageRank, exposes
enclosing-symbol metadata, and survives across editor sessions.

### When to use which tool

| You want… | Use | Don't use |
|---|---|---|
| Find a symbol by name or glob (`make_*`, `*_target`) | `mcp__rts__find_symbol` or `rts-bench query find-symbol` | `rg '^fn '`, `rg '^class '` |
| Find who calls a function | `mcp__rts__find_callers` or `rts-bench query find-callers` | `rg 'name\\('` (false positives) |
| Find a string literal, error message, config value | `mcp__rts__grep` or `rts-bench query grep` | `rg 'literal'` |
| Refactor blast radius (transitive callers) | `mcp__rts__impact_of` or `rts-bench query impact-of` | manual BFS of `rg` results |
| Orient in an unfamiliar repo | `mcp__rts__outline_workspace` or `rts-bench query outline` | `find . -name '*.rs'` |
| Read a symbol's body | `mcp__rts__read_symbol` or `rts-bench query read-symbol` | `cat`, `Read` whole file |

### `grep` v2 — multi-line, structural, within-symbol (v0.6 alpha)

The cases agents have historically dropped to `rg` for — patterns that cross newlines, "find every `impl` that contains an `unsafe fn`", "find every `panic!` inside `fn parse_request`" — now compose on the same tool. Capability gate: `index_grep_v2` (or the three fine-grained strings `index_grep_multiline`, `index_grep_structural`, `index_grep_within_symbol`). Wire details: protocol-v0 §7.8b.

- **Multi-line regex.** Pass `multiline: true` *and* `regex: true`. The compiled pattern gets `(?ms)` semantics (`.` matches `\n`, `^/$` are per-line) and the file is scanned as one buffer. Use for multi-line `fn` signatures, multi-line error messages, embedded SQL. Adversarial patterns (`(?s).*` on a 4 MiB file) return `REGEX_TOO_COMPLEX`, not OOM.

  ```jsonc
  // "find every `pub async fn` whose return type spans multiple lines"
  { "text": "pub async fn[^{]*->\\s*\\n[^{]*\\{", "regex": true, "multiline": true }
  ```

- **Structural tree-sitter queries.** Pass `structural_query` (a raw S-expression) and `language` (required). Results carry per-match `captures: {name: [{start, end, text, truncated?}]}`. Predicates limited to the v1 whitelist (`#eq?`, `#not-eq?`, `#match?`, `#not-match?`, `#any-of?`, `#is?`, `#is-not?`).

  ```jsonc
  // "every impl block in the workspace"
  { "structural_query": "(impl_item) @impl", "language": ["rust"] }

  // intersection: every `impl` block that also contains the literal `unsafe fn`
  { "text": "unsafe fn", "structural_query": "(impl_item) @impl", "language": ["rust"] }
  ```

- **Within-symbol scope.** Pass `within_symbol: "name"` to keep only matches whose byte range lies strictly inside that symbol's def. Overloaded names (>16 defs) reject with `WITHIN_SYMBOL_TOO_MANY_DEFS` unless you opt in via `within_symbol_allow_overload: true`.

  ```jsonc
  // "find every `panic!` inside fn parse_request"
  { "text": "panic!", "within_symbol": "parse_request" }
  ```

All three modes compose with each other, with `file_glob`, and with `language` (AND semantics). v1 callers that pass none of the new fields see byte-identical responses.

### Two CLI shapes

`rts-bench query <sub>` returns the daemon's full JSON response —
ideal for `jq` pipelines and machine consumption. v0.5.6+ adds
`--output lines` for **`rg`-shaped output** (`path:line:content`) that
composes with `| head`, `| sort -u`, `| awk -F:`, `| xargs sed -i`.
Empty results emit nothing and exit 0, exactly like `rg`.

```sh
# rg-style: find all literals, get unique containing files.
rts-bench query --output lines grep --text 'panic!(' | awk -F: '{print $1}' | sort -u

# rg-style: list all symbols matching a pattern, sorted by name.
rts-bench query --output lines find-symbol --pattern 'parse_*' | sort

# Refactor preview: who calls X, transitively, depth 2?
rts-bench query --output lines impact-of --name socket_path_for_workspace
```

### MCP path (preferred for sustained agent sessions)

The `mcp__rts__*` tools speak the same protocol but skip the `rts-bench`
subprocess spawn — single-digit-ms latency per call. On **Claude Code
v2.1.121+** they're loaded eagerly per the project-local `.mcp.json`
in this repo (`"alwaysLoad": true`), so they appear in the
top-of-prompt tool list every session with no warm-up call required.

On **older Claude Code versions** (and any other MCP-aware host that
doesn't honor `alwaysLoad`), the tools are deferred behind
`ToolSearch`. Pre-load them once at session start:

```
ToolSearch(query: "select:mcp__rts__find_symbol,mcp__rts__find_callers,mcp__rts__grep,mcp__rts__outline_workspace,mcp__rts__impact_of,mcp__rts__read_symbol,mcp__rts__read_range,mcp__rts__read_symbol_at", max_results: 10)
```

After that single call, all eight tools are callable directly in the
remainder of the session without further `ToolSearch` round-trips.

### Active behavior nudge (v0.5.8+)

This repo ships a project-local Claude Code `PreToolUse` hook at
`.claude/hooks/rts-nudge.sh` (registered via `.claude/settings.json`)
that watches for `Bash` calls invoking `grep`/`rg`/`egrep`/`fgrep`/`find`
on workspace paths and emits a one-line informational nudge into the
agent's next-turn context suggesting the AST-precise `mcp__rts__*`
equivalent. The nudge is **never blocking** — the bash call proceeds
exactly as issued; the nudge is purely a habit-shift signal.

Opt out for a session by setting `RTS_HOOK_DISABLED=1`. The env var
propagates through subshells, make, cargo, and most subprocess
patterns (does NOT propagate through `sudo` without `-E`).

The hook is silent when the rts daemon isn't running, so it never
nags users without rts installed.

Test the hook locally with `.claude/hooks/tests/run-tests.sh` (pure
bash, no `bats` or other deps required; needs `jq` + `python3`).

### Where shell `grep` / `rg` is still the right tool

- Searching files outside the indexed workspace (vendored deps,
  `target/`, anything `.rtsignore`'d).
- Non-text content that the daemon's body-extension allowlist refuses
  (binary diffs, generated files).
- Multi-line regex matches across newlines — `Index.Grep`'s regex
  mode is single-line as of v0.5.5.
- One-shot grep when the daemon isn't running and spawning it would
  be slower than the search itself (e.g. trivial 5-file workspaces).

In those cases reach for `rg`. Otherwise the index is the answer.

## Project layout (post-pivot)

Cargo workspace with `resolver = "3"`, Rust 2024 edition, MSRV 1.85.

- `crates/rts-core/` — surviving tree-sitter wrapper + analyzer + 11
  grammars. Library only; no binaries. `#![forbid(unsafe_code)]`.
- `crates/rts-daemon/` — persistent workspace-pinned daemon. Binary
  `rts-daemon`. Speaks `docs/protocol-v0.md` over a Unix-domain socket.
- `crates/rts-mcp/` — agent-facing MCP server bridge. Binary `rts-mcp`.
  Speaks rmcp 1.6 over stdio to the agent, protocol-v0 to the daemon.
- `crates/rts-bench/` — bench harness. Binary `rts-bench`. The only
  operator-facing CLI in the v0.2 stack.
- `docs/protocol-v0.md` — daemon ↔ MCP wire spec.
- `docs/plans/` and `docs/brainstorms/` — active design artifacts.
- `spikes/p0-*` — independent crates carrying the P0 validation
  experiments (rmcp 1.6, redb 2, notify+debouncer). Excluded from the
  workspace; reproducible via the per-spike README.

## Build, test, lint

```sh
# Build everything (4 workspace members + tests + integration tests).
cargo build --workspace

# All tests, including the daemon + MCP + bench integration tests
# which spawn the actual binaries via stdio/Unix-socket round-trip.
cargo test --workspace

# Lint. Workspace lints in root Cargo.toml: unsafe_code = "deny".
cargo clippy --workspace --all-targets

# Per-crate work.
cargo test -p rts-daemon          # daemon-only
cargo test -p rts-mcp             # MCP-only (needs rts-daemon built)
cargo test -p rts-bench           # bench (needs rts-mcp + rts-daemon)
```

The integration tests in `rts-mcp` and `rts-bench` require their
sibling binaries to be built first. `cargo test --workspace` handles
this correctly; per-crate `cargo test -p` may need an explicit
`cargo build --workspace` first.

### Pre-push hook (optional)

`lefthook.yml` at the repo root runs `cargo fmt --check` and a scoped
`cargo clippy` on `git push`, matching what CI enforces, so format /
lint drift is caught locally instead of via a CI round-trip + force-push.

```sh
# One-time, if you don't already use lefthook globally:
brew install lefthook    # or: go install github.com/evilmartians/lefthook@latest
lefthook install         # writes pre-push into .git/hooks
```

Bypass for a single push with `LEFTHOOK=0 git push`. Contributors who
don't install lefthook are unaffected; CI is still the source of truth.

## Coding style

- **Edition**: Rust 2024.
- **Unsafe**: forbidden in `rts-core`, denied workspace-wide (overrides
  on a per-item basis only when load-bearing).
- **Naming**: modules / files `snake_case`; types & traits
  `PascalCase`; functions & vars `snake_case`; consts
  `UPPER_SNAKE_CASE`.
- **Errors**: `anyhow::Result` for binaries and internal call sites;
  protocol-level errors are typed (`ProtocolError` in `rts-daemon`,
  `DaemonError` in `rts-mcp`). Bubble up via `?`; do not panic in
  library code.
- **No comments without a "why"**: lean toward self-documenting code.
  Reserve doc comments for public APIs and for invariants a future
  reader couldn't derive from the code alone.
- **Tracing, not println**: every binary initialises
  `tracing_subscriber` to stderr. `rts-mcp` *must* keep stdout for
  JSON-RPC; logging to stdout will break Claude Code's parser.

## Testing conventions

- **Unit tests** in `#[cfg(test)] mod tests` inside each module.
- **Integration tests** in `crates/<member>/tests/<area>_round_trip.rs`.
  These spawn the real binaries and round-trip the protocol; no mocks
  of cross-crate interfaces.
- Descriptive test names (`commit_then_find_symbol_round_trips`,
  `live_create_of_secrets_file_is_filtered`). Include both happy paths
  and negative cases (e.g. `RANGE_OUT_OF_BOUNDS`, `OUT_OF_ROOT`).
- The bench's integration tests gracefully skip when `rg` isn't on
  `PATH` rather than failing — they refuse to silently produce a
  baseline-less measurement.

## Commit & PR conventions

- **Conventional Commits** scoped by crate or doc:
  `feat(rts-daemon): …`, `fix(rts-mcp): …`, `docs(protocol): …`,
  `chore(workspace): …`.
- PRs include a summary, testing notes (full `cargo test --workspace`
  count), and rollback considerations for changes that touch the
  protocol wire shape.

### Changelog fragments (v0.5.5+)

Each PR adds a **single Markdown fragment** to `changelog.d/`,
not a direct edit to `CHANGELOG.md`. This eliminates the per-PR
merge conflict that historically ate ~30 minutes per release
queue (every concurrent PR collided on the `## [Unreleased]`
section).

File name: `changelog.d/<PR-number>-<kind>-<short-slug>.md` —
e.g. `changelog.d/93-feat-grep-regex-mode.md`. Use `xxx` as a
placeholder until the PR number is assigned, then rename.

Fragment content: regular Markdown with a top-level `###`
header. No front-matter. See `changelog.d/README.md` for the full
spec.

At release time, run `scripts/build-changelog.sh <version>` to
concatenate all fragments under a new `## [<version>]` heading
and clear the fragments dir. The release commit then bundles the
CHANGELOG update, the fragment deletions, and the `Cargo.toml`
version bump together.

### Experimental surface gate (v0.6+)

New MCP tools and `rts` CLI subcommands land behind
`#[cfg(feature = "experimental")]` (the `experimental` Cargo feature, off by
default) until they're promoted to the stable, frozen surface in a release —
no promotion ladder, no `experimental_*` prefix, no per-feature paperwork.
Daemon-side or core-side experimental code declares its own `experimental`
feature in that crate, since Cargo features don't cross the
rts-mcp↔rts-daemon socket boundary.

## Security & configuration

- **Never** commit secrets. The `.gitignore` excludes `.env`,
  credentials, private keys, certs.
- The daemon refuses to run as root, sets `umask(0077)`, sets
  `RLIMIT_CORE=0` (+ `PR_SET_DUMPABLE=0` on Linux). Don't relax these
  for "ergonomics" — they're the security boundary.
- Protocol-v0 §13 secrets policy (filename blocklist + content scanner
  + extension allowlist) lives in
  [`crates/rts-daemon/src/filter.rs`](crates/rts-daemon/src/filter.rs).
  Both the watcher and read handlers consult it; extending the
  blocklist means updating both paths.

## Dependency hygiene

- The daemon and the MCP server link **zero HTTP code paths**. The
  bench's `--with-network` Anthropic SDK adapter (when it lands) is
  gated behind a feature flag + a `RTS_BENCH_ANTHROPIC_API_KEY` env
  var; CI asserts the daemon/MCP build trees stay HTTP-free via
  `cargo tree`.
- `tree-sitter` versions are pinned at the workspace level; per-grammar
  versions track the latest 0.23+ that's runtime-compatible with
  `tree-sitter 0.26`.

## What's archived, and why

If you go looking for a feature that the pre-pivot library shipped
(AI analyzers, taint analysis, SARIF output, the `tree-sitter-cli`
binary), it's in the git history before the pre-pivot cleanup PR.
Recovery is a manual port from that history; the v0.2 product surface
deliberately omits all of it. See [CHANGELOG.md](CHANGELOG.md)'s
v0.2.0-alpha.1 entry for the full archive manifest and rationale.
