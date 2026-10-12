# rts — AST-precise code search for AI coding agents

[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)](#license)
[![Languages](https://img.shields.io/badge/languages-13-brightgreen)](#languages)

`rts` is a local code-retrieval daemon plus an [MCP](https://modelcontextprotocol.io/) bridge that gives AI coding agents — Claude Code, Cursor, Continue, Aider, Cline — **AST-precise, ranked, millisecond-scale** access to your codebase (warm `read_symbol` p95 2.9 ms, measured at v0.3.1 — [`docs/development.md`](docs/development.md#first-mount-on-big-workspaces-takes-seconds)). It replaces the "agent runs `rg` and reads whole files" pattern with structured tool calls that return *exactly the bytes the agent needs* — a fraction of the context for the same answer ([numbers below](#why)).

It's local, offline, and per-workspace. No code leaves the machine.

## What you get over `rg`

Run against this repository at v0.9.0:

```sh
$ rg -n --sort path 'commit_batch\(' crates/ | head -n 6               # bash grep
crates/rts-core/src/verify/references.rs:609:        let snippet = b"fn f(){ commit_batch(x); }\nuse crate::store::CommitOptions;";
crates/rts-core/src/verify/references.rs:694:        let snippet = b"commit_batch(x)\nfrom store import CommitOptions\n";
crates/rts-core/src/verify/references.rs:777:                b"fn f( commit_batch(",
crates/rts-core/src/verify/signature_shape.rs:237:            "fn commit_batch(&mut self, entries: Vec<Entry>) -> Result<()> { todo!() }",
crates/rts-daemon/src/methods/index.rs:433:    /// `commit_batch(entries: &[Entry], flush: bool) -> Result<()>`. When
crates/rts-daemon/src/store/mod.rs:262:    pub fn commit_batch(
# 43 lines in all. 10 are not calls: the definition, five string literals,
# three doc comments, and a test whose own name ends in `commit_batch`.
```

```sh
$ rts-bench query --output lines find-callers --name commit_batch | head -n 6   # rts
crates/rts-daemon/src/store/mod.rs:2055:wipe_data_tables_clears_files_but_preserves_meta (fn)
crates/rts-daemon/src/store/mod.rs:2145:commit_then_find_symbol_round_trips (fn)
crates/rts-daemon/src/store/mod.rs:2207:list_files_with_defs_buckets_by_fid_and_keeps_shared_names (fn)
crates/rts-daemon/src/store/mod.rs:2266:list_files_with_defs_one_entry_per_name_per_file (fn)
crates/rts-daemon/src/store/mod.rs:2322:find_symbols_batch_matches_per_name_find_symbol (fn)
crates/rts-daemon/src/store/mod.rs:2395:find_symbols_batch_with_sids_returns_sids_for_known_names (fn)
# 33 lines in all: every call site, each with the function that makes the call
```

The 33 call sites are the same in both, but: **the definition, strings and comments are filtered out, every match shows the enclosing function**, and each caller carries a PageRank `rank_score` (in the JSON output). A refactor that touches `commit_batch`'s signature now has a *list of functions to update*, not a list of byte offsets.

And for non-symbol text — error messages, version pins, log strings — `grep` still has its place. `rts grep` does it AST-aware too:

```sh
$ rts-bench query --output lines grep --text 'panic!' | head -n 5
crates/rts-core/src/signature.rs:1025:[sig]             .unwrap_or_else(|| panic!("expected a signature for `{input}`"))
crates/rts-daemon/tests/read_round_trip.rs:523:[sig]             .unwrap_or_else(|| panic!("signature field for {symbol}; got {resp:?}"));
crates/rts-core/src/signature.rs:1212:[ts]             .unwrap_or_else(|| panic!("expected a typescript signature for `{input}`"))
crates/rts-core/src/signature.rs:1319:[go]             .unwrap_or_else(|| panic!("expected a go signature for `{input}`"))
crates/rts-core/src/signature.rs:1383:[java]             .unwrap_or_else(|| panic!("expected a java signature for `{input}`"))
# 125 matches in all. The [bracketed] prefix is the enclosing function name — refactoring `panic!` semantics has the list
```

## Why

| problem | with `rg` + `cat` | with `rts` |
|---|---|---|
| **False positives.** "Find `commit_batch`" matches calls, comments, doc strings, the def itself. | every match needs human filtering | AST-precise: `find_callers` returns only callers, not the def |
| **No structure.** "Who calls X?" returns text; the agent must re-parse to find enclosing function names. | the agent grep-then-reads each file | one tool call returns `(file, line, enclosing_function_name, kind)` |
| **No ranking.** Important code looks the same as utility code. | first matches are alphabetical-by-path | PageRank-sorted; central symbols first |
| **Token cost.** Reading whole files to answer "what does X look like?" | 94,285 tokens for `parse()`'s body (measurement below) | `read_symbol parse` returns the body: 28 tokens |
| **Stale views.** Long-running agents see the codebase at start-of-session. | re-read everything each turn | file-watcher keeps the index live; `content_version` lets agents detect stale reads |

The headline number: on the rts-core crate itself, getting one function's body costs **94,285 tokens via `rg` + read** vs **28 tokens via `rts`** — a 99.97% reduction, measured at v0.2.0-alpha.11 (May 2026) against the rts-core of that release and not re-run since ([`docs/development.md`](docs/development.md#token-reduction-numbers); [Reproduce](docs/development.md#running-the-benchmark)). The saving scales with file size: on a realistic ~75-line fixture the same comparison gives 97.2% ([`CHANGELOG.md`](CHANGELOG.md), 0.2.0-alpha.24).

## Quick start

### Install

```sh
# Prebuilt binaries (macOS arm64, Linux x86_64, Linux arm64):
VERSION=0.9.0 TARGET=aarch64-apple-darwin   # or x86_64-unknown-linux-gnu / aarch64-unknown-linux-gnu
curl -fsSL "https://github.com/njfio/rs-agent-code-utility/releases/download/v${VERSION}/rts-${VERSION}-${TARGET}.tar.gz" | tar -xz
# Verify: SHA256SUMS (integrity) + `gh attestation verify` (authenticity, v0.6.1+).
# Browser-downloaded macOS tarballs need `xattr -dr com.apple.quarantine "rts-${VERSION}-${TARGET}/"`.

# Or build from source:
cargo build --workspace --release
```

The tarball unpacks to `rts-${VERSION}-${TARGET}/` with four binaries — put them on your `PATH` together, since `rts-mcp` and `rts` look for `rts-daemon` next to themselves first:

| binary | what it is |
|---|---|
| `rts-mcp` | the MCP server your agent talks to (stdio) |
| `rts-daemon` | the indexer; auto-spawned by `rts-mcp` and `rts` |
| `rts` | the human CLI over the same queries ([below](#from-the-terminal)) |
| `rts-bench` | benchmarks, `rts-bench query` one-shots, and `doctor` |

### Wire into your agent

**Claude Code:**
```sh
claude mcp add rts -- $(which rts-mcp) --workspace "$PWD"
```
A `.mcp.json` in your repo root pins the rts tools as always-loaded (no `ToolSearch` round-trip per session). See [`docs/install.md`](docs/install.md) for Cursor / Continue / Aider / Cline snippets.

That's it. The MCP server auto-spawns the daemon on first connect; the daemon walks the workspace once (~1 s for 10k LOC, ~6 s for 100k on synthetic Rust workspaces, measured at v0.3.1 — [`docs/development.md`](docs/development.md#first-mount-on-big-workspaces-takes-seconds)) and watches for changes after that.

### Several roots, one daemon

One `rts-mcp` — and the one daemon behind it — can serve several workspace roots, e.g. a repo and its git worktrees. Name each root with its own `--workspace` (or list the extras in `RTS_MCP_ROOTS`, `:`-separated):

```sh
claude mcp add rts -- $(which rts-mcp) --workspace "$PWD" --workspace "$PWD/../my-worktree"
```

The first root is the start-up root; the others are mounted on first use, each with its own index and watcher. No tool takes a root parameter: each call is routed by its own path arguments (`file`, `glob`, `file_glob`, `edits[].file`, `claims[].file`). An absolute path under a root routes to that root (the longest match wins, so a worktree nested in the repo routes to the worktree); a relative path routes only when exactly one root has it. Anything else — a bare symbol name, or a relative path every worktree shares — goes to the start-up root. Every response carries a `_root` block (`path`, `workspace_id`, `resolved_by`) naming the root that answered, so to reach another root, pass an absolute path. On the wire this is the `multi_root` capability, `workspace_id` in the request envelope, and `Workspace.Unmount { root }` ([`docs/protocol-v0.md`](docs/protocol-v0.md)).

## What it gives your agent

Sixteen tools, all read-only: eight AST-precise lookup tools, six `verify_*` checks and gates, and two observability tools. Full schemas in [`docs/protocol-v0.md`](docs/protocol-v0.md) and, for every method including the `Index.Verify*` ones, [`schemas/v0/methods/`](schemas/v0/methods). The eight lookup tools:

| tool | when to reach for it |
|---|---|
| `find_symbol` | "Where is `X` defined?" Exact name or glob. AST-precise; no false positives from comments or strings. |
| `find_callers` | "Who calls `X`?" One indexed-graph lookup. AST-precise. |
| `impact_of` | "If I change `X`, what breaks?" Transitive caller closure (BFS, bounded). Refactor blast radius. |
| `read_symbol` | "Show me `X`'s body." Optional tree-shaken dependency closure; optional callers in the same response. |
| `read_symbol_at` | "What's at `src/foo.rs:42`?" Line-anchored, for compiler-error follow-up. |
| `read_range` | Explicit line range. Stack-trace frames, diff hunks. |
| `outline_workspace` | "I'm new to this repo — where do I start?" Token-budgeted structural map; Aider-style PageRank file ranking. |
| `grep` | Literal, regex, or **structural** (tree-sitter node-kind) search over indexed bytes. Returns matches with `enclosing_qualified_name` — the only `grep` you've used that says *which function the match is in*. |

The six `verify_*` tools (new in v0.9.0) check an agent's claims and proposed edits against the index, deterministically. The lookups answer with a `resolution` of `exact` / `not_found` / `indeterminate`, and `indeterminate` is never reported as a miss. The two gates, `verify_impact` and `verify_edit`, return a verdict on a change passed in as an argument; neither writes anything:

| tool | when to reach for it |
|---|---|
| `verify_symbol` | "Does `X` exist?" before you call or import it; a miss lists ranked did-you-mean candidates. |
| `verify_signature` | "Does this call match the definition?" Arity, parameters, return shape. |
| `verify_import` | "Does this import path resolve?" (final-segment resolution in v0). |
| `verify_claims` | Fact-check a batch of symbol, signature, import or location claims at once. |
| `verify_impact` | Declare a signature change, rename or removal; get its blast radius as `would_break` / `safe`. |
| `verify_edit` | Gate a proposed multi-file patch: broken callers, signature breaks, dangling references. |

The MCP server also exposes two observability tools — `daemon_stats` (per-method call counts) and `daemon_telemetry` (latency percentiles + cache-hit snapshot) — so you (and your agent) can see actual usage rather than guess.

The advertised `inputSchema` for `find_symbol` carries a `oneOf` (exactly one of `name` / `pattern`) and `grep`'s an `anyOf` (at least one of `text` / `structural_query`), so a client can see the rule the daemon enforces before it sends a call.

### The tool surface is a choice: `--tools`

`tools/list` travels in the context of every request, and all sixteen tools with their pinned
descriptions and schemas come to roughly **7,700 tokens per call** — more than some harnesses
budget for their entire tool surface. So the surface is selectable:

```sh
rts-mcp --workspace "$PWD" --tools core      # or: RTS_MCP_TOOLS=core
rts-mcp --workspace "$PWD" --tools find_symbol,read_symbol,find_callers
```

| surface | tools | ≈ tokens/call |
|---|---|---|
| `all` (default) | 16 | 7,723 |
| `verify` | 14 | not measured |
| `tsr` | 12 | not measured |
| `core` | 8 | 3,764 |
| a three-tool list | 3 | 1,374 |

Measured by driving `tools/list` against this repository when `--tools` landed (#168, before
v0.9.0 and before #178 added `oneOf`/`anyOf` to two schemas) — recorded in the `--tools` entry
of [`CHANGELOG.md`](CHANGELOG.md) 0.9.0 (`changelog.d/168-feat-tool-surface-profiles.md` until
the release).

`core` is the eight lookup tools — `outline_workspace`, `find_symbol`, `read_symbol`,
`read_symbol_at`, `read_range`, `find_callers`, `impact_of`, `grep` — for an agent that reads
and reasons. `verify` adds the six `verify_*` gates for an agent that edits. `tsr` is the
read-only subset described [below](#the-tsr-profile-and-inspect-records). A comma-separated
list names exactly what you want.

Under a profile the descriptions become one line each (0.7 KB instead of 11.1 KB), because the
pinned paragraphs exist to win the tool-selection moment against `Bash(grep)` — and when the
surface itself is the steering, eight tools each named for its job, the paragraphs are overhead.
The schemas do not shrink: they are most of what is left, and knowing that is why the numbers
above are per-surface rather than per-description.

A tool outside the surface is **not callable**, not merely unlisted: the server refuses it with
`tool X is not in this server's tool surface`, so a harness that caches an older `tools/list`
cannot keep calling what you turned off. A typo in a surface stops the server at startup and
lists the names that exist, rather than quietly serving a smaller surface.

### The `tsr` profile and inspect records

`--tools tsr` (or `RTS_MCP_TOOLS=tsr`) is the surface the TSR Decision Engine registers when
it uses rts as its *Inspect* substrate: twelve tools, every one a pure read or check —
`find_symbol`, `find_callers`, `read_symbol`, `read_symbol_at`, `read_range`, `grep` and the
six `verify_*` tools. `outline_workspace`, `impact_of` and the two observability tools are
left out, and the server instructions stop recommending `outline_workspace` when the surface
does not offer it.

The engine logs each call as an inspect record — `tool`, `args`, `content_version`,
`result_digest` (`blake3:` over the canonical JSON of the response) — whose shape is pinned by
[`schemas/inspect-record.schema.json`](schemas/inspect-record.schema.json). The conformance
test `crates/rts-mcp/tests/inspect_record.rs` builds a record from each of the twelve tools
through `rts-mcp --tools tsr` and validates it against the schema. What each field means, and
which tools' responses carry a `content_version`, is in
[`docs/tsr-inspect.md`](docs/tsr-inspect.md).

## From the terminal

`rts` runs the same queries from a shell (`rts --help`): `mount`, `find`, `grep`, `callers`,
`outline`, `read`, `stats`, `doctor`, `completions`, `telemetry`, and, new in v0.9.0, the
verification commands:

- **`rts impact <SYMBOL>`** — Verify the blast radius of an intended change to a symbol
  (`--change signature|remove|rename`; verdict `would_break` | `safe`).
- **`rts verify <PATH>`** — Verify a file's symbol/import references against the index
  (annotate-only; exit 1 when a reference provably has no definition).
- **`rts verify-edit --edits <FILE|->`** — Gate a proposed multi-file PATCH before it's
  written — the enterprise/CI pre-merge gate (`--fail-on none|warn|critical`; see
  [`AGENTS.md`](AGENTS.md) for the exit-code table).

A build with `--features experimental` also has `rts context`, `rts clones` and
`rts snapshot` (the entropy-v0 contract commands); the prebuilt binaries do not include them.

## How it's built

```
   AI coding agent (Claude Code / Cursor / Continue / Aider / Cline)
              │ stdio JSON-RPC, MCP
              ▼
       crates/rts-mcp        per-agent process; exposes up to 16 tools (--tools)
              │ Unix-domain socket, protocol-v0
              ▼
      crates/rts-daemon      auto-spawned; one index per mounted root
              │
      ┌───────┴────────────┐
      ▼                    ▼
   redb index         notify watcher
   defs · refs ·      (150 ms debounce,
   docs · pagerank    gitignore-aware,
   · enclosing        poll fallback)
```

**Single-uid**. Refuses to run as root. Sets `umask(0077)`, disables core dumps. **No HTTP client** in the default builds of `rts-daemon` and `rts-mcp` (the crate that also builds `rts`), which is what the prebuilt binaries are; [`scripts/check-daemon-http-free.sh`](scripts/check-daemon-http-free.sh) checks this with `cargo tree` (run it by hand — no CI workflow runs it today). The opt-in `telemetry` Cargo feature adds `ureq` to `rts-mcp` for `rts telemetry flush`; without it, `flush` exits with an error saying so. 13 languages indexed via tree-sitter — Rust, JS, TS, Python, C, C++, Go, Java, PHP, Ruby, Swift, C#, and Markdown — with AST-precise call edges on 10 of the 12 code grammars (added Java, PHP, Swift, C#), regex fallback on C and C++, and heading-level symbols for Markdown (prose; no call edges).

## Environment

Nothing needs setting. These are the variables the binaries read:

| variable | read by | effect |
|---|---|---|
| `RTS_MCP_TOOLS` | `rts-mcp` | Same as `--tools`; the flag wins. |
| `RTS_MCP_ROOTS` | `rts-mcp` | Extra workspace roots, `:`-separated — the same as extra `--workspace` flags. |
| `RTS_NO_AUTOSPAWN` | `rts` only | Anything but empty or `0`: `rts` connects only to a daemon already running for the workspace, and exits 3 if its socket is missing. It governs the initial connection; a reconnect after the daemon dies mid-command still spawns one. **`rts-mcp` ignores it** and always auto-spawns. |
| `RTS_DAEMON_BIN` | `rts-mcp`, `rts`, `rts-bench` | Path to `rts-daemon`. Default: next to the running binary, then `$PATH`. |
| `RTS_DEADLINE_MS` | `rts-mcp`, `rts` | Default `deadline_ms` stamped on daemon requests: 30000 when unset or unparsable, `0` for none, capped at 600000. |
| `RTS_LOG` | `rts-mcp`, `rts` | Tracing filter (stderr). `rts-mcp` falls back to `RUST_LOG`, then `rts_mcp=info,warn`; `rts` defaults to `warn`. |
| `RUST_LOG` | `rts-daemon` | The daemon's tracing filter (default `info`). The daemon does not read `RTS_LOG`. |
| `RTS_IDLE_SHUTDOWN_SECS` | `rts-daemon` | Idle seconds before the daemon exits; default 600. |
| `RTS_FORCE_POLL_WATCHER` | `rts-daemon` | Anything but empty, `0` or `false`: start with the polling watcher. |
| `RTS_INHERIT_DAEMON_STDERR` | `rts-mcp`, `rts` | Anything but empty or `0`: a daemon they spawn logs to their stderr. |
| `RTS_MCP_HEARTBEAT_INTERVAL_SECS`, `RTS_MCP_HEARTBEAT_TIMEOUT_SECS`, `RTS_MCP_RECONNECT_MAX_ATTEMPTS`, `RTS_MCP_RECONNECT_CEILING_SECS` | `rts-mcp`, `rts` | Connection resilience; defaults 10 s, 3 s, 8 attempts, 30 s. |
| `XDG_RUNTIME_DIR` | all | Socket directory on Linux (`$XDG_RUNTIME_DIR/rts/`); it must be set — there is no `/tmp` fallback. macOS uses `~/Library/Caches/rts/`. |
| `XDG_STATE_HOME` | `rts-daemon` | Index location, `$XDG_STATE_HOME/rts/<workspace_id>/db.redb`; default `~/.local/state` (macOS `~/Library/Caches`). |
| `XDG_CONFIG_HOME` | `rts`, `rts-daemon` | `rts` keeps its telemetry settings in `$XDG_CONFIG_HOME/rts/` (else `~/.config/rts/`); the daemon reads the global gitignore at `$XDG_CONFIG_HOME/git/ignore`. |
| `NO_COLOR` | `rts`, `rts-bench doctor` | Disable colour, like `--no-color`. |
| `RTS_BENCH_BIN` | `rts` | Path to `rts-bench` for `rts doctor`. |
| `RTS_TELEMETRY_ENDPOINT` | `rts` | Endpoint `rts telemetry` reports and `flush` would send to. |

Read only by a daemon built with `--features telemetry`: `RTS_BIN` (the `rts` it runs for the daily flush) and `RTS_TELEMETRY_INTERVAL_SECS`. For debugging and tests: `RTS_PROFILE_READ_SYMBOL` (daemon; per-stage timings to stderr) and `RTS_TEST_MOUNT_OPEN_DELAY_MS` (a test seam). `rts-bench` also reads `RTS_MCP_BIN`, `RTS_MCP_RECV_TIMEOUT_SECS`, `RTS_BENCH_INHERIT_STDERR` and `RTS_BENCH_LOG`. The hooks read `RTS_HOOK_DISABLED` and `RTS_BIN`.

## Status

**v0.9 — stable for daily use.** Latest release: `v0.9.0`. Used daily by the author on the rts codebase itself; looking for outside users — file an issue or a discussion.

**New in v0.9.0:**

- **Verification** — the six `verify_*` MCP tools, plus `rts impact`, `rts verify` and `rts verify-edit` on the command line.
- **Selectable tool surfaces** — `--tools` / `RTS_MCP_TOOLS` with the `all`, `core`, `verify` and `tsr` profiles or a list of names; a tool outside the surface is refused.
- **The `tsr` profile and inspect-record schema** (#181) — see [above](#the-tsr-profile-and-inspect-records).
- **Multi-root** (#179) — one daemon serves several mounted roots; `rts-mcp` routes each call by its path arguments. See [Several roots, one daemon](#several-roots-one-daemon).
- **Honest input schemas** (#178) — `find_symbol` and `grep` advertise the `oneOf`/`anyOf` the daemon enforces.

v0.8.0 brought per-request deadlines (`deadline_ms`; rts-mcp stamps a 30 s default, so a pathological scan returns `DEADLINE_EXCEEDED` instead of hanging your agent) and overload disambiguation (definitions carry a `parent`, so `find_symbol`/`read_symbol` tell `QueryBuilder::new` from `Parser::new` and accept a `parent` filter).

v0.7.0 brought markdown/prose indexing (a 13th language), structural-query grep (`--structural-query`/`--within-symbol`/`--multiline`), and reliability hardening (cold mount on this repo went from ~104 s to ~5 s by no longer scanning gitignored `target/`, measured at v0.7.0 — [`CHANGELOG.md`](CHANGELOG.md); mount-race + caller-prose fixes).

Pre-1.0 means the **wire protocol (protocol-v0)** may change additively and the **on-disk redb index** may change between minor versions (the daemon auto-rebuilds on upgrade; a *downgrade* across a schema bump needs a one-time state-dir wipe). The **user-facing surface will not break without a version bump.**

**Frozen in v0.6** (tool/subcommand *names + argument shapes*; additive flags are not frozen):

- **10 MCP tools** — `outline_workspace`, `find_symbol`, `read_symbol`, `read_symbol_at`, `read_range`, `find_callers`, `impact_of`, `grep`, `daemon_stats`, `daemon_telemetry`
- **10 `rts` CLI subcommands** — `mount`, `find`, `grep`, `callers`, `outline`, `read`, `stats`, `doctor`, `completions`, `telemetry`

The tools and subcommands added since (the six `verify_*` tools; `impact`, `verify`, `verify-edit`) are not in that list.

**Not frozen (pre-1.0 mutable):** the protocol-v0 wire format (additive changes only) and the on-disk redb schema (auto-rebuilt on upgrade).

Also live: the `.claude/hooks/rts-nudge.sh` PreToolUse hook that nudges agents toward rts when they reach for `Bash grep`/`rg`/`find`, and the `.claude/hooks/rts-verify.sh` PostToolUse hook that runs `rts verify` on each file an agent writes and feeds any invented symbol back to it (both opt out via `RTS_HOOK_DISABLED=1`); the PageRank ranker's `answerable_coverage` on the audited rts-core corpus is gated in CI (≥ 0.95; 1.00 when the gate was added — [`.github/workflows/ci.yml`](.github/workflows/ci.yml)).

What's *not* yet done: macOS Intel prebuilt binaries (build from source), Windows port (Unix sockets; v1.x candidate), full macOS notarization (browser-downloaded tarballs need `xattr -dr com.apple.quarantine`), public agent-bench baseline.

## More documentation

- **[`docs/install.md`](docs/install.md)** — per-agent wiring (Claude Code, Cursor, Continue, Aider, Cline).
- **[`docs/protocol-v0.md`](docs/protocol-v0.md)** — daemon ↔ MCP wire protocol. Capability list, per-method schemas, per-release wire-shape evolution.
- **[`docs/development.md`](docs/development.md)** — bench commands, known limitations, the per-phase status table, building from source, contributing.
- **[`AGENTS.md`](AGENTS.md)** — coding standards, commit conventions, the "use rts, not grep" cheatsheet.
- **[`CHANGELOG.md`](CHANGELOG.md)** — per-release notes.
- **[`agent-bench/README.md`](agent-bench/README.md)** — the SWE-bench-lite harness that measures whether rts actually shifts agent behavior.

## License

MIT OR Apache-2.0. See [`LICENSE-MIT`](LICENSE-MIT) and [`LICENSE-APACHE`](LICENSE-APACHE).
