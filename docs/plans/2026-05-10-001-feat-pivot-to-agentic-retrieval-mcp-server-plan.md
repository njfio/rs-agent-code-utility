---
title: "feat: Pivot to agentic retrieval MCP server with hot daemon index"
type: feat
status: active
date: 2026-05-10
origin: docs/brainstorms/2026-05-10-agentic-retrieval-mcp-requirements.md
deepened: 2026-05-10
spikes_completed: 2026-05-11
---

# feat: Pivot to agentic retrieval MCP server with hot daemon index

## Spike Validation (P0 complete — 2026-05-11)

All three P0 spikes built and ran successfully against this worktree on macOS arm64 (rustc 1.90.0). See [spikes/](spikes/) for code and per-spike RESULTS.md files.

| Spike | Result | Key measurement |
|---|---|---|
| [P0.1 rmcp 1.6 hello-world](spikes/p0-1-rmcp-hello/RESULTS.md) | GO | tools/call round-trip = **80 µs** end-to-end over stdio |
| [P0.2 redb storage smoke](spikes/p0-2-redb-smoke/RESULTS.md) | STRONG GO | shared-txn lookup p95 = **1.8 µs**; batched-write 100 files = **12.8 ms** (None) / 28.5 ms (Immediate); 10k symbols in 4.53 MiB on disk |
| [P0.3 notify + debouncer-full](spikes/p0-3-notify-smoke/RESULTS.md) | PARTIAL GO | 150 ms debounce works; **macOS produces no `RenameMode::*` events for `fs::rename`** — daemon needs content-hash-based rename detection |

**Plan corrections required from spike findings** (applied below):

1. **`redb = "2"`, not `4`** — current is `2.6.3` on crates.io (May 2026). The redb-schema agent's "4.1.0" claim was wrong; framework-docs had it right. `Durability::None` + `Durability::Immediate` both exist in 2.6 and worked in the spike. (The earlier note that `Durability::Eventual` was "removed" is now moot — `None` is the canonical batched primitive regardless.)
2. **`schemars = "1"`, not `"0.8"`** — `rmcp 1.6` pulls `schemars 1.x` transitively. Pinning `schemars = "0.8"` directly produces a duplicate-major-version build where my `#[derive(JsonSchema)]` impls the wrong trait. Verified failure mode in P0.1.
3. **`Parameters` import path** is `rmcp::handler::server::wrapper::Parameters` — NOT `rmcp::handler::server::tool::Parameters` as the framework-docs agent claimed. The latter is private. Compiler suggests the correct path; rmcp's own test suite uses the corrected one.
4. **`ServerInfo` is `#[non_exhaustive]`** — cannot construct via struct literal. Canonical pattern is `let mut info = ServerInfo::new(caps); info.server_info.name = ...; info.instructions = Some(...); info`. Both `ServerInfo` and `Implementation` block `{}`-construction.
5. **macOS rename behavior**: `notify-debouncer-full 0.7` does **NOT** produce `EventKind::Modify(ModifyKind::Name(RenameMode::*))` events for either atomic-rename (write-tmp + rename-over) or cross-directory rename on macOS FSEvents in our test config. The framework-docs agent's `match` arms on `RenameMode::From`/`To`/`Both` would silently drop every rename in production. Workaround required in P6 (see §Daemon §Watcher addendum below).
6. **redb txn-open is ~0.8 µs on macOS arm64**, not the 50-200 µs the performance oracle predicted. Long-lived `ReadTransaction` per reader task is still a measurable ~2× p50 win and free to implement, but it is **not** "the single biggest warm-path win" as originally claimed.
7. **Token budget reality check**: 500 files of synthetic data = 4.53 MiB redb file. Linear extrapolation to 100k LOC ≈ 45 MiB on-disk, sitting just under S3's 50 MB target. Plan's "100k-LOC scope only" caveat on S3 is well-placed; verified empirically.
8. **fs::write of an existing file reports as `Create`, not `Modify(Data)`** on macOS FSEvents. Daemon must treat `Create` and `Modify(Data)` symmetrically in the event handler.

## Enhancement Summary

**Deepened on**: 2026-05-10 via 10 parallel research + review agents (repo research, learnings researcher, best-practices researcher, framework-docs researcher, SpecFlow analyzer, redb schema specialist, Aider repo-map specialist, framework specifics, SignatureRenderer + tree-shake specialist, architecture strategist, performance oracle, security sentinel, agent-native reviewer, simplicity reviewer, data-integrity guardian).

### Key improvements vs. the original plan

1. **Version corrections (load-bearing)**: `rmcp 0.16` → **`rmcp 1.6`** (the 0.x line was renumbered to 1.x). `redb 2.6` → **`redb 4.x`** (current; `Durability::Eventual` removed — only `None` and `Immediate` remain; batched-durability pattern updated). New required dep **`streaming-iterator = "0.1"`** for the tree-sitter 0.26 `QueryCursor::matches` iterator (no longer a regular `Iterator`).
2. **Renamed + split v1 tools** for verb-uniformity and to dodge function-calling union-type schemas: `repo_map` → `outline_workspace`; `lookup_symbol` → `find_symbol`; `get_slice` split into `read_symbol(name)` + `read_range(file, lines)`. Pin LLM-facing `description` strings as schema artifacts in P5.
3. **Drop `memmap2` segments**; store skeleton blobs in a `skeletons` redb table. Eliminates the only `unsafe` block and the torn-write/generation invariant entirely. (P0.4 spike retired.)
4. **Defer session dedup (R6) to v1.1** with a redesigned shape (`{signature, body_omitted: true, see_earlier_id, force_resend}`) — the original `see_earlier` pointer is hostile to MCP clients that flatten responses between turns.
5. **New mandatory architectural details for P5 protocol-v0**: capability negotiation (not single-version), `content_version` field on every slice/lookup response (v2 safe-edit ready), explicit cold-state semantics, parse-in-parallel + commit-serial writer drain, long-lived `ReadTransaction` per reader task (single biggest warm-path win).
6. **New mandatory security additions** (security sentinel HIGH findings): per-OS local auth recipe (`SO_PEERCRED` / `LOCAL_PEERCRED` / named-pipe ACL), path-traversal hardening (`O_NOFOLLOW`, per-read prefix check, refuse symlinked workspace components), workspace identity binds `(dev, inode, canonical_path)` (defeats symlink-swap), default secrets blocklist (`.env`, `id_rsa`, `*.pem`, `*.key`) that overrides `.gitignore`, code-extension allowlist for body returns, resource limits (mpsc bounds, in-flight cap, `token_budget` cap), `umask(0077)`, refuse-to-run-as-root, core-dump suppression.
7. **New per-language `SignatureRenderer` + tree-shake closure rules** with concrete tree-sitter anchor nodes per language (verified against grammars and the existing `src/languages/` adapters), per-language closure depths, stop-lists, and macro policy.
8. **Aider repo-map algorithm pinned to exact recipe** — MultiDiGraph of files (not symbols), edge weight `mul × sqrt(num_refs)` with the explicit multiplier formula, NetworkX-default PageRank params (α=0.85, max_iter=100, tol=1e-6), greedy-pack via binary search over prefix length. PageRank scores **precomputed at index build + incrementally patched** (performance oracle requirement — naive runtime PR is 50-300ms on 100k-symbol graphs, blowing S1).
9. **Confirmed O(n²) bug to delete in P4**: [src/semantic_graph.rs:510-548](src/semantic_graph.rs:510) `build_file_relationships` creates `same_file` edges between every pair of symbols in a file. Pollutes any future PageRank graph; not refactored — deleted.
10. **CI gates expanded**: `cargo audit -D warnings`, `cargo deny check`, assert `cargo tree -p rts-daemon` contains zero `reqwest`/`hyper`/`rustls`/`sqlx` entries (defense-in-depth on the CVE retirement claim).
11. **Phasing tightened**: P0 reduced to 2 days, P2 and P3 merged into one PR, P5 expanded with all the protocol-v0 details surfaced by SpecFlow + agent-native + security + data-integrity reviews. **Estimated total: 8-10 weeks instead of 10-12.**
12. **v1 scope explicitly Linux + macOS local FS**. Windows + network mounts: v1.1. `service-manager` install: v1.1. Tier-2 languages (the 9 beyond Rust/Python/TS for `SignatureRenderer`): gated on S2 measurement, ship in P8.

### Major tensions surfaced and resolved

| Tension | Source | Decision |
|---|---|---|
| Daemon vs embedded in `rts-mcp` | Architecture-strategist (keep) vs simplicity reviewer (drop) | **Keep daemon.** redb is single-process-at-open-time; two concurrent MCP clients (Cursor + Claude Code) cannot share an on-disk index without a daemon. R11 (multi-client install) requires it. |
| PageRank vs BFS-by-refcount | Performance oracle + Aider research (PageRank works, ≤30 LOC) vs simplicity reviewer (BFS until S2 fails) | **Ship PageRank** (precomputed + incremental). Aider's recipe is the only published validated approach to ≥50% reduction; the implementation is modest. |
| Session dedup mechanism | Agent-native review (`see_earlier` pointer is broken for MCP clients) vs original brainstorm (R6 required) | **Defer R6 to v1.1.** Redesigned shape (in-band signature + `body_omitted`) carried forward. v1 ships without dedup; bench measurement informs v1.1 priority. |
| memmap2 segments vs redb blobs | Plan default (memmap) vs simplicity reviewer + data-integrity guardian (drop) | **Drop memmap2.** Skeleton blobs go in a `skeletons` redb table; no torn-write race; no `unsafe`. |
| `forbid(unsafe_code)` everywhere vs flexibility | Plan default vs simplicity reviewer | **`forbid` on `rts-core`** (leaf library, no `unsafe` survives the cut), **`deny`** on `rts-mcp` / `rts-daemon` (escape hatch for future justified `unsafe`). |
| Single binary vs workspace of crates | Simplicity reviewer (2 crates) vs plan (5 crates) | **4 crates**: `rts-core`, `rts-daemon`, `rts-mcp`, `rts-bench`. `rts-cli` collapses into `rts-bench` subcommands. |

### Sections newly added during deepening

- §Local trust model & security boundary
- §Path canonicalization matrix (per OS)
- §Default secrets policy
- §Resource limits
- §Concrete redb schema
- §SignatureRenderer rules per language
- §Tree-shake closure rules per language
- §Aider repo-map algorithm (concrete recipe)
- §Decisions resolved during deepening

---

## Overview

Convert the existing ~148k-LOC `rust_tree_sitter` crate (today: library that *calls* LLMs for code analysis) into a **persistent local daemon + MCP stdio server** that *serves* AI coding agents (Claude Code, Cursor, Cline, Aider) with token-efficient, AST-precise code retrieval.

v1 ships **four MCP tools** — `outline_workspace`, `find_symbol`, `read_symbol`, `read_range` — backed by a workspace-scoped daemon that holds a hot tree-sitter index, watches files via `notify`, persists derived state to `redb` (no on-disk segments in v1), and is accessed by per-agent stdio MCP processes over a Unix-domain socket (named pipe on Windows — v1.1). Token reduction comes from precise slicing, signature-only skeletons, and tree-shaken AST/symbol-graph closures — all deterministic, fully offline, no LLM in the server. Session-aware dedup (R6) is **deferred to v1.1** with a redesigned shape (see §Decisions).

Getting there requires (a) a forced tree-sitter ABI bump (0.20 → 0.26.8) including the Query→QueryCursor + `streaming_iterator` API migration, (b) severing the one structural coupling between the surviving core and the cut buckets, (c) archiving four major capability areas (AI service layer, security analyzers, refactoring engines, wiki + dev tooling — ~30k+ LOC), (d) introducing a Cargo workspace, and (e) building a brand-new daemon + MCP stack on a greenfield (no existing IPC/MCP/watcher scaffolding in the repo).

## Problem Statement

Today's `rust_tree_sitter` is a library + CLI built for humans and for itself. Its README calls it an "Agent Code Utility," but its architecture is the opposite of what an agent wants:

- The "AI" features are *outbound* (we call OpenAI / Anthropic / Gemini). No agent can call *us*.
- There is no daemon, no IPC, no MCP server, no file watcher, no persistent index. Greenfield in every operational sense.
- The default build pulls in `ml`, `net`, `db` features → candle, hf-hub, tokenizers, reqwest, sqlx — three of which carry CVEs flagged in [docs/DEPENDENCY_AUDIT_REPORT.md](docs/DEPENDENCY_AUDIT_REPORT.md).
- A single coupling — `analyzer.rs` ↔ `advanced_security` — leaks security types into the public `FileInfo` struct and blocks clean archival of the security bucket. **Deepening confirmed**: 11 reference sites in `analyzer.rs` including doctest examples at [src/analyzer.rs:56](src/analyzer.rs:56) and [src/analyzer.rs:82](src/analyzer.rs:82).
- Many large modules (wiki gen, refactoring, AST transform, semantic-context taint machinery, AI service layer) do not serve agent retrieval. Keeping them slows builds, bloats the binary, multiplies maintenance, and dilutes the product story.
- **Confirmed O(n²) hot-path bug** that would pollute any future retrieval: [src/semantic_graph.rs:510-548](src/semantic_graph.rs:510) `build_file_relationships` emits a `same_file` edge between every pair of symbols in a file with weight 0.3. Outer loop runs this per file. On 100k LOC with avg 50 symbols/file across 500 files: ~625k spurious edges. **Deleted in P4**, not refactored.

Meanwhile coding agents — Claude Code, Cursor, Cline, Aider — currently burn tokens and wall-clock time orienting themselves by reading whole files, running `rg`, and re-parsing the same code every turn. There is a token-aware retrieval layer they all wish existed; no Rust-native one currently ships with the breadth (12 languages) + speed profile we can deliver.

See origin: [docs/brainstorms/2026-05-10-agentic-retrieval-mcp-requirements.md](docs/brainstorms/2026-05-10-agentic-retrieval-mcp-requirements.md) for the full product framing.

## Proposed Solution

A focused pivot to a **persistent local daemon + MCP stdio server** with four v1 tools, built on a slimmed core extracted into a Cargo workspace.

**Three-binary architecture:**
- `rts-daemon` (background process, one per workspace): owns the file watcher, parser pool, in-memory hot-tree cache, on-disk `redb` index, and PageRank score table. Speaks a small newline-JSON wire protocol over a Unix-domain socket. Auto-spawns on first MCP connect; idle-shutdown after 10 min.
- `rts-mcp` (per-agent stdio process, spawned by the agent client): thin MCP server using the official `rmcp = "1.6"` Rust SDK. Translates the four MCP tools into daemon RPCs.
- `rts-bench` (operator binary): benchmark harness + admin/inspect subcommands (formerly `rts-cli`). Allowed an outbound HTTP exception (`--with-network`) for the Anthropic `countTokens` oracle; the daemon and `rts-mcp` are strictly local-only.

**Four v1 MCP tools** (all `readOnlyHint=true`, `destructiveHint=false`, `openWorldHint=false`, `idempotentHint=true`):

| Tool | Purpose | Schema (sketch) |
|---|---|---|
| `outline_workspace` | Token-budgeted structural map of the workspace; first-call orientation | `{ glob?: string, token_budget?: number }` → outline (dotted text + structured sidecar) |
| `find_symbol` | Locate a named symbol; always returns a list of matches with `rank_score` | `{ name: string, kind?: string, file?: string }` → `{ matches: [{ qualified_name, kind, file, range, signature, rank_score }], truncated: bool }` |
| `read_symbol` | Read source of a named symbol; `shape={signature\|body\|both}`; optional tree-shaken dependency closure | `{ name: string, file?: string, kind?: string, shape?: "signature"\|"body"\|"both", token_budget?: number, include_dependencies?: bool, force_resend?: bool }` → slice + `content_version` |
| `read_range` | Read explicit `file + [start_line, end_line]` range; for stack traces, diffs, exact spans | `{ file: string, start_line: number, end_line: number, token_budget?: number }` → slice + `content_version` |

Plus an MCP **resource** for discoverability: `rts://capabilities` returning `{ protocol_version, languages, symbol_kinds_per_language, max_token_budget, indexing_state }`.

Tool-description strings (LLM-facing) are pinned in P5 as schema artifacts and include negative guidance ("do not use for…, fall back to your shell tool"). See §Tool descriptions below.

**Two v1 token-reduction mechanisms** (R6 deferred to v1.1):
- Precise slicing + skeleton mode (signatures only via per-language `SignatureRenderer`, bodies on demand).
- Tree-shaken context (AST/symbol-graph closure of minimum required surrounding declarations, per-language depth + edge-kind rules).

**Stack (all crate versions verified May 2026):**
- `rmcp = "1"` with features `["server", "macros", "transport-io", "schemars"]` (current as of May 2026 is 1.6.0; renamed from 0.x line; do not pin to 0.16) **[verified in P0.1]**
- `schemars = "1"` **[corrected after P0.1]** — rmcp 1.6 pulls `schemars 1.x` transitively; direct dep on `0.8` produces duplicate-major-version build failure
- `tree-sitter = "0.26"` (latest patch; ABI 15 default, min compat 13)
- `streaming-iterator = "0.1"` (required by tree-sitter 0.26 `QueryCursor::matches`/`captures`)
- `redb = "2"` **[corrected after P0.2]** — current is `2.6.3` on crates.io (May 2026); pure-Rust, ACID, MVCC, single-writer/many-reader
- `notify = "8.2"` + `notify-debouncer-full = "0.7"` (150 ms debounce, rename-aware)
- `ignore = "0.4.23"` (already in deps; reuse existing `analyzer.rs:collect_files_ignore`)
- `blake3 = "1"` (content hashing)
- `lasso = "0.7"` with `ThreadedRodeo` (concurrent string interner — single-threaded `Rodeo` would serialize readers)
- `petgraph = "0.6"` + a hand-rolled PageRank (~30 lines, see §Aider repo-map algorithm). `petgraph-graphalg` accepted if it builds cleanly.
- `unicode-normalization = "0.1"` (macOS NFC path normalization)
- `service-manager = "0.7"` — deferred to v1.1
- `tokio` (workspace-pinned, `rts-daemon`-only)
- `tracing` + `tracing-subscriber` (stderr only; stdout reserved for JSON-RPC)
- Rust edition **2024**, MSRV **1.85**, `#![forbid(unsafe_code)]` on `rts-core`; `#![deny(unsafe_code)]` on `rts-daemon` / `rts-mcp` (no `unsafe` is required in v1 after dropping `memmap2`, but `deny` leaves the escape hatch).

## Technical Approach

### Workspace shape (after migration)

```
rust_tree_sitter/
├── Cargo.toml                # workspace manifest (resolver = "3")
├── crates/
│   ├── rts-core/             # surviving parsing + indexing core (~12-15k LOC)
│   ├── rts-daemon/           # background service binary (new)
│   ├── rts-mcp/              # MCP stdio server binary (new)
│   └── rts-bench/            # benchmark harness + inspect subcommands (new; absorbs former rts-cli)
├── archive/                  # cut buckets, NOT in workspace, kept for git history
└── docs/
    ├── protocol-v0.md        # Daemon ↔ MCP wire protocol (P5 deliverable)
    ├── install.md            # Per-agent config snippets (P9)
    ├── benchmarks.md         # Methodology, corpus pinning, S1/S2/S3 protocol (P9)
    ├── architecture.md       # Overall design (P5/P6)
    └── ...
```

**Workspace dependency direction (hard constraint, validated in CI):**
- `rts-daemon` depends on `rts-core`, never the reverse.
- `rts-mcp` depends on `rts-core`, never `rts-daemon` (talks to it only over the socket).
- `rts-bench` depends only on `rts-mcp` (subprocess) and its own JSON parsing — explicitly forbidden from linking `rts-core` shortcuts. Bench must measure what real agents see.

### What survives the cut, restructured into `rts-core`

(see origin: brainstorm's surviving-core list; confirmed by repo research)

- `parser.rs`, `tree.rs`, `query.rs` (with the Query→QueryCursor + `streaming_iterator` migration applied in P1)
- `languages/{c,cpp,go,java,javascript,kotlin,php,python,ruby,rust,swift,typescript}.rs` (9,143 LOC, low-coupled)
- `symbol_table.rs`, `semantic_graph.rs` (with the O(n²) `build_file_relationships` **deleted**), `code_map.rs`
- `file_cache.rs` (with **LRU replacement** for the current first-key eviction, [src/file_cache.rs:106-115](src/file_cache.rs:106))
- `error.rs`, `constants.rs`
- A new `signature/` module with a per-language `SignatureRenderer` trait (rules below)
- A new `closure.rs` for the tree-shake walker (rules below)

**Conditional survival:**
- `semantic_context.rs` (1,995 LOC) — currently authored to feed taint/security. **Audit needed in P4** via `rg "use crate::(advanced_security|taint_analysis|complexity_analysis|...)" src/semantic_context.rs`. Architecture-strategist flagged this as a possible scope-bust if it imports cut buckets. If imports cleanly, keep only the data-flow primitives needed for tree-shake; excise sanitization machinery. If entangled, salvage minimum and write fresh.
- `advanced_cache.rs` (798 LOC) — likely over-engineered; replace with a simple `lru::LruCache` adapter; defer the actual on-disk store to `redb`.
- `infrastructure/` (cache, config) — keep only what `rts-core` needs; drop `database`/`http_client`/`rate_limiter` (tied to the AI service layer cut).
- `analyzer.rs` (2,328 LOC) — refactored down to a thin "build index from workspace" orchestrator. **`FileInfo.security_vulnerabilities` field is removed** (P2 sole structural change to a public type).

### Cut buckets (archived, not migrated)

(see origin: brainstorm's "Any of these existing capabilities you want to preserve in v1: archive all")

- AI service layer, security analyzers, refactoring + AST transform engines, wiki + dev tooling — see origin §Scope Boundaries for the full file list.
- ML/embeddings stack (candle, hf-hub, tokenizers) — also retires `RUSTSEC` advisories on `ring`, `sqlx`, `paste` etc. per [docs/DEPENDENCY_AUDIT_REPORT.md](docs/DEPENDENCY_AUDIT_REPORT.md). CI gate added in P2: `cargo deny check advisories bans`, plus `cargo tree -p rts-daemon` assertion that `reqwest`/`hyper`/`rustls`/`sqlx` are absent.
- Cargo features collapse: `default = ["std", "ml", "net", "db"]` → `default = ["std"]`. `ml`, `net`, `db`, `demo` features and their gated optional deps removed.

### Daemon ↔ MCP wire protocol (designed in P5)

`docs/protocol-v0.md` is the source of truth. Required contents:

1. **Wire format**: newline-delimited JSON envelope. `{ "id", "method", "params" }` request; `{ "id", "result"|"error", "partial?", "content_version?" }` response. Max message size 16 MiB; oversize → `MESSAGE_TOO_LARGE`. Stdout = JSON-RPC only; stderr = logs (rmcp 1.6 stdio gotcha).
2. **Method catalog (v0)**: `Daemon.Ping`, `Workspace.Mount`, `Workspace.Status`, `Workspace.Unmount`, `Index.Outline`, `Index.FindSymbol`, `Index.ReadSymbol`, `Index.ReadRange`, `Session.Open`, `Session.Close`. Notably **dropped from the original draft**: `Session.MarkDeduped` (leaky abstraction per architecture review), `Daemon.Cancel` per-step cancellation (Tokio `select!` on the request future suffices for v1; mid-closure cancellation is v2).
3. **Capability negotiation** (architecture review high-leverage edit): `Daemon.Ping` response includes `{ "protocol": "0", "capabilities": ["outline", "find_symbol", "read_symbol", "read_range", "rank_score", "tree_shake"] }`. v2 features (search, call-graph, edits) become new capability strings under the same `protocol: "0"`. **Single-version semver on the wire would force lock-step releases**; capability negotiation avoids it.
4. **`content_version` field on every slice response**: `blake3(file_content) || file_mtime_ns || index_generation`. v2 safe-edits will need byte-precise stable identifiers; cheap to add now, expensive to retrofit.
5. **Workspace identity** (data-integrity blocker + security HIGH): bind to **`(dev_id, inode, canonical_path)`**, not just `canonical_path`. Defeats symlink-swap attacks (security F9). Canonicalization matrix per OS:
   - **macOS**: `realpath()` + NFC-normalize via `unicode-normalization` (HFS+/APFS store NFD; users type NFC).
   - **Linux**: bytes-are-bytes + UTF-8 validate; reject non-UTF-8 paths with `INVALID_WORKSPACE_PATH`.
   - **Windows (v1.1)**: `GetFinalPathNameByHandleW` to resolve junctions + 8.3 names; lowercase ASCII portion only (Turkish dotted-I gotcha if you locale-uppercase).
   - Daemon socket path: `${XDG_RUNTIME_DIR}/rts/<hash>.sock` (Linux) or `~/Library/Caches/rts/<hash>.sock` (macOS). Refuse to start if `XDG_RUNTIME_DIR` unset on Linux (security F2: never fall back to `/tmp/rts-$UID/`).
   - redb file: `${XDG_STATE_HOME}/rts/<hash>/db.redb` — **outside the workspace** (data-integrity #8). On `Workspace.Mount` resume after idle, re-canonicalize; if path/inode changed, return `WORKSPACE_VANISHED`.
   - Conformance test matrix: `/Users/me/proj/`, `/Users/me/proj/../proj`, `/private/var/folders/.../proj` (macOS tmp-symlink case) must all canonicalize to the same daemon.
6. **Concurrency model**: many MVCC readers OK; single writer-drain task drains a `tokio::mpsc` from the watcher. Parse-in-parallel (rayon workers) + commit-serial (one redb txn per debounce window batched, NOT per file — performance oracle). Bounded mpsc (depth 256) with explicit `BUSY` backpressure on overflow.
7. **Cold-state semantics**: every request returns `{ "partial": true, "indexing_progress": { "files_done": N, "files_total": M } }` if initial index build is in flight. Public `workspace_status` MCP tool/resource lets agents poll. **S1 "cold" measurement starts after `ready` flip + first-byte**, not at process spawn.
8. **Session id (deferred for R6 in v1.1)**: when revived, synthesize 128-bit id at `Session.Open`; bind to MCP-client identity via kernel peer-credentials (Unix socket `SO_PEERCRED` / `LOCAL_PEERCRED`), **NOT** via `Mcp-Client-Name`/`Mcp-Client-Version` headers (those are agent-controllable via prompt injection — observability metadata only). 5-minute reconnect window so MCP-server restart doesn't dump state.
9. **Auth boundary** (security F1): mode `0600` on socket file + parent dir `0700` + `umask(0077)` before `bind()`. **Enforce kernel-level peer-credential check**: `SO_PEERCRED` (Linux), `LOCAL_PEERCRED`/`getpeereid()` (macOS). Refuse if peer euid != daemon euid. **Refuse to run as root** at daemon startup (`if geteuid() == 0 { abort }`).
10. **Resource limits** (security F7): per-connection in-flight cap of 16 concurrent tool calls; `token_budget` capped at 200_000; connection-establishment rate-limit per peer pid; bounded mpsc with backpressure exposed via `Workspace.Status`.
11. **Local trust model section in protocol-v0.md**: explicit statement of single-uid trust boundary — same-uid processes are trusted; cross-uid is the attack surface.
12. **Error code catalog**: `INDEX_NOT_READY`, `WORKSPACE_VANISHED`, `SCHEMA_VERSION_NEWER`, `MESSAGE_TOO_LARGE`, `BUSY`, `STORAGE_FULL`, `INCOMPATIBLE_VERSION`, `INVALID_WORKSPACE_PATH`, etc., each mapped to JSON-RPC error codes.

### Default secrets policy (security F5)

`.gitignore` is **not a security boundary**. Default exclusions enforced beyond `.gitignore`:

- Filename blocklist regex (excluded from indexing, never returnable by any tool):
  ```
  (^|/)\.env(\..*)?$                        # .env, .env.production, .env.local
  | (^|/)id_[rd]sa(\.pub)?$                 # SSH keys
  | (^|/)id_ecdsa(\.pub)?$
  | (^|/)id_ed25519(\.pub)?$
  | .*\.(pem|p12|pfx|key|kdbx|jks|crt|cer)$ # certs / keystores
  | .*credentials.*\.json$                  # gcloud, aws-style
  | (^|/)\.aws/(credentials|config)$
  | (^|/)\.npmrc$ | (^|/)\.pypirc$
  ```
- Content-pattern scanner at index time: flag-and-exclude files containing high-entropy strings matching AWS keys (`AKIA[0-9A-Z]{16}`), GitHub tokens (`gh[pousr]_[A-Za-z0-9]{36,}`), JWTs (`eyJ[A-Za-z0-9_-]{10,}\.eyJ`), or PEM headers (`-----BEGIN .* (PRIVATE )?KEY-----`).
- `.rtsignore` file in workspace root: additionally enforced beyond `.gitignore` (does not unignore — only adds).
- **`read_symbol`/`read_range` body returns gated on a code-extension allowlist** (`.rs`, `.py`, `.ts`, `.tsx`, `.js`, `.jsx`, `.go`, `.java`, `.c`, `.h`, `.cpp`, `.hpp`, `.cc`, `.cs`, `.php`, `.rb`, `.swift`, `.kt`, `.scala`, plus `.md`/`.toml`/`.yaml` for code-adjacent context). Other extensions: signature-only, no body.
- Document explicit warning in README: "rts-daemon indexes everything in the workspace not gitignored or blocklisted; do not point at directories containing secrets unless the secrets are in blocklisted filenames."

### Path safety (security F4)

- `WalkBuilder::follow_links(false)` (already default in `ignore 0.4.23`; verify explicitly).
- **Refuse `Workspace.Mount` if any component of the workspace path is a symlink.** This is stricter than `realpath()`-once, but eliminates the entire symlink-escape attack surface for v1.
- On every file open (not just Mount): re-canonicalize and verify the path starts with `canonical_workspace_root + "/"`. Use `openat(O_NOFOLLOW)`. **The watcher delivers paths; the daemon must NEVER trust the watcher's path without re-checking.**
- Refuse paths containing `..` segments in any incoming RPC.

### Concrete redb schema (replaces the deferred storage-engine spike)

Per the redb research:

```rust
// IDs (newtypes around u32; Key+Value impls auto-derived via small macro)
pub struct FileId(pub u32);
pub struct SymbolId(pub u32);

// File metadata
const FILES:       TableDefinition<u32, &[u8]>       // postcard(FileMeta)
const PATH_TO_FID: TableDefinition<&str, u32>
const FID_TO_PATH: TableDefinition<u32, &str>

// Symbol intern
const NAME_TO_SID: TableDefinition<&str, u32>
const SID_TO_NAME: TableDefinition<u32, &str>

// Definition / reference multimaps
const DEFS:        MultimapTableDefinition<u32, &[u8]>  // postcard(DefSite)
const REFS:        MultimapTableDefinition<u32, &[u8]>  // postcard(RefSite)

// Inverse index for invalidation on file save
const FID_DEFS:    MultimapTableDefinition<u32, u32>    // file -> symbols defined in it
const FID_REFS:    MultimapTableDefinition<u32, u32>    // file -> symbols referenced in it

// Skeleton blobs (replaces the dropped memmap segments)
const SKELETONS:   TableDefinition<u32, &[u8]>

// PageRank scores (precomputed at index build, incrementally patched on file change)
const PR_SCORES:   TableDefinition<u32, f64>            // FileId -> score

// Metadata: schema_version, workspace_fingerprint, last_checkpoint_seq, next_fid, next_sid
const META:        TableDefinition<&str, &[u8]>
```

`FileMeta` = `{ content_hash: [u8;32] /* blake3 */, mtime_ns: i64, lang: u8, parse_status: u8, oversize: bool }`. Files >4 MiB marked `oversize=true`, indexed by `(size, mtime)` only, excluded from skeleton/closure (data-integrity #7).

**Encoding**: `postcard` for values (≈zero-overhead, no_std-friendly, deterministic). Keys are fixed-width `u32` big-endian via redb's built-in impl.

**Multimap semantics**: a popular symbol (`new`, `from`) has hundreds of `DefSite` entries. Multimaps insert/scan in O(log n) page touches; alternative `TableDefinition<u32, Vec<DefSite>>` rewrites the full vec on every update — wrong choice.

**Write batching**: writer-drain task batches all parsed-file deltas in one `redb::WriteTransaction` per debounce window (150ms), commits at `Durability::None`; a periodic empty `Durability::Immediate` commit every 5s or every N=50 files flushes durably (canonical redb pattern). P0.2 measured **12.8 ms** for 100 files in one `None`-durability txn, **28.5 ms** at `Immediate`. A `git checkout` 2000-file storm: re-parse in parallel via rayon, funnel `SymbolDelta` records into the bounded mpsc, single batched txn per debounce window — ~250 ms total expected (sub-linear scaling per B-tree COW amortization) vs ~30 s naive per-file commit.

**Reader pattern**: keep a **long-lived `ReadTransaction` per reader task**, refresh only when the writer signals a new generation. P0.2 measured: shared-txn lookup p50 = **0.67 µs** vs fresh-txn-per-query p50 = **1.46 µs** — a 2.2× p50 win, ~1.4× tail win. Performance oracle's "50-200µs txn-open" prediction was off for macOS arm64 (actual: ~0.8 µs), so the sharing optimization is **not** the dominant warm-path lever — but it's free to implement and still measurable. P6 should adopt the pattern.

**Schema versioning**: `META["schema_version"]`. On open mismatch, **rebuild from scratch** (index is a derived cache — see #11 below). On `disk.schema_version > binary.schema_version`, daemon refuses to start with exit `SCHEMA_VERSION_NEWER`. Never silently downgrade.

**Lock authority**: redb's own `Database::create` takes an exclusive flock. PID file is hint-only — on `O_EXCL` collision, check `kill(pid, 0)` + start-time match; if stale, **rename** to `<pid>.pid.stale.<timestamp>` (don't unlink — forensics) and retry. redb refusing to open is the real safety net.

**The index is a derived cache.** `rm -rf ${XDG_STATE_HOME}/rts/<hash>/` is always safe and is the supported recovery procedure. Daemon rebuilds on next start. No `restore-index` in v1.

### Aider repo-map algorithm (concrete recipe)

Per the Aider research agent:

- **Graph type**: `MultiDiGraph` with **file nodes** (not symbol nodes). Symbols are edge labels via the `ident` field.
- **Tag extraction**: per-language `tags.scm` queries cribbed from `tree-sitter-language-pack` (Apache-2.0; carry per-file LICENSE + credit Aider). Categories collapse to `def` / `ref` once on the graph.
- **Edge weight per (referencer, definer) for each ident**: `weight = mul × sqrt(num_refs)` where
  ```
  mul = 1.0
      × 10  if ident in mentioned_idents
      × 10  if compound name && len >= 8  (snake/kebab/camelCase heuristic)
      × 0.1 if ident.starts_with("_")
      × 0.1 if len(defines[ident]) > 5    (ubiquitous identifiers)
      × 50  if referencer is in chat_files
  ```
- **Personalization vector**: `100 / len(personalized_fnames)` per qualifying file. A file qualifies if it's in chat-mentioned files, recently-edited files, or any path component matches a `mentioned_ident`.
- **PageRank parameters**: NetworkX defaults — α=0.85, max_iter=100, tol=1e-6, power iteration with row-stochastic transition. Handle degenerate input (no edges, no defs in personalization): retry without personalization; bail to alphabetical if still degenerate.
- **Rust implementation**: hand-rolled (~30 lines, pseudocode given by Aider research agent), flattening parallel edges to summed weights for ~5-10× speedup with identical scores. `petgraph` is fine as the graph container.
- **Precompute + incremental patch** (performance oracle requirement): full PageRank runs once at index build (~50-300ms on a 100k-symbol graph; one-time cost). On file change, only nodes within 2 hops of the changed file need re-scoring (push-flow approximate PageRank, Andersen et al. 2006 — ~1ms for local update). Personalization vector applied at query time via a single weighted-pull pass over precomputed scores (~1-5ms). **Without this, S1 fails on the 20% `outline_workspace` slice of the query mix.**
- **Greedy budget-packing**: binary search over the prefix length `middle` of the ranked tag list. Render via `grep-ast`-style `TreeContext` line-rendering (Rust port required; ~200 LOC). Accept when `|tokens - budget| / budget < 0.15`. Cuts at tag granularity, never mid-symbol.
- **Output format**: plain-text dotted outline (file path + `⋮...` + relevant lines) as the primary content block; a structured JSON sidecar resource (`rts://outline.json`) for downstream tools that re-rank. LLMs read dotted outlines cleanly.

**Quality differentiators over baseline Aider**:
- **FQN normalization**: Aider's `Foo::new` and `Bar::new` collide as plain `new`. Our tag-extraction pass disambiguates via enclosing scope.
- **Down-weight test files**: post-PR `× 0.3` for paths matching `tests/**`, `**/test_*.{rs,py,go}`, `spec/**`, `*_test.go`. Aider's `× 0.1 if >5 defs` is insufficient for test dominance.
- **Barrel-file detection**: `mod.rs`, `lib.rs`, `index.ts`, `__init__.py` with only refs and no substantive defs → render as one-line stub instead of full outline entry.
- **Per-session novelty scoring**: when R6 (v1.1) lands, penalize files already returned this session by a small multiplier.

### SignatureRenderer rules per language

Trait shape:

```rust
pub trait SignatureRenderer {
    fn render(&self, def: Node, src: &[u8]) -> Rendered;  // byte range over original src, ending at body-start
}
```

Strategy: re-emit byte range over original source ending at the last token before the body. Default excludes: function body, doc comments. Default includes: visibility, modifiers (`async`/`unsafe`/`static`/`const`/`final`/`abstract`/`override`/etc.), generics with bounds, parameter list with types, return type, `where`/`throws`/`requires` clauses, decorators/annotations that are children of the signature node.

| Language | Anchor nodes | Body-start cutoff | Gotcha |
|---|---|---|---|
| Rust | `function_item`, `function_signature_item`, `impl_item`, `trait_item`, `struct_item`, `enum_item`, `type_item`, `const_item`, `static_item` | `start_byte(body field) /* block */` | Outer doc comments (`///`) are sibling `line_comment` not children — walk previous siblings if needed |
| Python | `function_definition`, `decorated_definition`, `class_definition` | byte after the `:` opening the suite | Anchor on `decorated_definition` when present, not inner `function_definition` |
| TypeScript | `function_declaration`, `method_definition`, `method_signature`, `class_declaration`, `interface_declaration`, `type_alias_declaration` | `start_byte(statement_block)` | Two grammars (`typescript`, `tsx`); pick by extension. Overloads = sequential `function_signature`s + one `function_declaration` |
| JavaScript | `function_declaration`, `arrow_function`, `method_definition`, `class_declaration` | `start_byte(statement_block or body)` | JSDoc comments are sibling-only; never in default range |
| Go | `function_declaration`, `method_declaration` (with `receiver`), `type_declaration` | `start_byte(block_body)` | godoc requires immediately-preceding comment with no blank line — preserve adjacency when re-rendering |
| Java | `method_declaration`, `constructor_declaration`, `class_declaration`, `interface_declaration`, `record_declaration` | `start_byte(block_or_constructor_body)` | Annotations on parameters are inside `formal_parameter::modifiers` — don't strip them |
| C | `function_definition`, declarations with `function_declarator`, `struct_specifier`, `enum_specifier` | `start_byte(compound_statement)` | Preprocessor directives are NOT in `function_definition` subtree; indexer associates out-of-band. K&R-style old declarations need extra-careful range handling |
| C++ | `function_definition`, `template_declaration`, `class_specifier`, `namespace_definition` | `start_byte(body)` | `[[nodiscard]]` attributes are part of `attribute_specifier`. Macros expanding to declarations (`EXPORT void foo();`) parse as `ERROR` — degrade gracefully |
| PHP | `function_definition`, `method_declaration`, `class_declaration`, `enum_declaration` | `start_byte(compound_statement)` | PHP 8 `#[attribute_list]` is part of signature; abstract methods end with `;` |
| Ruby | `method`, `singleton_method`, `class`, `module` | `end_byte(parameters_or_method_name)` | No return-type syntax; Sorbet `sig {}` is a preceding `call` sibling — walk back if rich-mode requested |
| Swift | `function_declaration`, `init_declaration`, `class_declaration`, `protocol_declaration` | `start_byte(function_body)` | Community grammar lags official Swift; biggest source of `ERROR` nodes — needs raw-bytes-to-first-`{` fallback |
| Kotlin | `function_declaration`, `class_declaration`, `property_declaration` | `start_byte(function_body)` (block or `=`-expression) | Community grammar lags K2; single-expression body still ends before `=` |

Output struct: `Rendered { byte_range: Range<usize>, kind: SymbolKind, name: String, visibility: Option<Vis>, modifiers: Vec<Modifier> }`. Re-emit bytes verbatim — preserves formatting, cheap, no reconstruction.

**Shipping order**: Rust, Python, TypeScript in P7 (covers the test corpus); Go, Java, C, C++ in P8 early; PHP, Ruby, Swift, Kotlin in P8 late — Swift/Kotlin renderers ship with explicit "best-effort, expect ERROR-node fallback" caveat in the bench.

### Tree-shake closure rules per language

Per the SignatureRenderer specialist's deliverable 2:

| Language | Depth | Edge kinds expanded |
|---|---|---|
| Rust | 2 | TypeRef, Bound (trait bounds), Implements, Annotation (identity only), Import (`use` path) |
| Java | 3 | TypeRef, Inherits, Implements, Annotation, Import |
| TypeScript | 3 | TypeRef, Inherits, Implements, TypeAlias chain, Import |
| JavaScript | 1 + import-set | JSDoc TypeRef, Import only |
| Python | 1 + import-set fallback | Decorator, Annotation (PEP 484 hints), Inherits, Import |
| Go | 2 | TypeRef, Implements (seed-mentioned interfaces only), Import |
| C | 2 | TypeRef (struct/typedef), `#include` of translation unit |
| C++ | 2 | TypeRef, Bound (concepts/requires), Inherits, TemplateArg, Include |
| PHP | 2 | TypeRef, Inherits, Implements, Use (namespace), Annotation |
| Ruby | 1 + include-set | Inherits, Include/extend/prepend, constants in seed scope |
| Swift | 2 | TypeRef, Inherits, Conforms, Bound, Attribute |
| Kotlin | 2 | TypeRef, Inherits, Bound, Annotation, Import |

Each language has a YAML stop-list (Rust: `core::`, `alloc::`, `std::`, `Vec`, `String`, `Box`, `Arc`, `Rc`, `Option`, `Result`, `HashMap`, primitives, etc.; Python: `builtins`, `typing`, `collections.abc`; Java: `java.lang.*`; etc.). User can override.

**Macro / metaprogramming policy**:
- Rust `macro_rules!` and proc macros: **opaque**. Emit invocation byte range as-is; do not expand. Don't include macro definitions unless seed directly references the macro.
- Python decorators: include signature one-hop. `@dataclass`/`@cache`/`@property` stop-listed by default.
- TypeScript conditional/mapped types: include alias textual form; don't evaluate.
- C/C++ `#define`: include `preproc_def` text up to 256 bytes if seed signature mentions the identifier.
- Java/Kotlin/Swift annotations: include annotation type's signature one hop; don't recurse into members.

**Budget overflow**:
- Estimate per-signature cost via `bytes / 3.0` (corrected from `3.5` — code tokenizes denser than English prose per performance oracle), CJK-aware if any identifier byte ≥0x80.
- On overflow: don't admit; record in `truncated_symbols` set; mark parent edge `truncated_at: <symbol_id>`; **drain queue but stop expanding further**.
- Response always carries `closure_truncated: bool` + flat list — never an error.
- **Seed always emitted, even if over budget** (degenerate case: very large seed; honest signal back to agent).

**Algorithm shape**: BFS via `VecDeque`. `closure_set: HashSet<SymbolId>` for cycle break. Iterate `symbol_refs` in source order (`start_byte` ascending) for stable output. Wall-clock cap (5ms default for `read_symbol` with `include_dependencies=true`) — exceed → mark `wall_clock_truncated: true`.

For body-mode seeds, walk body to collect Call edges, but Call edges only count for closure expansion if per-language config opts in (Rust does NOT by default; TypeScript does at depth 1).

### Architecture diagram

```
Coding agent (Claude Code, Cursor, Cline, Aider)
     │  stdio (MCP JSON-RPC, ProtocolVersion::V_2024_11_05)
     │
     ▼
┌──────────────────┐
│ rts-mcp          │  per-agent process, rmcp 1.6
│ (stdio)          │  4 tools + capabilities resource
└──────────────────┘
     │  Unix-domain socket (newline-JSON, protocol-v0)
     │  capability-negotiated; SO_PEERCRED checked
     ▼
┌─────────────────────────────────────────────────────┐
│ rts-daemon (one per workspace; tier-User only)      │
│                                                     │
│  ┌────────────────┐    ┌────────────────────┐       │
│  │ Watcher        │───▶│ Writer-drain task  │       │
│  │ notify 8.2 +   │    │ (single, mpsc 256, │       │
│  │ debouncer-full │    │  parse parallel,   │       │
│  │ 150ms; ignore  │    │  commit serial)    │       │
│  │ pre-filter;    │    └────────┬───────────┘       │
│  │ secrets+ext    │             ▼                   │
│  │ blocklist      │   ┌─────────────────────┐       │
│  └────────────────┘   │ redb 4.x store      │       │
│                       │ (files, symbols,    │       │
│  ┌────────────────┐   │  refs, skeletons,   │       │
│  │ Parser pool    │──▶│  PR scores, meta)   │       │
│  │ (thread-local  │   │ MVCC readers; one   │       │
│  │  per language) │   │ long-lived ReadTxn  │       │
│  └─────┬──────────┘   │ per reader task.    │       │
│        ▼              └─────────────────────┘       │
│  ┌────────────────┐                                 │
│  │ Hot-tree LRU   │   PageRank scores precomputed   │
│  │ (Arc<Tree>,    │   at index build, push-flow     │
│  │  evict-cold)   │   patched on file change.       │
│  └────────────────┘                                 │
│                                                     │
│  Reader tasks (N): outline / find / read_symbol /   │
│  read_range. ThreadedRodeo for symbol intern.       │
└─────────────────────────────────────────────────────┘
```

### Tool descriptions (LLM-facing, pinned in P5)

- **`outline_workspace`**: *"Return a token-budgeted structural map of this workspace — file tree, top symbols per file, signatures only. Use first when you need orientation in an unfamiliar repo or when picking which files to read next. Do not use for finding a specific known symbol — call `find_symbol` instead. Do not use for reading a file you already know — call `read_symbol` or `read_range`."*
- **`find_symbol`**: *"Locate a named symbol (function, class, type, method, etc.) across the workspace. Returns a list of `matches` with definition location, signature, and `rank_score`. Use when you know the name. For partial / fuzzy / textual matches, this v1 server has no search — fall back to your shell `rg` tool."*
- **`read_symbol`**: *"Read the source of a named symbol. `shape=signature` returns just the declaration (cheap). `shape=body` returns the full implementation. `include_dependencies=true` adds the minimum surrounding types/imports the symbol references — use when you'll want to call/modify it without reading more. Prefer this over reading whole files."*
- **`read_range`**: *"Read explicit line range `[start_line, end_line]` from a file. Use for stack-trace frames, diff hunks, and other cases where you already have an exact location. For symbol-by-name access, use `read_symbol` instead."*

### Implementation Phases

#### P0 — Spikes (2 days, time-boxed; dropped from original 1-week scope)

Three short spikes (P0.4 memmap spike retired with the `memmap2` decision):

- **P0.1**: `rmcp 1.6` hello-world server. Tool that echoes input. Verify it round-trips end-to-end in Claude Code via local stdio. Confirms `ProtocolVersion::V_2024_11_05` works; nails down the `JsonSchema` derive pattern.
- **P0.2**: `redb 4.x` storage smoke. Build a toy `symbols` multimap on a 10k-LOC fixture; measure point-lookup latency (target <2µs warm), single-batched-txn write throughput on 100-file delta (target <50ms), on-disk size.
- **P0.3**: `notify 8.2` + `notify-debouncer-full 0.7` smoke on this worktree. Verify rename detection via `RenameMode::Both`/`From`/`To`, `need_rescan()` overflow signal, FSEvents coalescing on macOS, inotify watch count under stress.

**Exit criteria**: each spike's go/no-go recorded with measurements. If any spike fails its budget, the plan reconvenes for fallback (`redb` → `sqlx` + SQLite WAL is the documented fallback).

#### P1 — Tree-sitter ABI bump (1 week)

Forced precursor: tree-sitter `0.20 → 0.26.8` + all 12 grammars + Query API migration.

- Bump `tree-sitter = "0.26"`, add `streaming-iterator = "0.1"`.
- Bump each grammar to a known-good ABI 14/15 version (pin exact; hand-pin `tree-sitter-swift` / `-kotlin` which lag).
- Migrate `Query::new(language, …)` → `Query::new(&language, …)`.
- Move `set_match_limit`, `set_byte_range`, `set_point_range`, `set_max_start_depth` from `Query` onto `QueryCursor`.
- Rewrite `for m in cursor.matches(…)` loops to `while let Some(m) = it.next()` with `use streaming_iterator::StreamingIterator`. Grep targets: every call to `QueryCursor::matches`/`captures` in `src/query.rs` and `src/languages/*.rs`.
- `LookaheadIterator::iter_names()` stays the same name (earlier-research note was incorrect — confirmed against 0.26 docs).
- Add a startup smoke test that loads every `Language` into a `Parser` and parses a 1-line file per language. Run in CI; gates the PR.

**Exit criteria**: `cargo test --workspace`, `cargo clippy -- -D warnings`, `cargo fmt -- --check` all green. No other phases run before this PR lands.

#### P2+P3 — Uncoupling + Archive (one PR, 2 weeks; phases merged per simplicity review)

(Resolves SpecFlow C6 and bundles uncoupling + archive into a single coherent `0.2.0-alpha.1` tag rather than two interim broken states.)

- **Sever `analyzer.rs ↔ advanced_security`** at all 11 reference sites including doctest examples:
  - Remove field `FileInfo.security_vulnerabilities` ([src/analyzer.rs:223](src/analyzer.rs:223)).
  - Remove field `CodebaseAnalyzer.security_analyzer` ([src/analyzer.rs:295](src/analyzer.rs:295)).
  - Drop the security branch in `::new()` (311), `::default()` (2230), and both analyze paths (780, 943).
  - Remove `enable_security` from `AnalysisConfig`.
  - Fix module-level doctest examples at [src/analyzer.rs:56](src/analyzer.rs:56) and [src/analyzer.rs:82](src/analyzer.rs:82).
  - `cargo test --doc` must pass.
- **Pre-archive audit** (architecture review high recommendation): run `rg "use crate::(advanced_security|taint_analysis|complexity_analysis|smart_refactoring|advanced_ai_analysis|ai_analysis|reasoning_engine|intent_mapping|embeddings|wiki|ast_transformation|refactoring|enhanced_security|sql_injection_detector|command_injection_detector|fuzz_testing|integration_testing|test_coverage|ci_cd_integration|performance_benchmarking|code_evolution)" src/{code_map,semantic_context,semantic_graph,symbol_table,file_cache,analyzer,parser,tree,query,advanced_cache}.rs` and resolve every coupling. **If `semantic_context.rs` shows entanglement, expand the phase scope; do not silently absorb.**
- **Trim `src/lib.rs` re-exports**: remove `AdvancedSecurityAnalyzer as SecurityScanner`, `SecretsDetector`, `IntentMappingSystem`, `AdvancedAIAnalyzer`, `SmartRefactoringEngine`, `OwaspDetector`, `TaintAnalyzer`, the `intent_mapping_stub` shim at lines 204-205, and every other cut-bucket re-export.
- **Reduce default features**: `default = ["std", "ml", "net", "db"]` → `default = ["std"]`. Remove the `ml`, `net`, `db`, `demo` features.
- **Drop now-unused deps**: `candle-core`, `candle-nn`, `candle-transformers`, `hf-hub`, `tokenizers`, `reqwest`, `sqlx`, `governor`, `tower`, `crc32fast`, `pulldown-cmark`, `flate2`, `base64`, `syntect`, `rustyline`. Keep `tokio`/`tracing`/`dashmap` for return in `rts-daemon`.
- **Archive the cut buckets**: `git mv src/{ai,ai_analysis.rs,advanced_ai_analysis.rs,embeddings.rs,intent_mapping*.rs,reasoning_engine.rs,taint_analysis.rs,sql_injection_detector.rs,command_injection_detector.rs,security,enhanced_security.rs,advanced_security.rs,smart_refactoring.rs,refactoring.rs,ast_transformation.rs,wiki,fuzz_testing.rs,integration_testing.rs,test_coverage.rs,ci_cd_integration.rs,performance_benchmarking.rs,code_evolution.rs}` → `archive/`. Move dependent tests/examples to `archive/tests/` and `archive/examples/`.
- **Add CI gates**: `cargo deny check advisories bans licenses`, `cargo audit -D warnings`, plus an assertion script that `cargo tree -p rust_tree_sitter` contains zero `reqwest`/`hyper`/`rustls`/`sqlx`/`candle-*` entries.
- **CHANGELOG**: `0.2.0-alpha.1` heading with `### BREAKING CHANGES` listing removed types and features. Conventional-commit body. Bump version.

**Exit criteria**: green CI; binary size drops ≥30% on `tree-sitter-cli`; `tokei` shows surviving crate <40k LOC.

#### P4 — Cargo workspace + `rts-core` extraction (2 weeks)

- Convert root to a Cargo workspace; create `crates/rts-core/` and move surviving modules into it.
- Workspace-wide `edition = "2024"`, `rust-version = "1.85"`, `resolver = "3"`.
- Add `#![forbid(unsafe_code)]` to `rts-core` (verified: no `unsafe` survives the cut — the only one was in archived `embeddings.rs`).
- **LRU replacement** for [src/parser.rs:154-159](src/parser.rs:154) and [src/file_cache.rs:106-115](src/file_cache.rs:106) using `lru` crate.
- **`ThreadedRodeo` symbol interner** (performance oracle critical fix) — `Rodeo` would serialize concurrent readers and break the warm p95 budget. ~10-30ns overhead vs single-threaded; negligible.
- Replace `eprintln!` lock-failure logs with `tracing::warn!` at [src/parser.rs:96-98](src/parser.rs:96) and [src/file_cache.rs:97](src/file_cache.rs:97).
- **Delete `semantic_graph.rs::build_file_relationships`** ([src/semantic_graph.rs:510-548](src/semantic_graph.rs:510)) — the O(n²) `same_file` edge generator that would pollute any future PageRank. Replace with the tags.scm-driven ref→def edges from §Aider repo-map algorithm.
- Decide and execute on `semantic_context.rs` post-audit (P2 audit informs this).
- Drop `advanced_cache.rs` entirely; replace with a small `lru::LruCache` adapter at use sites.
- Re-export a clean `rts_core` public API: `Index`, `Symbol`, `Definition`, `Reference`, `Signature`, `WorkspaceOutline`, plus tree-sitter pass-throughs.
- CI gate: `cargo clippy -- -D clippy::unwrap_used -D clippy::expect_used` in non-test code.

**Exit criteria**: `rts-core` compiles standalone with `forbid(unsafe_code)`. No `unwrap()` in library code (clippy gates pass).

#### P5 — Daemon ↔ MCP protocol-v0 design (1 week, doc-only)

**No code in this phase.** Write `docs/protocol-v0.md` covering:
- Wire format + framing + max message size + error code catalog
- Method catalog (the 10 verbs above)
- **Capability negotiation** (high-leverage architecture-review edit)
- `content_version` field on all slice/lookup responses
- Workspace identity model with the per-OS canonicalization matrix + `(dev, inode, canonical_path)` binding
- Concurrency model: parse-parallel + commit-serial, bounded mpsc, in-flight cap
- Cold-state semantics (`partial: true` + `indexing_progress`; S1 measurement reset)
- Session-id sourcing (deferred for v1.1 R6; document the shape with `force_resend`)
- Cancellation contract (Tokio `select!` on request future)
- Auth boundary (mode + parent-dir + peer-credential check + named-pipe ACL for v1.1)
- **Local trust model & threat model** (security sentinel top recommendation): explicit single-uid trust boundary
- **Local Auth Recipe appendix** with concrete syscalls per OS
- **Path safety** (canonicalize + per-read prefix check + symlink rejection + inode binding)
- **Default secrets policy** (blocklist regex + content-pattern scanner + extension allowlist for body)
- **Resource limits** with concrete numbers
- JSON Schema fragments for every method

**Exit criteria**: doc reviewed and merged; subsequent code PRs cite section anchors.

#### P6 — Daemon (3 weeks)

Build `crates/rts-daemon/` implementing protocol-v0 on a Unix-domain socket.

- **Lifecycle**: PID-file + lockfile under `${XDG_RUNTIME_DIR}/rts/<workspace_hash>.{pid,lock}`. Refuse to start if `XDG_RUNTIME_DIR` unset on Linux. **Refuse to start as root** (`geteuid()==0 → abort`). `umask(0077)` at startup. `prctl(PR_SET_DUMPABLE, 0)` on Linux / `setrlimit(RLIMIT_CORE, 0)` (prevent core-dump leaks). Auto-spawn-on-first-MCP-connect. Idle-shutdown after 10 min.
- **Tokio runtime**: multi-thread (CPU count) for the daemon (multiple clients); current-thread for `rts-mcp`.
- **Workspace mount**: validate path against §Path safety; claim redb lock (authoritative); rename stale PID via `.stale.<timestamp>` if found dead; start `ignore::WalkBuilder` walk (reuse [src/analyzer.rs:423-461](src/analyzer.rs:423) `collect_files_ignore`); honor secrets blocklist + extension allowlist; transition `indexing` → `ready`. Refuse if path is on a network mount (data-integrity #3).
- **Watcher**: `notify::RecommendedWatcher` wrapped in `notify-debouncer-full`, 150 ms debounce. Pre-filter ignored dirs via `ignore::gitignore::Gitignore::matched_path_or_any_parents` and editor-swap-file regex (vim `.swp`/`4913`/`~`, JetBrains `___jb_tmp___`, VS Code `.tmp.NNN`, Emacs `.#`/`#…#`). On `event.need_rescan()` overflow, force re-walk of affected subtree; transition workspace to `indexing` until done. `PollWatcher` fallback when `notify::ErrorKind::MaxFilesWatch` or network-mount detected.
- **macOS rename workaround (P0.3 finding)**: `notify-debouncer-full 0.7` does NOT produce `EventKind::Modify(ModifyKind::Name(RenameMode::*))` events for `fs::rename` on macOS FSEvents in our config. Atomic-rename (write-tmp + rename-over) and cross-dir rename both surface as `Create + Modify(Data) + Other`. The daemon's event handler MUST NOT depend on `RenameMode::*` matching. Two paths:
  - **Symmetric path**: treat `Create` and `Modify(Data)` the same — both trigger re-parse + upsert. Renames just look like a delete-then-create pair (or a fresh-create) and we pay one extra parse. Acceptable for v1 and the simplest correct design.
  - **Content-hash rename detection (optional)**: maintain a `path → blake3(first 64 KiB)` map; on `Create` of a previously-unseen path that matches a recently-`Remove`d path's content, skip re-parse and just relink. Defer to v1.1 unless re-parse cost on rename storms (large `git checkout`s) is measurably hot in P9.
- **`Create` vs `Modify(Data)` symmetry (P0.3 finding)**: `fs::write` of an existing file reports as `Create` on macOS, not `Modify(Data)`. Do not branch on event kind to decide whether to re-parse; branch only on path identity.
- **Parser pool**: thread-local `Parser` per rayon worker, keyed by `Language`. tree-sitter `Parser` is `!Send` across concurrent parses; a single mutex would serialize all parsing.
- **Hot-tree LRU**: `lru::LruCache<FileId, Arc<Tree>>` sized to RAM budget. Performance oracle revised tree-memory estimate to **8-12× source bytes**, not 3-5× — for 100k LOC sized ~5MB total source, full-tree cache fits at ~50MB; for 1M LOC monorepos the LRU is partial and cold misses re-parse from disk (`fs::read` + parse). Tier 2 — a larger "skeleton-only" cache from the redb `SKELETONS` table — backs the LRU so cold misses reconstruct from skeleton without full re-parse for the common signature-only requests.
- **redb store**: per §Concrete redb schema. Single writer-drain task; `Durability::None` per debounce window + periodic `Immediate` flush. **One long-lived `ReadTransaction` per reader task** (single biggest warm-path win).
- **PageRank precompute + incremental patch** per §Aider repo-map algorithm; stored in `PR_SCORES` table.
- **Error model**: every error maps to a protocol-v0 error code. No panics in library code; clippy-deny `unwrap_used`/`expect_used` in `rts-daemon`.

**Exit criteria**: daemon passes a protocol conformance test suite (added in this phase). Survives `kill -9` of the watcher task without dropping client connections. Memory budget verified.

#### P7 — MCP server (1-2 weeks)

Build `crates/rts-mcp/` using `rmcp 1.6`.

- Four tool definitions via `#[tool_router]` + `#[tool]` + `#[tool_handler]` macros. `Parameters<T>` types deriving `schemars::JsonSchema`.
- **Imports correct as verified in P0.1**: `use rmcp::handler::server::{router::tool::ToolRouter, wrapper::Parameters};` — NOT `handler::server::tool::Parameters` (private). Server struct must carry `tool_router: ToolRouter<Self>` and call `Self::tool_router()` in its constructor.
- **`ServerInfo` is `#[non_exhaustive]`**: construct via `let mut info = ServerInfo::new(ServerCapabilities::builder().enable_tools().build()); info.server_info.name = ...; info.server_info.version = ...; info.instructions = Some(...); info`. Both `ServerInfo` and `Implementation` block struct-literal construction.
- **Error contract verified in P0.1**: argument validation failures surface as JSON-RPC `-32602 "Invalid params"` errors (NOT `CallToolResult` with `isError: true`). Reserve `CallToolResult::error(...)` for "tool ran but found nothing / failed" cases the agent should see.
- MCP **resource**: `rts://capabilities` for discoverability.
- **stdio hygiene**: `tracing_subscriber::fmt().with_writer(std::io::stderr).with_ansi(false)`; stdout reserved for JSON-RPC.
- **`ProtocolVersion::V_2024_11_05`** for broad client compat (2025-06-18 has `structuredContent` — adopt in v1.1 if clients support it).
- **`partial: true` handling**: when client provides `_meta.progressToken`, emit `ProgressNotificationParam` mid-call; else embed `{partial, indexing_progress}` in the JSON content payload (no top-level `partial` field exists in MCP spec).
- **Error model**: argument validation → `Err(McpError::invalid_params)`; tool ran but found nothing / timed out → `CallToolResult::error(...)`.
- **Connection to daemon**: discover socket via workspace path → `blake3((dev_id, inode, canonical_path))` → socket file. If socket missing, spawn `rts-daemon` and wait up to 5s with backoff (loser of the spawn race polls for winner's socket, doesn't respawn).
- **`tokens_returned` + `token_counter` in every response payload** (agent-native critical fix — agents need this to track their own budget).
- Skeleton mode renderers: Rust, Python, TypeScript shipped in P7; others in P8.

**Exit criteria**: `rts-mcp` works end-to-end in Claude Code via stdio. `claude mcp add` flow documented. The four tools enumerate and round-trip.

#### P8 — Token-reduction depth (2-3 weeks; some gated on S2 measurement)

- **Per-language `SignatureRenderer`** for remaining 9 languages (Go, Java, C, C++, PHP, Ruby, Swift, Kotlin). Per-language fixture tests. Swift / Kotlin ship with explicit "best-effort + ERROR-node raw-byte fallback" caveat.
- **Tree-shake closure walker** per §Tree-shake closure rules per language: per-language depth + edge-kind config + stop-list YAML + macro policy + budget-overflow + cycle-break. Property-based test (`proptest`) for invariants.
- **PageRank quality differentiators**: FQN normalization, test-file down-weighting, barrel-file detection.
- **Telemetry**: `tracing` spans on every tool call; structured fields for `cache_hit`, `tokens_returned`, `partial`, `closure_truncated`. Opt-in via `RTS_TELEMETRY=1`; sink to `${XDG_STATE_HOME}/rts/<hash>.jsonl` with 64-MiB rotation + 3-file retention; silent-drop on `ENOSPC`.

**Exit criteria**: S2 bench shows ≥50% reduction. Property tests pass.

#### P9 — Benchmarks + agent compatibility + install (2 weeks)

- **`crates/rts-bench/`**:
  - Fixture corpus: pinned in `corpus.lock` (per-repo `{name, git_url, commit_sha, tarball_url, tarball_sha256, archive_size_bytes}`). Candidates: `tokio-rs/tokio` (~95k LOC Rust), `mitmproxy/mitmproxy` (Python), `microsoft/vscode-extension-samples` (TS). Restore is idempotent; `rts-bench fixture restore` verifies SHA256 before extract; total budget ≤1 GB. Fixtures land in `corpus/` (gitignored).
  - **5 baseline tasks** (enumerated):
    1. Locate definition of a named function across the repo.
    2. Get the body of a named function (≤200 LOC).
    3. Find all callers of a named function.
    4. Summarize a module (top-N exported symbols within a 1k-token budget).
    5. Fix-import scenario (given a file, list types referenced but not imported).
  - Baseline runner: subprocess `rg -n <pattern>` + simulated `read_file`; captures tokens needed to reach a task-correct response.
  - MCP runner: subprocess `rts-mcp` per task; captures tokens returned + tool call count.
  - **Network exception**: bench harness uses Anthropic SDK `messages.countTokens()` as the token oracle. Gated behind `--with-network` flag. **API key from env only** (`RTS_BENCH_ANTHROPIC_API_KEY`), never argv, never logged, `tracing` redaction. Daemon and `rts-mcp` link zero HTTP code paths (CI asserts via `cargo tree`).
  - Model pin: record current model id (e.g., `claude-sonnet-4-6-<date>`) in `corpus.lock`.
  - Output: `bench-<sha>.json` with per-task `baseline_tokens` / `mcp_tokens` / `reduction%`. CI gate: median reduction ≥50%.
  - **Latency bench (S1)**: synthetic 100k-LOC fixture, 1000 randomised queries (mix 50% `find_symbol` / 30% `read_symbol` / 20% `outline_workspace`), report p50/p95/p99 cold and warm. Plus a "queries under sustained write load" variant (architecture review recommendation 11) — re-running queries while a `git checkout` storm hits the watcher.
  - **Footprint bench (S3)**: record peak RSS during indexing and serving; on-disk index size; index build time.
- **Agent compatibility**:
  - **Claude Code**: `.mcp.json` snippet + `claude mcp add` command in `docs/install.md`. Smoke test on macOS arm64.
  - **Cursor**: `~/.cursor/mcp.json` snippet. Smoke-tested.
  - Cline + Aider + Continue snippets documented (not formally tested).
- **Distribution**: `cargo install --path crates/rts-mcp` and `cargo install --path crates/rts-daemon`. Add `release.yml` GitHub Action for prebuilt binaries (Linux x86_64/aarch64, macOS x86_64/aarch64). Windows: v1.1.
- **Docs sweep**: rewrite `README.md` from scratch. Delete `INSTRUCTIONS.md`/`CLI_README.md`/`.windsurferrules`/`.clinerules` (or move to `archive/`). Add `docs/install.md`, `docs/protocol-v0.md`, `docs/benchmarks.md`, `docs/architecture.md`.

**Exit criteria**: S1, S2, S3, S4 all measured and passing. CHANGELOG `0.2.0` entry with BREAKING-CHANGE marker. Tag `v0.2.0`.

## Alternative Approaches Considered

(see origin: "Alternatives Considered" — repeating with deepening insights)

- **"Preserve everything, expose existing analyzers as MCP tools."** Rejected (origin + deepening).
- **"Per-session in-memory only, no daemon."** Rejected.
- **"On-disk index, no daemon (stateless server)."** Rejected.
- **"Two binaries (tiny agent core + keep existing CLI)."** Rejected.
- **"Token reduction via LLM summarization."** Rejected.
- **"sled or fjall for storage"**: rejected; sled still alpha; fjall maintainer wind-down. `redb 4.x` is the stable pick. (see research: framework-docs §4.)
- **"jsonrpsee for transport"**: rejected; rmcp bundles JSON-RPC + stdio + MCP envelope.
- **"Hand-roll MCP"**: rejected; `rmcp 1.6` macro-driven schemas are an ergonomic win.
- **NEW: "Drop the daemon, embed in `rts-mcp`"** (simplicity reviewer): **rejected**. redb is single-process-at-open-time; two concurrent MCP clients per workspace (R11's explicit target) cannot share an on-disk index without a daemon. Multi-client architecture is the daemon's real argument, not latency.
- **NEW: "Drop `memmap2` segments, use redb blobs"** (simplicity + data-integrity): **accepted**. Skeleton blobs fit in a `SKELETONS` redb table. Eliminates the only `unsafe`, the torn-write race, and an entire spike.
- **NEW: "Replace PageRank with BFS-by-refcount"** (simplicity reviewer): **rejected**. Aider's recipe is ~30 lines; performance oracle's "precompute + incremental patch" makes it fast enough. Validated against ≥50% reduction in Aider's own work.
- **NEW: "`see_earlier` pointer for session dedup"** (original plan): **rejected**. Agent-native reviewer flagged that MCP clients flatten responses between turns; the pointer is unrecoverable. Redesigned shape for v1.1: in-band signature + `body_omitted: true` + `force_resend`.
- **NEW: "Single-version protocol-v0"** (original plan): **rejected**. Architecture-strategist argues capability negotiation is required to avoid v2 wire breaks. Adopted.

## System-Wide Impact

### Interaction Graph

Agent invokes an MCP tool → `rts-mcp` (stdio, rmcp 1.6) → `rts-daemon` (Unix socket, protocol-v0 envelope) → daemon reader task (long-lived `ReadTransaction`) → redb point lookup or multimap scan → skeleton blob via `SKELETONS` table or body re-read via re-parse / hot-tree LRU → response → MCP tool result → agent.

Two levels deep on the writer path: file save → notify event → `notify-debouncer-full` (150 ms window) → ignore + secrets + extension pre-filter → bounded mpsc to writer-drain task → rayon-parallel reparse via parser pool (thread-local Parsers) → batched `WriteTransaction` (one per debounce window) upserts symbols/refs/skeleton blob + bumps PageRank scores via push-flow patch → commit `Durability::None` → workspace_status reflects new generation → reader tasks pick up the new generation on next request.

### Error & Failure Propagation

- Tree-sitter parse error → file marked `parse_failed` in `FileMeta.parse_status`; tool calls referencing that file return `partial: true` with `parse_failed_files: [...]`.
- Watcher overflow (`Event::need_rescan()`) → daemon forces full re-walk of the affected subtree; queries return `partial: true` until complete.
- redb durability failure → daemon trusts redb's two-phase commit recovery; rebuilds from scratch only on `Database::open` error or unparseable metadata.
- Unix-socket disconnect mid-tool-call → daemon cancels via the request task's `CancellationToken` (tied to the request future via Tokio `select!`).
- Daemon crash → MCP server detects via socket EOF, attempts auto-respawn (backoff up to 3 retries); session-dedup is in-memory and resets cleanly (R6 v1.1).
- Parser timeout (per-language budget; default 5s carried over from [src/parser.rs:110-111](src/parser.rs:110)) → mark file `parse_timeout`.
- Out-of-disk → daemon returns `STORAGE_FULL`; serves cached reads until cleared.
- `WORKSPACE_VANISHED` → returned when daemon resumes from idle and finds the canonical workspace path / inode has changed; MCP server reports cleanly.

### State Lifecycle Risks

- **redb single-writer**: enforced by `Database`'s flock + writer-drain serialization. Documented invariant: no MCP tool handler ever takes a write txn.
- **Hot-tree LRU stale-tree**: trees pin `(FileId, generation)`; watcher bumps generation on file change and evicts. Reads check pinned vs current generation; mismatch → re-parse.
- **Skeleton blob consistency**: every reader sees `(skeleton, symbol_table, refs)` from one MVCC snapshot — redb's per-`ReadTransaction` consistency contract. No torn-read possible.
- **Multi-daemon race**: redb flock is authoritative; PID file is hint-only; stale PID renamed not unlinked (forensics).
- **Workspace fingerprint**: `blake3(sorted_list_of((canonical_relative_path, content_hash)) || schema_version || ignore_rule_digest)` stored in META. >10% files changed at startup → rebuild. Content hash (not mtime) defeats `git checkout` false positives.
- **Session dedup ghost entries**: N/A in v1 (deferred to v1.1).

### API Surface Parity

- Today's `tree-sitter-cli` exposes 14 subcommands; v1 has none of them as public commitments. Version bump to `0.2.0` makes this explicit.
- The new public surface is `rts-core`'s `Index` API + the protocol-v0 method catalog + the four MCP tools + the `rts://capabilities` resource.
- **`rts-bench` is the ONLY operator surface**; all useful inspection commands (`workspace_status`, `reindex`, `cache_stats`) are MCP tools or resources. CI rule added: "any `rts-bench` subcommand operating on a live workspace must be backed by an MCP tool or resource" (agent-native review).

### Integration Test Scenarios

Five cross-layer scenarios:

1. **Cold MCP connect during initial index** — start daemon on a 100k-LOC workspace; immediately fire `outline_workspace`. Expect `partial: true` with progress, then a follow-up after `Workspace.Status=ready` returns full result. Verifies cold-state semantics.
2. **Concurrent MCP clients** — Claude Code + Cursor both connect; both fire `read_symbol` of the same symbol simultaneously. Expect both succeed; both get session-distinct response ids; redb MVCC readers don't block each other.
3. **Edit-during-query** — `read_symbol(foo)` mid-flight; file containing `foo` is saved. Expect snapshot-consistent response: either pre-edit or post-edit clean, never torn.
4. **Watcher overflow recovery** — `git checkout` 2000 files. Daemon flips to `indexing`; queries return `partial: true`; re-walk completes; final state is consistent.
5. **Workspace symlink swap** — daemon mounted at `/workspaces/proj` which is a symlink; attacker swaps target. On next access, daemon detects `(dev, inode)` mismatch and returns `WORKSPACE_VANISHED`. Verifies security F9.

(Original scenario 5 about MCP-restart hot dedup is deferred to v1.1 with R6.)

## Acceptance Criteria

### Functional Requirements

- [ ] **R1**. MCP-first surface; 4 v1 tools `outline_workspace`, `find_symbol`, `read_symbol`, `read_range` + `rts://capabilities` resource (see origin §Requirements R1; tool names finalized during deepening).
- [ ] **R2**. `outline_workspace(token_budget)` returns token-budgeted dotted-text outline + structured JSON sidecar.
- [ ] **R3**. `find_symbol` returns a list of matches (always a list, even of length 1) with `rank_score`; AST-precise, multi-language.
- [ ] **R4**. `read_symbol` returns body or skeleton via per-language `SignatureRenderer`; `include_dependencies=true` invokes the tree-shake closure walker.
- [ ] **R5**. Tree-shaken context per language depth + edge-kind rules; closure-truncated responses carry `closure_truncated: true` + flat list; never error.
- [ ] **R6 (deferred to v1.1)**. Session-aware dedup with redesigned in-band shape: `{signature, body_omitted: true, see_earlier_id, force_resend}`. v1 omits dedup; deemed acceptable per simplicity + agent-native reviews.
- [ ] **R7**. Persistent `rts-daemon` per workspace; on-disk index in `redb`; PageRank scores precomputed at index build + incrementally patched.
- [ ] **R8**. All 12 languages preserved.
- [ ] **R9**. Local-only — `cargo tree -p rts-daemon` asserts zero `reqwest`/`hyper`/`rustls`/`sqlx` (CI gate). Bench harness exception explicit and opt-in.
- [ ] **R10**. `.gitignore`, global gitignore honored; `.rtsignore` custom file honored; default secrets blocklist + content-pattern scanner additively enforced; code-extension allowlist gates body returns.
- [ ] **R11**. Drop-in MCP install: documented for Claude Code + Cursor; Cline/Aider/Continue snippets included.

### Non-Functional Requirements (S1–S4 with measurement protocol)

- [ ] **S1 — Query latency**. Pinned 100k-LOC fixture; query mix 50% `find_symbol` / 30% `read_symbol` / 20% `outline_workspace`; 1000 randomised queries. **Warm**: daemon ≥60s running + ≥1 prior query against same workspace; p95 < 10ms. **Cold**: daemon up, `Workspace.Status=ready`, no prior query this session; p95 < 100ms. Second variant: **under sustained write load** (parallel `git checkout` storm); p95 < 50ms warm.
- [ ] **S2 — Token reduction ≥50%**. 5-task bench suite (enumerated above). Token oracle: Anthropic `messages.countTokens()` with model id pinned in `corpus.lock`. Median reduction across tasks ≥50%. Network exception explicit; daemon offline.
- [ ] **S3 — Footprint**. Index build <5s on 100k-LOC fixture (cold disk). On-disk index <50 MB. Resident daemon RSS <200 MB at steady-state. Documented as **100k-LOC scope only**; larger monorepos may need tuning per performance oracle's tree-memory revision.
- [ ] **S4 — Agent compatibility**. Working end-to-end in Claude Code + Cursor on macOS arm64; documented config snippets work from a clean install.

### Quality Gates

- [ ] `cargo build --workspace` clean.
- [ ] `cargo test --workspace` green (including the 5 integration scenarios).
- [ ] `cargo clippy --workspace --all-targets -- -D warnings -D clippy::unwrap_used -D clippy::expect_used` clean in non-test code.
- [ ] `cargo fmt --workspace -- --check` clean.
- [ ] `cargo doc --workspace --no-deps` clean.
- [ ] `#![forbid(unsafe_code)]` on `rts-core`; `#![deny(unsafe_code)]` on `rts-daemon`, `rts-mcp` (no `unsafe` is required in v1 after dropping memmap2; deny leaves a door).
- [ ] `cargo audit -D warnings` + `cargo deny check advisories bans licenses` clean.
- [ ] **Dependency-set assertion** (security F10): `cargo tree -p rts-daemon` and `cargo tree -p rts-mcp` contain zero `reqwest`/`hyper`/`rustls`/`sqlx`/`candle-*`/`hf-hub` entries.
- [ ] Protocol conformance test suite passes against the daemon.
- [ ] `rts-bench` reports a complete `bench-<sha>.json`; CI gates on S2 ≥50%.

## Success Metrics

- **Primary**: S1–S4 all pass.
- **Secondary**:
  - Binary size: `rts-mcp` stripped < 6 MB; `rts-daemon` stripped < 15 MB.
  - Build time (clean release build of full workspace) < 60s on a modern laptop.
  - At least one external agent maintainer or third-party blog post links the project within 30 days of v0.2.0.

## Dependencies & Prerequisites

- **Hard external deps**: `rmcp = "1.6"`, `schemars = "0.8"`, `tree-sitter = "0.26"`, twelve grammar crates pinned, `streaming-iterator = "0.1"`, `redb = "4"`, `notify = "8.2"`, `notify-debouncer-full = "0.7"`, `ignore = "0.4.23"`, `blake3 = "1"`, `lru = "0.12"`, `lasso = "0.7"` (with `ThreadedRodeo`), `petgraph = "0.6"`, `unicode-normalization = "0.1"`, `tokio` (daemon only), `tracing`, `serde`/`serde_json`, `postcard`, `regex`.
- **Soft deps**: `service-manager = "0.7"` (v1.1), Homebrew tap (v1.1).
- **Toolchain**: Rust 1.85+ (edition 2024). CI matrix: macOS arm64, Linux x86_64 (Linux aarch64, Windows x86_64 → v1.1).

## Risk Analysis & Mitigation

| Risk | Severity | Likelihood | Mitigation |
|---|---|---|---|
| `tree-sitter-swift` / `-kotlin` lag breaks the 0.26 bump | High | Medium | P1 pins per-grammar; CI smoke test loads every language. Fallback: keep laggards at old version under conditional compile. |
| `semantic_context.rs` is more entangled with cut buckets than assumed | Medium | Medium | P2 pre-audit (architecture-review high recommendation); expand scope if found. |
| `redb` single-writer + multi-MCP-client load causes writer backpressure | Medium | Medium | Parse-parallel + commit-serial pattern; bounded mpsc with explicit `BUSY`; "queries under sustained write load" S1 variant verifies. |
| `notify` misses events on macOS / Linux under burst load | High | Medium | `notify-debouncer-full` + `need_rescan()` overflow handling + `PollWatcher` fallback. |
| RAM budget exceeded on 1M-LOC monorepo (8-12× tree memory) | High | Medium | Scope S3 to 100k LOC; hot-tree LRU + skeleton-only tier for cold. |
| MCP spec drift breaks `rmcp` compat | Medium | Medium | Pin `rmcp 1.6`; isolate MCP layer behind thin trait. |
| Workspace symlink-swap / path-traversal attack | High (security) | Low | Refuse symlinked workspace components; `(dev, inode)` binding; `O_NOFOLLOW`; per-read prefix check. |
| Secrets exposure via `.env`/keys not in `.gitignore` | High (security) | High | Default secrets blocklist + content-pattern scanner + extension allowlist for body returns. |
| Cross-uid Unix-socket connect | High (security) | Low | Mode `0600`, parent dir `0700`, `SO_PEERCRED`/`LOCAL_PEERCRED` enforcement. |
| `service-manager` system-install grants root access to user workspaces | High (security) | Low | Forbid `ServiceLevel::System`; `refuse-to-run-as-root` startup check (regardless of source). |
| Cross-workspace daemon collisions (nested git repos) | Medium | High | Workspace pinned at Mount; out-of-root paths rejected on every read. |
| Bench API-key leak | Medium | Medium | env-only via `RTS_BENCH_ANTHROPIC_API_KEY`; `--with-network` opt-in; `tracing` redaction; never argv; never in `corpus.lock`. |
| PageRank precompute fails to scale on 100k-symbol graphs | Medium | Low | Power-iteration profiled in P0/P9; incremental push-flow patch keeps per-edit cost <1ms. |
| Bench `countTokens` model id deprecated mid-bench | Low | Medium | Model id pinned in `corpus.lock`; re-pin on annual cadence. |

## Resource Requirements

- **Engineering**: One full-time engineer for ~8-10 weeks at the phased cadence above (reduced from 10-12 by phase merges). Parallelism opportunities flagged: P5 doc can run concurrently with P4 extraction; P9 fixture scaffolding can run concurrently with P6 daemon work; P8 per-language renderers parallelize across languages.
- **Infrastructure**: GitHub Actions (Linux x86_64, macOS arm64). Anthropic API key for bench harness (<$1/run).
- **Fixtures**: ~120 MB pinned external repos in `corpus/` (gitignored; restored via `rts-bench fixture restore`).

## Future Considerations (v2+)

- Structured search (semantic + lexical + tree-sitter pattern DSL as MCP tool).
- Code reasoning (callers/callees, blast-radius, diff-aware structured changes).
- Safe edits (`edit_symbol`, `rename_symbol`, `apply_patch`) — `content_version` field is the wire-level hook.
- Session-aware dedup (R6 with the redesigned shape; v1.1).
- Windows support; network-mount support; embeddings / hybrid semantic search; remote/hosted streamable-HTTP transport.
- Service-manager install (`service-manager 0.7`, `ServiceLevel::User` only).

## Documentation Plan

- `README.md` — full rewrite.
- `docs/install.md` — per-agent config snippets (P9 deliverable).
- `docs/protocol-v0.md` — wire protocol (P5 source of truth).
- `docs/benchmarks.md` — S1/S2/S3 methodology, corpus pinning, reproducibility.
- `docs/architecture.md` — workspace shape, daemon design, on-disk format.
- `CHANGELOG.md` — `0.2.0` entry with `BREAKING CHANGE` markers.
- Archive (or delete): `INSTRUCTIONS.md`, `CLI_README.md`, `.windsurferrules`, `.clinerules/`.
- Keep & update: `AGENTS.md`, `CONTRIBUTING.md`.

## Decisions Resolved During Deepening

| # | Decision | Origin | Resolved by |
|---|---|---|---|
| D1 | Tool names: `outline_workspace`, `find_symbol`, `read_symbol`, `read_range` (rename + split) | Origin R1 / agent-native review | Plan §Proposed Solution |
| D2 | Drop `memmap2` segments; skeletons in `SKELETONS` redb table | Simplicity + data-integrity reviews | Plan §Concrete redb schema |
| D3 | Defer R6 session dedup to v1.1 with redesigned shape | Agent-native + simplicity reviews | Plan §Proposed Solution + Risk table |
| D4 | Keep daemon (against simplicity reviewer's recommendation) | Architecture + redb research | Plan §Alternative Approaches |
| D5 | `redb 4.x` (not 2.6); `Durability::None` + periodic `Immediate` flush | Framework-docs + redb research | Plan §Concrete redb schema |
| D6 | `rmcp 1.6` (not 0.16) | Framework-docs research | Plan §Proposed Solution |
| D7 | Add `streaming-iterator = "0.1"` for tree-sitter 0.26 query API | Framework-docs research | Plan §Stack |
| D8 | Capability negotiation in protocol-v0 (not single-version) | Architecture review | Plan §Daemon ↔ MCP wire protocol |
| D9 | `content_version` field on every slice/lookup response | Architecture review | Plan §Daemon ↔ MCP wire protocol |
| D10 | Delete [src/semantic_graph.rs:510-548](src/semantic_graph.rs:510) O(n²) `build_file_relationships` in P4 | Performance oracle | Plan §P4 + §Problem Statement |
| D11 | Long-lived `ReadTransaction` per reader task | Performance oracle | Plan §Concrete redb schema |
| D12 | `ThreadedRodeo`, not `Rodeo`, for symbol interning | Performance oracle | Plan §P4 |
| D13 | PageRank precomputed at index build + incremental push-flow patch | Performance oracle + Aider research | Plan §Aider repo-map algorithm |
| D14 | Tree memory revised to 8-12× source bytes; scope S3 to 100k LOC | Performance oracle | Plan §S3 + Risk table |
| D15 | Token approximator `bytes / 3.0` (not 3.5), CJK-aware | Performance oracle | Plan §Tree-shake closure rules |
| D16 | Per-OS path canonicalization matrix (macOS NFC, Linux UTF-8, Windows v1.1) | Data-integrity guardian | Plan §Daemon ↔ MCP wire protocol §5 |
| D17 | Workspace identity = `(dev_id, inode, canonical_path)` (defeats symlink swap) | Security sentinel F9 + data-integrity | Plan §Daemon ↔ MCP wire protocol §5 |
| D18 | Default secrets blocklist + content-pattern scanner + extension allowlist | Security sentinel F5 | Plan §Default secrets policy |
| D19 | Refuse symlinked workspace components; per-read prefix check; `O_NOFOLLOW` | Security sentinel F4 | Plan §Path safety |
| D20 | `SO_PEERCRED` / `LOCAL_PEERCRED` peer-credential enforcement | Security sentinel F1 | Plan §Daemon ↔ MCP wire protocol §9 |
| D21 | Resource limits: bounded mpsc, in-flight cap 16, `token_budget` cap 200k | Security sentinel F7 | Plan §Daemon ↔ MCP wire protocol §10 |
| D22 | `umask(0077)`, refuse-to-run-as-root, `prctl(PR_SET_DUMPABLE, 0)` | Security sentinel F12/F13 | Plan §P6 |
| D23 | redb file at `${XDG_STATE_HOME}/rts/<hash>/db.redb` outside workspace | Data-integrity #8 | Plan §Concrete redb schema |
| D24 | `WORKSPACE_VANISHED` error on Mount-resume if `(dev, inode)` changed | Data-integrity #8 | Plan §Error & Failure Propagation |
| D25 | Index is derived cache; `rm -rf state-dir` is supported recovery | Data-integrity #11 | Plan §Concrete redb schema |
| D26 | Workspace fingerprint = `blake3((path, content_hash)* || schema_version || ignore_digest)` | Data-integrity #4 | Plan §State Lifecycle Risks |
| D27 | Refuse to open schema-newer redb files; never silently downgrade | Data-integrity #6 | Plan §Concrete redb schema |
| D28 | Files >4 MiB indexed by `(size, mtime)` only; excluded from skeleton/closure | Data-integrity #7 | Plan §Concrete redb schema |
| D29 | redb's `Database::create` flock is authoritative; PID file is hint-only; rename-stale | Data-integrity #5 | Plan §Concrete redb schema |
| D30 | Phases P2 + P3 merge into one PR | Simplicity reviewer | Plan §Implementation Phases |
| D31 | `rts-cli` collapses into `rts-bench` subcommands; 4 crates not 5 | Simplicity + agent-native | Plan §Workspace shape |
| D32 | `forbid(unsafe_code)` on `rts-core`; `deny(unsafe_code)` on `rts-daemon`/`rts-mcp` | Simplicity reviewer | Plan §Stack |
| D33 | v1 scope = Linux + macOS local FS; Windows + network mounts = v1.1 | Multiple reviewers | Plan §Future Considerations + Risk table |
| D34 | Telemetry opt-in via `RTS_TELEMETRY=1`; 64 MiB rotation × 3; silent-drop on ENOSPC | Data-integrity #12 | Plan §P8 |
| D35 | `idempotentHint=true` + per-tool `title` field on all 4 MCP tools | Agent-native review | Plan §Proposed Solution |
| D36 | `tokens_returned` + `token_counter` in every MCP response payload | Agent-native review | Plan §P7 |
| D37 | `rts://capabilities` MCP resource for discoverability | Agent-native review | Plan §Proposed Solution |
| D38 | Tool descriptions pinned as schema artifacts in P5 | Agent-native review | Plan §Tool descriptions |
| D39 | `find_symbol` always returns a list with `rank_score`; never silently top-1 | Agent-native review | Plan §Proposed Solution |
| D40 | CI gate: any `rts-bench` workspace subcommand must be backed by an MCP tool/resource | Agent-native review | Plan §API Surface Parity |

## Outstanding Questions

### Resolve Before Implementation Starts

(none — all D1-D40 decisions land in this plan; remaining items are tuning, not blocking)

### Deferred to Implementation (small empirical decisions)

- [Affects P4] Final disposition of `semantic_context.rs` post-coupling audit — keep slim, salvage minimum, or rewrite.
- [Affects P0.2] If redb storage spike fails latency budget, fall back to `sqlx` + SQLite WAL — re-baseline S3.
- [Affects P6] Hot-tree LRU exact size (start ~5000 entries; tune against corpus).
- [Affects P8] Per-language closure depth tuning vs measured S2 quality.
- [Affects P9] Whether `corpus/` is vendored (tarball under git LFS?) or `rts-bench fixture restore` fetches at run time. Default: runtime fetch.
- [Affects P9] Pick `cl100k_base` (tiktoken-rs) or Anthropic-pinned tokenizer as the canonical bench oracle — current plan pins Anthropic `countTokens` model id; revisit if API access becomes an issue.

## Sources & References

### Origin

- **Origin document**: [docs/brainstorms/2026-05-10-agentic-retrieval-mcp-requirements.md](docs/brainstorms/2026-05-10-agentic-retrieval-mcp-requirements.md). Key decisions carried forward: AI coding agents as primary consumer via MCP; ruthless ~70% surface cut; v1 = three retrieval primitives (now four after the agent-native split); persistent daemon + on-disk index; token reduction via slicing + skeletons + tree-shaken context + (R6 session dedup deferred to v1.1); 12 languages preserved; local-only/offline; S1–S4 acceptance gates with shipped benchmark harness.

### Internal References

- Surviving core: [src/parser.rs](src/parser.rs), [src/tree.rs](src/tree.rs), [src/query.rs](src/query.rs), [src/languages/](src/languages), [src/symbol_table.rs](src/symbol_table.rs), [src/semantic_graph.rs](src/semantic_graph.rs) (with [src/semantic_graph.rs:510-548](src/semantic_graph.rs:510) `build_file_relationships` to be DELETED in P4), [src/code_map.rs](src/code_map.rs), [src/file_cache.rs](src/file_cache.rs), [src/analyzer.rs:423-461](src/analyzer.rs:423) (reuse ignore-aware walk).
- Uncoupling target: [src/analyzer.rs:56](src/analyzer.rs:56), [src/analyzer.rs:82](src/analyzer.rs:82), [src/analyzer.rs:223](src/analyzer.rs:223), [src/analyzer.rs:295](src/analyzer.rs:295), and refs at lines 56/82/223/738/753/792/810/899/915/955/968.
- Cargo manifest: [Cargo.toml](Cargo.toml) (features and deps to trim in P2).
- Conventions: [AGENTS.md](AGENTS.md), [INSTRUCTIONS.md](INSTRUCTIONS.md), [.clinerules/rust rules.md](.clinerules/rust%20rules.md).
- Audit context: [docs/DEPENDENCY_AUDIT_REPORT.md](docs/DEPENDENCY_AUDIT_REPORT.md), [docs/MEMORY_SAFETY_AUDIT.md](docs/MEMORY_SAFETY_AUDIT.md), [docs/CODE_QUALITY_REVIEW.md](docs/CODE_QUALITY_REVIEW.md).

### External References (verified May 2026)

- **MCP**:
  - Spec 2025-11-25: https://modelcontextprotocol.io/specification/2025-11-25
  - Transports (2025-11-25): https://modelcontextprotocol.io/specification/2025-11-25/basic/transports
  - 2026 roadmap: https://blog.modelcontextprotocol.io/posts/2026-mcp-roadmap/
  - Future of MCP transports (Dec 2025): https://blog.modelcontextprotocol.io/posts/2025-12-19-mcp-transport-future/
  - `rmcp` Rust SDK: https://github.com/modelcontextprotocol/rust-sdk · https://crates.io/crates/rmcp · https://docs.rs/rmcp/1.6.0/rmcp/
- **tree-sitter 0.26**: https://docs.rs/crate/tree-sitter/latest · https://docs.rs/tree-sitter/0.26.8/tree_sitter/struct.QueryCursor.html · https://github.com/tree-sitter/tree-sitter/releases
- **streaming-iterator**: https://docs.rs/streaming-iterator
- **notify 8.2** + **debouncer-full 0.7**: https://docs.rs/crate/notify/latest · https://docs.rs/notify-debouncer-full/0.7.0/notify_debouncer_full/
- **redb 4.x**: https://github.com/cberner/redb · https://docs.rs/redb/latest/redb/ · https://docs.rs/redb/latest/redb/enum.Durability.html · https://github.com/cberner/redb/blob/master/docs/design.md
- **`ignore` 0.4**: https://docs.rs/ignore/latest/ignore/ · https://docs.rs/ignore/latest/ignore/struct.WalkBuilder.html
- **Tokio graceful shutdown**: https://tokio.rs/tokio/topics/shutdown
- **`service-manager`** (v1.1): https://github.com/chipsenkbeil/service-manager-rs
- **Rust 2024 edition**: https://doc.rust-lang.org/edition-guide/rust-2024/index.html · https://blog.rust-lang.org/2025/02/20/Rust-1.85.0/
- **rust-analyzer architecture** (salsa, durable incrementality): https://rust-analyzer.github.io/book/contributing/architecture.html · https://rust-analyzer.github.io/blog/2023/07/24/durable-incrementality.html
- **gopls scalability**: https://go.dev/blog/gopls-scalability · https://go.dev/gopls/design/implementation
- **Aider repo-map**: https://aider.chat/2023/10/22/repomap.html · https://aider.chat/docs/repomap.html · https://github.com/Aider-AI/aider/blob/main/aider/repomap.py · https://github.com/Aider-AI/aider/tree/main/aider/queries
- **Aider SWE-bench harness**: https://github.com/Aider-AI/aider-swe-bench
- **SWE-bench Verified**: https://www.swebench.com/verified.html
- **Serena MCP** (symbol-verb API reference): https://github.com/oraios/serena
- **2025-2026 prior art**: https://github.com/pdavis68/RepoMapper · https://github.com/CodeGraphContext/CodeGraphContext · https://github.com/DeusData/codebase-memory-mcp · https://github.com/websines/codegraph-mcp
- **`grep-ast`** (TreeContext renderer for porting): https://github.com/Aider-AI/grep-ast
- **LSP 3.17** (encoding & DocumentSymbol): https://microsoft.github.io/language-server-protocol/specifications/lsp/3.17/specification/
- **universal-ctags** (signature/typeref reference): https://docs.ctags.io/en/latest/man/ctags.1.html
- **Anthropic token counting**: https://platform.claude.com/docs/en/build-with-claude/token-counting
