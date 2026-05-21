# `protocol-v0` — Daemon ↔ MCP wire protocol

**Status**: Draft 2 — **alpha.30 baseline (2026-05-13)**. Originally P5 deliverable of the agentic-retrieval MCP pivot (see [docs/plans/2026-05-10-001-feat-pivot-to-agentic-retrieval-mcp-server-plan.md](plans/2026-05-10-001-feat-pivot-to-agentic-retrieval-mcp-server-plan.md)); this draft tracks the **shipped** wire surface as of `v0.2.0-alpha.30`. See [Appendix F](#appendix-f--wire-shape-evolution-by-alpha) for per-alpha additive changes since Draft 1. The next pre-v0.3 addition is the v0.3 code-graph KB extension (see [docs/plans/2026-05-13-001-feat-v0.3-code-graph-kb-plan.md](plans/2026-05-13-001-feat-v0.3-code-graph-kb-plan.md)).
**Audience**: anyone implementing `rts-daemon` (P6) or `rts-mcp` (P7), and anyone reviewing the cross-process contract between them.
**Scope**: the wire protocol between **one `rts-daemon`** (background service, one per workspace) and **N `rts-mcp` clients** (per-agent stdio MCP server processes that talk to the daemon over a Unix-domain socket / named pipe). The MCP surface that *agents* see is governed by the [MCP 2025-11-25 spec](https://modelcontextprotocol.io/specification/2025-11-25) and is not redefined here — this document covers only the daemon's private side.

---

## 1. Trust model

`protocol-v0` is a **single-user, local-only** protocol.

The threat boundary is the user account:
- **Trusted**: every process owned by the same uid as the daemon.
- **Untrusted**: every process owned by a different uid, every remote system, every untrusted file on disk that hasn't been opened, every byte coming over the network.

What this implies:
- Cross-uid access is the attack surface. The socket file mode, parent-directory permissions, and kernel peer-credential checks (§9) defend against same-host other-uid actors.
- Same-uid processes are trusted as far as the operating system trusts them. A malicious same-uid process can already do anything the daemon can; the daemon does not try to defend against it.
- The daemon refuses to run as root. The retrieval product has no business being privileged.
- Path safety (§6) and the default secrets policy (§13) defend against *content* on disk that shouldn't leak through the MCP surface — these are about preventing the agent's prompt-injection surface from being weaponised, not about a host-level attacker.

This document does not specify a TLS, encryption, or multi-user story. Adding one is a v2-or-later concern.

---

## 2. Architecture overview

```
Coding agent (Claude Code, Cursor, Cline, Aider, Continue, ...)
      │   MCP / JSON-RPC over stdio (protocol version 2024-11-05 by default)
      ▼
┌──────────────────┐
│ rts-mcp          │  per-agent process, rmcp 1.6
│ (stdio binary)   │  exposes 7 tools: outline_workspace, find_symbol,
└─────────┬────────┘  find_callers, impact_of, read_symbol,
                     read_symbol_at, read_range
                     + rts://capabilities resource
          │
          │   protocol-v0  (this document)
          │   newline-delimited JSON over a Unix domain socket
          │   (named pipe on Windows; v1.1)
          ▼
┌──────────────────────────────────────────────────┐
│ rts-daemon (one per workspace)                   │
│  Watcher (notify+debouncer-full, 150 ms)         │
│  Parser pool (rayon, thread-local per language)  │
│  Hot-tree LRU + skeleton blobs                   │
│  redb store (single writer, MVCC readers)        │
│  Session-aware dedup state (v1.1)                │
└──────────────────────────────────────────────────┘
```

Multiple `rts-mcp` processes (one per agent) may simultaneously talk to a single `rts-daemon`. Per-MCP-process state is light (just the active session id and outstanding-request map); the heavy state — index, hot trees, dedup cache — lives in the daemon.

---

## 3. Wire format

### 3.1 Transport

- **Unix domain socket** (Linux, macOS) at a per-workspace, per-user path (§5.2).
- **Windows named pipe** (v1.1). Same envelope, different socket primitive.

Each connection is full-duplex. Multiple in-flight requests on a single connection are supported (the client demultiplexes by `id`). Implementations SHOULD NOT open more than one connection per `rts-mcp` process under steady state; pooling is for the daemon side via Tokio's multi-thread runtime.

### 3.2 Framing

**Newline-delimited JSON.** One JSON value per line, terminated by `\n` (LF only — never CRLF). The parser MUST tolerate an optional trailing `\r` before the `\n` for compatibility with line-buffered Windows tooling.

- No `Content-Length` header.
- No JSON-RPC 2.0 envelope (we are *inspired by* JSON-RPC but do not claim conformance).
- UTF-8 only. Implementations MUST reject invalid UTF-8 on the wire with `INVALID_FRAME` (§14).

### 3.3 Max message size

`16 MiB` per message in either direction. Exceeding the cap closes the connection with `MESSAGE_TOO_LARGE` (§14). Tool authors who want larger payloads should chunk over multiple requests using ranges (§7.5) or page tokens.

### 3.4 Request and response shape

```jsonc
// Request
{
  "id":        "<u64 monotonic per connection>", // required
  "method":    "Index.LookupSymbol",              // required
  "params":    { ... },                           // required (may be {} for verbs that take no args)
  "cancel_id": "<opaque client-chosen string>"    // optional; v0.6+ (capability `cancellable_queries`)
}
```

The optional `cancel_id` field lets a client mark a request as
cancellable from another connection (or a later request on the same
connection) via `Daemon.Cancel { cancel_id }`. Format: any non-empty
string of 1..=256 chars; the client picks (UUID, counter, etc.) and is
responsible for uniqueness across in-flight requests. Cancellable
handlers (v0.6+: `Index.Grep`, `Index.FindSymbol`, `Index.FindCallers`,
`Index.ReadSymbol`, `Index.Outline`, `Workspace.Mount`) cooperatively
poll the token at hot-loop boundaries and return `CANCELLED` (§14)
when tripped. Pre-v0.6 daemons ignore the field; clients that don't
set it see byte-identical behavior to v0.5.x.

```jsonc
// Response (success)
{
  "id":     "<echoes request.id>",
  "result": { ... }
}
```

```jsonc
// Response (error)
{
  "id":    "<echoes request.id>",
  "error": {
    "code":    "INDEX_NOT_READY",                // see §14
    "message": "human-readable reason",
    "data":    { ... }                            // optional, error-specific structure
  }
}
```

```jsonc
// Notification (no response expected; rare in v0)
{
  "method": "Daemon.Telemetry",
  "params": { ... }
}
```

Notifications have **no `id` field** and never get a response. v0 only emits `Daemon.Telemetry` notifications (opt-in, §17).

Field rules:
- `id` MUST be a JSON string holding a decimal `u64`. Strings (not numbers) so very large ids survive JS-style float-precision round-tripping in tooling.
- `method` MUST match the regex `^[A-Z][A-Za-z]+\.[A-Z][A-Za-z]+$` (capability + verb, dot-separated).
- `params` MUST be a JSON object (never `null`, array, or scalar).

### 3.5 Partial responses

Any response payload MAY include a top-level `partial` boolean field with value `true`. When present:
- The accompanying `result` is a best-effort answer based on the index's *current* state.
- A `progress` sub-object MUST be included; see §8.
- The client MAY wait for `Workspace.Status` to flip to `ready` and re-issue the same request to get a complete answer.

```jsonc
{
  "id": "42",
  "result": { ... },
  "partial": true,
  "progress": { "files_done": 1234, "files_total": 5000, "phase": "indexing" }
}
```

### 3.6 `content_version`

Any response payload that returns code text or symbol locations MUST include a top-level `content_version` field. Format:

```text
content_version = blake3(file_content)[:16] || "@" || file_mtime_ns_decimal || "+" || index_generation_decimal
```

Example: `"a7b0c1d2e3f40516@1747000000000000000+47"`.

This is the **v2 safe-edit hook** (architecture-review high-leverage edit). When v2 ships `edit_symbol` / `apply_patch`, the agent will pass back the `content_version` it last saw; the daemon will refuse the edit if any component has advanced (stale view). v0 servers MUST emit the field; v0 clients SHOULD record it but MAY treat it as opaque.

---

## 4. Capability negotiation

`protocol-v0` uses **capability negotiation, not single-version semver**. The agent or daemon can advertise new behaviour additively without forcing lock-step releases.

### 4.1 `Daemon.Ping`

```jsonc
// req
{ "id": "1", "method": "Daemon.Ping", "params": {} }

// resp
{
  "id": "1",
  "result": {
    "protocol":     "0",                          // semver-style major; v1 is the breaking re-cut
    "daemon":       { "name": "rts-daemon", "version": "0.2.0-alpha.35", "git_sha": "c12e525..." },
    "capabilities": ["outline", "find_symbol", "read_symbol", "read_range",
                     "rank_score", "tree_shake", "partial_responses",
                     "content_version", "secrets_blocklist",
                     "pagerank_filewise",
                     "closure_walker",
                     "read_symbol_at", "fuzzy_match",
                     "polling_fallback",
                     "find_callers", "read_symbol.include_callers",
                     "pagerank_symbolwise",
                     "impact_of",
                     "find_symbol_limit_param",      // v0.4.1+
                     "find_symbol_doc_field",        // v0.5.0+
                     "find_symbol_doc_filter",       // v0.5.2+
                     "find_symbol_pre_filter_count", // v0.5.2+
                     "find_symbol_signature_field", // v0.5.3+
                     "index_grep",                   // v0.5.4+
                     "index_grep_multiline",         // v0.6 alpha+
                     "index_grep_structural",        // v0.6 alpha+
                     "index_grep_within_symbol",     // v0.6 alpha+
                     "index_grep_v2",                // v0.6 alpha+ (bundle)
                     "cancellable_queries"],         // v0.6+
    "uptime_ms":    123456
  }
}
```

The client MUST NOT depend on capabilities that aren't in the advertised list. The daemon MUST advertise every behaviour the client could reasonably depend on. Adding a capability is non-breaking; removing one *is* breaking (mint a new capability string instead).

### 4.2 Reserved future capabilities

These strings are reserved and MUST NOT be advertised by `protocol-v0` daemons unless the corresponding code is implemented:

- `session_dedup` — R6 deferred to v1.1 (§9.5).
- `incremental_pagerank` — P8 push-flow ranking (deferred from alpha.20 memoization).
- `safe_edits` — v2 `edit_symbol` / `apply_patch`.
- `structured_search` — v2 semantic + lexical search.

Reserved for the **v0.3 code-graph KB** extension (see [v0.3 plan](plans/2026-05-13-001-feat-v0.3-code-graph-kb-plan.md)). Each is advertised independently when its implementing PR lands:

- ~~`find_callers`~~ — **advertised** as of `v0.2.0-alpha.32` (U2'). `Index.FindCallers` returns direct callers of a named symbol; see §7.7c.
- ~~`impact_of`~~ — **advertised** as of `v0.2.0-alpha.35` (U5). `Index.ImpactOf` returns transitive caller closure via BFS over reverse edges, bounded by depth + token + node-count + wall-clock; see §7.7d.
- ~~`read_symbol.include_callers`~~ — **advertised** as of `v0.2.0-alpha.32` (U2'). `Index.ReadSymbol.params.include_callers: bool` composes with `include_dependencies`; see §7.7.
- ~~`pagerank_symbolwise`~~ — **advertised** as of `v0.2.0-alpha.34` (U4). Symbol-level PageRank fills `rank_score` in `Index.FindSymbol` + `Index.FindCallers` responses; `find_symbol` results sort by descending rank by default. Clients pinned to v0.2 insertion-order ordering can pass `sort: "lexical"` on `Index.FindSymbol.params` to opt out.
- `call_graph` (umbrella; reserved but **not advertised by itself** — agents should branch on the four fine-grained strings above; **all four now advertised**).

Reserved for the **v0.4 / v0.5 semantic-retrieval extensions**. Advertised independently when implemented:

- ~~`find_symbol_limit_param`~~ — **advertised** as of `v0.4.1`. `Index.FindSymbol.params.limit: u32` (range `1..=4096`, default `256`) caps the returned `matches[]` size. Pre-v0.4.1 daemons silently ignored the field. The 4096 ceiling exists for offline eval tooling; agents should leave at default.
- ~~`find_symbol_doc_field`~~ — **advertised** as of `v0.5.0`. `Index.FindSymbol.matches[].doc` carries extracted doc-comment text. v0.5.0 ships Rust (`///`/`//!`); v0.5.x patches extend to Go, Swift, Python, JavaScript / TypeScript / C / C++ (`/** */`), Ruby (`#`), PHP (PHPDoc), Java (Javadoc). Pre-v0.5 daemons return `null` for all symbols.
- ~~`find_symbol_doc_filter`~~ — **advertised** as of `v0.5.2`. `Index.FindSymbol.params.doc_contains: Option<String>` filters matches by case-insensitive substring against doc-comment text. Enables behavior-shaped queries (e.g. `doc_contains: "evict"` returns documented symbols whose comments mention eviction).
- ~~`find_symbol_pre_filter_count`~~ — **advertised** as of `v0.5.2`. `Index.FindSymbol.result.pre_filter_count: Option<usize>` reports the candidate count before any filter ran. Present iff a filter was active; lets agents distinguish empty-because-filter-rejected-all from empty-because-pattern-matched-nothing.
- ~~`find_symbol_signature_field`~~ — **advertised** as of `v0.5.3`. `Index.FindSymbol.params.include_signature: bool` (default `false`) populates each match's `signature` field via the per-language `SignatureRenderer`. Renders are cached per `(path, byte_range, mtime)` on the daemon, so repeated pattern queries on the same workspace amortize the parse. Default off preserves the pre-v0.5.3 wire shape (`signature: null`).
- ~~`index_grep`~~ — **advertised** as of `v0.5.4`. `Index.Grep` method: literal-substring search across indexed file bytes. Closes the agent-loop hole where `find_symbol` couldn't help find non-symbol content (error messages, version strings, log output). MVP is literal case-insensitive-by-default; regex / `file_glob` / `context_lines` / enclosing-symbol resolution are filed for follow-up. See §7.8b.

### 4.3 Version mismatch

A client SHOULD send `Daemon.Ping` as its first request after connecting. If `result.protocol != "0"`, the client MUST disconnect and surface the mismatch to its agent. The daemon does not refuse v1 clients on the v0 wire — it just answers `Daemon.Ping` honestly and lets the client decide.

---

## 5. Workspace identity

### 5.1 Canonicalization (per OS)

The daemon canonicalises every workspace path it sees. The matrix is **strict and deterministic** — same inputs MUST land on the same daemon.

| OS | Rule |
|---|---|
| **macOS** | `realpath()` + NFC-normalize via the `unicode-normalization` crate. HFS+/APFS store NFD; users type NFC. Refuse non-UTF-8 sequences (`INVALID_WORKSPACE_PATH`). |
| **Linux** | `realpath()` + UTF-8 validate the bytes. Refuse non-UTF-8 paths (`INVALID_WORKSPACE_PATH`). No normalisation beyond `realpath`. |
| **Windows (v1.1)** | `GetFinalPathNameByHandleW` to resolve junctions + 8.3 short names. Lowercase the ASCII range only — **do NOT** use locale-aware uppercase/lowercase (Turkish dotted-`I` collisions). Preserve case in non-ASCII for display but hash on the ASCII-lowercased form. |

The canonical path is the SI input to identity below. Two clients passing `/Users/me/proj/`, `/Users/me/proj/../proj`, and `/private/var/folders/.../proj` (macOS tmp-via-symlink) MUST canonicalise to the same daemon.

### 5.2 Workspace fingerprint

Workspace identity binds **three** pieces (security-review F9: defeats symlink-swap):

```text
workspace_id = blake3(dev_id_u64_le || inode_u64_le || canonical_path_utf8)[:16]
```

- `dev_id`: from `stat(canonical_path).st_dev`.
- `inode`: from `stat(canonical_path).st_ino`.
- `canonical_path`: per §5.1.

On every `Workspace.Mount`, the daemon re-stats the path and verifies `(dev, inode)` matches the stored fingerprint. If it changed (symlink swap, mount move, dir replaced), the daemon returns `WORKSPACE_VANISHED` and tears down the previous mount.

### 5.3 Socket path

```text
Linux:   ${XDG_RUNTIME_DIR}/rts/ws-${workspace_id_hex16}.sock   (v0.5.4+)
         ${XDG_RUNTIME_DIR}/rts/default.sock                    (bootstrap)
macOS:   ${HOME}/Library/Caches/rts/ws-${workspace_id_hex16}.sock   (v0.5.4+)
         ${HOME}/Library/Caches/rts/default.sock                    (bootstrap)
Windows: \\.\pipe\rts.${user_sid}.${workspace_id_hex16}        (v1.1)
```

`${workspace_id_hex16}` is the first 8 bytes of `blake3(canonical_workspace_path_bytes)`, hex-encoded — 16 chars. Two distinct workspace roots produce distinct sockets, so concurrent daemons (one per workspace) coexist on the same UID without `WORKSPACE_MISMATCH`.

The `default.sock` bootstrap path is kept for the no-workspace case (daemons started without `--workspace`, e.g. some test harnesses, and pre-v0.5.4 clients). Post-v0.5.4 production callers always know their workspace at spawn time and route to the per-workspace path.

Linux MUST refuse to start if `XDG_RUNTIME_DIR` is unset. There is **no `/tmp/rts-$UID/` fallback** — the symlink-attack surface on `/tmp` is too large (security-review F2).

### 5.4 redb file path

```text
Linux:   ${XDG_STATE_HOME:-$HOME/.local/state}/rts/${workspace_id_hex}/db.redb
macOS:   ${HOME}/Library/Caches/rts/${workspace_id_hex}/db.redb
Windows: %LOCALAPPDATA%\rts\${workspace_id_hex}\db.redb        (v1.1)
```

The redb file lives **outside the workspace** (data-integrity #8). Deleting `${XDG_STATE_HOME}/rts/${workspace_id_hex}/` is always a safe recovery — the index is a derived cache and gets rebuilt on next `Workspace.Mount`.

### 5.5 Multi-workspace and nested git repos

- One daemon per workspace. Workspaces are pinned at `Workspace.Mount` time.
- Subdirectory queries with paths under the mounted root are fine.
- Out-of-root paths in any request are rejected with `OUT_OF_ROOT` (§14).
- **Nested git repos inside a workspace are one daemon, not many.** `Workspace.Mount` for the parent dominates. The MCP server is responsible for choosing the right root; clients that want per-sub-repo isolation should `Workspace.Unmount` + remount.

### 5.6 Network mounts

Refuse to start on network mounts. Implementation: read `/proc/self/mountinfo` (Linux) or `getmntinfo()` (macOS) at startup and on `Workspace.Mount`, match the workspace's containing mount against `{nfs, nfs4, cifs, smbfs, fuse.sshfs, fuse.gvfsd}`, and abort with `WORKSPACE_ON_NETWORK_MOUNT` if matched. Polling watcher fallback is **not** acceptable here — the lockfile guarantees rust-analyzer-style multi-host issues are out of scope for v0.

---

## 6. Path safety

(security-review HIGH findings F4, F5 collapsed.)

### 6.1 Refuse symlinked workspace roots at Mount

`Workspace.Mount` rejects with `MOUNT_HAS_SYMLINK` if the workspace root itself (the leaf of the supplied path) is a symlink. **Ancestor symlinks are tolerated** — macOS structurally symlinks `/var → /private/var` and `/tmp → /private/tmp`, and many development setups have symlinked parent directories (Homebrew aliases, conda envs, etc.). Enforcing "no symlinks anywhere in the path" broke too many legitimate cases for too little additional security: the real defence against root-replacement-after-mount is the `(dev, inode)` fingerprint binding in `verify_unchanged` (§5.2), which catches swaps the strict ancestor scan was nominally protecting against, and catches them at remount time without false positives at first mount.

What we still refuse at Mount:
- The workspace-root leaf being a symlink (the obvious "I mounted a symlink that points at the attacker's tree" case).
- `..` segments anywhere in the user-supplied path (`PATH_TRAVERSAL`).

### 6.2 Per-read prefix check

Every file the daemon opens (whether driven by the watcher or by an incoming request) MUST be re-canonicalised and verified to start with `${canonical_workspace_root}/`. The watcher's path stream is **not** trusted as-is — events can be racy under rename storms. Use `openat(O_NOFOLLOW)` on Linux/macOS; document the Windows equivalent for v1.1.

### 6.3 No `..` segments

Any incoming RPC whose `params` contain a path with `..` segments is rejected with `PATH_TRAVERSAL`. This is belt-and-suspenders to the canonicalisation rules; the daemon never resolves `..` in client-provided paths.

### 6.4 `.gitignore` + global ignore + `.rtsignore`

The walker uses the `ignore` crate's `WalkBuilder` with:
- `git_ignore(true)`, `git_global(true)`, `git_exclude(true)`, `ignore(true)`
- `follow_links(false)` (default; verified explicitly)
- An additional custom-filename `add_custom_ignore_filename(".rtsignore")` so projects can over-ignore beyond what they ship in `.gitignore`

`.codexignore` and `.cursorignore` are **not** honoured in v0. Pick one cross-agent name (`.rtsignore`); it's a v1.1 question whether to honour the other two as aliases.

---

## 7. Method catalog

The v0 method namespace is `^[A-Z][a-z]+\.[A-Z][A-Za-z]+$`. Methods are grouped under capabilities:

| Namespace | Verbs | Capability |
|---|---|---|
| `Daemon.*`   | `Ping`, `Stats`, `Cancel` (v0.6+), `Telemetry` (notification) | always (`Cancel` gated on `cancellable_queries`) |
| `Workspace.*` | `Mount`, `Unmount`, `Status` | always |
| `Index.*`    | `Outline`, `FindSymbol`, `FindCallers`, `ImpactOf`, `ReadSymbol`, `ReadSymbolAt`, `ReadRange` | `outline`, `find_symbol` (+ `fuzzy_match` for `pattern`), `find_callers`, `impact_of`, `read_symbol` (+ `closure_walker` for `include_dependencies`, + `read_symbol.include_callers` for `include_callers`), `read_symbol_at`, `read_range` |
| `Session.*`  | `Open`, `Close` | always; **v1.1**: `MarkDeduped` under `session_dedup` |

Total v0 surface as of alpha.35: **13 methods + 1 notification**. (`Workspace.Mount`, `Workspace.Unmount`, `Workspace.Status`, `Daemon.Ping`, `Session.Open`, `Session.Close`, `Index.Outline`, `Index.FindSymbol`, `Index.FindCallers`, `Index.ImpactOf`, `Index.ReadSymbol`, `Index.ReadSymbolAt`, `Index.ReadRange`, plus `Daemon.Telemetry` notification.) `Index.ReadSymbolAt` shipped in alpha.24; `Index.FindCallers` and `Index.ReadSymbol.include_callers` shipped in alpha.32; `Index.ImpactOf` ships in alpha.35. See [Appendix F](#appendix-f--wire-shape-evolution-by-alpha).

`Daemon.Cancel { cancel_id }` ships in **v0.6** under the
`cancellable_queries` capability; see §7.1b. Clients attach an
optional `cancel_id` to the request envelope (§3.4) and later send
`Daemon.Cancel` with the same id to trip the in-flight handler.
Cooperative cancellation — handlers poll the token at hot-loop
boundaries and return `CANCELLED` (§14). The pre-v0.6 behavior (close
the socket to abandon a request, or wait for the 30 s soft deadline)
still works and is the right choice for non-cancellable handlers.

`Session.MarkDeduped` was struck from v0 per architecture review (leaky abstraction). When R6 ships in v1.1, dedup is decided by the daemon, signalled in-band as `{ body_omitted: true, see_earlier_id: ... }` in slice responses; clients don't need to mark.

---

## 7. Method reference

### 7.0 Conventions

- All schemas below use JSON Schema 2020-12 vocabulary.
- All ranges are 0-based, half-open byte offsets unless explicitly `[start_line, end_line]` 1-based inclusive.
- All slice text is UTF-8.

### 7.1 `Daemon.Ping`

Heartbeat + capability discovery. Idempotent, cheap, no side effects.

**`params`** (object, all optional):
```jsonc
{}
```

**`result`**: see §4.1.

### 7.1b `Daemon.Cancel` (v0.6+, capability `cancellable_queries`)

Trip the in-flight request that registered the given `cancel_id`.
Idempotent: an unknown id (typo, already-completed request, or one
that was never registered) returns `{ cancelled: false }` with no
error. Returns immediately — the actual handler abort happens
cooperatively at the next poll inside the targeted handler (per-match
for the structural scanner, per-file/per-match for the multiline
regex, per-batch tick for the mount cold-walk drain).

**`params`**:
```jsonc
{ "cancel_id": "q-42" }
```

**`result`**:
```jsonc
{ "cancelled": true }     // a registered token was tripped
{ "cancelled": false }    // no such id (stale or never registered)
```

Telemetry: `Daemon.Stats.cancellations.total` increments by one on
every real hit (not on stale cancels). `Daemon.Stats.cancellations.in_flight`
is the current registry size — a point-in-time gauge of cancellable
requests outstanding.

Targeted requests return `CANCELLED` (§14, custom code `-32099`). This
is not a programming error; clients that issued the cancel should
treat it as the expected response and not retry without changing the
plan.

Handlers that honor cancellation in v0.6: `Index.Grep`,
`Index.FindSymbol`, `Index.FindCallers`, `Index.ReadSymbol`,
`Index.Outline`, `Workspace.Mount`. Other methods accept `cancel_id`
silently — `Daemon.Cancel` against their ids returns
`{ cancelled: false }` because no token gets registered for them.

### 7.2 `Workspace.Mount`

Establish (or join) the workspace this connection will operate on.

**`params`**:
```jsonc
{ "root": "/absolute/path/to/workspace" }
```

**`result`**:
```jsonc
{
  "workspace_id":  "a7b0c1d2e3f40516",
  "state":         "indexing",       // "indexing" | "ready"
  "progress":      { "files_done": 0, "files_total": 0, "phase": "walking" },
  "index_generation": 0,             // monotonic; bumps on every committed write
  "languages":     ["rust","javascript","typescript","python","c","cpp",
                    "go","java","php","ruby","swift"]   // 11 in v1; Kotlin v1.1
}
```

Errors: `INVALID_WORKSPACE_PATH`, `MOUNT_HAS_SYMLINK`, `WORKSPACE_VANISHED`, **`WORKSPACE_MISMATCH`** (alpha.36+), `WORKSPACE_ON_NETWORK_MOUNT`, `OUT_OF_ROOT` (if the path resolves outside the daemon's filesystem), `STORAGE_FULL` (if `${XDG_STATE_HOME}/rts/` is unwritable).

After `Workspace.Mount` returns, the connection is bound to that workspace; subsequent `Index.*` calls operate on it. A connection MUST `Mount` exactly once.

### 7.3 `Workspace.Unmount`

Tell the daemon this client is done with the workspace. Last-unmount triggers the daemon's idle-shutdown timer (10 min default).

**`params`**: `{}`
**`result`**: `{ "drained": true }`

### 7.4 `Workspace.Status`

Poll the indexing state. Cheap; safe to call between every other request.

**`params`**: `{}`
**`result`**:
```jsonc
{
  "state":            "indexing",                       // "indexing" | "ready" | "degraded"
  "progress":         { "files_done": 1234, "files_total": 5000, "phase": "parsing" },
  "index_generation": 47,
  "parse_failed_files": 3,                              // parses that returned ERROR; queryable
  "watcher_status":   "ok",                             // "ok" | "polling_fallback" | "overflowed_rewalking"
  "uptime_ms":        123456,
  "memory_rss_bytes": 156_000_000                       // best-effort; for visibility
}
```

`state="degraded"` means the daemon is up but operating on a stale index (e.g. `redb` write backpressure, watcher fallback). Reads still answer; writes may lag.

### 7.5 `Index.Outline`

Token-budgeted structural map of the workspace. Backs the `outline_workspace` MCP tool.

**`params`**:
```jsonc
{
  "token_budget":   8192,                  // u32, 1..200_000
  "glob":           "src/**/*.rs",         // optional; ignored if absent
  "mentioned_files": ["src/lib.rs"],       // optional; biases PageRank personalisation
  "mentioned_idents": ["build_index"]      // optional; biases PageRank
}
```

**`result`**:
```jsonc
{
  "outline_text":    "...",                // grep-ast-style dotted plain text; primary content
  "outline_json":    { "files": [ ... ] }, // structured sidecar; same data, richer
  "tokens_returned": 7842,
  "token_counter":   "bytes_div_3",        // see §11
  "files_considered": 543,
  "files_included":   89
}
```

Errors: `INDEX_NOT_READY` (only when `partial: false` was implicitly assumed; see §8), `BUDGET_TOO_SMALL` (token_budget < minimal-viable; e.g. < 50).

### 7.6 `Index.FindSymbol`

AST-precise definition + references + signature for a named or pattern-matched symbol. Always returns a **list** (length ≥ 0), never silently top-1; the agent disambiguates.

**`params`** (one of `name` or `pattern` is required; both is `INVALID_PARAMS`):
```jsonc
{
  "name":    "build_index",          // optional; exact match
  "pattern": "build_*",              // optional; glob: `*` (any run, including empty) and `?` (single char). Mutually exclusive with name. Capability: `fuzzy_match` (alpha.24+).
  "kind":    "fn",                   // optional; one of: fn, struct, enum, type, trait, const, static, impl, method, class, interface, module
  "file":    "src/index/mod.rs",     // optional; filter
  "sort":    "rank",                 // optional; "rank" (default; descending rank_score) | "lexical" (alphabetical-by-file). Capability: `pagerank_symbolwise` (alpha.34+).
  "limit":   256,                    // optional; max matches in `result.matches[]`. Range 1..=4096; default 256. Capability: `find_symbol_limit_param` (v0.4.1+).
  "doc_contains":       "evict",     // optional; case-insensitive substring filter against doc text. Capability: `find_symbol_doc_filter` (v0.5.2+).
  "include_signature":  false        // optional; default false. When true, populates `matches[].signature` via per-language SignatureRenderer. Capability: `find_symbol_signature_field` (v0.5.3+).
}
```

The glob matcher has **no character classes** and **no escapes** — `*` and `?` only. Agents that need regex-like expressivity (e.g. character classes) should compose multiple `pattern` queries client-side; a flagged regex mode is on the v1.1 candidate list pending a concrete user request.

**Sort order (alpha.34+, capability `pagerank_symbolwise`):** `matches[]` is sorted by descending `rank_score` (symbol-level PageRank over the workspace call graph) by default. Pass `sort: "lexical"` for back-compat with v0.2's alphabetical-by-`(file, start_byte)` ordering. The `limit` cap applies *after* sorting, so `pattern="*"` with rank sort returns the top-K most-central symbols. Clients that don't advertise the capability still receive the new default sort — daemons advertising `pagerank_symbolwise` use ranked order unless `sort: "lexical"` is explicit.

**Limit (v0.4.1+, capability `find_symbol_limit_param`):** the optional `limit` parameter caps the number of returned matches. Range `1..=4096`. The default of 256 matches pre-v0.4.1 behavior — pre-v0.4.1 daemons silently ignored the field. The 4096 ceiling exists for offline eval tooling (`rts-bench semantic`); **setting `limit` above the default in an agent call is almost always a mistake** because LLM contexts can't usefully digest more than a few hundred matches.

**Doc field (v0.5.0+, capability `find_symbol_doc_field`):** `matches[].doc` carries extracted doc-comment text for documented symbols, `null` for undocumented or pre-v0.5 daemons. v0.5.0 ships Rust (`///`/`//!`) support. v0.5.x patches extend coverage to Go, Swift, Python (`"""..."""`), JavaScript / TypeScript / C / C++ (JSDoc / Doxygen `/** ... */`), Ruby (`#`), PHP (PHPDoc), Java (Javadoc).

**Doc-text filter (v0.5.2+, capability `find_symbol_doc_filter`):** `params.doc_contains: Option<String>` — case-insensitive substring filter against the doc-comment text. Symbols with no doc never match. Useful for behavior-shaped queries ("find the cache eviction code"). When set, the pre-rank candidate cap expands automatically so the filter sees the full ranked pool.

**Pre-filter count (v0.5.2+, capability `find_symbol_pre_filter_count`):** `result.pre_filter_count: Option<usize>` — present only when at least one filter (`kind`, `file`, or `doc_contains`) was active. Reports the unfiltered candidate population — the number of `(name, file, kind)` hits that matched the base `name` / `pattern` before any filter ran. Lets agents distinguish `matches: []` because the pattern matched nothing from `matches: []` because the active filters rejected every candidate. Omitted when no filter ran (back-compat). v0.5.4 extended coverage from `doc_contains` alone to all three filter types.

**Signature field (v0.5.3+, capability `find_symbol_signature_field`):** `params.include_signature: bool` — when true, each match's `signature` field is populated via the per-language `SignatureRenderer` (the same code path `Index.ReadSymbol shape=signature` uses). Renders are cached on the daemon per `(path, byte_range, mtime)`, so repeated pattern queries on the same workspace amortize the parse cost.

**Default-on heuristic (v0.5.3+):** when `include_signature` is omitted, the daemon auto-enables it for *small-result* queries — the cases where the agent's most likely next step is `read_symbol` on the top hit, and an extra round trip is pure waste. Specifically:

| Query shape | Auto-default |
|---|---|
| `name` exact lookup (any limit) | `true` |
| `pattern` with `limit <= 10` | `true` |
| `pattern` with default 256 (or any larger explicit limit) | `false` |
| `include_signature` explicitly set | honored verbatim |

Pre-v0.5.3 clients reading `signature: null` see strictly more populated fields after this change — `null` becomes a real string for the affected query shapes. Clients relying on the pre-v0.5.3 null can opt out per-call with `include_signature: false`.

**`result`**:
```jsonc
{
  "matches": [
    {
      "qualified_name": "rts_core::index::build_index",
      "kind":           "fn",
      "file":           "src/index/mod.rs",
      "range":          { "start_line": 42, "end_line": 58, "start_byte": 1024, "end_byte": 1456 },
      "signature":      "pub fn build_index(workspace: &Path) -> Result<Index>",
      "doc":            "Walk the workspace and build a fresh index.",
      "visibility":     "public",
      "rank_score":     0.0421                // PageRank-derived; higher = more central
    }
  ],
  "truncated":         false,                  // true if list was clipped at the effective `limit`
  "pre_filter_count":  158                     // optional (v0.5.2+); present iff a filter was active
}
```

Errors: `INDEX_NOT_READY`, `INVALID_PARAMS` (e.g. unknown `kind`; `limit` outside 1..=4096).

### 7.7 `Index.ReadSymbol`

Read source for a named symbol. Optionally walks the tree-shaken closure of types/imports it references.

**`params`**:
```jsonc
{
  "name":                 "build_index",            // required
  "file":                 "src/index/mod.rs",       // optional disambiguator
  "kind":                 "fn",                     // optional disambiguator
  "shape":                "body",                   // "signature" | "body" | "both"  (default "body")
  "token_budget":         4096,                     // optional; default 4096
  "include_dependencies": false,                    // tree-shake closure walk?
  "include_callers":      false,                    // v0.3 (alpha.32+, cap: read_symbol.include_callers)
  "force_resend":         false                     // v1.1: override the session-dedup `body_omitted` short-circuit
}
```

When `include_callers: true`, the response carries a `callers: [...]` array with the same entry shape as §7.7c `Index.FindCallers.callers[]`, plus a `callers_truncated: bool` flag (separate from `closure_truncated` to preserve v0.2 wire semantics). Token-budget priority: body fills first, then `dependencies` (when requested), then `callers`. Capability: `read_symbol.include_callers`.

**`result`** (full body):
```jsonc
{
  "qualified_name": "rts_core::index::build_index",
  "kind":           "fn",
  "file":           "src/index/mod.rs",
  "range":          { "start_line": 42, "end_line": 58, "start_byte": 1024, "end_byte": 1456 },
  "shape":          "body",
  "text":           "pub fn build_index(...) -> Result<Index> {\n    // ...\n}\n",
  "content_version": "a7b0c1d2e3f40516@1747000000000000000+47",
  "tokens_returned": 320,
  "token_counter":   "bytes_div_3",
  "dependencies":    [                           // present when include_dependencies=true
    { "qualified_name": "rts_core::error::Result", "kind": "type", "file": "src/error.rs",
      "range": {...}, "signature": "pub type Result<T> = std::result::Result<T, Error>;" }
  ],
  "closure_truncated": false,                   // true if the closure didn't fit in token_budget
  "truncated_symbols": []                        // names that were skipped; agent can re-request individually
}
```

**`result`** (session-deduped, v1.1, capability `session_dedup`):
```jsonc
{
  "qualified_name":  "rts_core::index::build_index",
  "kind":            "fn",
  "file":            "src/index/mod.rs",
  "range":           {...},
  "shape":           "body",
  "signature":       "pub fn build_index(workspace: &Path) -> Result<Index>",  // in-band, never the full body
  "body_omitted":    true,
  "see_earlier_id":  "resp_2024_11_b7d2",       // opaque token; agent may use force_resend=true to override
  "content_version": "a7b0c1d2e3f40516@1747000000000000000+47",
  "tokens_returned": 24,
  "token_counter":   "bytes_div_3"
}
```

Errors: `INDEX_NOT_READY`, `SYMBOL_NOT_FOUND`, `AMBIGUOUS_SYMBOL` (force the agent to disambiguate via `file` or `kind` — alternatively the daemon MAY return the top-K and a `truncated: true` flag; that path is preferred), `OUT_OF_ROOT`, `BUDGET_TOO_SMALL`.

### 7.7b `Index.ReadSymbolAt`

Read source for the symbol whose def-range covers `(file, line)`. The **compiler-error flow** primitive: take a diagnostic like `error[E0308] --> src/foo.rs:42:18` and one call returns the containing function body + (optional) dependency closure. Avoids the two-call "find then read" pattern when the agent already has a precise location. Capability: `read_symbol_at` (alpha.24+).

**`params`**:
```jsonc
{
  "file":                 "src/foo.rs",     // required, workspace-relative
  "line":                 42,                // required, 1-based
  "column":               18,                // optional; 1-based; tie-breaker only in v0 (inert without column→byte mapping). Lands with v1.1 incremental parser reuse.
  "shape":                "body",            // "signature" | "body" | "both"  (default "body")
  "token_budget":         4096,              // optional; default 4096
  "include_dependencies": false              // closure walk; same semantics as §7.7
}
```

**`result`**: same wire shape as §7.7 `Index.ReadSymbol` (body or session-deduped variant). `qualified_name` is the innermost enclosing def whose def-range covers the line; range tie-breakers prefer smaller ranges (innermost wins). When no def covers the line — e.g. a blank gap, a comment-only region, a top-level statement outside any function — returns `SYMBOL_NOT_FOUND` with `data: { "file", "line" }`.

Errors: `INDEX_NOT_READY`, `SYMBOL_NOT_FOUND` (no def covers the line), `OUT_OF_ROOT`, `FILE_NOT_INDEXED`, `RANGE_OUT_OF_BOUNDS` (line > file LOC), `INVALID_PARAMS` (line < 1).

### 7.7c `Index.FindCallers`

Return the direct callers of a named symbol. One redb lookup over the persistent ref graph (v0.3 U1) — no per-file re-parsing. Backs the `find_callers` MCP tool. Capability: `find_callers` (alpha.32+).

**`params`**:
```jsonc
{
  "name":   "build_index",          // required, exact match
  "kind":   "fn",                   // optional; filter on the *enclosing* def's kind (fn / method / etc.)
  "file":   "src/index/mod.rs"      // optional; filter to callers originating from one file
}
```

**`result`**:
```jsonc
{
  "callers": [
    {
      "enclosing_qualified_name": "rts_core::cli::main",      // null when caller_sid is None (file-scope call)
      "kind":                     "fn",                       // null when caller_sid is None
      "file":                     "src/cli.rs",
      "range": {                                              // the call site
        "start_byte": 4520, "end_byte": 4531,
        "start_line": 142,  "end_line":  142
      },
      "enclosing_def_range": {                                // the caller's own def range (null when caller_sid is None)
        "start_byte": 4400, "end_byte": 5200,
        "start_line": 138,  "end_line":  160
      },
      "rank_score": 0.0                                       // placeholder until v0.3 U4 (cap: `pagerank_symbolwise`)
    }
  ],
  "truncated": false                                          // true when more than 256 callers existed
}
```

Result is sorted by `(file, range.start_byte)` for stable output across calls; capped at 256 entries (mirrors `Index.FindSymbol`'s `MAX_MATCHES`).

Errors: `INDEX_NOT_READY`, `SYMBOL_NOT_FOUND` (no `NAME_TO_SID` entry — symbol is not workspace-defined or never indexed; mirrors `Index.FindSymbol` error path), `INVALID_PARAMS` (`name` empty or >256 chars; unknown `kind` value).

**When to use vs related methods:**
- Use `find_callers` for callers-only (cheap; no body read).
- Use `read_symbol --include-callers` when you also want the symbol's body in the same round trip.
- Use `impact_of` for *transitive* callers (refactor blast radius); see §7.7d.

### 7.7d `Index.ImpactOf`

Return the transitive caller closure of a named symbol — every function that directly or indirectly calls it. BFS over the reverse reference graph, bounded by depth, token budget, node count, and a wall-clock cap. Capability: `impact_of` (alpha.35+).

The refactor blast-radius query: "if I change `X`'s signature, what touches it?" — surfaces all the functions an agent needs to update, prioritised by depth (direct first) and PageRank (most-central first).

**`params`**:
```jsonc
{
  "name":               "build_index",   // required, exact match
  "depth":              2,                // optional; BFS depth cap (1..=4). Default 2.
  "token_budget":       4096,             // optional; standard §16 50..=200000 window. Default 4096.
  "max_nodes":          200,              // optional; max distinct caller entries (1..=10000). Default 200.
  "exclude_test_paths": true              // optional; filter callers in test-shaped files. Default true.
}
```

**`result`**:
```jsonc
{
  "impact": [
    {
      "qualified_name":   "rts_core::cli::run",
      "kind":             "fn",
      "file":             "src/cli.rs",
      "range": {                          // the *caller's def* range (not the call site)
        "start_byte": 4400, "end_byte": 5200,
        "start_line": 138,  "end_line":  160
      },
      "depth":      1,                    // 1-based BFS depth (direct callers = 1)
      "rank_score": 0.012                 // symbol-level PageRank of the caller (alpha.34+)
    }
  ],
  "closure_truncated":    false,          // token budget exhausted while BFS still had entries
  "wall_clock_truncated": false,          // 50ms wall-clock cap fired
  "depth_truncated":      false,          // at least one frontier hit max_depth with unvisited callers
  "node_count_truncated": false,          // max_nodes cap fired
  "tokens_returned":      1247,
  "token_counter":        "bytes_div_3"
}
```

Result is sorted by `(depth ASC, rank_score DESC, file ASC, start_byte ASC)` — direct callers first, then most-central callers within each depth tier, then deterministic tiebreakers. The four truncation flags are independent so agents can tell *why* the result is partial.

**Wire-shape trim** (per [v0.3 plan Deepening §F3](plans/2026-05-13-001-feat-v0.3-code-graph-kb-plan.md)): the original 9-field per-entry shape was trimmed to 6 — `signature` and nested `callers[]` arrays were YAGNI'd. Agents who need a caller's signature follow up with `read_symbol(name=qualified_name, shape="signature")`; agents who need *that* caller's callers follow up with `find_callers` or another `impact_of`.

Errors: `INDEX_NOT_READY`, `SYMBOL_NOT_FOUND` (mirrors `Index.FindCallers`), `BUDGET_TOO_SMALL`/`BUDGET_TOO_LARGE` per §16, `INVALID_PARAMS` (`name` empty or >256 chars).

**When to use vs related methods:**
- Use `find_callers` for depth-1 only (cheaper, more focused).
- Use `impact_of` when you're about to refactor a public function and want the whole blast radius.
- `exclude_test_paths: true` (default) skips callers in `/tests/`, `_test.rs`, `.spec.ts` etc. — the single biggest noise reducer for refactor flows. Pass `false` when deciding which tests to update.

### 7.8 `Index.ReadRange`

Read explicit line/byte range. For stack traces, diff hunks, exact spans.

**`params`**:
```jsonc
{
  "file":         "src/index/mod.rs",
  "start_line":   42,
  "end_line":     58,
  "token_budget": 4096           // optional; clips with a `truncated_at` marker
}
```

**`result`**: same shape as `Index.ReadSymbol` body but with `qualified_name: null` and no `dependencies` / closure info.

Errors: `INDEX_NOT_READY`, `FILE_NOT_INDEXED`, `OUT_OF_ROOT`, `RANGE_OUT_OF_BOUNDS`, `BUDGET_TOO_SMALL`.

### 7.8b `Index.Grep` (v0.5.4+, capability `index_grep`)

Literal-substring search across all indexed file bytes. Closes the agent-loop hole where `Index.FindSymbol` and `Index.FindCallers` can't help find content that isn't a symbol name or doc-comment text — error message literals, version strings, log output, configuration values, embedded URLs, magic constants.

**`params`**:
```jsonc
{
  "text":             "timeout reading MCP response",  // 1..=1024 chars
  "limit":            256,                              // optional; 1..=4096, default 256
  "case_insensitive": true                              // optional; default true
}
```

**`result`**:
```jsonc
{
  "matches": [
    {
      "file":      "crates/rts-bench/src/mcp_runner.rs",
      "range":     { "start_line": 165, "end_line": 165, "start_byte": 5507, "end_byte": 5535 },
      "line_text": "        .map_err(|_| anyhow!(\"timeout reading MCP response\"))??;"
    }
  ],
  "truncated":          false,    // true if `limit` was reached before scanning finished
  "files_scanned":      245,      // total indexed files iterated
  "files_with_matches": 1
}
```

**Semantics**:
- Iterates the indexed file set (the same files `Index.Outline` covers). Files larger than 4 MiB are skipped (counted toward `files_scanned`).
- `line_text` is the full line containing the match, lossy-UTF-8-encoded and truncated to 512 bytes with `…` suffix when over budget. Long lines (minified JS, generated tables) don't blow up the response.
- `range` covers the literal match itself (not the whole line). Byte offsets are stable across calls until the file's content_version changes.
- `truncated: true` indicates more matches exist in the workspace than `limit` allowed; agents should narrow the query (longer literal, narrower term, etc.) rather than paginate.

**Out of scope for the v0.5.4 MVP** (filed for follow-up):
- Regex syntax (`text` is always a literal in v0.5.4).
- `file_glob` to restrict scope.
- `context_lines` for surrounding lines around each match.
- `enclosing_qualified_name` / `enclosing_kind` on each match (similar to `Index.FindCallers`'s shape).

Errors: `INVALID_PARAMS` (empty `text`, `text` > 1024 chars, `limit` outside `1..=4096`).

#### v0.6 additions (capability `index_grep_v2`)

`Index.Grep` gains five additive optional input fields and three new capability strings, gated independently. v1 callers (no new fields) see byte-identical responses on the unchanged code path; v2 callers MUST gate on the relevant capability string before sending new fields. The bundle capability `index_grep_v2` advertises all three new modes together for clients that prefer one check.

**Additional `params`**:
```jsonc
{
  // existing v1 fields preserved …

  // v0.6: regex multi-line mode. Sets `dot_matches_new_line(true) + multi_line(true)`
  // on the compiled regex and scans the file as one buffer. Requires `regex: true`;
  // the literal path crosses newlines already, so `multiline: true` on a literal call
  // is rejected with `MULTILINE_REQUIRES_REGEX`. Capability: `index_grep_multiline`.
  "multiline":                     false,

  // v0.6: raw tree-sitter S-expression query, evaluated against the parsed tree of
  // every file matching the `language` filter. Captures are returned per-match (see
  // result shape below). Validated via `Query::new` at request time and cached
  // (`(language, query_text)` LRU, capacity 64). Capability: `index_grep_structural`.
  // **Requires `language`** (single id or list).
  "structural_query":              "(impl_item) @impl",

  // v0.6: post-filter to matches whose byte range lies strictly inside the def byte
  // range of a named symbol. Single exact qualified name in v1; overloaded names
  // (>16 defs) are rejected with `WITHIN_SYMBOL_TOO_MANY_DEFS` unless the caller
  // opts in via `within_symbol_allow_overload: true`. Capability:
  // `index_grep_within_symbol`.
  "within_symbol":                 "parse_request",
  "within_symbol_allow_overload":  false,

  // v0.6: file-set filter applicable to every scan mode (literal, regex, structural).
  // **Required** when `structural_query` is set; optional otherwise. Intersects with
  // `file_glob` (AND semantics: a file must satisfy both filters). Capability:
  // `index_grep_v2`.
  "language":                      ["rust"]
}
```

**Composition matrix (binding contract).** The six axes (`text`, `regex`, `multiline`, `structural_query`, `within_symbol`, `language`) produce the following resolved scan modes. Source of truth: `crates/rts-daemon/src/methods/grep_v2/compose.rs`.

| `text`     | `regex` | `multiline` | `structural_query` | `within_symbol` | `language`   | Result                                   |
|------------|---------|-------------|--------------------|-----------------|--------------|------------------------------------------|
| Some       | n/false | n/false     | None               | opt             | opt          | v1 literal substring scan                |
| Some       | true    | n/false     | None               | opt             | opt          | v1 regex scan (single-line)              |
| Some       | true    | true        | None               | opt             | opt          | multi-line regex (whole-file buffer)     |
| None       | any     | true        | None               | —               | —            | REJECT `MULTILINE_REQUIRES_REGEX`        |
| Some       | n/false | true        | any                | —               | —            | REJECT `MULTILINE_REQUIRES_REGEX`        |
| None       | any     | any         | Some               | opt             | **required** | structural scan                          |
| Some       | n/false | n/false     | Some               | opt             | **required** | structural ∩ literal                     |
| Some       | true    | any         | Some               | opt             | **required** | structural ∩ regex                       |
| any        | any     | any         | Some               | —               | None         | REJECT `STRUCTURAL_REQUIRES_LANGUAGE`    |
| None       | any     | any         | None               | —               | —            | REJECT `NO_SEARCH_SOURCE_PROVIDED`       |
| Some('')   | any     | any         | any                | —               | —            | REJECT `INVALID_TEXT_LENGTH`             |
| Some(>1024)| any     | any         | any                | —               | —            | REJECT `INVALID_TEXT_LENGTH`             |

`within_symbol` applies as a post-pass filter regardless of which mode resolved (strict containment: the match byte range must lie strictly inside the resolved def byte range). `language` is an OR set: `["rust","ts"]` matches files of either language; `file_glob ∩ language` is AND.

**Additional result fields** (present-when-relevant; absent on unchanged-path v1 calls — mirrors §7.6's `pre_filter_count` precedent):

```jsonc
{
  "matches": [
    {
      // existing v1 fields preserved byte-for-byte …
      // present only on structural matches (i.e. when the call set `structural_query`):
      "captures": {
        "impl": [
          { "start": {"line": 43, "col": 0}, "end": {"line": 87, "col": 1}, "text": "impl Foo for Bar { …" }
        ],
        "name": [
          { "start": {"line": 43, "col": 5}, "end": {"line": 43, "col": 8}, "text": "Foo" }
        ]
      }
    }
  ],
  // existing v1 fields preserved …

  // present (top-level) when row caps, capture-byte caps, or wall-clock caps were hit;
  // omitted otherwise. The existing v1 `truncated: bool` keeps its meaning for the
  // limit-reached case; the new metadata block disambiguates which budget tripped.
  "truncated":                   true,
  "truncation_reason":           "rows_seen_exceeded_max",  // or "wall_clock", "capture_bytes"
  "rows_seen":                   8192,
  "rows_returned":               4096,

  // present when a structural query was compiled successfully against at least one
  // of the requested languages but failed against the others; the call succeeds
  // with results from the languages that compiled. Absent when every requested
  // language compiled or every one failed (the latter is `STRUCTURAL_QUERY_INVALID`).
  "partial_failures": [
    { "language": "ts", "error": "Query error at 1:0: invalid node type 'impl_item'" }
  ]
}
```

Per-capture `text` is truncated at `STRUCTURAL_MAX_CAPTURE_BYTES` (8 KiB); when truncated, the capture object gains `"truncated": true`. Position units are `{line, col}` (1-based line, 0-based col, mirroring v1 match coordinates).

**Predicate whitelist (v1).** Agent-supplied S-expression queries may use only the following predicates; any other predicate (including custom `#contains?`-style extensions) fails with `STRUCTURAL_QUERY_PREDICATE_NOT_ALLOWED`:

- `#eq?`, `#not-eq?` — string equality; no regex compile.
- `#match?`, `#not-match?` — regex compile against a daemon-wide shared budget (each predicate regex must compile under `PREDICATE_REGEX_DFA_LIMIT`, currently 256 KiB — more conservative than the outer `MULTILINE_DFA_SIZE_LIMIT`).
- `#any-of?` — string membership.
- `#is?`, `#is-not?` — node-property test; no regex compile.

The whitelist is documented for tree-sitter 0.26 (currently pinned). A future grammar upgrade may require re-validation.

**Resource budgets.** Constants (source: `crates/rts-daemon/src/methods/grep_v2/limits.rs`, lands in U5):

| Constant                              | Value         | Purpose                                              |
|---------------------------------------|---------------|------------------------------------------------------|
| `MULTILINE_DFA_SIZE_LIMIT`            | 32 MiB        | regex DFA cap on the `multiline: true` path          |
| `MULTILINE_NFA_SIZE_LIMIT`            | 32 MiB        | regex NFA cap on the `multiline: true` path          |
| `PREDICATE_REGEX_DFA_LIMIT`           | 256 KiB       | per-`#match?`/`#not-match?` predicate compile cap    |
| `STRUCTURAL_WALL_CLOCK_MS`            | 5 000 ms      | total wall-clock budget per structural scan          |
| `STRUCTURAL_MAX_ROWS`                 | 4 096         | hard cap on structural matches per response          |
| `STRUCTURAL_MAX_CAPTURE_BYTES`        | 8 192         | per-capture text truncation threshold                |
| `STRUCTURAL_MAX_CAPTURES_PER_MATCH`   | 64            | upper bound on distinct captures per match record    |
| `WITHIN_SYMBOL_MAX_DEFS`              | 16            | overload threshold without opt-in                    |
| `QUERY_LRU_CAPACITY`                  | 64            | compiled-`Query` LRU entry cap                       |

Wall-clock budgets are checked between files (not mid-file). Cap breaches return `truncated: true` + metadata; they're not errors.

**Capabilities advertised** (on `Daemon.Ping.result.capabilities`):

- `index_grep_multiline` — `multiline: true` honored on the regex path.
- `index_grep_structural` — `structural_query` honored; per-match `captures` returned.
- `index_grep_within_symbol` — `within_symbol` (+ `within_symbol_allow_overload`) honored.
- `index_grep_v2` — bundle string; advertised iff all three above are.

Clients SHOULD gate on these strings; a pre-v0.6 daemon silently drops unknown input fields and the call falls back to v1 semantics.

**New error codes** (each emits as `INVALID_PARAMS` with the listed `data.code` string; see §14):

| `data.code`                              | Trigger                                                                                 |
|------------------------------------------|-----------------------------------------------------------------------------------------|
| `MULTILINE_REQUIRES_REGEX`               | `multiline: true` on the literal path (rejected, not silently coerced)                  |
| `STRUCTURAL_REQUIRES_LANGUAGE`           | `structural_query` set, `language` missing or empty                                     |
| `NO_SEARCH_SOURCE_PROVIDED`              | neither `text` nor `structural_query` provided                                          |
| `INVALID_TEXT_LENGTH`                    | `text` is empty or > 1024 chars (mirrors v1; surfaced via the v2 envelope)              |
| `STRUCTURAL_QUERY_INVALID`               | `Query::new(language, query_text)` failed for every requested language; `data.error_message` carries the tree-sitter diagnostic |
| `STRUCTURAL_QUERY_PREDICATE_NOT_ALLOWED` | query uses a predicate outside the v1 whitelist                                         |
| `WITHIN_SYMBOL_NOT_FOUND`                | `within_symbol` resolved to zero defs                                                   |
| `WITHIN_SYMBOL_TOO_MANY_DEFS`            | `within_symbol` resolved to > 16 defs without `within_symbol_allow_overload: true`; `data.def_count` carries the count |
| `REGEX_TOO_COMPLEX`                      | regex compile exceeded `MULTILINE_DFA_SIZE_LIMIT` (or NFA equivalent)                   |
| `STRUCTURAL_QUERY_TIMEOUT`               | structural scan exceeded `STRUCTURAL_WALL_CLOCK_MS`                                     |
| `UNKNOWN_LANGUAGE`                       | `language` contains an identifier the daemon doesn't index                              |

Note: `WITHIN_SYMBOL_NOT_FOUND`, `WITHIN_SYMBOL_TOO_MANY_DEFS`, `STRUCTURAL_QUERY_INVALID`, `STRUCTURAL_QUERY_PREDICATE_NOT_ALLOWED`, `REGEX_TOO_COMPLEX`, and `STRUCTURAL_QUERY_TIMEOUT` are emitted from the U4/U5 execution paths (not pure-input validation) and so depend on those units landing. Until U5 lands, the validator surfaces the input-shape codes only (`MULTILINE_REQUIRES_REGEX`, `STRUCTURAL_REQUIRES_LANGUAGE`, `NO_SEARCH_SOURCE_PROVIDED`, `INVALID_TEXT_LENGTH`).

**Telemetry.** `Daemon.Stats` gains three new sub-counters as siblings of the existing `index_grep` field — `index_grep_multiline`, `index_grep_structural`, `index_grep_within_symbol`. Each bumps when its corresponding param is set and active (e.g., `multiline: false` does NOT bump `index_grep_multiline`); the parent `index_grep` bumps on every call. Lands with U7.

### 7.9 `Session.Open`

Open a session. Returns an opaque session id the client carries on subsequent requests (v1.1: enables session-aware dedup; v0: required but otherwise inert).

**`params`**:
```jsonc
{
  "client_name":    "claude-code",          // optional; observability metadata only — NOT authoritative
  "client_version": "1.0.42"                // optional; observability metadata only
}
```

**`result`**:
```jsonc
{
  "session_id":          "sess_b7d2c1f4e5a60718",  // opaque, 128-bit hex
  "reconnect_window_ms": 300000,                    // 5 minutes; how long the session survives reconnects
  "dedup_ttl_ms":        900000                     // 15 minutes; per-entry TTL in the dedup cache
}
```

**Authoritative identity** is kernel peer credentials: `SO_PEERCRED` on Linux, `LOCAL_PEERCRED`/`getpeereid()` on macOS, named-pipe ACLs on Windows (v1.1). `client_name` / `client_version` are observability metadata only; they are agent-controllable via prompt injection and MUST NOT influence access decisions.

### 7.10 `Session.Close`

Releases the session immediately. The daemon drops the dedup cache for that session within `reconnect_window_ms` even without an explicit close.

**`params`**: `{ "session_id": "sess_b7d2c1f4e5a60718" }`
**`result`**: `{}`

### 7.11 `Daemon.Telemetry` (notification)

Emitted iff the connection opted in via `Workspace.Mount`'s `enable_telemetry: true` (default false) — capability `telemetry`. Best-effort, fire-and-forget; dropped silently on slow consumers.

```jsonc
{
  "method": "Daemon.Telemetry",
  "params": {
    "ts_ns":    1747000000000000000,
    "kind":     "tool_call",
    "tool":     "Index.ReadSymbol",
    "ms":       3.2,
    "cache":    "tree_lru_hit",
    "dedup":    "miss",
    "partial":  false,
    "tokens_returned": 320
  }
}
```

### 7.11b `Daemon.Telemetry` (RPC, v0.6+, capability `daemon_telemetry`)

Pull-style snapshot of the daemon's raw telemetry collector inputs. Distinct from the §7.11 notification (which is push-style and per-event). The receiver-side bounded-enum filter still runs in `rts-mcp`; this RPC just hands the collectors their data without forcing the CLI to mount the workspace twice. HTTP-free — the telemetry POST lives behind a separate `--features telemetry` gate in the `rts` binary.

**`params`**: `{}`
**`result`**:

```jsonc
{
  "uptime_secs":                       12345,
  "languages_indexed":                 ["rust", "python"],
  "method_counts":                     { "Index.FindSymbol": 7, "Index.Grep": 23 },
  "method_latency_p50_ms":             { "Index.FindSymbol": 2 },
  "method_latency_p99_ms":             { "Index.FindSymbol": 8 },
  "error_counts":                      { "INVALID_PARAMS": 3 },
  "cache_hit_rate":                    0.84,
  "cold_walk_ms_p50":                  230,
  "workspace_files":                   47123,
  "unresolved_refs_count":             117,
  "unresolved_refs_gc_runs_total":     12,
  "unresolved_refs_gc_dropped_total":  184
}
```

Field notes:

- `unresolved_refs_count` (u64, capability `daemon_telemetry_unresolved_refs_count`) — size of the UNRESOLVED_REFS multimap at snapshot time. Each row is a reference the resolver couldn't bind to a defined symbol; forward references decrement the count when their callee finally lands in a later commit, while true externals (stdlib `Vec`, `println!`, etc.) accumulate permanently. Lower is better. A regression that breaks an extractor surfaces as the count jumping up — the real-repo CI bench gates on this.
- `unresolved_refs_gc_runs_total` and `unresolved_refs_gc_dropped_total` (u64 each, capability `daemon_telemetry_unresolved_refs_gc`) — cumulative counters reflecting cleanup work the daemon did on its own. `runs_total` increments once per removed file the writer processed; `dropped_total` increments by the number of orphaned `UNRESOLVED_REFS` rows the GC actually deleted (rows whose source file was deleted before its forward reference resolved). Together they **bound the growth** of `unresolved_refs_count`: a healthy long-running daemon sees `dropped_total` advance as files disappear, keeping `unresolved_refs_count` flat-ish. A jump in `unresolved_refs_count` without matching `dropped_total` advancement points at an extractor regression (the class of bug PR #118's PHP `method_declaration` gap exemplifies). Both counters reset on daemon restart.
- Map keys are sourced from closed-enum strings (`CallCounters::snapshot`, `MethodLatencyHistograms::enumerated`, `ErrorCode::as_wire_str`, `writer::lang_tag_to_name`); no user-controlled identifiers reach the wire.

---

## 8. Cold-state semantics

The daemon may be **indexing** (initial walk, or post-watcher-overflow rewalk) when a request arrives.

Rules:
- All `Index.*` methods MUST answer even while `state="indexing"`. They return `partial: true` (§3.5) plus the best-effort result the index can produce.
- `Workspace.Status` always answers with current progress.
- The client MAY repeat the same request after polling `Workspace.Status` to `ready` and observing `index_generation` advance.
- **S1 cold latency target** (per the plan) is measured from "`Workspace.Status` returned `ready` + first byte of the next request" — NOT from process spawn. The first `Workspace.Mount` after a daemon start may take seconds; that's the build cost, not the cold-query cost.
- A "warm" query is one served while `state="ready"` with the relevant data already in the hot-tree LRU / `redb` page cache.

---

## 9. Concurrency model

### 9.1 Reader side

- Many concurrent readers, no exclusion. The daemon dispatches each request to a Tokio task.
- Each reader task holds **one long-lived `redb::ReadTransaction`** (the perf-oracle recommendation), refreshed only when the writer task signals a new `index_generation`.
- Reader tasks use the parser pool (one `tree-sitter::Parser` per rayon worker — `Parser` is `!Send` across concurrent parses).

### 9.2 Writer side

- **Exactly one writer task** drains a bounded `tokio::mpsc::channel` of `(FileId, ParseResult)` updates from the watcher.
- Parse work fans out via rayon; results funnel back through the mpsc.
- The writer task collects a debounce-window's worth of deltas (150 ms or N=128 events, whichever first) and commits them in **one `redb::WriteTransaction`** at `Durability::None`. A periodic empty `Immediate` commit every 5 s flushes durably (canonical redb batched pattern).
- On commit, `index_generation` bumps and a watch channel signals reader tasks to refresh.

### 9.3 Backpressure

The writer's mpsc has bounded depth **256**. When full:
- The watcher's debouncer stalls (it `send().await`s); no events are dropped.
- `Workspace.Status` flips `state` to `"degraded"`.
- A `Daemon.Telemetry` notification fires with `kind: "writer_backpressure"`.

### 9.4 Per-connection limits

Per connection, the daemon enforces:
- **Max 16 concurrent in-flight requests.** A 17th request that arrives before any of the 16 has completed gets `BUSY` immediately.
- **Max 200 000 token budget** on any retrieval request. Larger requests get `BUDGET_TOO_LARGE`.
- **No explicit RPS cap** in v0; the in-flight cap is the main control.

### 9.5 Session-aware dedup (v1.1, capability `session_dedup`)

When implemented:
- State lives in the daemon, keyed by `(workspace_id, session_id)`.
- Per-session bounded LRU of `blake3(returned_text_bytes)` → `response_id`.
- Capacity ≈ 10 MiB per session; TTL 15 min per entry.
- On a `read_symbol` / `read_range` hit (same blake3 of would-be-returned bytes), the daemon swaps the body for `{ body_omitted: true, see_earlier_id, signature }` and a `force_resend` param re-fetches it.
- Daemon respawn → dedup state lost (it's in-memory). The 5-min reconnect window for sessions across `rts-mcp` process restarts is a separate concern (the session id survives; the dedup cache for it may or may not).

---

## 10. Cancellation

v0 has no explicit `Daemon.Cancel` wire method. Cancellation works by:
- **Connection drop**: dropping the socket cancels every in-flight request from that client. Reader tasks observe via a `tokio::sync::CancellationToken` derived from the connection's task tree.
- **Soft deadline**: each request runs under a `tokio::select!` against a 30 s wall clock. On timeout the daemon returns `DEADLINE_EXCEEDED`. (S1 budgets are far under 30 s; this is the safety belt.)
- **Mid-closure cancellation**: not in v0. Tree-shake walkers check a budget after each expansion but do not poll a cancellation token between layers. v2 may introduce `Daemon.Cancel(request_id)` if profiling justifies it.

---

## 11. Token counting

### 11.1 Runtime budgeting (hot path)

Fast approximator `bytes / 3` for code (corrected from the originally-planned `/3.5`; per perf-oracle, code tokenises denser than English prose). CJK-aware: any byte ≥ `0x80` in an identifier increases the per-byte factor by ~1.5×.

`tokens_returned` and `token_counter: "bytes_div_3"` are emitted on every retrieval response so the agent can track its own budget.

### 11.2 Benchmark oracle (offline only)

`rts-bench` uses Anthropic's `messages.countTokens()` with a pinned model id for S2 measurement. **This path is not exercised by the daemon** — the daemon is offline.

---

## 12. Auth boundary

(security-review HIGH finding F1.)

### 12.1 Socket file permissions

- Linux/macOS: socket file mode `0600`, owner = current uid. Parent directory mode `0700`, owner = current uid.
- The daemon `umask(0077)` at startup, then creates the parent directory (idempotent) and binds the socket. Mode is explicit, not inherited.

### 12.2 Peer-credential check

After every `accept()`, the daemon retrieves the peer's uid via:
- Linux: `getsockopt(fd, SOL_SOCKET, SO_PEERCRED)`.
- macOS: `LOCAL_PEERCRED` via `getsockopt`, then validate against current uid; fall back to `getpeereid()` if `LOCAL_PEERCRED` returns 0.
- Windows (v1.1): named-pipe ACL DACL configured to allow only current SID; verify via `GetNamedPipeClientProcessId` + `OpenProcessToken` + `GetTokenInformation(TokenUser)`.

If the peer's effective uid is not the daemon's, close the connection without responding and log at `tracing::warn!`.

### 12.3 Refuse-to-run-as-root

The daemon process refuses to start if `geteuid() == 0` (or the Windows equivalent of running as SYSTEM / a privileged account). Abort with exit code `EX_USAGE` and a clear message. The plan's reasoning: a code-retrieval daemon should never run privileged. Same for `service-manager` install paths (v1.1 — `ServiceLevel::User` only).

### 12.4 No core dumps

Linux: `prctl(PR_SET_DUMPABLE, 0)` after privilege checks. macOS: `setrlimit(RLIMIT_CORE, 0)`. Defends against post-crash leaks of indexed source content via stack dumps.

---

## 13. Default secrets policy

(security-review HIGH finding F5. `.gitignore` is not a security boundary.)

### 13.1 Filename blocklist (excluded from indexing)

```regex
(^|/)\.env(\..*)?$
| (^|/)id_(rsa|dsa|ecdsa|ed25519)(\.pub)?$
| .*\.(pem|p12|pfx|key|kdbx|jks|crt|cer)$
| .*credentials.*\.json$
| (^|/)\.aws/(credentials|config)$
| (^|/)\.npmrc$
| (^|/)\.pypirc$
| (^|/)\.htpasswd$
```

Matched files are not indexed at all and are not returnable by any tool. Configurable via a `secrets_blocklist` array in the workspace config (v1.1).

### 13.2 Content-pattern scanner

At index time, files are scanned for high-entropy strings matching:
- AWS access key: `AKIA[0-9A-Z]{16}`
- GitHub token: `gh[pousr]_[A-Za-z0-9]{36,}`
- Generic JWT: `eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{16,}`
- Stripe live key: `sk_live_[A-Za-z0-9]{24,}`
- PEM block header: `-----BEGIN .*(PRIVATE )?KEY-----`

Matched files are flagged and excluded from index; they appear in `Workspace.Status` under `secrets_excluded_files: N` but no path leak. Re-running with `RTS_SCAN_LEAK_LIST=1` (env var on the daemon) dumps the path list to stderr for the user's debugging — never over the wire.

### 13.3 `.rtsignore` extension

Repository-local `.rtsignore` is honoured in addition to `.gitignore` (§6.4). Cannot un-ignore; only adds.

### 13.4 Code-extension allowlist for body returns

`Index.ReadSymbol` / `Index.ReadRange` with `shape="body"` or unspecified MUST return a body only for files matching:
```text
.rs .py .ts .tsx .js .jsx .go .java .c .h .cpp .hpp .cc .cs .php .rb .swift .kt
.md .toml .yaml .yml .json .xml
```

Other extensions: signature-only or `OUT_OF_ALLOWED_BODY_EXTENSIONS` (the agent can still get signatures and structure). This narrows the impact of a determined prompt-injection-driven secret-exfiltration attack on files that slipped past §13.1 and §13.2.

---

## 14. Error code catalog

All errors use string codes (not JSON-RPC numeric codes — easier to grep, more agent-friendly).

| Code | Meaning | Retriable? |
|---|---|---|
| `INVALID_FRAME` | non-UTF-8 or non-JSON on the wire | No (connection closes) |
| `MESSAGE_TOO_LARGE` | request/response exceeded 16 MiB | No |
| `INVALID_PARAMS` | params object failed schema validation | No (without param fix) |
| `INVALID_WORKSPACE_PATH` | non-UTF-8 / non-existent / non-canonicalisable path | No |
| `MOUNT_HAS_SYMLINK` | any path component was a symlink | No (resolve outside, pass canonical) |
| `WORKSPACE_VANISHED` | `(dev, inode)` mismatch on remount — symlink swap, mount move, or dir replaced under the daemon | No (workspace went away) |
| `WORKSPACE_MISMATCH` (alpha.36+) | second `Workspace.Mount` from the same connection asked for a different canonical path than this daemon is already pinned to. Use a fresh daemon socket for the other path (auto-spawn handles this if the path hash differs) | No (connect via the correct socket) |
| `WORKSPACE_ON_NETWORK_MOUNT` | path is on NFS/SMB/etc. | No |
| `OUT_OF_ROOT` | path resolved outside the mounted workspace | No |
| `PATH_TRAVERSAL` | `..` segment in a client-provided path | No |
| `INDEX_NOT_READY` | only when `partial: false` was implied by the caller | Yes (poll `Workspace.Status`) |
| `SYMBOL_NOT_FOUND` | name resolves to zero matches | No (rephrase) |
| `AMBIGUOUS_SYMBOL` | multiple defs; pass `file`/`kind` to disambiguate (rarely used; prefer returning all with `truncated`) | No |
| `FILE_NOT_INDEXED` | path is below root but excluded (gitignore/secrets/extension) | No |
| `RANGE_OUT_OF_BOUNDS` | range refers to lines/bytes past EOF | No |
| `BUDGET_TOO_SMALL` | `token_budget` too small for the minimal viable answer | Yes (with larger budget) |
| `BUDGET_TOO_LARGE` | `token_budget` > 200 000 | No |
| `BUSY` | in-flight cap of 16 hit on this connection | Yes (backoff + retry) |
| `STORAGE_FULL` | redb / segment store ran out of disk | No (operator action) |
| `SCHEMA_VERSION_NEWER` | on-disk redb is newer than daemon binary | No (upgrade binary) |
| `DEADLINE_EXCEEDED` | 30 s soft deadline tripped | Yes (likely indicates a pathological request) |
| `CANCELLED` | cooperative cancellation tripped via `Daemon.Cancel { cancel_id }` (v0.6+, capability `cancellable_queries`); custom numeric `-32099`. Not a programming error — clients that issued the cancel should treat this as the expected response | No (rephrase or retry with a fresh `cancel_id`) |
| `INCOMPATIBLE_VERSION` | protocol major mismatch (currently unreachable — v0 is the only major) | No |
| `INTERNAL_ERROR` | bug in the daemon; should be reported | Yes (rarely fixes itself) |

`error.data` MAY carry structured detail (e.g. `{ "expected_uid": 501, "got_uid": 0 }` for the auth check, or `{ "files_done": 1234, "files_total": 5000 }` for `INDEX_NOT_READY` — same shape as `progress`).

### 14.1 MCP-shim transport errors (`DAEMON_UNAVAILABLE` / `DAEMON_DOWN`)

The `rts-mcp` shim's connection manager (Plan
`docs/plans/2026-05-19-004-feat-mcp-server-resilience-plan.md`, v0.6+,
capability `mcp_connection_resilience`) surfaces two **shim-emitted**
error codes when the daemon socket is mid-reconnect. These are not
daemon-side codes — the daemon never emits them; they originate in
the shim and reach the MCP host with custom JSON-RPC numeric codes
distinct from the application range:

| String code | Numeric code | Meaning | Retriable? |
|---|---|---|---|
| `DAEMON_UNAVAILABLE` | `-32098` | Transient: the shim is in `Reconnecting` state. `error.data.retry_after_ms` carries the wall-clock hint until the next reconnect attempt. `error.data.attempt` is the current retry attempt (1-indexed). | Yes — wait `retry_after_ms` and retry. |
| `DAEMON_DOWN` | `-32097` | Sustained: reconnect attempts exhausted after `RTS_MCP_RECONNECT_MAX_ATTEMPTS` (default 8); ceiling-interval (`RTS_MCP_RECONNECT_CEILING_SECS`, default 30) retries continue forever. `error.data.first_failure_ms_ago` carries how long the daemon has been unreachable. | Eventually — recovery promotes back to `Connected` automatically when the daemon returns; agents seeing this should surface to the user. |

Both shapes set `error.data.transient: true|false` so agents can branch
on a single boolean without parsing the code string.

**Heartbeat ↔ idle-shutdown interaction.** The shim's heartbeat issues
`Daemon.Ping` every `RTS_MCP_HEARTBEAT_INTERVAL_SECS` (default 10s).
The daemon's idle-shutdown is already gated on `active_connections > 0`
(§15.2), but the heartbeat additionally bumps `last_activity` so a
future loosening of the connection-count gate still sees fresh
traffic. **An MCP shim that's still attached keeps its daemon alive —
this is intentional.**

**Environment knobs** (all have documented defaults; nothing requires
user setup):

| Env var | Default | Effect |
|---|---|---|
| `RTS_MCP_HEARTBEAT_INTERVAL_SECS` | `10` | Wait between heartbeat `Daemon.Ping` calls. |
| `RTS_MCP_HEARTBEAT_TIMEOUT_SECS` | `3` | Per-ping timeout; on timeout the manager demotes to `Reconnecting`. |
| `RTS_MCP_RECONNECT_MAX_ATTEMPTS` | `8` | Bounded attempts before transitioning to `Down`. Retries continue at ceiling forever after. |
| `RTS_MCP_RECONNECT_CEILING_SECS` | `30` | Backoff ceiling. Schedule is `1s, 2s, 4s, 8s, 16s, 30s, 30s, …`. |

Source of truth: `crates/rts-mcp/src/connection.rs`.

**`Index.Grep` v2 sub-codes (v0.6, capability `index_grep_v2`).** Every v2 validation/execution error returns the protocol-level code `INVALID_PARAMS` and carries a stable `data.code` string that lets agents branch without parsing free-form messages. The strings are documented in §7.8b's "v0.6 additions" table; the closed set is:

`MULTILINE_REQUIRES_REGEX`, `STRUCTURAL_REQUIRES_LANGUAGE`, `NO_SEARCH_SOURCE_PROVIDED`, `INVALID_TEXT_LENGTH`, `STRUCTURAL_QUERY_INVALID`, `STRUCTURAL_QUERY_PREDICATE_NOT_ALLOWED`, `WITHIN_SYMBOL_NOT_FOUND`, `WITHIN_SYMBOL_TOO_MANY_DEFS`, `REGEX_TOO_COMPLEX`, `STRUCTURAL_QUERY_TIMEOUT`, `UNKNOWN_LANGUAGE`.

Source of truth: `crates/rts-daemon/src/methods/grep_v2/errors.rs`.

---

## 15. State lifecycle

### 15.1 Daemon startup

1. `geteuid() != 0` check; abort if root.
2. `umask(0077)`.
3. `prctl(PR_SET_DUMPABLE, 0)` / `setrlimit(RLIMIT_CORE, 0)`.
4. Bind socket at the per-workspace path (§5.3). PID file `+ .lock` next to it; `flock(LOCK_EX|LOCK_NB)` is authoritative (redb's `Database::create` also takes the flock — that's the real safety net, not the PID file).
5. Open redb at `${XDG_STATE_HOME}/rts/${workspace_id_hex}/db.redb`. Refuse if `schema_version > BINARY_SCHEMA_VERSION` (`SCHEMA_VERSION_NEWER`).
6. Compare stored workspace fingerprint against current `(dev, inode, canonical_path)`. Mismatch → rebuild from scratch.
7. Spawn watcher + writer-drain + reader pool. Initial `WalkBuilder` walk.

### 15.2 Workspace lifecycle

- `Workspace.Mount` is idempotent within a single connection — second call returns the current state without re-walking.
- Multiple `Workspace.Mount` calls from *different* connections all bind to the same workspace; the daemon keeps a refcount.
- `Workspace.Unmount` decrements the refcount.
- When the refcount reaches 0, the **idle-shutdown timer** starts. After 10 minutes of zero connections, the daemon exits cleanly.

### 15.3 Stale PID file

On startup, if the PID file exists:
1. Read `{pid, start_time}` from it.
2. `kill(pid, 0)` to test liveness.
3. Compare start_time to `/proc/<pid>/stat` (Linux) / `proc_pidinfo` (macOS) to defend against pid reuse.
4. If stale: **rename** to `<pid>.pid.stale.<unix_ns>` (do not unlink — preserves forensics) and continue.
5. If live and not us: `EXIT_DAEMON_ALREADY_RUNNING`.

### 15.4 redb corruption recovery

Trust redb's own two-phase commit. The only daemon-side recovery is:
- On `Database::create` returning `DatabaseError::Storage(_)`: log + rebuild from scratch.
- On metadata-row missing or `schema_version` parse failure: rebuild from scratch.
- The redb file is a derived cache; deleting it is always safe (§5.4).

### 15.5 Auto-spawn race

When `rts-mcp` finds no socket, it spawns a daemon and waits up to 5 seconds for the socket to appear. If two MCP processes auto-spawn simultaneously:
1. Both fork+exec a daemon.
2. Both daemons try to take the redb flock.
3. The loser exits with `EXIT_DAEMON_ALREADY_RUNNING` immediately (one-line message on stderr).
4. The losing MCP process polls and connects to the winner's socket within its 5 s window.

No PID-file fancy handshake required — `redb::Database::create`'s flock is the arbiter.

---

## 16. Resource limits (concrete numbers)

| Limit | Value | Override |
|---|---|---|
| Socket message size | 16 MiB | hard-coded |
| Per-connection in-flight requests | 16 | hard-coded |
| Per-request `token_budget` ceiling | 200 000 | hard-coded |
| Writer mpsc depth | 256 | hard-coded |
| Soft deadline per request | 30 s | hard-coded |
| Idle shutdown after last unmount | 10 min | `RTS_IDLE_SHUTDOWN_SECS` env |
| Hot-tree LRU capacity | ~5000 entries | `RTS_TREE_LRU_SIZE` env |
| Per-session dedup cache (v1.1) | ~10 MiB, 15 min TTL | hard-coded |
| Session reconnect window (v1.1) | 5 min | hard-coded |
| Auto-spawn wait window (`rts-mcp` side) | 5 s | hard-coded |
| Files above this size: skip skeleton/closure | 4 MiB | hard-coded |
| Content-pattern scan window | first 64 KiB of file | hard-coded |

Env-var overrides exist for the values most likely to want tuning in the field (idle shutdown, tree LRU). Everything else is fixed at the binary level to avoid configuration drift across deployments.

---

## 17. Telemetry & observability

Off by default. The daemon emits `tracing` spans on every tool call:
```text
target: rts_daemon::tool_call
fields: tool, ms, cache (tree_lru_hit | tree_lru_miss | reparse), dedup, partial,
        tokens_returned, file_id, workspace_id
```

Two output sinks:
1. **`tracing` to stderr** (always; respects `RUST_LOG`).
2. **JSONL sink** at `${XDG_STATE_HOME}/rts/${workspace_id_hex}.jsonl`. **Opt-in via `RTS_TELEMETRY=1`.** Rotated at 64 MiB; keep the last 3 files (cap ≈ 192 MiB per workspace). Silent-drop on `ENOSPC` (do not block the hot path); increment a `telemetry_dropped` counter exposed via `Workspace.Status`.

The wire-level `Daemon.Telemetry` notification (§7.11) is the live-streaming variant for clients that want it. Disabled by default; opt-in per `Workspace.Mount`.

---

## 18. JSON Schema fragments

These are normative for `params` validation. The daemon SHOULD reject schema-non-conforming requests with `INVALID_PARAMS` before doing any work.

### 18.1 `Workspace.Mount.params`

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": {
    "root": { "type": "string", "minLength": 1 },
    "enable_telemetry": { "type": "boolean", "default": false }
  },
  "required": ["root"],
  "additionalProperties": false
}
```

### 18.2 `Index.Outline.params`

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": {
    "token_budget":     { "type": "integer", "minimum": 50, "maximum": 200000 },
    "glob":             { "type": "string" },
    "mentioned_files":  { "type": "array", "items": { "type": "string" } },
    "mentioned_idents": { "type": "array", "items": { "type": "string" } }
  },
  "required": ["token_budget"],
  "additionalProperties": false
}
```

### 18.3 `Index.FindSymbol.params`

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": {
    "name":    { "type": "string", "minLength": 1, "maxLength": 256 },
    "pattern": { "type": "string", "minLength": 1, "maxLength": 256 },
    "kind":    { "type": "string", "enum": ["fn", "struct", "enum", "type", "trait",
                                             "const", "static", "impl", "method",
                                             "class", "interface", "module"] },
    "file":    { "type": "string" },
    "sort":    { "type": "string", "enum": ["rank", "lexical"], "default": "rank" }
  },
  "additionalProperties": false,
  "oneOf": [
    { "required": ["name"],    "not": { "required": ["pattern"] } },
    { "required": ["pattern"], "not": { "required": ["name"] } }
  ]
}
```

`name` and `pattern` are mutually exclusive; daemons reject "neither" and "both" with `INVALID_PARAMS`. `pattern` glob syntax: `*` (zero-or-more chars) and `?` (one char); no character classes, no escapes.

### 18.4 `Index.ReadSymbol.params`

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": {
    "name":                 { "type": "string", "minLength": 1, "maxLength": 256 },
    "file":                 { "type": "string" },
    "kind":                 { "type": "string", "enum": ["fn","struct","enum","type",
                                                          "trait","const","static",
                                                          "impl","method","class",
                                                          "interface","module"] },
    "shape":                { "type": "string", "enum": ["signature","body","both"],
                              "default": "body" },
    "token_budget":         { "type": "integer", "minimum": 50, "maximum": 200000 },
    "include_dependencies": { "type": "boolean", "default": false },
    "include_callers":      { "type": "boolean", "default": false },
    "force_resend":         { "type": "boolean", "default": false }
  },
  "required": ["name"],
  "additionalProperties": false
}
```

### 18.4c `Index.FindCallers.params`

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": {
    "name": { "type": "string", "minLength": 1, "maxLength": 256 },
    "kind": { "type": "string", "enum": ["fn", "struct", "enum", "type", "trait",
                                          "const", "static", "impl", "method",
                                          "class", "interface", "module"] },
    "file": { "type": "string" }
  },
  "required": ["name"],
  "additionalProperties": false
}
```

### 18.4d `Index.ImpactOf.params`

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": {
    "name":               { "type": "string", "minLength": 1, "maxLength": 256 },
    "depth":              { "type": "integer", "minimum": 1, "maximum": 4 },
    "token_budget":       { "type": "integer", "minimum": 50, "maximum": 200000 },
    "max_nodes":          { "type": "integer", "minimum": 1, "maximum": 10000 },
    "exclude_test_paths": { "type": "boolean", "default": true }
  },
  "required": ["name"],
  "additionalProperties": false
}
```

Out-of-window `depth` / `max_nodes` values are clamped (not rejected) — daemons running an older alpha won't `INVALID_PARAMS` on a request that targets a tighter future window.

### 18.4b `Index.ReadSymbolAt.params`

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": {
    "file":                 { "type": "string", "minLength": 1 },
    "line":                 { "type": "integer", "minimum": 1 },
    "column":               { "type": "integer", "minimum": 1 },
    "shape":                { "type": "string", "enum": ["signature","body","both"],
                              "default": "body" },
    "token_budget":         { "type": "integer", "minimum": 50, "maximum": 200000 },
    "include_dependencies": { "type": "boolean", "default": false },
    "include_callers":      { "type": "boolean", "default": false }
  },
  "required": ["file", "line"],
  "additionalProperties": false
}
```

`column` is accepted but inert in v0 (tie-breaker only). Lands with v1.1 incremental parser reuse.
`include_callers` (alpha.32+) mirrors `Index.ReadSymbol.params.include_callers`.

### 18.5 `Index.ReadRange.params`

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": {
    "file":         { "type": "string" },
    "start_line":   { "type": "integer", "minimum": 1 },
    "end_line":     { "type": "integer", "minimum": 1 },
    "token_budget": { "type": "integer", "minimum": 50, "maximum": 200000 }
  },
  "required": ["file", "start_line", "end_line"],
  "additionalProperties": false,
  "allOf": [{ "if": { "required": ["start_line", "end_line"] },
              "then": { "properties": {
                          "end_line": { "minimum": { "$data": "1/start_line" } } } } }]
}
```

(The `$data`-style cross-field constraint is informational; daemons MAY validate semantically rather than via JSON Schema.)

### 18.6 `Session.Open.params`

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": {
    "client_name":    { "type": "string", "maxLength": 128 },
    "client_version": { "type": "string", "maxLength": 128 }
  },
  "additionalProperties": false
}
```

### 18.7 `Session.Close.params`

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": {
    "session_id": { "type": "string", "pattern": "^sess_[0-9a-f]{16,}$" }
  },
  "required": ["session_id"],
  "additionalProperties": false
}
```

---

## Appendix A — Local-auth recipe per OS

### A.1 Linux

```rust
use std::os::unix::net::UnixListener;
use std::os::unix::io::AsRawFd;
use std::os::fd::AsRawFd as _;

// At startup, before bind():
nix::sys::stat::umask(nix::sys::stat::Mode::from_bits(0o077).unwrap());

// Ensure parent dir exists with 0700.
std::fs::create_dir_all(parent_dir)?;
nix::sys::stat::chmod(parent_dir, nix::sys::stat::Mode::from_bits(0o700).unwrap())?;

let listener = UnixListener::bind(socket_path)?;
nix::sys::stat::chmod(socket_path, nix::sys::stat::Mode::from_bits(0o600).unwrap())?;

// On each accepted connection:
loop {
    let (stream, _addr) = listener.accept().await?;
    let fd = stream.as_raw_fd();
    let cred: libc::ucred = nix::sys::socket::getsockopt(fd, nix::sys::socket::sockopt::PeerCredentials)?;
    if cred.uid != nix::unistd::geteuid().as_raw() {
        // Close without responding; log at warn.
        drop(stream);
        continue;
    }
    spawn_handler(stream);
}
```

### A.2 macOS

```rust
// Same umask + parent-dir + bind + chmod recipe.
// Peer credential check uses LOCAL_PEERCRED (or getpeereid as fallback).

let (uid, _gid) = match nix::sys::socket::getsockopt(fd, nix::sys::socket::sockopt::LocalPeerCred) {
    Ok(xucred) => (xucred.cr_uid, xucred.cr_gid),
    Err(_) => nix::unistd::getpeereid(fd)?,
};
if uid != nix::unistd::geteuid().as_raw() {
    drop(stream);
    continue;
}
```

### A.3 Windows (v1.1 sketch)

```text
- Create named pipe with PIPE_REJECT_REMOTE_CLIENTS and an explicit
  DACL allowing only the current user SID (FILE_GENERIC_READ |
  FILE_GENERIC_WRITE).
- On each accepted connection: GetNamedPipeClientProcessId →
  OpenProcessToken → GetTokenInformation(TokenUser) → compare against
  current SID; mismatch → close + log.
```

---

## Appendix B — What's intentionally not in v0

- **Multi-host / network transport.** v0 is local-only by design.
- **Per-symbol locking.** Reader concurrency is per-connection; per-symbol fanout isn't worth the complexity yet.
- **`Daemon.Cancel`.** Connection drop is enough for v0.
- **Mid-closure cancellation tokens.** A budgeted walker is sufficient.
- **Bulk endpoints (`Index.FindSymbols`, `Index.ReadSymbols`).** Clients can pipeline.
- **Pagination.** All v0 responses fit within `MAX_MATCHES=256` or `MESSAGE_TOO_LARGE`; explicit pagination is v2.
- **Persistent sessions across daemon restarts.** Session id + dedup live in daemon memory; respawn flushes them. The 5-min reconnect window only covers MCP-process churn while the daemon stays up.
- **Per-file ACLs.** Single-uid trust model (§1).

---

## Appendix C — Decisions resolved from the deepening

Cross-references to specific deepening findings, for the implementer to verify nothing got dropped:

| Decision | This doc | Origin |
|---|---|---|
| Capability negotiation (not single-version) | §4 | architecture-strategist review |
| `content_version` on slice/lookup responses | §3.6, §7.7 | architecture-strategist review |
| Workspace identity = `(dev, inode, canonical_path)` | §5.2 | security F9 + data-integrity #4 |
| Per-OS canonicalisation matrix | §5.1 | data-integrity #9 |
| Refuse symlinked workspace components at Mount | §6.1 | security F4 |
| Per-read prefix check, never trust the watcher | §6.2 | security F4 |
| Default secrets policy + content scanner + extension allowlist | §13 | security F5 |
| Peer-credential auth + `umask(0077)` + parent-dir 0700 | §12 | security F1 |
| Refuse-to-run-as-root | §12.3 | security F12/F13 |
| Refuse network-mounted workspaces (no `/tmp` fallback) | §5.6, §5.3 | security F2/F3 |
| 16-in-flight cap, 200 000 token budget cap, bounded mpsc | §9.4, §9.3, §16 | security F7 |
| `tokens_returned` + `token_counter` in every response | §3.5, §11 | agent-native review |
| `Find/ReadSymbol` always returns a list with `rank_score` | §7.6 | agent-native review |
| `body_omitted: true` + `see_earlier_id` + `force_resend` (vs raw pointer) | §7.7 v1.1 path | agent-native review |
| `Workspace.Status` is a public verb (not only internal) | §7.4 | agent-native review |
| `Daemon.Cancel` and `Session.MarkDeduped` dropped from v0 | §7 catalog | architecture-strategist review |
| Session id authoritative from kernel peer-creds, not agent headers | §7.9, §12.2 | security F13 + architecture review |
| Single writer-drain task, parse-parallel + commit-serial, batched txn | §9.1-§9.3 | perf-oracle |
| Long-lived `redb::ReadTransaction` per reader task | §9.1 | perf-oracle |
| Token approximator `bytes/3` (not `/3.5`), CJK-aware | §11.1 | perf-oracle |
| redb file at `${XDG_STATE_HOME}/rts/<hash>/db.redb` (outside workspace) | §5.4 | data-integrity #8 |
| Files >4 MiB indexed by `(size, mtime)` only | §16 | data-integrity #7 |
| redb flock authoritative; PID file is hint-only; stale PID renamed | §15.3, §15.5 | data-integrity #5 |
| Refuse to open schema-newer redb | §15.1 step 5 | data-integrity #6 |
| Telemetry opt-in `RTS_TELEMETRY=1`; 64 MiB rotation × 3; silent-drop on ENOSPC | §17 | data-integrity #12 |

---

## Appendix D — Open questions deferred to P6

- **Exact watcher debounce on macOS for atomic-rename clusters.** P0.3 confirmed `RenameMode::*` doesn't fire on macOS; the daemon's watcher event handler will treat `Create` and `Modify(Data)` symmetrically and reconcile via content-hash if needed. Final tuning is empirical, against the bench corpus.
- **Closure depth defaults per language.** P8 deliverable; doesn't change the wire protocol, only the algorithm behind `include_dependencies`.
- **Per-language `SignatureRenderer` rule for Swift and PHP.** Swift's `tree-sitter-swift` is community-maintained (ERROR-node fallback). PHP's grammar split into `LANGUAGE_PHP` vs `LANGUAGE_PHP_ONLY` — v0 wires PHP via `LANGUAGE_PHP` (covers HTML-embedded too); P8 verifies this is the right choice.
- **Whether `Daemon.Telemetry` notifications should also surface watcher events.** Probably yes for debuggability; left for P6 to decide once the watcher's event stream is concrete.

---

## Appendix E — Wire-protocol versioning policy

v0 freezes the **shapes** in §3 (envelope) and §7 (method namespaces and JSON Schemas above). Additive evolution within v0 is allowed via:
- New capability strings in `Daemon.Ping.result.capabilities`.
- New optional fields in existing `params` / `result` objects (clients MUST ignore unknown fields).
- New error codes (clients MUST treat unknown codes as non-retriable by default).
- New methods in the existing namespaces (`Workspace.Foo`, `Index.Bar`).

Breaking changes require minting `protocol-v1.md`. Examples of changes that would break:
- Removing a method or field.
- Changing the meaning of a field while keeping its name.
- Changing the framing or transport at the wire-byte level.

The daemon MUST NOT advertise `protocol: "1"` until a v1 spec exists and the daemon implements it.

---

## Appendix F — Wire-shape evolution by alpha

This appendix tracks every additive wire-shape change between Draft 1 (P5 deliverable, pre-implementation) and Draft 2 (this revision, alpha.30 baseline). Each entry lists the alpha that shipped the change, the capability string that advertises it, and the spec section(s) that document the resulting shape. Entries are additive per Appendix E — clients that ignored an unknown field before still work after.

| Alpha | Capability | Wire-shape change | Doc sections |
|---|---|---|---|
| `alpha.18` | `pagerank_filewise` | `Index.FindSymbol.result.matches[*].rank_score` and `Index.Outline` PageRank personalisation via `mentioned_files`/`mentioned_idents` | §7.5, §7.6 |
| `alpha.20` | (none — internal) | OutlineCache memoization; no wire change | — |
| `alpha.22` | `closure_walker` | `Index.ReadSymbol.params.include_dependencies: bool`; `result.dependencies[]`, `result.closure_truncated: bool`, `result.truncated_symbols[]` | §7.7 |
| `alpha.24` | `read_symbol_at`, `fuzzy_match` | New method `Index.ReadSymbolAt(file, line, column?)`; `Index.FindSymbol.params.name` made optional; new `Index.FindSymbol.params.pattern` (glob) | §7.6, §7.7b, §18.3, §18.4b |
| `alpha.25` | `polling_fallback` | `Workspace.Status.result.watcher_status` enum extended with `polling_fallback` and `overflowed_rewalking` | §7.4 |
| `alpha.26` | (none — internal) | `rts-bench query` CLI subcommand; talks to daemon over the same socket using existing methods. No wire-shape change. | — |
| `alpha.27` | (none — internal) | tags.scm reference precision in `closure_walker`'s identifier filter. Same wire shape; better-quality contents. | — |
| `alpha.28` | (none — internal) | `crate::language` per-language dispatcher refactor. No wire change. | — |
| `alpha.29` | (none — internal) | OnceLock query cache + signature renderer perf. No wire change. | — |
| `alpha.30` | (none — internal) | JS/TS tags.scm reference queries (extends alpha.27 to JS/TS). Same wire shape; better-quality contents on JS/TS workspaces. | — |
| `alpha.31` | (none — internal) | **v0.3 U1**: persistent reference graph (REFS / FID_REFS / SID_REFS_OUT tables; SCHEMA_VERSION 1→2). `outline::compute` reads indexed edges. Same wire shape; no agent-visible changes. | — |
| `alpha.32` | `find_callers`, `read_symbol.include_callers` | **v0.3 U2'**: new method `Index.FindCallers(name, kind?, file?)` returns direct callers. `Index.ReadSymbol.params.include_callers: bool` composes callers into the existing response with a separate `callers_truncated` flag. | §7.7, §7.7c, §18.4, §18.4b, §18.4c |
| `alpha.33` | (none — internal) | **v0.3 U3**: `closure::compute` swaps from at-query-time tree-sitter parsing to reading `SID_REFS_OUT`. Same wire shape; faster cold calls. Also fixed a latent local-variable bug in U1's `enclosing_caller_sid` that under-populated `SID_REFS_OUT`. | — |
| `alpha.34` | `pagerank_symbolwise` | **v0.3 U4**: symbol-level PageRank fills `rank_score` in `Index.FindSymbol` and `Index.FindCallers` responses (was a `0.0` placeholder). `Index.FindSymbol.matches[]` sorts by descending rank by default; `sort: "lexical"` opts out. Single-slot generation-keyed cache mirroring `OutlineCache` (alpha.20). | §4.1, §4.2, §7.6, §18.3 |
| `alpha.35` | `impact_of` | **v0.3 U5** (final): new method `Index.ImpactOf(name, depth?, token_budget?, max_nodes?, exclude_test_paths?)` returns the transitive caller closure via BFS over reverse edges. Four independent truncation flags (`closure_truncated`, `wall_clock_truncated`, `depth_truncated`, `node_count_truncated`) tell the agent why a result is partial. Test-path exclusion (`/tests/`, `_test.rs`, `.spec.ts`) is on by default. Wire shape trimmed from the plan's 9 fields to 6 per Deepening §F3 (no `signature`, no nested `callers[]`). | §4.1, §4.2, §7, §7.7d, §18.4d |
| `v0.6 alpha` | `index_grep_multiline`, `index_grep_structural`, `index_grep_within_symbol`, `index_grep_v2` | **`Index.Grep` v2** (`index_grep_v2` bundle): five additive optional input fields (`multiline`, `structural_query`, `within_symbol`, `within_symbol_allow_overload`, `language`); per-match `captures` on structural results; top-level `truncated`/`truncation_reason`/`rows_seen`/`rows_returned` on cap breaches; `partial_failures[]` on cross-language structural runs. 11 new `data.code` sub-codes under `INVALID_PARAMS`. Predicate whitelist (7 entries) on agent-supplied S-expression queries. Three new `Daemon.Stats` sub-counters. v1 callers unchanged byte-for-byte. | §4.1, §7.8b, §14 |
| `v0.6 alpha` | (shim-only — no daemon capability) | **MCP shim resilience** (Plan 004): `rts-mcp` connection manager adds background heartbeat (`Daemon.Ping` every `RTS_MCP_HEARTBEAT_INTERVAL_SECS`, default 10s) and reconnect-with-backoff. Tool calls during a disconnect window return two new MCP-shim error codes: `DAEMON_UNAVAILABLE` (numeric `-32098`, transient — `error.data.retry_after_ms` hint) and `DAEMON_DOWN` (numeric `-32097`, sustained). Schedule: `1s, 2s, 4s, 8s, 16s, 30s, 30s, 30s`; ceiling-interval retries continue forever past the bounded-attempt cap. Daemon wire protocol unchanged. | §14.1 |

Capability strings present in `Daemon.Ping.result.capabilities` after alpha.35 (canonical list, in advertisement order): `outline`, `find_symbol`, `read_symbol`, `read_range`, `rank_score`, `tree_shake`, `partial_responses`, `content_version`, `secrets_blocklist`, `pagerank_filewise`, `closure_walker`, `read_symbol_at`, `fuzzy_match`, `polling_fallback`, `find_callers`, `read_symbol.include_callers`, `pagerank_symbolwise`, `impact_of`. v0.6 alpha appends `index_grep_multiline`, `index_grep_structural`, `index_grep_within_symbol`, `index_grep_v2` (see §7.8b).

**v0.3 plan complete:** all four code-graph KB capability strings (`find_callers`, `read_symbol.include_callers`, `pagerank_symbolwise`, `impact_of`) advertised. The `call_graph` umbrella reserved string remains unused — agents branch on the four fine-grained strings instead.

### How to extend protocol-v0 in a future alpha

When an alpha PR adds a new wire field, method, capability, or error code:

1. Add the change to the appropriate spec section (§3–§18) with a `(capability: <string>, alpha.NN+)` annotation in the prose.
2. Append a row to the table above with the alpha number, capability string, and section pointers.
3. Update the capability list in §4.1 if the new string becomes advertised.
4. Update §4.2 if the new string was previously reserved.

The PR description SHOULD link to the section(s) it changed so reviewers can verify the wire-shape contract.

---

*This document is the source of truth for the daemon-side wire protocol. The MCP-facing surface (`outline_workspace`, `find_symbol`, `find_callers`, `read_symbol`, `read_symbol_at`, `read_range`, `rts://capabilities`) is governed by [docs/plans/2026-05-10-001-feat-pivot-to-agentic-retrieval-mcp-server-plan.md](plans/2026-05-10-001-feat-pivot-to-agentic-retrieval-mcp-server-plan.md) and the MCP 2025-11-25 spec; future MCP-tool changes should land in that plan, not here. The v0.3 code-graph KB extension lives in [docs/plans/2026-05-13-001-feat-v0.3-code-graph-kb-plan.md](plans/2026-05-13-001-feat-v0.3-code-graph-kb-plan.md).*
