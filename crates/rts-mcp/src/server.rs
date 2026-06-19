//! `RtsServer` — the rmcp 1.6 `ServerHandler` that fronts `rts-daemon`.
//!
//! Surfaces four MCP tools (`outline_workspace`, `find_symbol`,
//! `read_symbol`, `read_range`) plus the `rts://capabilities` resource.
//! Each tool call translates to one `Index.*` request on the persistent
//! Unix-socket connection held by the server.

use rmcp::{
    ErrorData as McpError, ServerHandler,
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{CallToolResult, Content, ServerCapabilities, ServerInfo},
    tool, tool_handler, tool_router,
};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Value, json};

use rts_mcp::connection::{ConnectionError, ConnectionManager};

// Built-in tool descriptions are pinned inline (the `#[tool(description = ...)]`
// macro expects a literal string and does not accept const-path expressions).
// Source: plan §"Tool descriptions (LLM-facing, pinned in P5)".
//
// v0.6 cooperative cancellation note (capability `cancellable_queries`):
// the underlying daemon protocol accepts an optional `cancel_id: String`
// at the JSON-RPC envelope level on any request, and exposes
// `Daemon.Cancel { cancel_id }` that trips the matching in-flight
// request with `error.code: CANCELLED`. The MCP tool surface here
// does **not** expose `cancel_id` as a per-tool argument — agents
// typically can't reframe mid-call from inside a tool invocation
// anyway, and adding it to every tool schema would clutter the
// agent's view. Hosts that want to wire cancellation can address
// the daemon directly through the same Unix socket; see
// `docs/protocol-v0.md` for the wire shape.

#[derive(Debug, Deserialize, JsonSchema)]
pub struct OutlineArgs {
    /// Optional gitignore-style glob to restrict the outline (e.g.
    /// `"src/**"`). When unset, the full workspace is summarised.
    #[serde(default)]
    pub glob: Option<String>,
    /// Optional token budget. The daemon clips the outline at this value
    /// and sets `truncated: true` when the budget bites. Range: 50..=200000.
    #[serde(default)]
    pub token_budget: Option<u64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct FindSymbolArgs {
    /// Exact name to find. Mutually exclusive with `pattern`. Use this
    /// when you know the symbol's name.
    #[serde(default)]
    pub name: Option<String>,
    /// Glob pattern over symbol names (`*` = any chars, `?` = one char).
    /// Mutually exclusive with `name`. Examples: `make_*`, `*_target`,
    /// `read_*_at`, `*`. Use this when you only know roughly what the
    /// symbol is called — replaces the "fall back to shell rg" workaround.
    #[serde(default)]
    pub pattern: Option<String>,
    /// Optional `kind` filter: `fn`, `struct`, `enum`, `type`, `trait`,
    /// `const`, `static`, `impl`, `method`, `class`, `interface`, `module`,
    /// `heading` (v0.7.0 — markdown H1–H6; depth is in the rendered
    /// signature and the hierarchical `qualified_name`).
    #[serde(default)]
    pub kind: Option<String>,
    /// Optional `file` filter (workspace-relative path) to disambiguate
    /// when the same name lives in multiple files.
    #[serde(default)]
    pub file: Option<String>,
    /// Optional: only return defs whose nearest enclosing container
    /// (impl/class/struct/…) name equals this. Disambiguates overloads
    /// across types — e.g. `parent: "QueryBuilder"` for `QueryBuilder::new`.
    #[serde(default)]
    pub parent: Option<String>,
    /// Maximum number of results. Defaults to 256 — leave at default
    /// for normal agent use (LLM contexts can't usefully digest more).
    /// Range: 1..=4096. The 4096 ceiling exists for offline evaluation
    /// tooling (`rts-bench semantic`); setting `limit` above the
    /// default in an agent call is almost always a mistake.
    #[serde(default)]
    pub limit: Option<u32>,
    /// Filter matches to those whose doc-comment text contains the
    /// given substring (case-insensitive). Useful for behavior-shaped
    /// queries: `doc_contains: "retry"` returns documented symbols
    /// whose comments mention retry behavior, regardless of identifier
    /// name. Symbols with no doc comment never match. Capability:
    /// `find_symbol_doc_filter` (v0.5.2+).
    #[serde(default)]
    pub doc_contains: Option<String>,
    /// When `true`, populate each match's `signature` field via
    /// rts-core's per-language SignatureRenderer (Rust, Python,
    /// TypeScript, JavaScript, Go, Java, C, C++, PHP, Ruby, Swift).
    /// Default `false` — the field stays `null` to preserve the
    /// pre-v0.5.3 wire shape. Use this for outline-style lookups
    /// where you want signatures without paying for `read_symbol`
    /// per match. Renders are cached per file across calls.
    /// Capability: `find_symbol_signature_field` (v0.5.3+).
    #[serde(default)]
    pub include_signature: Option<bool>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ReadSymbolArgs {
    /// The symbol name to read — exact match only.
    pub name: String,
    /// Optional `file` filter to disambiguate.
    #[serde(default)]
    pub file: Option<String>,
    /// Optional `kind` filter to disambiguate.
    #[serde(default)]
    pub kind: Option<String>,
    /// Optional: only resolve a def whose nearest enclosing container
    /// (impl/class/struct/…) name equals this. Disambiguates overloads
    /// across types — e.g. `parent: "QueryBuilder"` for `QueryBuilder::new`.
    #[serde(default)]
    pub parent: Option<String>,
    /// `signature` returns just the declaration; `body` (default) returns
    /// the full implementation; `both` returns both.
    #[serde(default)]
    pub shape: Option<String>,
    /// Token budget for the response. Range: 50..=200000.
    #[serde(default)]
    pub token_budget: Option<u64>,
    /// When `true`, also include the minimum surrounding types/imports the
    /// symbol references (tree-shaken closure).
    #[serde(default)]
    pub include_dependencies: bool,
    /// When `true`, also include `callers[]`: the direct callers of this
    /// symbol (same shape as `find_callers.callers[]`). Composes with
    /// `include_dependencies` — body wins token budget first, then deps,
    /// then callers. Use this when you want the symbol *and* its
    /// neighborhood in one round trip.
    #[serde(default)]
    pub include_callers: bool,
    /// v1.1 session-dedup override. Accepted but inert in v0.
    #[serde(default)]
    pub force_resend: bool,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct FindCallersArgs {
    /// Exact name of the symbol whose callers to find.
    pub name: String,
    /// Optional `kind` filter on the *enclosing* def — restrict callers
    /// to functions / methods / etc. Accepts the same loose-string
    /// form as `find_symbol.kind`.
    #[serde(default)]
    pub kind: Option<String>,
    /// Optional `file` filter (workspace-relative path) — restrict
    /// callers to those originating from one file.
    #[serde(default)]
    pub file: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct VerifySymbolArgs {
    /// The symbol name to verify — bare (`commit_batch`) or qualified
    /// (`Store::commit_batch`). 1..=256 chars.
    pub name: String,
    /// Optional `kind` filter (`fn`, `method`, `struct`, `enum`,
    /// `trait`, `const`, `module`, …). Same loose-string form as
    /// `find_symbol.kind`. Disambiguates same-named defs of different
    /// kinds.
    #[serde(default)]
    pub kind: Option<String>,
    /// Optional language filter (`rust`, `python`, …). Advisory in v0.
    #[serde(default)]
    pub lang: Option<String>,
    /// Optional `file` filter (workspace-relative path). Scopes the
    /// existence check (and the ambiguity decision) to one file.
    #[serde(default)]
    pub file: Option<String>,
    /// Optional content-version echo. Returned verbatim in the
    /// response; does not affect the result in v0.
    #[serde(default)]
    pub content_version: Option<String>,
}

/// Claimed signature shape for `verify_signature`.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct ClaimedSignatureArgs {
    /// Claimed parameter count, excluding any receiver (`self`/`cls`).
    pub arity: u32,
    /// Claimed parameter names, in order.
    #[serde(default)]
    pub params: Vec<String>,
    /// Claimed return type (string-compared against the actual).
    #[serde(default)]
    pub returns: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct VerifySignatureArgs {
    /// Symbol name — bare (`commit_batch`) or qualified
    /// (`Store::commit_batch`). 1..=256 chars.
    pub name: String,
    /// Optional `kind` filter (`fn`, `method`, …) to disambiguate
    /// same-named defs of different kinds.
    #[serde(default)]
    pub kind: Option<String>,
    /// Optional language filter (`rust`, `python`, …). Advisory in v0.
    #[serde(default)]
    pub lang: Option<String>,
    /// Optional `file` filter (workspace-relative) to disambiguate
    /// overloaded names across files.
    #[serde(default)]
    pub file: Option<String>,
    /// The signature shape you believe the symbol has.
    pub claimed: ClaimedSignatureArgs,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct VerifyImportArgs {
    /// The import path, e.g. `crate::store::CommitOptions`. Only the
    /// final segment is resolved against the index in v0.
    pub path: String,
    /// Optional language hint. Advisory in v0.
    #[serde(default)]
    pub lang: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct VerifyClaimsArgs {
    /// The batch of claims to verify. Each item is a JSON object tagged
    /// by `type`: `symbol` ({name, kind?, lang?, file?}),
    /// `signature` ({name, claimed{arity, params?, returns?}, …}),
    /// `import` ({path, lang?}), or `location`
    /// ({symbol, file, line, kind?}).
    pub claims: Vec<serde_json::Value>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ImpactOfArgs {
    /// Exact name of the symbol whose transitive callers we want.
    pub name: String,
    /// BFS depth. Default 2; hard cap 4. Higher values produce
    /// exponentially more nodes; the `max_nodes` cap is the real
    /// signal/noise gate past depth 3.
    #[serde(default)]
    pub depth: Option<u32>,
    /// Token budget for the response. Default 4096.
    #[serde(default)]
    pub token_budget: Option<u64>,
    /// Max distinct caller entries returned. Default 200. Hard
    /// ceiling 10000.
    #[serde(default)]
    pub max_nodes: Option<u32>,
    /// When `true` (default), skip callers whose enclosing file
    /// looks like a test file (`/tests/`, `_test.rs`, `.spec.ts`,
    /// etc.). The single biggest noise reducer on real
    /// refactor-impact queries.
    #[serde(default)]
    pub exclude_test_paths: Option<bool>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct VerifyImpactArgs {
    /// Symbol whose change you want to gate — bare (`commit_batch`) or
    /// qualified (`Store::commit_batch`). 1..=256 chars.
    pub symbol: String,
    /// The kind of change you intend: `signature`, `remove`, or `rename`.
    pub change: String,
    /// For `change: signature` — the proposed new signature header, e.g.
    /// `commit_batch(entries: &[Entry], flush: bool) -> Result<()>`. When
    /// present and parseable, the arity is compared against the indexed
    /// def; absent or undecidable → conservative `would_break` if there
    /// are any callers, with `resolution: indeterminate`.
    #[serde(default)]
    pub new_signature: Option<String>,
    /// Blast-radius depth. Default 1 (direct callers only) — a gate wants
    /// immediate breakage. Hard cap 4.
    #[serde(default)]
    pub depth: Option<u32>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ProposedEditArg {
    /// Workspace-relative path of the file being edited.
    pub file: String,
    /// FULL post-edit content of the file (not a diff hunk).
    pub content: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct VerifyEditArgs {
    /// The proposed post-edit file states. Each entry's `content` is the
    /// COMPLETE new content of `file`. Non-empty; each `file` is 1..=1024
    /// chars; combined content is bounded (~2 MiB).
    pub edits: Vec<ProposedEditArg>,
    /// Optional filter over which finding kinds to report: `broken_caller`,
    /// `dangling_ref`, `signature_break`, `new_symbol`. Omit to run all
    /// four. Unknown names are ignored.
    #[serde(default)]
    pub checks: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ReadSymbolAtArgs {
    /// Workspace-relative file path.
    pub file: String,
    /// 1-indexed line containing the symbol to read. Compiler-error
    /// flow: take the `:LINE` from `error[E0308] --> path:LINE:COL`.
    pub line: u32,
    /// Optional 1-indexed column inside the line.
    #[serde(default)]
    pub column: Option<u32>,
    /// `signature` returns just the declaration; `body` (default) returns
    /// the full implementation; `both` returns both.
    #[serde(default)]
    pub shape: Option<String>,
    /// Token budget for the response. Range: 50..=200000.
    #[serde(default)]
    pub token_budget: Option<u64>,
    /// When `true`, also include the minimum surrounding types/imports
    /// the symbol references (tree-shaken closure).
    #[serde(default)]
    pub include_dependencies: bool,
    /// When `true`, also include `callers[]`: the direct callers of
    /// the resolved symbol. Same shape as `find_callers.callers[]`.
    #[serde(default)]
    pub include_callers: bool,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ReadRangeArgs {
    /// Workspace-relative path of the file to read.
    pub file: String,
    /// First line of the range (1-indexed, inclusive).
    pub start_line: u32,
    /// Last line of the range (1-indexed, inclusive).
    pub end_line: u32,
    /// Token budget for the response. Range: 50..=200000.
    #[serde(default)]
    pub token_budget: Option<u64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GrepArgs {
    /// Pattern to search for across indexed file bytes.
    /// 1..=1024 characters. **By default this is a LITERAL substring
    /// search — regex metacharacters like `.` `*` `(` `\b` are
    /// treated as their literal selves.** To interpret `text` as a
    /// regex (`regex` crate syntax: `TODO\(.*?\)`, `\bunsafe\b`,
    /// `\d+ms`), pass `regex: true`. Case-insensitive by default in
    /// both modes (override with `case_insensitive: false`).
    ///
    /// Use literal mode for error messages, version pins, log
    /// strings, config values, embedded URLs — content `find_symbol`
    /// can't reach because it isn't a symbol name or doc-comment.
    /// Use regex mode for shape-based patterns. Capability:
    /// `index_grep` (v0.5.4+).
    ///
    /// v0.6: optional — provide `text` OR `structural_query` (or
    /// both for intersection). When neither is set the daemon
    /// returns `NO_SEARCH_SOURCE_PROVIDED`.
    #[serde(default)]
    pub text: Option<String>,
    /// Maximum number of matches to return. Defaults to 256;
    /// range 1..=4096. Above the default is almost always a tooling
    /// problem — agents should narrow the search instead.
    #[serde(default)]
    pub limit: Option<u32>,
    /// Case-insensitive matching. Defaults to `true` (agent-friendly).
    /// Set `false` for exact-case matches (rare). Applies to both
    /// literal and regex modes.
    #[serde(default)]
    pub case_insensitive: Option<bool>,
    /// v0.5.5+ opt-in regex mode. When `true`, `text` is interpreted
    /// as a `regex` crate pattern (byte-level matching). Defaults
    /// to `false` (literal mode). Use for: `TODO\(.*?\)`,
    /// `\bunsafe\b`, `\d+ms`. Compilation errors surface as
    /// `INVALID_PARAMS` with the compiler's diagnostic so you can
    /// self-correct.
    #[serde(default)]
    pub regex: Option<bool>,
    /// v0.5.5+ file-path glob filter. When set, only files whose
    /// workspace-relative path matches this glob are scanned. Uses
    /// `globset` syntax: `*.rs`, `src/**/*.toml`,
    /// `crates/{rts-core,rts-daemon}/**/*.rs`. Pairs with `text`
    /// or `text + regex` to scope a search — equivalent to
    /// `rg --type rust foo` without leaving the indexed file set.
    #[serde(default)]
    pub file_glob: Option<String>,
    /// v0.6 multi-line regex mode (capability `index_grep_multiline`).
    /// When `true` AND `regex: true`, the regex engine treats indexed
    /// file bytes as one logical buffer per file: `.` matches `\n`,
    /// `^`/`$` match line boundaries, and `(?s)` / `(?m)` flags are
    /// honored. Required for patterns that span newlines (multi-line
    /// function signatures, SQL fragments, multi-line error
    /// messages). REJECTED with `MULTILINE_REQUIRES_REGEX` when set
    /// on the literal `text` path (literal substring search is
    /// already byte-wise across newlines; multiline is a regex
    /// concept only). Has its own DFA size budget (32 MB) to bound
    /// adversarial patterns; over-budget regexes return
    /// `REGEX_TOO_COMPLEX` instead of panicking or hanging.
    #[serde(default)]
    pub multiline: Option<bool>,
    /// v0.6 raw tree-sitter S-expression structural query
    /// (capability `index_grep_structural`). Runs the query against
    /// the parsed tree of every file matching the `language` filter
    /// and returns matches with a per-match `captures` map keyed by
    /// the query's named captures. Example query for "find every
    /// `impl` block containing an `unsafe fn`":
    /// `(impl_item body: (declaration_list (function_item) @fn))`
    /// — captures named `@fn`.
    ///
    /// Requires `language` (returns `STRUCTURAL_REQUIRES_LANGUAGE`
    /// otherwise). Predicates whitelisted to `#eq?`, `#not-eq?`,
    /// `#match?`, `#not-match?`, `#any-of?`, `#is?`, `#is-not?`;
    /// anything else returns `STRUCTURAL_QUERY_PREDICATE_NOT_ALLOWED`.
    /// Composes with `text`/`pattern` (intersection) and
    /// `within_symbol` (filter); see `docs/protocol-v0.md` §7.8b.
    #[serde(default)]
    pub structural_query: Option<String>,
    /// v0.6 byte-range scope filter (capability
    /// `index_grep_within_symbol`). When set, returned matches are
    /// filtered to those whose byte range lies strictly inside the
    /// def byte range of the named symbol(s). Useful for
    /// "find every `panic!` inside `fn parse_request`" — pairs
    /// `find_symbol` resolution with `grep` filtering in one call.
    ///
    /// `within_symbol: "name"` resolves the name via the same
    /// lookup as `find_symbol`. Returns `WITHIN_SYMBOL_NOT_FOUND` on
    /// zero matches. When the name resolves to more than 16 defs
    /// (overloaded names like `new`/`main`/`default`), returns
    /// `WITHIN_SYMBOL_TOO_MANY_DEFS` unless
    /// `within_symbol_allow_overload: true` is also set, in which
    /// case matches across the union of all def byte ranges are
    /// returned.
    #[serde(default)]
    pub within_symbol: Option<String>,
    /// v0.6 opt-in to multi-def `within_symbol`. Defaults to `false`.
    /// See `within_symbol` above.
    #[serde(default)]
    pub within_symbol_allow_overload: Option<bool>,
    /// v0.6 language filter (capability `index_grep_v2`). When set,
    /// only files whose language is in this list are scanned.
    /// Intersects with `file_glob` (AND semantics). **Required** when
    /// `structural_query` is set; optional otherwise. Accepted values
    /// match the daemon's indexed-language identifiers: `rust`,
    /// `javascript`, `typescript`, `python`, `c`, `cpp`, `go`, `java`,
    /// `php`, `ruby`, `swift`, `csharp`.
    #[serde(default)]
    pub language: Option<Vec<String>>,
}

/// Empty arg struct for `daemon_stats`. The rmcp `tool_router` macro
/// expects every `#[tool]` function to take `Parameters<T>`; this
/// `Empty` placeholder satisfies that contract for parameterless
/// tools without polluting the wire schema.
#[derive(Debug, Default, Deserialize, JsonSchema)]
pub struct EmptyArgs {}

#[derive(Clone)]
pub struct RtsServer {
    // The `#[tool_router]` macro generates dispatch through `tool_router`;
    // rustc can't see through the macro for the dead-code analysis.
    #[allow(dead_code)]
    tool_router: ToolRouter<Self>,
    /// v0.6+: connection manager owns the daemon socket plus the
    /// background heartbeat / reconnect tasks (see
    /// `connection.rs` and Plan 004). Replaces the bare
    /// `Arc<Mutex<DaemonClient>>` and the inline retry loop the
    /// pre-resilience server carried — tool calls now see structured
    /// `DAEMON_UNAVAILABLE` / `DAEMON_DOWN` errors when the daemon
    /// is mid-reconnect rather than blocking on the daemon mutex.
    connection: ConnectionManager,
    instructions: String,
}

#[tool_router]
impl RtsServer {
    /// Build a server around an established [`ConnectionManager`]. The
    /// manager owns the socket and the background heartbeat /
    /// reconnect tasks; this struct is the rmcp tool-router shim that
    /// translates between MCP `tools/call` envelopes and daemon RPCs.
    pub fn new(connection: ConnectionManager, instructions: String) -> Self {
        Self {
            tool_router: Self::tool_router(),
            connection,
            instructions,
        }
    }

    /// Clone the connection manager. Used by `main.rs` (when it needs
    /// to keep a handle after `serve()` consumes the server) and by
    /// test code that drives the server directly. The manager is
    /// `Clone` (Arc-counted internals), so this is cheap.
    #[allow(dead_code)]
    pub fn connection(&self) -> ConnectionManager {
        self.connection.clone()
    }

    /// Forward a method to the daemon via the connection manager.
    /// Returns `ConnectionError`, which preserves the structured
    /// disconnection states (`DaemonUnavailable` / `DaemonDown`) so
    /// the tool layer can emit JSON-RPC `-32098` / `-32097` codes.
    ///
    /// The pre-resilience inline retry-on-disconnect loop has moved
    /// into the manager (`crates/rts-mcp/src/connection.rs`); calls
    /// here are one-shot. Concurrent tool calls during a known
    /// disconnect window all see the same structured error without
    /// queueing on the daemon mutex (no thundering-herd).
    async fn call_daemon(&self, method: &str, params: Value) -> Result<Value, ConnectionError> {
        self.connection.call(method, params).await
    }

    #[tool(
        description = "PageRank-sorted structural map of this workspace: file tree, top symbols per file, signatures only, token-budgeted. Prefer this over `Bash(ls -R)` / `tree` / `find . -name '*.rs'` when you need orientation in an unfamiliar repo — shell tools dump raw paths; this returns importance-ranked symbols with signatures in one round trip. Use when the task includes 'orient', 'overview', 'where do I start', 'what's in this repo', or you're about to pick which files to read next. Do not use when you already know the symbol name (call `find_symbol`) or the file (call `read_symbol`/`read_range`). Output shape: `{outline_text, files_considered, truncated}` — the text is grouped by file with each symbol's kind + signature inline."
    )]
    async fn outline_workspace(
        &self,
        Parameters(args): Parameters<OutlineArgs>,
    ) -> Result<CallToolResult, McpError> {
        let mut params = serde_json::Map::new();
        if let Some(g) = args.glob {
            params.insert("glob".into(), Value::String(g));
        }
        if let Some(b) = args.token_budget {
            params.insert("token_budget".into(), Value::Number(b.into()));
        }
        match self
            .call_daemon("Index.Outline", Value::Object(params))
            .await
        {
            Ok(v) => Ok(success_json(&v)),
            Err(e) => Ok(connection_error_to_call_result(&e)),
        }
    }

    #[tool(
        description = "Locate symbol definitions (function, class, type, method, trait, etc.) by exact `name` or glob `pattern` (`*`, `?`). Prefer this over `Bash(grep '^fn name')` / `Bash(rg)` for ANY code-identifier search — shell grep matches comments, strings, doc-blocks, and variable references; this returns only AST-confirmed definitions with kind, path, byte range, PageRank score, and (opt-in) rendered signature. Use when the task includes 'find', 'where is X defined', 'locate', or you have a partial name like `make_*` / `*_target`. Pair with `doc_contains: \"retry\"` for behavior-shaped queries that grep can't express. The returned metadata typically saves a follow-up `read_symbol`."
    )]
    async fn find_symbol(
        &self,
        Parameters(args): Parameters<FindSymbolArgs>,
    ) -> Result<CallToolResult, McpError> {
        let mut params = serde_json::Map::new();
        if let Some(n) = args.name {
            params.insert("name".into(), Value::String(n));
        }
        if let Some(p) = args.pattern {
            params.insert("pattern".into(), Value::String(p));
        }
        if let Some(k) = args.kind {
            params.insert("kind".into(), Value::String(k));
        }
        if let Some(f) = args.file {
            params.insert("file".into(), Value::String(f));
        }
        if let Some(p) = args.parent {
            params.insert("parent".into(), Value::String(p));
        }
        if let Some(n) = args.limit {
            params.insert("limit".into(), Value::Number(n.into()));
        }
        if let Some(s) = args.doc_contains {
            params.insert("doc_contains".into(), Value::String(s));
        }
        if let Some(b) = args.include_signature {
            params.insert("include_signature".into(), Value::Bool(b));
        }
        match self
            .call_daemon("Index.FindSymbol", Value::Object(params))
            .await
        {
            Ok(v) => Ok(success_json(&v)),
            Err(e) => Ok(connection_error_to_call_result(&e)),
        }
    }

    #[tool(
        description = "Direct callers of a named symbol — every call site that invokes this function/method, AST-precise. Prefer this over `Bash(grep 'name(')` / `Bash(rg 'name\\(')` for caller searches — shell grep matches local variables, doc comments, and string literals; this walks the indexed reference graph (one redb lookup, no parsing) and returns only real call edges with the enclosing function's `qualified_name` + `kind`. Use when the task includes 'who calls', 'callers of', 'is this dead code', or you're scoping a refactor at depth-1. For transitive callers use `impact_of`; for symbol-plus-callers in one round trip use `read_symbol --include-callers`."
    )]
    async fn find_callers(
        &self,
        Parameters(args): Parameters<FindCallersArgs>,
    ) -> Result<CallToolResult, McpError> {
        let mut params = serde_json::Map::new();
        params.insert("name".into(), Value::String(args.name));
        if let Some(k) = args.kind {
            params.insert("kind".into(), Value::String(k));
        }
        if let Some(f) = args.file {
            params.insert("file".into(), Value::String(f));
        }
        match self
            .call_daemon("Index.FindCallers", Value::Object(params))
            .await
        {
            Ok(v) => Ok(success_json(&v)),
            Err(e) => Ok(connection_error_to_call_result(&e)),
        }
    }

    #[tool(
        description = "Check whether a symbol (function, type, method, …) actually exists in this workspace, AST-precise. Prefer this over `Bash(grep 'fn name')` / `Bash(rg name)` before you call or import a symbol you're unsure about — shell grep matches comments, strings, and unrelated text and can't tell you you've invented a name; this returns `exists` + `resolution` (exact | not_found | indeterminate) and, on a miss, a ranked `candidates[]` did-you-mean shortlist so you self-correct. Use when the task includes 'does X exist', 'is there a function called X', 'verify', or you're about to reference a symbol from memory. Disambiguate overloaded names with `file` or `kind` (multiple defs → `indeterminate`). A miss is a result, not an error."
    )]
    async fn verify_symbol(
        &self,
        Parameters(args): Parameters<VerifySymbolArgs>,
    ) -> Result<CallToolResult, McpError> {
        let mut params = serde_json::Map::new();
        params.insert("name".into(), Value::String(args.name));
        if let Some(k) = args.kind {
            params.insert("kind".into(), Value::String(k));
        }
        if let Some(l) = args.lang {
            params.insert("lang".into(), Value::String(l));
        }
        if let Some(f) = args.file {
            params.insert("file".into(), Value::String(f));
        }
        if let Some(cv) = args.content_version {
            params.insert("content_version".into(), Value::String(cv));
        }
        match self
            .call_daemon("Index.VerifySymbol", Value::Object(params))
            .await
        {
            Ok(v) => Ok(success_json(&v)),
            Err(e) => Ok(connection_error_to_call_result(&e)),
        }
    }

    #[tool(
        description = "Check whether a call matches a function/method's actual definition, AST-precise. Prefer this over `Bash(grep 'fn name')` or eyeballing a `read_symbol` body before you write a call: it resolves the indexed def, reads its real arity/params/returns, and returns `match` plus a structured `diff[]` (issue kinds: arity, unknown_param, param_order, return_shape) so you fix the exact mismatch. Use when the task includes 'does this call match', 'right arguments', 'verify signature', or you're about to call a function from memory. `indeterminate` (with `reason`, `match` omitted) when the language is unsupported or the params are variadic; `not_found` + ranked `candidates[]` when the symbol doesn't exist."
    )]
    async fn verify_signature(
        &self,
        Parameters(args): Parameters<VerifySignatureArgs>,
    ) -> Result<CallToolResult, McpError> {
        let mut params = serde_json::Map::new();
        params.insert("name".into(), Value::String(args.name));
        if let Some(k) = args.kind {
            params.insert("kind".into(), Value::String(k));
        }
        if let Some(l) = args.lang {
            params.insert("lang".into(), Value::String(l));
        }
        if let Some(f) = args.file {
            params.insert("file".into(), Value::String(f));
        }
        let mut claimed = serde_json::Map::new();
        claimed.insert("arity".into(), Value::Number(args.claimed.arity.into()));
        claimed.insert(
            "params".into(),
            Value::Array(args.claimed.params.into_iter().map(Value::String).collect()),
        );
        if let Some(r) = args.claimed.returns {
            claimed.insert("returns".into(), Value::String(r));
        }
        params.insert("claimed".into(), Value::Object(claimed));
        match self
            .call_daemon("Index.VerifySignature", Value::Object(params))
            .await
        {
            Ok(v) => Ok(success_json(&v)),
            Err(e) => Ok(connection_error_to_call_result(&e)),
        }
    }

    #[tool(
        description = "Check whether the final segment of an import/use path actually resolves to an indexed symbol, AST-precise. Prefer this over `Bash(rg 'CommitOptions')` before you add a `use crate::store::CommitOptions;` line: shell grep matches comments and strings and can't tell you you've invented a name. Returns `resolves` + `resolution` (exact | not_found | indeterminate) and, on a miss, a ranked `candidates[]` did-you-mean shortlist. Use when the task includes 'does this import exist', 'is X importable', 'verify import', or you're about to import a path from memory. THIN in v0: only the final path segment is resolved; an undecidable multi-segment path returns `indeterminate` rather than a confident false negative."
    )]
    async fn verify_import(
        &self,
        Parameters(args): Parameters<VerifyImportArgs>,
    ) -> Result<CallToolResult, McpError> {
        let mut params = serde_json::Map::new();
        params.insert("path".into(), Value::String(args.path));
        if let Some(l) = args.lang {
            params.insert("lang".into(), Value::String(l));
        }
        match self
            .call_daemon("Index.VerifyImport", Value::Object(params))
            .await
        {
            Ok(v) => Ok(success_json(&v)),
            Err(e) => Ok(connection_error_to_call_result(&e)),
        }
    }

    #[tool(
        description = "Batch-verify a list of claims (symbol exists / signature matches / import resolves / symbol is at file:line) in one call, AST-precise. Prefer this over a manual sequence of `Bash(grep)` checks when you want to ground-truth several facts you wrote from memory at once — e.g. before submitting a patch or summarizing a codebase. Each claim is `{type: symbol|signature|import|location, …}`; returns per-claim `results[]` plus a `grounding_rate` summary. Use when the task includes 'verify these', 'fact-check', 'are these correct', or you produced several symbol/signature/import claims to validate. Indeterminate claims are excluded from the grounding-rate denominator (no false negatives); the rate is null when nothing was decidable."
    )]
    async fn verify_claims(
        &self,
        Parameters(args): Parameters<VerifyClaimsArgs>,
    ) -> Result<CallToolResult, McpError> {
        let mut params = serde_json::Map::new();
        params.insert("claims".into(), Value::Array(args.claims));
        match self
            .call_daemon("Index.VerifyClaims", Value::Object(params))
            .await
        {
            Ok(v) => Ok(success_json(&v)),
            Err(e) => Ok(connection_error_to_call_result(&e)),
        }
    }

    #[tool(
        description = "Transitive caller closure — the full refactor blast radius of a symbol. BFS over the indexed reverse-reference graph; returns every function that directly or indirectly calls `name`, bounded by depth (default 2, max 4), `max_nodes` (default 200), and a 50ms wall-clock cap. Use this instead of a manual BFS over `Bash(grep)` results when the task includes 'impact of', 'blast radius', 'what breaks if I change', or you're about to rename a public function. Test-path filter is on by default — pass `exclude_test_paths: false` to include tests. Entries carry `depth` and `rank_score` (sort: depth asc, rank_score desc); four independent truncation flags say *why* a result is partial. For depth-1 only, prefer `find_callers` (cheaper)."
    )]
    async fn impact_of(
        &self,
        Parameters(args): Parameters<ImpactOfArgs>,
    ) -> Result<CallToolResult, McpError> {
        let mut params = serde_json::Map::new();
        params.insert("name".into(), Value::String(args.name));
        if let Some(d) = args.depth {
            params.insert("depth".into(), Value::Number(d.into()));
        }
        if let Some(b) = args.token_budget {
            params.insert("token_budget".into(), Value::Number(b.into()));
        }
        if let Some(m) = args.max_nodes {
            params.insert("max_nodes".into(), Value::Number(m.into()));
        }
        if let Some(e) = args.exclude_test_paths {
            params.insert("exclude_test_paths".into(), Value::Bool(e));
        }
        match self
            .call_daemon("Index.ImpactOf", Value::Object(params))
            .await
        {
            Ok(v) => Ok(success_json(&v)),
            Err(e) => Ok(connection_error_to_call_result(&e)),
        }
    }

    #[tool(
        description = "Gate an edit before you make it: declare a change to a symbol (`signature`, `remove`, `rename`) and get the blast radius as a pass/fail `verdict` (would_break | safe). Prefer this over a manual `impact_of` plus eyeballing, or `Bash(grep 'name(')`, before you rename or change a function's arity: it resolves the def, walks the reverse-reference graph for direct callers, and for `signature` compares the new arity to the real one (pass `new_signature`). Use when the task says 'is it safe to change' or 'will this break callers'. `would_break` lists `affected_callers[]` with a per-caller `reason`; `safe` means no *arity* break only — a same-arity param-type change isn't detected, so still skim the callers; `not_found` returns ranked `candidates[]`."
    )]
    async fn verify_impact(
        &self,
        Parameters(args): Parameters<VerifyImpactArgs>,
    ) -> Result<CallToolResult, McpError> {
        let mut params = serde_json::Map::new();
        params.insert("symbol".into(), Value::String(args.symbol));
        params.insert("change".into(), Value::String(args.change));
        if let Some(s) = args.new_signature {
            params.insert("new_signature".into(), Value::String(s));
        }
        if let Some(d) = args.depth {
            params.insert("depth".into(), Value::Number(d.into()));
        }
        match self
            .call_daemon("Index.VerifyImpact", Value::Object(params))
            .await
        {
            Ok(v) => Ok(success_json(&v)),
            Err(e) => Ok(connection_error_to_call_result(&e)),
        }
    }

    #[tool(
        description = "Gate a PROPOSED multi-file edit before you write it: pass the full post-edit `content` of each patched file and get a pass/warn/fail `verdict` with structured `findings`. The flagship check — prefer this over eyeballing a diff or a manual `find_callers` sweep after a refactor: it re-parses each file, diffs the defs, and queries the live index for callers of any def you remove or whose arity you change (callers inside your own patch are excluded, so a callee+caller edited together stays clean). Use when the task is 'is this patch safe' or right before a cross-file rename/signature change. `fail` lists `broken_caller` / `signature_break` sites; `dangling_ref` (warning) and `new_symbol` (info) round it out; `files_skipped` bumps a clean pass to warn."
    )]
    async fn verify_edit(
        &self,
        Parameters(args): Parameters<VerifyEditArgs>,
    ) -> Result<CallToolResult, McpError> {
        let mut params = serde_json::Map::new();
        let edits: Vec<Value> = args
            .edits
            .into_iter()
            .map(|e| {
                let mut m = serde_json::Map::new();
                m.insert("file".into(), Value::String(e.file));
                m.insert("content".into(), Value::String(e.content));
                Value::Object(m)
            })
            .collect();
        params.insert("edits".into(), Value::Array(edits));
        if let Some(checks) = args.checks {
            params.insert(
                "checks".into(),
                Value::Array(checks.into_iter().map(Value::String).collect()),
            );
        }
        match self
            .call_daemon("Index.VerifyEdit", Value::Object(params))
            .await
        {
            Ok(v) => Ok(success_json(&v)),
            Err(e) => Ok(connection_error_to_call_result(&e)),
        }
    }

    #[tool(
        description = "Read the source of the symbol enclosing a given `file:line` location. Prefer this over `Bash(cat file)` / `Read(file)` + manual scrolling when the task includes a compiler-error location, a stack-trace frame, a diff hunk pointer, or any `path:LINE` reference — shell reads pull the whole file; this returns only the innermost enclosing definition (precise byte range) with optional `include_dependencies` closure-walking and `include_callers` neighborhood. Use when input looks like `error[E0308] --> src/lib.rs:42:18`, a panic backtrace, or `git blame` output. Same wire shape as `read_symbol`. Faster than: read file, scroll, identify enclosing function, then `read_symbol`."
    )]
    async fn read_symbol_at(
        &self,
        Parameters(args): Parameters<ReadSymbolAtArgs>,
    ) -> Result<CallToolResult, McpError> {
        let mut params = serde_json::Map::new();
        params.insert("file".into(), Value::String(args.file));
        params.insert("line".into(), Value::Number(args.line.into()));
        if let Some(c) = args.column {
            params.insert("column".into(), Value::Number(c.into()));
        }
        if let Some(s) = args.shape {
            params.insert("shape".into(), Value::String(s));
        }
        if let Some(b) = args.token_budget {
            params.insert("token_budget".into(), Value::Number(b.into()));
        }
        if args.include_dependencies {
            params.insert("include_dependencies".into(), Value::Bool(true));
        }
        if args.include_callers {
            params.insert("include_callers".into(), Value::Bool(true));
        }
        match self
            .call_daemon("Index.ReadSymbolAt", Value::Object(params))
            .await
        {
            Ok(v) => Ok(success_json(&v)),
            Err(e) => Ok(connection_error_to_call_result(&e)),
        }
    }

    #[tool(
        description = "Read the source of a named symbol by exact `name`. Prefer this over `Bash(cat file)` / `Read(file)` when you know the symbol name — shell reads pull entire files (often 1000+ lines for a 20-line function); this returns just the symbol at its precise byte range, with content-version invalidation so you never get stale bytes after an edit. Use when the task includes 'show me X', 'read function X', 'what does X do', 'show the body of X'. `shape=signature` returns the declaration only (cheap); `shape=body` (default) returns the full implementation; `include_dependencies=true` adds the tree-shaken closure of types/imports the symbol references; `include_callers=true` adds direct callers in one round trip (saves a `find_callers` call). Disambiguate overloaded names with `file` or `kind`."
    )]
    async fn read_symbol(
        &self,
        Parameters(args): Parameters<ReadSymbolArgs>,
    ) -> Result<CallToolResult, McpError> {
        let mut params = serde_json::Map::new();
        params.insert("name".into(), Value::String(args.name));
        if let Some(f) = args.file {
            params.insert("file".into(), Value::String(f));
        }
        if let Some(k) = args.kind {
            params.insert("kind".into(), Value::String(k));
        }
        if let Some(p) = args.parent {
            params.insert("parent".into(), Value::String(p));
        }
        if let Some(s) = args.shape {
            params.insert("shape".into(), Value::String(s));
        }
        if let Some(b) = args.token_budget {
            params.insert("token_budget".into(), Value::Number(b.into()));
        }
        if args.include_dependencies {
            params.insert("include_dependencies".into(), Value::Bool(true));
        }
        if args.include_callers {
            params.insert("include_callers".into(), Value::Bool(true));
        }
        if args.force_resend {
            params.insert("force_resend".into(), Value::Bool(true));
        }
        match self
            .call_daemon("Index.ReadSymbol", Value::Object(params))
            .await
        {
            Ok(v) => Ok(success_json(&v)),
            Err(e) => Ok(connection_error_to_call_result(&e)),
        }
    }

    #[tool(
        description = "Read an explicit `[start_line, end_line]` range from an indexed file. Prefer this over `Bash(cat file)` / `Bash(sed -n 'A,Bp')` / `Read(file)` when you already have an exact line range and only need that slice — shell reads pull the whole file; this returns just the requested bytes against the daemon's content-versioned snapshot (no stale reads after edits). Use when the task includes a diff hunk, a stack-trace frame range, a CI log line span, or a `LINE_NO` annotation from another tool. For symbol-by-name access use `read_symbol`; for symbol-at-location use `read_symbol_at`."
    )]
    async fn read_range(
        &self,
        Parameters(args): Parameters<ReadRangeArgs>,
    ) -> Result<CallToolResult, McpError> {
        let mut params = serde_json::Map::new();
        params.insert("file".into(), Value::String(args.file));
        params.insert("start_line".into(), Value::Number(args.start_line.into()));
        params.insert("end_line".into(), Value::Number(args.end_line.into()));
        if let Some(b) = args.token_budget {
            params.insert("token_budget".into(), Value::Number(b.into()));
        }
        match self
            .call_daemon("Index.ReadRange", Value::Object(params))
            .await
        {
            Ok(v) => Ok(success_json(&v)),
            Err(e) => Ok(connection_error_to_call_result(&e)),
        }
    }

    #[tool(
        description = "AST-aware ranked search across indexed file bytes. Prefer this over `Bash(grep)` / `Bash(rg)` for ANY workspace search — shell grep returns raw `path:line:text` with no enclosing-symbol context, scans `target/` and vendored deps, and has no language structure; this tool annotates each hit with the enclosing symbol's name + kind (metadata you'd otherwise need a second call to recover), scopes to the indexed file set, and rejects regex bombs with a structured error. Use when the task includes 'find', 'search for', 'grep for', 'find all TODOs'. Default: case-insensitive literal. Opt-in: `regex`, `multiline`, `file_glob`, `language`. v0.6: `structural_query` (tree-sitter S-expressions), `within_symbol` (scope to one function's body). Modes compose (AND)."
    )]
    async fn grep(
        &self,
        Parameters(args): Parameters<GrepArgs>,
    ) -> Result<CallToolResult, McpError> {
        let mut params = serde_json::Map::new();
        // `text` is optional in v0.6 (`structural_query` may be the
        // sole search source). Pass it through only when present so
        // the daemon's validator sees the same shape the caller
        // emitted.
        if let Some(t) = args.text {
            params.insert("text".into(), Value::String(t));
        }
        if let Some(n) = args.limit {
            params.insert("limit".into(), Value::Number(n.into()));
        }
        if let Some(b) = args.case_insensitive {
            params.insert("case_insensitive".into(), Value::Bool(b));
        }
        if let Some(b) = args.regex {
            params.insert("regex".into(), Value::Bool(b));
        }
        if let Some(g) = args.file_glob {
            params.insert("file_glob".into(), Value::String(g));
        }
        // v0.6 additive fields. Forward only when set so the wire
        // shape stays minimal on v1-shape calls.
        if let Some(b) = args.multiline {
            params.insert("multiline".into(), Value::Bool(b));
        }
        if let Some(q) = args.structural_query {
            params.insert("structural_query".into(), Value::String(q));
        }
        if let Some(s) = args.within_symbol {
            params.insert("within_symbol".into(), Value::String(s));
        }
        if let Some(b) = args.within_symbol_allow_overload {
            params.insert("within_symbol_allow_overload".into(), Value::Bool(b));
        }
        if let Some(langs) = args.language {
            params.insert(
                "language".into(),
                Value::Array(langs.into_iter().map(Value::String).collect()),
            );
        }
        match self.call_daemon("Index.Grep", Value::Object(params)).await {
            Ok(v) => Ok(success_json(&v)),
            Err(e) => Ok(connection_error_to_call_result(&e)),
        }
    }

    #[tool(
        description = "Daemon session telemetry — per-method call counts for this daemon process. Useful for honest dogfood reflection (\"am I actually using the rts surface, or reaching for grep/Read?\"). Returns total_calls, uptime_ms, daemon version, and a per-method breakdown (find_symbol, grep, find_callers, impact_of, read_symbol, …). Counters reset on daemon restart — they describe this process's served traffic. Capability: `daemon_stats` (v0.5.7+)."
    )]
    async fn daemon_stats(
        &self,
        Parameters(_): Parameters<EmptyArgs>,
    ) -> Result<CallToolResult, McpError> {
        match self
            .call_daemon("Daemon.Stats", Value::Object(serde_json::Map::new()))
            .await
        {
            Ok(v) => Ok(success_json(&v)),
            Err(e) => Ok(connection_error_to_call_result(&e)),
        }
    }

    #[tool(
        description = "Daemon-side counter and latency snapshot for telemetry analysis. Use INSTEAD OF `daemon_stats` when you need per-method latency percentiles (p50/p99), cache-hit-rate aggregation, or error-code frequencies — `daemon_stats` returns raw counters but no derived metrics. Use when the task includes 'how fast is X', 'is the cache effective', 'what error codes appear most', 'workspace size'. Returns ~12 collector fields in a single round-trip; computing equivalents from `daemon_stats` requires the caller to maintain its own histogram state across snapshots. Counters are the same population that opt-in telemetry pings would send (see `rts telemetry preview`). No paths, no symbol names, no content."
    )]
    async fn daemon_telemetry(
        &self,
        Parameters(_): Parameters<EmptyArgs>,
    ) -> Result<CallToolResult, McpError> {
        match self
            .call_daemon("Daemon.Telemetry", Value::Object(serde_json::Map::new()))
            .await
        {
            Ok(v) => Ok(success_json(&v)),
            Err(e) => Ok(connection_error_to_call_result(&e)),
        }
    }
}

#[tool_handler]
impl ServerHandler for RtsServer {
    fn get_info(&self) -> ServerInfo {
        let mut info = ServerInfo::new(ServerCapabilities::builder().enable_tools().build());
        info.server_info.name = "rts-mcp".into();
        info.server_info.version = env!("CARGO_PKG_VERSION").into();
        info.instructions = Some(self.instructions.clone());
        info
    }
}

/// Format a daemon JSON result as MCP text content. Agents parse JSON out of
/// the text body — `structuredContent` is a v2025-06-18 feature we'll opt
/// into in v1.1.
fn success_json(value: &Value) -> CallToolResult {
    let text = serde_json::to_string(value).unwrap_or_else(|e| format!("{{\"error\":\"{e}\"}}"));
    CallToolResult::success(vec![Content::text(text)])
}

/// Map a connection-or-daemon-side error to a `CallToolResult::error`.
/// The agent gets a structured payload `{ code, message, data }` so it
/// can act on:
///
/// - `DAEMON_UNAVAILABLE` (transient; retry in `retry_after_ms`)
/// - `DAEMON_DOWN` (sustained outage; surface to user)
/// - `INDEX_NOT_READY` (poll), `SYMBOL_NOT_FOUND` (rephrase),
///   `OUT_OF_ROOT` (drop the path), etc.
///
/// without parsing English text.
///
/// Per protocol-v0 §7.6, `find_symbol` empty results are a *success*
/// path with `matches: []`, not an error — so this function only fires
/// for real protocol or transport errors.
fn connection_error_to_call_result(e: &ConnectionError) -> CallToolResult {
    let body = json!({
        "error": {
            "code":    e.code(),
            "message": e.message(),
            "data":    e.data(),
        }
    });
    let text = serde_json::to_string(&body).unwrap_or_else(|_| e.to_string());
    CallToolResult::error(vec![Content::text(text)])
}
