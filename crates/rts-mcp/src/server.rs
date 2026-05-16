//! `RtsServer` — the rmcp 1.6 `ServerHandler` that fronts `rts-daemon`.
//!
//! Surfaces four MCP tools (`outline_workspace`, `find_symbol`,
//! `read_symbol`, `read_range`) plus the `rts://capabilities` resource.
//! Each tool call translates to one `Index.*` request on the persistent
//! Unix-socket connection held by the server.

use std::sync::Arc;

use rmcp::{
    ErrorData as McpError, ServerHandler,
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{CallToolResult, Content, ServerCapabilities, ServerInfo},
    tool, tool_handler, tool_router,
};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::sync::Mutex;

use crate::daemon_client::{DaemonClient, DaemonError};

// Built-in tool descriptions are pinned inline (the `#[tool(description = ...)]`
// macro expects a literal string and does not accept const-path expressions).
// Source: plan §"Tool descriptions (LLM-facing, pinned in P5)".

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
    /// `const`, `static`, `impl`, `method`, `class`, `interface`, `module`.
    #[serde(default)]
    pub kind: Option<String>,
    /// Optional `file` filter (workspace-relative path) to disambiguate
    /// when the same name lives in multiple files.
    #[serde(default)]
    pub file: Option<String>,
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

#[derive(Clone)]
pub struct RtsServer {
    // The `#[tool_router]` macro generates dispatch through `tool_router`;
    // rustc can't see through the macro for the dead-code analysis.
    #[allow(dead_code)]
    tool_router: ToolRouter<Self>,
    daemon: Arc<Mutex<DaemonClient>>,
    /// v0.4: workspace path needed for lazy `Workspace.Mount`.
    /// rts-mcp used to call Mount immediately at startup; with the
    /// daemon's prewarm-on-spawn (PR #51), deferring Mount until
    /// the first agent tool call lets the daemon's background walk
    /// overlap with the seconds-to-minutes between session start and
    /// the user's first code question. By the time Mount fires, the
    /// daemon's prewarm has already populated the index — Mount hits
    /// the idempotent path and returns immediately.
    workspace: std::path::PathBuf,
    /// Whether `Workspace.Mount` has been called for this session.
    /// `AtomicBool` so the (cheap) fast-path in `call_daemon` is a
    /// single relaxed load. Synchronization for the slow-path
    /// (do-the-mount) happens through the daemon `Mutex` we already
    /// hold there — no double-mount race possible.
    ///
    /// Wrapped in `Arc` because `RtsServer: Clone` (rmcp requirement)
    /// and `AtomicBool` itself is not `Clone`.
    mounted: Arc<std::sync::atomic::AtomicBool>,
    instructions: String,
}

#[tool_router]
impl RtsServer {
    pub fn new(daemon: DaemonClient, workspace: std::path::PathBuf, instructions: String) -> Self {
        Self {
            tool_router: Self::tool_router(),
            daemon: Arc::new(Mutex::new(daemon)),
            workspace,
            mounted: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            instructions,
        }
    }

    /// Forward a method to the daemon. On the FIRST call (or after
    /// a prior `Workspace.Mount` failure), this also issues
    /// `Workspace.Mount` so subsequent tool calls have a workspace
    /// to read from.
    ///
    /// The `daemon` mutex serializes — concurrent tool calls don't
    /// race on the mount; the first one in does the mount, the
    /// others wait on the mutex and see `mounted == true` by the
    /// time they get the lock.
    async fn call_daemon(&self, method: &str, params: Value) -> Result<Value, DaemonError> {
        let mut guard = self.daemon.lock().await;
        if !self.mounted.load(std::sync::atomic::Ordering::Acquire) {
            let mount_resp = guard
                .call(
                    "Workspace.Mount",
                    serde_json::json!({ "root": self.workspace }),
                )
                .await?;
            let workspace_id = mount_resp["workspace_id"].as_str().unwrap_or("<unknown>");
            tracing::info!(
                target: "rts_mcp",
                "lazy-mounted workspace {} as id={} on first tool call",
                self.workspace.display(),
                workspace_id,
            );
            self.mounted
                .store(true, std::sync::atomic::Ordering::Release);
        }
        guard.call(method, params).await
    }

    #[tool(
        description = "Return a token-budgeted structural map of this workspace — file tree, top symbols per file, signatures only. Use first when you need orientation in an unfamiliar repo or when picking which files to read next. Do not use for finding a specific known symbol — call `find_symbol` instead. Do not use for reading a file you already know — call `read_symbol` or `read_range`."
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
            Err(e) => Ok(daemon_error_to_call_result(&e)),
        }
    }

    #[tool(
        description = "Locate symbols (function, class, type, method, etc.) across the workspace. Either `name` (exact) or `pattern` (glob: `*` and `?`) is required. Use `name` when you know it; use `pattern` (e.g. `make_*`, `*_target`, `read_*_at`) when you only know roughly what it's called. Returns a list of `matches` with definition location, signature, and `rank_score`. Prefer this over shell `rg` for any symbol-shaped query — it's AST-precise (no comment/string false positives) and returns structured byte ranges."
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
            Err(e) => Ok(daemon_error_to_call_result(&e)),
        }
    }

    #[tool(
        description = "Find direct callers of a symbol — where else in the workspace does code call into this function/method? Cheap (one redb lookup; no parsing). Use for: refactor impact preview at depth-1, 'is this function dead?', 'who depends on this API?'. Returns `callers[]` with each call site's file/range plus the enclosing function's `qualified_name` and `kind`. \n\nWhen to use which: this tool returns callers ONLY (no body). Use `read_symbol --include-callers` when you also need the symbol's own body. Use `impact_of` for *transitive* callers (whole blast radius). Avoid shell `rg` for caller queries — it has high false-positive noise from local variables, comments, and string mentions; this is AST-precise via the indexed reference graph."
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
            Err(e) => Ok(daemon_error_to_call_result(&e)),
        }
    }

    #[tool(
        description = "Transitive caller closure — the full refactor blast radius of a symbol. BFS over the reverse reference graph; returns every function that directly or indirectly calls the named symbol, bounded by depth (default 2, max 4), token budget, node count (default 200), and a 50ms wall-clock cap. Each entry carries its BFS `depth` and `rank_score` so agents can prioritize the most-central callers. Results sort by (depth ascending, rank_score descending). \n\nWhen to use which: `find_callers` is depth-1 (direct callers only) — cheaper and more focused. `impact_of` is depth-N with bounds — use when you're about to refactor a public function and want to know everything that touches it. Test-path filter (`/tests/`, `_test.rs`, `.spec.ts`) is on by default; pass `exclude_test_paths: false` to include test callers (e.g. when deciding which tests to update). \n\nTruncation: four independent flags (`closure_truncated`, `wall_clock_truncated`, `depth_truncated`, `node_count_truncated`) tell you *why* a result is partial. Hub symbols often hit `node_count_truncated` first; raise `max_nodes` if you can tolerate the noise."
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
            Err(e) => Ok(daemon_error_to_call_result(&e)),
        }
    }

    #[tool(
        description = "Read the source of the symbol containing a given line in a file. Use this when you have a location (file + line) but not the name — e.g. from a compiler error like `error[E0308] --> src/lib.rs:42:18`. Returns the innermost enclosing definition with the same wire shape as `read_symbol`, including optional `include_dependencies` closure walking. Faster than: read the file, scroll to the line, identify the enclosing function, then `read_symbol`."
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
            Err(e) => Ok(daemon_error_to_call_result(&e)),
        }
    }

    #[tool(
        description = "Read the source of a named symbol. `shape=signature` returns just the declaration (cheap). `shape=body` returns the full implementation. `include_dependencies=true` adds the minimum surrounding types/imports the symbol references — use when you'll want to call/modify it without reading more. `include_callers=true` adds the direct callers in one round trip — use when you want symbol-plus-neighborhood (alternative to a second `find_callers` call). Prefer this over reading whole files."
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
            Err(e) => Ok(daemon_error_to_call_result(&e)),
        }
    }

    #[tool(
        description = "Read explicit line range [start_line, end_line] from a file. Use for stack-trace frames, diff hunks, and other cases where you already have an exact location. For symbol-by-name access, use `read_symbol` instead."
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
            Err(e) => Ok(daemon_error_to_call_result(&e)),
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

/// Map a daemon-side `error` envelope to a `CallToolResult::error`. The
/// agent gets a structured payload `{ code, message, data }` so it can act
/// on `INDEX_NOT_READY` (poll later), `SYMBOL_NOT_FOUND` (rephrase), or
/// `OUT_OF_ROOT` (drop the path) without parsing English text.
///
/// Note: per protocol-v0 §7.6, `find_symbol` empty results are a *success*
/// path with `matches: []`, not an error — so this function only fires for
/// real protocol errors.
fn daemon_error_to_call_result(e: &DaemonError) -> CallToolResult {
    let body = json!({
        "error": {
            "code":    e.code,
            "message": e.message,
            "data":    e.data.clone().unwrap_or(Value::Null),
        }
    });
    let text = serde_json::to_string(&body).unwrap_or_else(|_| e.to_string());
    CallToolResult::error(vec![Content::text(text)])
}
