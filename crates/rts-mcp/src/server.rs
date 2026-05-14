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
    instructions: String,
}

#[tool_router]
impl RtsServer {
    pub fn new(daemon: DaemonClient, instructions: String) -> Self {
        Self {
            tool_router: Self::tool_router(),
            daemon: Arc::new(Mutex::new(daemon)),
            instructions,
        }
    }

    async fn call_daemon(&self, method: &str, params: Value) -> Result<Value, DaemonError> {
        let mut guard = self.daemon.lock().await;
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
        match self
            .call_daemon("Index.FindSymbol", Value::Object(params))
            .await
        {
            Ok(v) => Ok(success_json(&v)),
            Err(e) => Ok(daemon_error_to_call_result(&e)),
        }
    }

    #[tool(
        description = "Find direct callers of a symbol — where else in the workspace does code call into this function/method? Cheap (one redb lookup; no parsing). Use for: refactor impact preview at depth-1, 'is this function dead?', 'who depends on this API?'. Returns `callers[]` with each call site's file/range plus the enclosing function's `qualified_name` and `kind`. \n\nWhen to use which: this tool returns callers ONLY (no body). Use `read_symbol --include-callers` when you also need the symbol's own body. Use `impact_of` (when v0.3 U5 ships) for *transitive* callers (whole blast radius). Avoid shell `rg` for caller queries — it has high false-positive noise from local variables, comments, and string mentions; this is AST-precise via the indexed reference graph."
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
