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
    /// The symbol name to find — exact match only. For partial / fuzzy
    /// search, fall back to the shell `rg` tool.
    pub name: String,
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
    /// v1.1 session-dedup override. Accepted but inert in v0.
    #[serde(default)]
    pub force_resend: bool,
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
        description = "Locate a named symbol (function, class, type, method, etc.) across the workspace. Returns a list of `matches` with definition location, signature, and `rank_score`. Use when you know the name. For partial / fuzzy / textual matches, this v1 server has no search — fall back to your shell `rg` tool."
    )]
    async fn find_symbol(
        &self,
        Parameters(args): Parameters<FindSymbolArgs>,
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
            .call_daemon("Index.FindSymbol", Value::Object(params))
            .await
        {
            Ok(v) => Ok(success_json(&v)),
            Err(e) => Ok(daemon_error_to_call_result(&e)),
        }
    }

    #[tool(
        description = "Read the source of a named symbol. `shape=signature` returns just the declaration (cheap). `shape=body` returns the full implementation. `include_dependencies=true` adds the minimum surrounding types/imports the symbol references — use when you'll want to call/modify it without reading more. Prefer this over reading whole files."
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
