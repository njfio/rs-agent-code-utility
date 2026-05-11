//! Minimal rmcp 1.6 MCP server with a single `echo` tool.
//!
//! Validates the macro-driven tool authoring pattern, the stdio transport,
//! and `ProtocolVersion::V_2024_11_05`. Stdout is JSON-RPC only; logs go to stderr.

use anyhow::Result;
use rmcp::{
    ErrorData as McpError, ServerHandler,
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{CallToolResult, Content, ServerCapabilities, ServerInfo},
    service::ServiceExt,
    tool, tool_handler, tool_router,
};
use schemars::JsonSchema;
use serde::Deserialize;

#[derive(Debug, Deserialize, JsonSchema)]
pub struct EchoArgs {
    /// The text to echo back to the caller.
    pub text: String,
}

#[derive(Clone)]
pub struct HelloServer {
    tool_router: ToolRouter<Self>,
}

#[tool_router]
impl HelloServer {
    pub fn new() -> Self {
        Self {
            tool_router: Self::tool_router(),
        }
    }

    #[tool(
        description = "Echo the input text back to the caller. Used to validate the MCP round-trip end-to-end."
    )]
    async fn echo(
        &self,
        Parameters(args): Parameters<EchoArgs>,
    ) -> Result<CallToolResult, McpError> {
        Ok(CallToolResult::success(vec![Content::text(args.text)]))
    }
}

#[tool_handler]
impl ServerHandler for HelloServer {
    fn get_info(&self) -> ServerInfo {
        let mut info = ServerInfo::new(ServerCapabilities::builder().enable_tools().build());
        info.server_info.name = "rmcp-hello-spike".into();
        info.server_info.version = env!("CARGO_PKG_VERSION").into();
        info.instructions = Some("Spike: echo tool for MCP round-trip validation".into());
        info
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    tracing::info!("rmcp_hello_server starting (pid={})", std::process::id());
    let server = HelloServer::new();
    let service = server.serve(rmcp::transport::stdio()).await?;
    service.waiting().await?;
    tracing::info!("rmcp_hello_server shut down");
    Ok(())
}
