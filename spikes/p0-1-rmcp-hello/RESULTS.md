# P0.1 — rmcp 1.6 hello-world MCP server results

**Date**: 2026-05-11
**Platform**: macOS arm64 (Darwin 25.4.0)
**Versions confirmed**: `rmcp 1.6.0`, `schemars 1.2.1`, `tokio 1.x`, `tracing 0.1`
**Toolchain**: rustc 1.90.0 (homebrew); edition 2024; rust-version 1.85.

## Verdict: GO — with corrections to the plan's claimed API surface

A minimal stdio MCP server with one `echo` tool builds and round-trips end-to-end. The macro-driven authoring pattern (`#[tool_router]` / `#[tool]` / `#[tool_handler]`) works. Schema auto-derivation from `schemars::JsonSchema` produces correct JSON Schema 2020-12 output.

**Several specifics from the deepening's framework-docs research agent are wrong** — corrected below. The plan needs updates in §Stack and §P5/P7.

## Round-trip test results (all PASS)

All 5 assertions in the test client met:

```
client: initialize response in 313.5 ms       ← one-time cold startup
client: tools/list response in 224 µs
client: tools/call response in 79.7 µs        ← steady-state tool latency
client: server shutdown in 625 µs

PASS: all assertions met
```

### What it verified

1. **`initialize`** round-trip: server responds with `protocolVersion: "2024-11-05"`, `capabilities.tools: {}`, populated `serverInfo.name`/`version`, and the `instructions` string.
2. **`tools/list`** round-trip: returns the `echo` tool with an `inputSchema` produced by `schemars` 2020-12 dialect — `text` field marked required, description carried from the doc-comment on `EchoArgs.text`.
3. **`tools/call` with `echo`** round-trip: echoes the input verbatim; `isError: false`.
4. **`tools/call` with missing required field**: server returns a JSON-RPC `-32602 "Invalid params"` error (NOT a `CallToolResult::error` with `isError: true`). Confirms the framework-docs agent's bifurcated error model — argument validation goes through `Err(McpError::invalid_params(...))` and surfaces as a protocol-level error, while tool-level "ran but failed" failures go through `CallToolResult::error(...)`.
5. **Server shutdown** is clean when stdin closes — 625 µs from EOF to process exit.

### Latency budget implications

The plan's S1 budget is **<10 ms p95 warm** end-to-end. The MCP layer alone (over stdio between two local processes) is:

- `tools/call` round-trip with a no-op tool: **~80 µs**

Combined with the P0.2 redb measurements (~1.5 µs warm point lookup), the daemon has ~9.9 ms of headroom for the actual retrieval work (closure walk, signature rendering, response serialization, plus the Unix-socket hop daemon ↔ MCP server). S1 looks comfortably achievable.

The 313 ms `initialize` latency is a one-time per-client-connect cost. Mostly Tokio runtime startup + schema derivation + stdio framing handshake. Plan should consider whether to bump up the "cold" S1 measurement window (currently `<100 ms`) to be more realistic — though in practice `initialize` only fires once per agent session.

## Plan corrections required

Three concrete fixes to the plan based on what rmcp 1.6.0 actually exposes vs. what the framework-docs research agent reported:

### 1. `schemars` version — `1`, NOT `0.8`

The plan's §Stack lists `schemars = "0.8"`. **rmcp 1.6 pulls `schemars 1.2.1` transitively, and the macro-generated derives use that version.** Pinning a direct `schemars = "0.8"` produces a duplicate-major-version build where my `derive(JsonSchema)` produces an impl of the wrong trait. Result:

```
error[E0277]: the trait bound `Parameters<EchoArgs>: JsonSchema` is not satisfied
  one version of crate `schemars` used here (0.8.22)
  required for `Parameters<EchoArgs>` to implement `rmcp::schemars::JsonSchema`
```

**Fix**: pin `schemars = "1"` in the plan (currently 1.2.1 latest). The framework-docs agent's claim that "rmcp 1.6 is still on 0.8" is wrong as of May 2026.

### 2. `Parameters` import path

Plan/framework-docs uses `rmcp::handler::server::tool::Parameters`. **Wrong** — that path is private. The compiler suggests the correct import:

```rust
use rmcp::handler::server::wrapper::Parameters;
```

This matches rmcp's own test suite (`tests/test_tool_macros.rs`). Fix in §P7 implementation notes.

### 3. `ServerInfo` construction is via a builder, not struct-literal

Both `ServerInfo` (= `InitializeResult` type alias) and `Implementation` are `#[non_exhaustive]`, so the framework-docs agent's pattern...

```rust
ServerInfo {
    protocol_version: ProtocolVersion::V_2024_11_05,
    capabilities: ...,
    server_info: Implementation { name: ..., version: ..., ..Default::default() },
    instructions: ...,
}
```

...does **not** compile. The canonical pattern (per rmcp's own tests):

```rust
fn get_info(&self) -> ServerInfo {
    let mut info = ServerInfo::new(ServerCapabilities::builder().enable_tools().build());
    info.server_info.name = "rmcp-hello-spike".into();
    info.server_info.version = env!("CARGO_PKG_VERSION").into();
    info.instructions = Some("...".into());
    info
}
```

`ServerInfo::new(capabilities)` constructs with default protocol version + `Implementation::from_build_env()` for the name/version (pulled from Cargo build env). Field mutation works because individual fields are `pub`; only struct-literal construction is blocked by `#[non_exhaustive]`. Fix in §P7 implementation notes.

## Cargo dependency manifest that worked

For reference, what actually built and passed all 5 round-trip assertions:

```toml
[package]
name = "p0-1-rmcp-hello"
version = "0.1.0"
edition = "2024"
rust-version = "1.85"

[dependencies]
rmcp = { version = "1", features = ["server", "macros", "transport-io", "schemars"] }
schemars = "1"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
tokio = { version = "1", features = ["macros", "rt-multi-thread", "io-std", "io-util", "process", "time", "net"] }
anyhow = "1"
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter", "fmt"] }
```

Plan should mirror this exactly. Notable: rmcp 1.6 requires the `schemars` feature flag for the `JsonSchema`-derived input schemas to wire through.

## Code patterns confirmed for P7

### Server struct must carry the ToolRouter

```rust
use rmcp::handler::server::router::tool::ToolRouter;

#[derive(Clone)]
pub struct HelloServer {
    tool_router: ToolRouter<Self>,
}

#[tool_router]
impl HelloServer {
    pub fn new() -> Self {
        Self { tool_router: Self::tool_router() }
    }
    // ... #[tool] methods ...
}
```

`Self::tool_router()` is a method synthesised by the `#[tool_router]` macro. The field MUST be named `tool_router` (default convention) unless you pass `router = <field>` to the macro.

### Tool method signature

```rust
#[tool(description = "...")]
async fn echo(&self, Parameters(args): Parameters<EchoArgs>) -> Result<CallToolResult, McpError> {
    Ok(CallToolResult::success(vec![Content::text(args.text)]))
}
```

The pattern-binding `Parameters(args): Parameters<EchoArgs>` destructures the wrapper inline. Return type can also be `String` (auto-wrapped) per rmcp's test suite, but `Result<CallToolResult, McpError>` is the explicit form.

### Stdio main

```rust
#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)  // critical: stderr only
        .with_ansi(false)
        .init();
    let service = HelloServer::new().serve(rmcp::transport::stdio()).await?;
    service.waiting().await?;
    Ok(())
}
```

`current_thread` flavor is correct for stdio (the JSON-RPC stream is inherently sequential). `with_ansi(false)` keeps Claude Code's stderr parser from choking on color codes.

## What's NOT verified by this spike (deferred)

- **Real MCP client compatibility** (Claude Code, Cursor) — the test client speaks raw JSON-RPC over stdio, which is what those clients also do, but exact protocol negotiation details may differ. P9 will smoke this end-to-end via `claude mcp add`.
- **Progress notifications** (`_meta.progressToken`) and `partial: true` responses — not exercised. Plan deferred this to P7; framework-docs agent's recommended pattern (use `peer().notify_progress(...)`) needs validation.
- **Resources** (`rts://capabilities`) — not exercised. Plan adds these in P7; needs separate verification.
- **`ProtocolVersion::V_2025_06_18`** — not tried; `V_2024_11_05` works and is broadly compatible.
- **Multiple tools on one server** — only one tool here. The macro pattern should compose, per rmcp's tests, but isn't measured for compilation cost or runtime overhead.
- **Concurrent requests** — stdio MCP is inherently sequential per connection; not exercised.

## Reproduction

```bash
cd spikes/p0-1-rmcp-hello
cargo build --release
RMCP_HELLO_SERVER_BIN=./target/release/rmcp_hello_server ./target/release/rmcp_hello_client
```

Expected output ends with `PASS: all assertions met`.
