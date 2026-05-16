//! MCP retrieval runner: subprocess `rts-mcp` + JSON-RPC over stdio.
//!
//! Mirrors `crates/rts-mcp/tests/mcp_round_trip.rs` so the bench harness
//! talks to the real binary the agent would launch — no in-process
//! shortcuts. Captures `tokens_returned` from each `Content::text` body so
//! the bench report has a like-for-like number to compare against the
//! baseline.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow};
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};

/// Result of a single MCP `tools/call`. Wire-stable so the bench report can
/// decode this verbatim into `mcp.*`.
#[derive(Debug, Clone)]
#[allow(dead_code)] // fields are read in report JSON via direct field access in future slices
pub struct McpCall {
    /// `tokens_returned` from the daemon's response when present
    /// (`read_symbol`/`read_range`); otherwise the `bytes / 3`
    /// approximation over the raw response text.
    pub tokens: u64,
    /// Number of `Content` items in the response.
    pub content_items: usize,
    /// Raw response text — kept short here because reports tend to
    /// archive these and 10 KB JSON bodies bloat the run output fast.
    pub response_text_len: usize,
    /// Wall-clock duration of this single call, in milliseconds.
    pub elapsed_ms: u128,
    /// `result.isError` from the response, if present.
    pub is_error: bool,
    /// Parsed JSON body of the first `Content::text` item, when it
    /// decoded as a JSON object. Consumers (e.g. the footprint bench
    /// polling `outline_workspace.files_considered`) reach into this
    /// directly. `None` for non-JSON bodies or empty responses.
    pub result_body: Option<Value>,
}

/// Result of an MCP retrieval session — n tool calls plus the workspace
/// mount handshake.
#[derive(Debug, Clone, Default)]
pub struct McpRun {
    pub tokens: u64,
    pub calls: Vec<McpCall>,
    pub elapsed_ms: u128,
}

pub struct McpSession {
    child: Child,
    stdin: ChildStdin,
    reader: BufReader<ChildStdout>,
    next_id: u64,
}

impl McpSession {
    /// Spawn `rts-mcp --workspace <workspace>` with the test/bench
    /// `RTS_DAEMON_BIN` pointing at a known daemon binary, perform the
    /// MCP initialize handshake, and return a session ready for
    /// `tools/call`.
    pub async fn spawn(
        rts_mcp_bin: &Path,
        rts_daemon_bin: &Path,
        workspace: &Path,
        extra_env: &[(&str, &str)],
    ) -> Result<Self> {
        let mut cmd = Command::new(rts_mcp_bin);
        cmd.arg("--workspace")
            .arg(workspace)
            .env("RTS_LOG", "warn")
            .env("RTS_DAEMON_BIN", rts_daemon_bin)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            // RTS_BENCH_INHERIT_STDERR=1 surfaces daemon + mcp logs
            // for debugging. Default to null so normal bench runs
            // aren't noisy.
            .stderr(
                if std::env::var("RTS_BENCH_INHERIT_STDERR")
                    .map(|v| !v.is_empty() && v != "0")
                    .unwrap_or(false)
                {
                    Stdio::inherit()
                } else {
                    Stdio::null()
                },
            )
            .kill_on_drop(true);
        for (k, v) in extra_env {
            cmd.env(k, v);
        }
        let mut child = cmd.spawn().with_context(|| {
            format!(
                "spawn {} --workspace {}",
                rts_mcp_bin.display(),
                workspace.display()
            )
        })?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| anyhow!("rts-mcp stdin closed"))?;
        let reader = BufReader::new(
            child
                .stdout
                .take()
                .ok_or_else(|| anyhow!("rts-mcp stdout closed"))?,
        );

        let mut session = Self {
            child,
            stdin,
            reader,
            next_id: 1,
        };
        session.handshake().await?;
        Ok(session)
    }

    async fn handshake(&mut self) -> Result<()> {
        let init = json!({
            "jsonrpc": "2.0",
            "id": self.alloc_id(),
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": { "name": "rts-bench", "version": env!("CARGO_PKG_VERSION") }
            }
        });
        self.send(&init).await?;
        let _ = self.recv().await?;
        let initialized = json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
            "params": {}
        });
        self.send(&initialized).await?;
        Ok(())
    }

    fn alloc_id(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }

    async fn send(&mut self, msg: &Value) -> Result<()> {
        let mut bytes = serde_json::to_vec(msg)?;
        bytes.push(b'\n');
        self.stdin.write_all(&bytes).await?;
        self.stdin.flush().await?;
        Ok(())
    }

    /// Per-call timeout for `recv()`. Defaults to 30s — large enough
    /// to cover cold-mount of a ~100k-LOC workspace (the daemon's
    /// first walk before the writer settles). Overridable via
    /// `RTS_MCP_RECV_TIMEOUT_SECS` for pathologically-large workspaces.
    fn recv_timeout(&self) -> Duration {
        const DEFAULT_SECS: u64 = 30;
        let secs = std::env::var("RTS_MCP_RECV_TIMEOUT_SECS")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .filter(|n| *n >= 1 && *n <= 600)
            .unwrap_or(DEFAULT_SECS);
        Duration::from_secs(secs)
    }

    async fn recv(&mut self) -> Result<Value> {
        let mut buf = Vec::new();
        let timeout = self.recv_timeout();
        let n = tokio::time::timeout(timeout, self.reader.read_until(b'\n', &mut buf))
            .await
            .map_err(|_| {
                anyhow!(
                    "no MCP response after {}s — daemon may still be indexing the workspace \
                     (first mount of ~100k LOC takes 5-30s). \
                     Set RTS_MCP_RECV_TIMEOUT_SECS=60 for very large workspaces; \
                     run with RTS_BENCH_INHERIT_STDERR=1 to see daemon-side progress.",
                    timeout.as_secs()
                )
            })??;
        if n == 0 {
            return Err(anyhow!("rts-mcp closed stdout"));
        }
        serde_json::from_slice(&buf).context("decode MCP response")
    }

    /// One `tools/call`. Polls up to `max_retries` times when the response is
    /// `isError` with a `INDEX_NOT_READY` body — the writer is asynchronous,
    /// and the first call against a fresh workspace can land before the
    /// initial walk commits.
    pub async fn tools_call(
        &mut self,
        name: &str,
        arguments: Value,
        max_retries: u32,
    ) -> Result<McpCall> {
        let mut last_err: Option<McpCall> = None;
        let start = Instant::now();
        for _ in 0..=max_retries {
            let id = self.alloc_id();
            let req = json!({
                "jsonrpc": "2.0",
                "id": id,
                "method": "tools/call",
                "params": { "name": name, "arguments": arguments.clone() }
            });
            self.send(&req).await?;
            let resp = self.recv().await?;
            let call = parse_tools_call_response(&resp, start.elapsed().as_millis());
            if call.is_error && response_has_code(&resp, "INDEX_NOT_READY") {
                last_err = Some(call);
                tokio::time::sleep(Duration::from_millis(120)).await;
                continue;
            }
            return Ok(call);
        }
        Ok(last_err.unwrap_or(McpCall {
            tokens: 0,
            content_items: 0,
            response_text_len: 0,
            elapsed_ms: start.elapsed().as_millis(),
            is_error: true,
            result_body: None,
        }))
    }

    /// Clean shutdown: drop stdin so `rts-mcp` exits, then reap the child.
    pub async fn close(mut self) -> Result<()> {
        drop(self.stdin);
        let _ = tokio::time::timeout(Duration::from_secs(5), self.child.wait()).await;
        Ok(())
    }

    /// PID of the spawned `rts-mcp` child. Returns `None` if the child
    /// already exited. The footprint bench uses this to walk down to
    /// the `rts-daemon` grandchild via `pgrep -P`.
    pub fn child_pid(&self) -> Option<u32> {
        self.child.id()
    }
}

fn response_has_code(resp: &Value, code: &str) -> bool {
    let body = match resp["result"]["content"][0]["text"].as_str() {
        Some(s) => s,
        None => return false,
    };
    match serde_json::from_str::<Value>(body) {
        Ok(v) => v["error"]["code"] == code,
        Err(_) => false,
    }
}

fn parse_tools_call_response(resp: &Value, elapsed_ms: u128) -> McpCall {
    let is_error = resp["result"]["isError"].as_bool().unwrap_or(false);
    let content = resp["result"]["content"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let mut tokens: u64 = 0;
    let mut response_text_len: usize = 0;
    let mut result_body: Option<Value> = None;
    for (i, item) in content.iter().enumerate() {
        if let Some(text) = item["text"].as_str() {
            response_text_len += text.len();
            // Prefer the daemon's reported `tokens_returned` when present.
            if let Ok(parsed) = serde_json::from_str::<Value>(text) {
                if i == 0 && parsed.is_object() {
                    result_body = Some(parsed.clone());
                }
                if let Some(t) = parsed["tokens_returned"].as_u64() {
                    tokens += t;
                    continue;
                }
            }
            tokens += crate::token::approx_tokens(text.len());
        }
    }
    McpCall {
        tokens,
        content_items: content.len(),
        response_text_len,
        elapsed_ms,
        is_error,
        result_body,
    }
}

/// Resolve the `rts-mcp` and `rts-daemon` binaries built by `cargo build`.
/// Defaults to `target/debug/{rts-mcp,rts-daemon}` relative to the
/// workspace root.
pub fn resolve_bin(name: &str) -> Result<PathBuf> {
    let env_key = format!("{}_BIN", name.replace('-', "_").to_ascii_uppercase());
    if let Ok(v) = std::env::var(&env_key) {
        if !v.is_empty() {
            return Ok(PathBuf::from(v));
        }
    }
    let cwd = std::env::current_dir().context("$PWD")?;
    let candidate = cwd.join("target").join("debug").join(name);
    if candidate.is_file() {
        return Ok(candidate);
    }
    Err(anyhow!(
        "could not find {name} binary; build with `cargo build --bin {name}` or set {env_key}"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parse_response_uses_daemon_tokens_when_present() {
        let resp = json!({
            "result": {
                "isError": false,
                "content": [{
                    "type": "text",
                    "text": "{\"tokens_returned\": 320, \"file\": \"src/lib.rs\"}"
                }]
            }
        });
        let c = parse_tools_call_response(&resp, 1);
        assert_eq!(c.tokens, 320);
        assert_eq!(c.content_items, 1);
        assert!(!c.is_error);
    }

    #[test]
    fn parse_response_falls_back_to_approx_tokens() {
        let resp = json!({
            "result": {
                "isError": false,
                "content": [{ "type": "text", "text": "abc" }]
            }
        });
        let c = parse_tools_call_response(&resp, 1);
        assert_eq!(c.tokens, 1); // div_ceil(3, 3) = 1
    }

    #[test]
    fn parse_response_flags_errors() {
        let resp = json!({
            "result": {
                "isError": true,
                "content": [{
                    "type": "text",
                    "text": "{\"error\":{\"code\":\"INDEX_NOT_READY\"}}"
                }]
            }
        });
        let c = parse_tools_call_response(&resp, 1);
        assert!(c.is_error);
        assert!(response_has_code(&resp, "INDEX_NOT_READY"));
    }
}
