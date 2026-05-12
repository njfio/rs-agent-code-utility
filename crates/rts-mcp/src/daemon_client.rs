//! Thin newline-delimited JSON client for the `rts-daemon` Unix-socket
//! wire-protocol described in `docs/protocol-v0.md` §3.
//!
//! The MCP server holds a single long-lived `DaemonClient` per stdio
//! conversation. The client is `&mut self` for `call(...)` — a single MCP
//! tool call maps to a single request/response on the socket, and stdio MCP
//! is sequential per connection, so we don't need fan-out concurrency here.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};

/// Per protocol-v0 §3.3 — the daemon hangs up on frames larger than this.
pub const MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;
/// Per-call timeout. Matches the daemon's 30 s soft deadline (§10) plus a
/// modest grace so a tripped deadline surfaces as a protocol error
/// (`DEADLINE_EXCEEDED`) rather than a client-side I/O timeout.
const CALL_TIMEOUT: Duration = Duration::from_secs(35);

pub struct DaemonClient {
    writer: OwnedWriteHalf,
    reader: BufReader<OwnedReadHalf>,
    /// Monotonic request id. Stringified on the wire — protocol-v0 §3.4
    /// requires string ids.
    next_id: AtomicU64,
}

impl DaemonClient {
    pub fn new(stream: UnixStream) -> Self {
        let (rd, wr) = stream.into_split();
        Self {
            writer: wr,
            reader: BufReader::new(rd),
            next_id: AtomicU64::new(1),
        }
    }

    fn alloc_id(&self) -> String {
        self.next_id.fetch_add(1, Ordering::Relaxed).to_string()
    }

    /// Send one request, await one response.
    ///
    /// Returns the JSON `result` body on success. On a wire-level
    /// `error` envelope, returns `Err(DaemonError { code, message, data })`
    /// so the caller can map daemon error codes to `CallToolResult::error`.
    pub async fn call(&mut self, method: &str, params: Value) -> Result<Value, DaemonError> {
        let id = self.alloc_id();
        let req = json!({ "id": id, "method": method, "params": params });
        let mut bytes = serde_json::to_vec(&req)
            .map_err(|e| DaemonError::transport(format!("encode request: {e}")))?;
        if bytes.len() + 1 > MAX_FRAME_BYTES {
            return Err(DaemonError::transport(format!(
                "request frame {} > {MAX_FRAME_BYTES} byte cap",
                bytes.len()
            )));
        }
        bytes.push(b'\n');

        let fut = async {
            self.writer
                .write_all(&bytes)
                .await
                .map_err(|e| DaemonError::transport(format!("write: {e}")))?;
            self.writer
                .flush()
                .await
                .map_err(|e| DaemonError::transport(format!("flush: {e}")))?;
            let mut buf = Vec::new();
            let n = self
                .reader
                .read_until(b'\n', &mut buf)
                .await
                .map_err(|e| DaemonError::transport(format!("read: {e}")))?;
            if n == 0 {
                return Err(DaemonError::transport("daemon closed connection"));
            }
            if buf.len() > MAX_FRAME_BYTES {
                return Err(DaemonError::transport(format!(
                    "response frame {} > {MAX_FRAME_BYTES} byte cap",
                    buf.len()
                )));
            }
            let resp: Value = serde_json::from_slice(&buf)
                .map_err(|e| DaemonError::transport(format!("decode response: {e}")))?;
            Ok(resp)
        };

        let resp = tokio::time::timeout(CALL_TIMEOUT, fut)
            .await
            .map_err(|_| DaemonError::transport(format!("timed out after {CALL_TIMEOUT:?}")))??;

        if resp.get("error").map(|v| !v.is_null()).unwrap_or(false) {
            let err = &resp["error"];
            return Err(DaemonError {
                code: err["code"].as_str().unwrap_or("INTERNAL_ERROR").to_string(),
                message: err["message"]
                    .as_str()
                    .unwrap_or("daemon returned error without message")
                    .to_string(),
                data: err.get("data").cloned(),
            });
        }
        Ok(resp.get("result").cloned().unwrap_or(Value::Null))
    }
}

/// A structured daemon error. `code` is the stable wire string from
/// protocol-v0 §14 (e.g. `"INDEX_NOT_READY"`, `"OUT_OF_ROOT"`).
#[derive(Debug, Clone)]
pub struct DaemonError {
    pub code: String,
    pub message: String,
    pub data: Option<Value>,
}

impl DaemonError {
    fn transport(message: impl Into<String>) -> Self {
        Self {
            code: "INTERNAL_ERROR".to_string(),
            message: message.into(),
            data: None,
        }
    }
}

impl std::fmt::Display for DaemonError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}] {}", self.code, self.message)
    }
}

impl std::error::Error for DaemonError {}

impl From<anyhow::Error> for DaemonError {
    fn from(e: anyhow::Error) -> Self {
        DaemonError::transport(format!("{e:#}"))
    }
}
