//! Thin newline-delimited JSON client for the `rts-daemon` Unix-socket
//! wire-protocol described in `docs/protocol-v0.md` §3.
//!
//! The MCP server holds a single long-lived `DaemonClient` per stdio
//! conversation. The client is `&mut self` for `call(...)` — a single MCP
//! tool call maps to a single request/response on the socket, and stdio MCP
//! is sequential per connection, so we don't need fan-out concurrency here.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};

/// Per protocol-v0 §3.3 — the daemon hangs up on frames larger than this.
pub const MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;
/// Per-call timeout. Matches rts-mcp's default stamped request deadline
/// (`RTS_DEADLINE_MS`, 30 s) plus a modest grace so a tripped deadline
/// surfaces as a protocol error (`DEADLINE_EXCEEDED`) rather than a
/// client-side I/O timeout. (A custom `RTS_DEADLINE_MS` above this
/// window would surface as an I/O timeout instead — acceptable for the
/// default; revisit if the per-call timeout needs to track the env value.)
const CALL_TIMEOUT: Duration = Duration::from_secs(35);

pub struct DaemonClient {
    writer: OwnedWriteHalf,
    reader: BufReader<OwnedReadHalf>,
    /// Monotonic request id. Stringified on the wire — protocol-v0 §3.4
    /// requires string ids.
    next_id: AtomicU64,
    /// v0.5.5+ reconnect state. When the daemon dies (crash, SIGTERM,
    /// upgrade), the next `call()` returns a transport error. The upper
    /// layer (`RtsServer::call_daemon`) inspects via
    /// [`DaemonError::is_disconnect`] and calls
    /// [`DaemonClient::reconnect`] to re-establish via auto-spawn —
    /// without this state the client couldn't re-resolve the daemon
    /// binary or pass the right `--workspace` to the new process.
    daemon_bin: PathBuf,
    /// Canonical workspace path. Threaded into `connect_with_auto_spawn`
    /// so the respawned daemon's per-workspace socket path matches the
    /// original (per `socket_path_for_workspace` from v0.5.4).
    workspace: PathBuf,
    /// Default deadline (ms) stamped on non-Mount requests. From
    /// `RTS_DEADLINE_MS` at construction: unset → Some(30_000); "0" →
    /// None (disabled); else parsed. See `stamped_deadline`.
    default_deadline_ms: Option<u64>,
}

/// The deadline rts-mcp stamps on a daemon request: the configured
/// default for every method EXCEPT `Workspace.Mount` (a cold-walk on a
/// big repo can legitimately run for minutes). `None` default = never
/// stamp. An explicit per-request deadline is not modeled here — the
/// CLI/other clients set `deadline_ms` directly on the wire.
fn stamped_deadline(default_ms: Option<u64>, method: &str) -> Option<u64> {
    match default_ms {
        Some(ms) if method != "Workspace.Mount" => Some(ms),
        _ => None,
    }
}

/// Parse the `RTS_DEADLINE_MS` value: `None` (unset) → Some(30_000)
/// default; "0" → None (disabled); a valid u64 → Some(v) clamped to the
/// daemon's accepted range; unparseable → Some(30_000) (fail safe to the
/// default rather than panicking).
///
/// The clamp matters: the daemon rejects an envelope `deadline_ms` above
/// its `MAX_DEADLINE_MS` (600_000) with `INVALID_PARAMS` *before* running
/// the handler. Without clamping, a user setting `RTS_DEADLINE_MS` above
/// that would have rts-mcp stamp an invalid deadline on every non-Mount
/// request, bricking all Index/Daemon queries until the env var is fixed.
/// We clamp to the max so "allow longer queries" degrades to "the longest
/// the daemon allows" instead of failing every call.
fn parse_deadline_env(raw: Option<&str>) -> Option<u64> {
    const DEFAULT_DEADLINE_MS: u64 = 30_000;
    /// Mirror of the daemon's `MAX_DEADLINE_MS` (protocol-v0 §3.4).
    const DAEMON_MAX_DEADLINE_MS: u64 = 600_000;
    match raw {
        None => Some(DEFAULT_DEADLINE_MS),
        Some(s) => match s.trim().parse::<u64>() {
            Ok(0) => None,
            Ok(v) => Some(v.min(DAEMON_MAX_DEADLINE_MS)),
            Err(_) => Some(DEFAULT_DEADLINE_MS),
        },
    }
}

/// Read `RTS_DEADLINE_MS` from the environment via `parse_deadline_env`.
fn default_deadline_from_env() -> Option<u64> {
    parse_deadline_env(std::env::var("RTS_DEADLINE_MS").ok().as_deref())
}

impl DaemonClient {
    pub fn new(stream: UnixStream, daemon_bin: PathBuf, workspace: PathBuf) -> Self {
        let (rd, wr) = stream.into_split();
        Self {
            writer: wr,
            reader: BufReader::new(rd),
            next_id: AtomicU64::new(1),
            daemon_bin,
            workspace,
            default_deadline_ms: default_deadline_from_env(),
        }
    }

    /// Re-establish the socket connection by re-running the auto-spawn
    /// flow. Used by the upper layer when a previous `call()` returned
    /// a disconnect-shaped transport error.
    ///
    /// Idempotent: if the daemon is still alive on the per-workspace
    /// socket, this just reconnects to it. If the daemon is gone,
    /// auto-spawn brings up a fresh one.
    ///
    /// **Caller responsibilities** (`RtsServer::call_daemon`):
    /// 1. Clear the `Workspace.Mount` sentinel — a fresh daemon needs
    ///    Mount before serving Index queries.
    /// 2. Retry the original call **once**. Repeated retries on
    ///    repeated disconnects indicate a deeper problem (daemon won't
    ///    stay up, binary path wrong, etc.) and should surface the
    ///    error rather than loop.
    pub async fn reconnect(&mut self) -> Result<(), DaemonError> {
        let stream =
            crate::socket::connect_with_auto_spawn(&self.daemon_bin, Some(&self.workspace))
                .await
                .map_err(|e| DaemonError::transport(format!("reconnect via auto-spawn: {e:#}")))?;
        let (rd, wr) = stream.into_split();
        self.writer = wr;
        self.reader = BufReader::new(rd);
        // Don't reset `next_id`: monotonic across reconnects is fine
        // (protocol-v0 §3.4 only requires uniqueness within a session,
        // and the daemon has fresh state anyway after a respawn).
        Ok(())
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
        let mut req = json!({ "id": id, "method": method, "params": params });
        if let Some(ms) = stamped_deadline(self.default_deadline_ms, method) {
            req["deadline_ms"] = json!(ms);
        }
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

    /// True iff the error indicates the socket connection is dead and
    /// a fresh daemon needs to be auto-spawned. The upper layer
    /// (`RtsServer::call_daemon`) checks this to decide whether to
    /// reconnect-and-retry.
    ///
    /// Recognised transport-layer signatures (must be `code ==
    /// "INTERNAL_ERROR"` AND the message contains one of):
    /// - `"Broken pipe"` — write failed because peer closed
    /// - `"Connection reset"` — peer aborted
    /// - `"daemon closed connection"` — read returned `n == 0`
    /// - `"connection refused"` — socket file gone before we wrote
    /// - `"unexpected end of file"` / `"EOF"` — partial read
    ///
    /// Anything else (including legitimate daemon-emitted errors like
    /// `INDEX_NOT_READY` or `OUT_OF_ROOT`) returns `false` — we don't
    /// want to reconnect on a working daemon's expected error path.
    pub fn is_disconnect(&self) -> bool {
        if self.code != "INTERNAL_ERROR" {
            return false;
        }
        let msg_lower = self.message.to_lowercase();
        msg_lower.contains("broken pipe")
            || msg_lower.contains("connection reset")
            || msg_lower.contains("daemon closed connection")
            || msg_lower.contains("connection refused")
            || msg_lower.contains("unexpected end of file")
            || msg_lower.contains("eof")
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stamps_default_on_queries_exempts_mount() {
        assert_eq!(stamped_deadline(Some(30_000), "Index.Grep"), Some(30_000));
        assert_eq!(
            stamped_deadline(Some(30_000), "Index.FindSymbol"),
            Some(30_000)
        );
        // Mount cold-walk can legitimately exceed any default → exempt.
        assert_eq!(stamped_deadline(Some(30_000), "Workspace.Mount"), None);
        // No configured default → never stamp.
        assert_eq!(stamped_deadline(None, "Index.Grep"), None);
    }

    #[test]
    fn parse_deadline_env_handles_unset_zero_value_garbage() {
        assert_eq!(parse_deadline_env(None), Some(30_000));
        assert_eq!(parse_deadline_env(Some("0")), None);
        assert_eq!(parse_deadline_env(Some("5000")), Some(5_000));
        assert_eq!(parse_deadline_env(Some("garbage")), Some(30_000));
        // Above the daemon max → clamped to 600_000 (not stamped invalid,
        // which the daemon would reject with INVALID_PARAMS on every call).
        assert_eq!(parse_deadline_env(Some("900000")), Some(600_000));
        assert_eq!(parse_deadline_env(Some("600000")), Some(600_000));
    }
}
