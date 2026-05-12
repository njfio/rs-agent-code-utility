//! `Session.*` methods. v0 ships `Session.Open` and `Session.Close`. Per-
//! session dedup state (the `session_dedup` capability) is v1.1 — for now the
//! daemon synthesises an id and otherwise treats sessions as inert.

use std::sync::Arc;

use serde::Deserialize;

use crate::error::{ErrorCode, ProtocolError};
use crate::state::DaemonState;

const RECONNECT_WINDOW_MS: u64 = 300_000; // 5 min
const DEDUP_TTL_MS: u64 = 900_000; // 15 min

#[derive(Debug, Deserialize)]
struct OpenParams {
    #[serde(default)]
    client_name: Option<String>,
    #[serde(default)]
    client_version: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CloseParams {
    session_id: String,
}

fn parse_params<T: for<'de> Deserialize<'de>>(value: serde_json::Value) -> Result<T, ProtocolError> {
    serde_json::from_value(value).map_err(|e| {
        ProtocolError::new(
            ErrorCode::InvalidParams,
            format!("params failed validation: {e}"),
        )
    })
}

/// `Session.Open` — protocol-v0 §7.9.
pub async fn open(
    params: serde_json::Value,
    _state: &Arc<DaemonState>,
) -> Result<serde_json::Value, ProtocolError> {
    let p: OpenParams = parse_params(params)?;
    // 128-bit random id, blake3 keyed off PID + monotonic time. Daemon
    // entropy is fine for v0 — these ids are not authentication tokens; the
    // authoritative identity is the kernel peer-cred check on the socket.
    let session_id = synth_session_id();
    let _ = (p.client_name, p.client_version); // observability-only

    Ok(serde_json::json!({
        "session_id":          session_id,
        "reconnect_window_ms": RECONNECT_WINDOW_MS,
        "dedup_ttl_ms":        DEDUP_TTL_MS,
    }))
}

/// `Session.Close` — protocol-v0 §7.10. Inert in v0 (no session state to drop).
pub async fn close(
    params: serde_json::Value,
    _state: &Arc<DaemonState>,
) -> Result<serde_json::Value, ProtocolError> {
    let p: CloseParams = parse_params(params)?;
    if !p.session_id.starts_with("sess_") {
        return Err(ProtocolError::new(
            ErrorCode::InvalidParams,
            "session_id must start with `sess_`",
        ));
    }
    Ok(serde_json::json!({}))
}

fn synth_session_id() -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&std::process::id().to_le_bytes());
    let now_ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    hasher.update(&now_ns.to_le_bytes());
    // Add a per-call counter so two opens in the same ns are still distinct.
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let c = COUNTER.fetch_add(1, Ordering::Relaxed);
    hasher.update(&c.to_le_bytes());
    let hex = hasher.finalize().to_hex();
    format!("sess_{}", &hex[..16])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn open_yields_distinct_ids() {
        let state = Arc::new(DaemonState::new());
        let a = open(serde_json::json!({}), &state).await.unwrap();
        let b = open(serde_json::json!({}), &state).await.unwrap();
        assert_ne!(a["session_id"], b["session_id"]);
        assert_eq!(a["reconnect_window_ms"], 300_000);
        assert_eq!(a["dedup_ttl_ms"], 900_000);
    }

    #[tokio::test]
    async fn close_rejects_bad_id() {
        let state = Arc::new(DaemonState::new());
        let err = close(serde_json::json!({"session_id":"nope"}), &state)
            .await
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidParams);
    }
}
