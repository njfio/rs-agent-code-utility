//! Wire protocol: parse/serialize the envelopes from `docs/protocol-v0.md` §3.
//!
//! All v0 messages are newline-delimited JSON. Each message is one JSON object
//! per line, terminated by `\n` (an optional trailing `\r` is tolerated).
//! Maximum message size 16 MiB (§3.3).

use serde::{Deserialize, Serialize};

use crate::error::{ErrorCode, ProtocolError};

/// Maximum single-message size on the wire (16 MiB).
pub const MAX_MESSAGE_BYTES: usize = 16 * 1024 * 1024;

/// Incoming request envelope.
///
/// `id` is a stringified `u64` per protocol-v0 §3.4 (strings survive JS-style
/// number-precision in tooling). `params` MUST be a JSON object.
///
/// `cancel_id` is an optional client-supplied string used to address
/// this request from a subsequent `Daemon.Cancel { cancel_id }`. It
/// lives in the envelope (not `params`) so handlers don't have to
/// thread it through their own param shapes. Defaults to `None` so
/// existing clients work unchanged.
#[derive(Debug, Deserialize)]
pub struct Request {
    pub id: String,
    pub method: String,
    #[serde(default = "empty_object")]
    pub params: serde_json::Value,
    #[serde(default)]
    pub cancel_id: Option<String>,
    /// Optional per-request deadline in milliseconds (protocol-v0 §3.4,
    /// capability `request_deadlines`). When set and the request runs
    /// longer, the daemon trips the request's `CancelToken` and returns
    /// `DEADLINE_EXCEEDED`. Range-validated in `methods::dispatch`.
    /// Absent (`None`) = no deadline; existing clients are unaffected.
    #[serde(default)]
    pub deadline_ms: Option<u64>,
}

fn empty_object() -> serde_json::Value {
    serde_json::Value::Object(serde_json::Map::new())
}

/// Outgoing response envelope.
///
/// Exactly one of `result` / `error` MUST be present. `partial` is set on
/// best-effort answers during indexing; `content_version` is set on slice
/// responses (added by per-method handlers, not the envelope).
#[derive(Debug, Serialize)]
pub struct Response {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<serde_json::Value>,
}

impl Response {
    pub fn ok(id: String, result: serde_json::Value) -> Self {
        Self {
            id,
            result: Some(result),
            error: None,
        }
    }

    pub fn err(id: String, err: &ProtocolError) -> Self {
        Self {
            id,
            result: None,
            error: Some(err.to_wire()),
        }
    }

    /// Serialize this response as a single newline-terminated UTF-8 line.
    pub fn into_line(self) -> serde_json::Result<Vec<u8>> {
        let mut bytes = serde_json::to_vec(&self)?;
        bytes.push(b'\n');
        Ok(bytes)
    }
}

/// Validate `method` against the v0 regex `^[A-Z][a-z]+\.[A-Z][A-Za-z]+$`.
pub fn is_valid_method_name(method: &str) -> bool {
    let mut parts = method.splitn(2, '.');
    let ns = match parts.next() {
        Some(s) => s,
        None => return false,
    };
    let verb = match parts.next() {
        Some(s) => s,
        None => return false,
    };
    if parts.next().is_some() {
        return false;
    }
    is_namespace_part(ns) && is_verb_part(verb)
}

fn is_namespace_part(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_ascii_uppercase() => {}
        _ => return false,
    }
    if !chars.clone().all(|c| c.is_ascii_lowercase()) {
        return false;
    }
    chars.count() >= 1
}

fn is_verb_part(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_ascii_uppercase() => {}
        _ => return false,
    }
    if !chars.clone().all(|c| c.is_ascii_alphabetic()) {
        return false;
    }
    chars.count() >= 1
}

/// Parse a single line of bytes (without the trailing `\n`) into a `Request`.
/// Maps every failure to a v0 error code.
pub fn parse_request_line(line: &[u8]) -> Result<Request, ProtocolError> {
    if line.len() > MAX_MESSAGE_BYTES {
        return Err(ProtocolError::new(
            ErrorCode::MessageTooLarge,
            format!(
                "message size {} exceeds {} bytes",
                line.len(),
                MAX_MESSAGE_BYTES
            ),
        ));
    }
    if std::str::from_utf8(line).is_err() {
        return Err(ProtocolError::new(
            ErrorCode::InvalidFrame,
            "message is not valid UTF-8",
        ));
    }
    let req: Request = serde_json::from_slice(line)
        .map_err(|e| ProtocolError::new(ErrorCode::InvalidFrame, format!("malformed JSON: {e}")))?;
    if !is_valid_method_name(&req.method) {
        return Err(ProtocolError::new(
            ErrorCode::InvalidParams,
            format!("invalid method name: {:?}", req.method),
        ));
    }
    if !req.params.is_object() {
        return Err(ProtocolError::new(
            ErrorCode::InvalidParams,
            "params must be a JSON object",
        ));
    }
    if req.id.is_empty() {
        return Err(ProtocolError::new(
            ErrorCode::InvalidParams,
            "id must be non-empty",
        ));
    }
    Ok(req)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn method_name_grammar() {
        assert!(is_valid_method_name("Daemon.Ping"));
        assert!(is_valid_method_name("Workspace.Mount"));
        assert!(is_valid_method_name("Index.FindSymbol"));
        assert!(is_valid_method_name("Session.Open"));

        assert!(!is_valid_method_name("daemon.ping")); // lowercase ns
        assert!(!is_valid_method_name("Daemon.ping")); // lowercase verb start
        assert!(!is_valid_method_name("Daemon")); // no dot
        assert!(!is_valid_method_name("Daemon..Ping")); // extra dot
        assert!(!is_valid_method_name("Daemon.Ping.X")); // three parts
        assert!(!is_valid_method_name("DAEMON.Ping")); // uppercase ns body
    }

    #[test]
    fn parse_minimal_request() {
        let req = parse_request_line(br#"{"id":"1","method":"Daemon.Ping","params":{}}"#).unwrap();
        assert_eq!(req.id, "1");
        assert_eq!(req.method, "Daemon.Ping");
        assert!(req.params.is_object());
    }

    #[test]
    fn parse_request_with_default_params() {
        let req = parse_request_line(br#"{"id":"7","method":"Daemon.Ping"}"#).unwrap();
        assert!(req.params.is_object());
        assert_eq!(req.params.as_object().unwrap().len(), 0);
    }

    #[test]
    fn parse_request_with_deadline_ms() {
        let req = parse_request_line(
            br#"{"id":"1","method":"Index.Grep","params":{},"deadline_ms":5000}"#,
        )
        .unwrap();
        assert_eq!(req.deadline_ms, Some(5000));
    }

    #[test]
    fn parse_request_without_deadline_ms_defaults_none() {
        let req = parse_request_line(br#"{"id":"1","method":"Daemon.Ping","params":{}}"#).unwrap();
        assert_eq!(req.deadline_ms, None);
    }

    #[test]
    fn parse_rejects_non_utf8() {
        let err = parse_request_line(&[0xff, 0xfe]).unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidFrame);
    }

    #[test]
    fn parse_rejects_bad_json() {
        let err = parse_request_line(br#"{"id":"1","method":"#).unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidFrame);
    }

    #[test]
    fn parse_rejects_array_params() {
        let err =
            parse_request_line(br#"{"id":"1","method":"Daemon.Ping","params":[]}"#).unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidParams);
    }

    #[test]
    fn parse_rejects_empty_id() {
        let err =
            parse_request_line(br#"{"id":"","method":"Daemon.Ping","params":{}}"#).unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidParams);
    }

    #[test]
    fn parse_rejects_bad_method() {
        let err = parse_request_line(br#"{"id":"1","method":"badName","params":{}}"#).unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidParams);
    }

    #[test]
    fn response_line_round_trips() {
        let resp = Response::ok("42".into(), serde_json::json!({"hi": true}));
        let line = resp.into_line().unwrap();
        assert!(line.ends_with(b"\n"));
        let s = std::str::from_utf8(&line).unwrap();
        let v: serde_json::Value = serde_json::from_str(s.trim_end()).unwrap();
        assert_eq!(v["id"], "42");
        assert_eq!(v["result"]["hi"], true);
        assert!(v.get("error").is_none() || v["error"].is_null());
    }
}
