//! Wire-protocol error codes (see `docs/protocol-v0.md` §14).
//!
//! Daemon-internal errors are kept separate from the wire-level `ErrorCode` so
//! we can decide one-by-one how to map them. The `ProtocolError` type carries
//! the wire code plus a human-readable message and optional structured data.

use serde::Serialize;

/// Every code defined in the v0 catalog. String-typed on the wire (not
/// numeric) for grep-ability. Some variants aren't yet emitted by this build
/// (`SymbolNotFound`, `AmbiguousSymbol`, etc.) but exist so future per-method
/// handlers can wire them in without churning the catalog.
#[allow(dead_code)] // see note above
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum ErrorCode {
    /// Connection-level: bad UTF-8 or non-JSON line.
    InvalidFrame,
    /// Single message exceeded the 16 MiB cap.
    MessageTooLarge,
    /// `params` failed schema validation.
    InvalidParams,
    /// Path passed in `Workspace.Mount` was non-UTF-8 / non-existent / non-canonicalisable.
    InvalidWorkspacePath,
    /// A component of the mounted path was a symlink (security: refuse-symlink rule).
    MountHasSymlink,
    /// `(dev, inode)` of the workspace path changed since the last mount.
    WorkspaceVanished,
    /// Path resolves to an NFS / SMB / fuse mount (unsupported in v0).
    WorkspaceOnNetworkMount,
    /// Path resolved outside the mounted workspace root.
    OutOfRoot,
    /// `..` segment found in a client-provided path.
    PathTraversal,
    /// The workspace is still indexing; the caller asked for a non-partial answer.
    IndexNotReady,
    /// `find_symbol`/`read_symbol` came back empty.
    SymbolNotFound,
    /// Multiple definitions; caller must disambiguate with `file` or `kind`.
    AmbiguousSymbol,
    /// Path is below root but excluded (gitignore, secrets blocklist, extension allowlist).
    FileNotIndexed,
    /// `start_line`/`end_line` past the end of the file.
    RangeOutOfBounds,
    /// `token_budget` is too small for a minimal-viable answer.
    BudgetTooSmall,
    /// `token_budget` is above the 200,000 cap.
    BudgetTooLarge,
    /// Per-connection in-flight cap of 16 hit.
    Busy,
    /// redb / segment store out of disk.
    StorageFull,
    /// On-disk schema is newer than this daemon binary supports.
    SchemaVersionNewer,
    /// Per-request 30s soft deadline tripped.
    DeadlineExceeded,
    /// Protocol major mismatch. (Unreachable in v0 — v0 is the only major.)
    IncompatibleVersion,
    /// Unexpected internal failure. Should be reported.
    InternalError,
}

impl ErrorCode {
    /// Stable wire-level name. Used in `error.code`.
    pub fn as_wire_str(self) -> &'static str {
        match self {
            ErrorCode::InvalidFrame => "INVALID_FRAME",
            ErrorCode::MessageTooLarge => "MESSAGE_TOO_LARGE",
            ErrorCode::InvalidParams => "INVALID_PARAMS",
            ErrorCode::InvalidWorkspacePath => "INVALID_WORKSPACE_PATH",
            ErrorCode::MountHasSymlink => "MOUNT_HAS_SYMLINK",
            ErrorCode::WorkspaceVanished => "WORKSPACE_VANISHED",
            ErrorCode::WorkspaceOnNetworkMount => "WORKSPACE_ON_NETWORK_MOUNT",
            ErrorCode::OutOfRoot => "OUT_OF_ROOT",
            ErrorCode::PathTraversal => "PATH_TRAVERSAL",
            ErrorCode::IndexNotReady => "INDEX_NOT_READY",
            ErrorCode::SymbolNotFound => "SYMBOL_NOT_FOUND",
            ErrorCode::AmbiguousSymbol => "AMBIGUOUS_SYMBOL",
            ErrorCode::FileNotIndexed => "FILE_NOT_INDEXED",
            ErrorCode::RangeOutOfBounds => "RANGE_OUT_OF_BOUNDS",
            ErrorCode::BudgetTooSmall => "BUDGET_TOO_SMALL",
            ErrorCode::BudgetTooLarge => "BUDGET_TOO_LARGE",
            ErrorCode::Busy => "BUSY",
            ErrorCode::StorageFull => "STORAGE_FULL",
            ErrorCode::SchemaVersionNewer => "SCHEMA_VERSION_NEWER",
            ErrorCode::DeadlineExceeded => "DEADLINE_EXCEEDED",
            ErrorCode::IncompatibleVersion => "INCOMPATIBLE_VERSION",
            ErrorCode::InternalError => "INTERNAL_ERROR",
        }
    }
}

/// Protocol-level error returned to a client over the wire.
///
/// Internal errors (lock failure, filesystem IO, redb panics) are mapped to
/// `InternalError` plus a short `message`; the structured data sub-field is
/// reserved for per-method specifics (e.g. `WorkspaceVanished` carries the
/// stored vs current `(dev, inode)`).
#[derive(Debug, thiserror::Error)]
#[error("{code:?}: {message}")]
pub struct ProtocolError {
    pub code: ErrorCode,
    pub message: String,
    pub data: Option<serde_json::Value>,
}

impl ProtocolError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            data: None,
        }
    }

    pub fn with_data(mut self, data: serde_json::Value) -> Self {
        self.data = Some(data);
        self
    }

    /// Convenience: render to the wire `error` object.
    pub fn to_wire(&self) -> serde_json::Value {
        let mut obj = serde_json::Map::new();
        obj.insert(
            "code".into(),
            serde_json::Value::String(self.code.as_wire_str().to_string()),
        );
        obj.insert(
            "message".into(),
            serde_json::Value::String(self.message.clone()),
        );
        if let Some(data) = &self.data {
            obj.insert("data".into(), data.clone());
        }
        serde_json::Value::Object(obj)
    }
}

impl From<anyhow::Error> for ProtocolError {
    fn from(e: anyhow::Error) -> Self {
        ProtocolError::new(ErrorCode::InternalError, format!("{e:#}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_strings_are_uppercase_snake() {
        let cases = [
            (ErrorCode::InvalidFrame, "INVALID_FRAME"),
            (ErrorCode::WorkspaceOnNetworkMount, "WORKSPACE_ON_NETWORK_MOUNT"),
            (ErrorCode::SchemaVersionNewer, "SCHEMA_VERSION_NEWER"),
            (ErrorCode::DeadlineExceeded, "DEADLINE_EXCEEDED"),
        ];
        for (code, expected) in cases {
            assert_eq!(code.as_wire_str(), expected);
        }
    }

    #[test]
    fn protocol_error_round_trips_to_wire() {
        let err = ProtocolError::new(ErrorCode::OutOfRoot, "path escapes workspace")
            .with_data(serde_json::json!({"requested": "/etc/passwd"}));
        let wire = err.to_wire();
        assert_eq!(wire["code"], "OUT_OF_ROOT");
        assert_eq!(wire["message"], "path escapes workspace");
        assert_eq!(wire["data"]["requested"], "/etc/passwd");
    }
}
