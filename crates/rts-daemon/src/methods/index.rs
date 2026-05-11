//! `Index.*` method handlers. v0 implements `Index.FindSymbol`; the other
//! verbs (`Outline`, `ReadSymbol`, `ReadRange`) are wired into the dispatcher
//! but still return `INDEX_NOT_READY` until later P6 slices.

use std::sync::Arc;

use serde::Deserialize;

use crate::error::{ErrorCode, ProtocolError};
use crate::state::DaemonState;
use crate::store::SymbolKind;

#[derive(Debug, Deserialize)]
struct FindSymbolParams {
    name: String,
    #[serde(default)]
    kind: Option<String>,
    #[serde(default)]
    file: Option<String>,
}

fn parse_params<T: for<'de> Deserialize<'de>>(value: serde_json::Value) -> Result<T, ProtocolError> {
    serde_json::from_value(value).map_err(|e| {
        ProtocolError::new(
            ErrorCode::InvalidParams,
            format!("params failed validation: {e}"),
        )
    })
}

/// `Index.FindSymbol` — protocol-v0 §7.6.
///
/// v0 contract:
/// - always returns a list (length ≥ 0), never errors with `SYMBOL_NOT_FOUND`
///   for empty results; the agent disambiguates via the list shape.
/// - `truncated: true` when the list was clipped to `MAX_MATCHES` (256).
/// - `rank_score` is a placeholder constant for this slice — the real
///   PageRank-driven ranking lands in the P8 token-reduction-depth phase.
pub async fn find_symbol(
    params: serde_json::Value,
    state: &Arc<DaemonState>,
) -> Result<serde_json::Value, ProtocolError> {
    const MAX_MATCHES: usize = 256;

    let p: FindSymbolParams = parse_params(params)?;
    if p.name.is_empty() || p.name.len() > 256 {
        return Err(ProtocolError::new(
            ErrorCode::InvalidParams,
            "`name` must be 1..=256 characters",
        ));
    }
    let kind_filter = p.kind.as_deref().map(SymbolKind::from_str_loose);
    let file_filter = p.file.as_deref();

    let store_arc = {
        let slot = state.store.lock().map_err(|e| {
            ProtocolError::new(ErrorCode::InternalError, format!("store state poisoned: {e}"))
        })?;
        match slot.as_ref() {
            Some(s) => s.clone(),
            None => {
                return Err(ProtocolError::new(
                    ErrorCode::IndexNotReady,
                    "no workspace mounted",
                ));
            }
        }
    };

    let hits = store_arc.find_symbol(&p.name).map_err(|e| {
        ProtocolError::new(
            ErrorCode::InternalError,
            format!("find_symbol storage error: {e:#}"),
        )
    })?;

    let mut matches = Vec::with_capacity(hits.len().min(MAX_MATCHES));
    for h in hits.into_iter() {
        if let Some(filter) = kind_filter {
            if h.kind != filter {
                continue;
            }
        }
        if let Some(filter) = file_filter {
            if h.file != filter {
                continue;
            }
        }
        matches.push(serde_json::json!({
            "qualified_name": h.name,
            "kind":           h.kind.as_wire_str(),
            "file":           h.file,
            "range": {
                "start_line": h.start_line,
                "end_line":   h.end_line,
                "start_byte": h.start_byte,
                "end_byte":   h.end_byte,
            },
            // v0: signature rendering is part of P8 SignatureRenderer; for now
            // the writer doesn't store extracted signatures.
            "signature": serde_json::Value::Null,
            "doc":       serde_json::Value::Null,
            "visibility": h.visibility.as_wire_str(),
            // Placeholder until P8 wires PageRank.
            "rank_score": 0.0,
        }));
        if matches.len() >= MAX_MATCHES {
            break;
        }
    }

    let truncated = matches.len() == MAX_MATCHES;
    Ok(serde_json::json!({
        "matches":   matches,
        "truncated": truncated,
    }))
}
