//! `Index.*` method handlers. v0 implements `Index.FindSymbol`,
//! `Index.ReadSymbol`, and `Index.ReadRange`. `Index.Outline` is still wired
//! into the dispatcher but returns `INDEX_NOT_READY` until the P6 outline
//! slice (which depends on the P8 PageRank score) lands.

use std::io::Read;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::Ordering;

use serde::Deserialize;
use serde_json::Value;

use crate::error::{ErrorCode, ProtocolError};
use crate::filter::BODY_ALLOWED_EXTENSIONS;
use crate::state::DaemonState;
use crate::store::{FoundSymbol, Store, SymbolKind};

/// `Index.ReadSymbol`/`Index.ReadRange` clamp at 4 MiB of returned text. The
/// 16 MiB wire cap (§3.3) is the hard ceiling; the 4 MiB cap leaves room for
/// the JSON envelope and the `tokens_returned`/`content_version` fields.
const MAX_TEXT_BYTES: usize = 4 * 1024 * 1024;
/// Per protocol-v0 §11.1 the v0 token counter is `bytes / 3`; agents are told
/// this via `token_counter: "bytes_div_3"` in the response. The wire-level
/// budget cap matches `params.token_budget`'s 200 000 ceiling (§18.4 / §18.5).
const TOKEN_COUNTER: &str = "bytes_div_3";
const TOKEN_BUDGET_MIN: u64 = 50;
const TOKEN_BUDGET_MAX: u64 = 200_000;

#[derive(Debug, Deserialize)]
struct FindSymbolParams {
    name: String,
    #[serde(default)]
    kind: Option<String>,
    #[serde(default)]
    file: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ReadRangeParams {
    file: String,
    start_line: u32,
    end_line: u32,
    #[serde(default)]
    token_budget: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct ReadSymbolParams {
    name: String,
    #[serde(default)]
    file: Option<String>,
    #[serde(default)]
    kind: Option<String>,
    #[serde(default)]
    shape: Option<String>,
    #[serde(default)]
    token_budget: Option<u64>,
    #[serde(default)]
    include_dependencies: bool,
    /// v1.1 session-dedup override. Accepted but inert in v0.
    #[serde(default)]
    #[allow(dead_code)]
    force_resend: bool,
}

fn parse_params<T: for<'de> Deserialize<'de>>(
    value: serde_json::Value,
) -> Result<T, ProtocolError> {
    serde_json::from_value(value).map_err(|e| {
        ProtocolError::new(
            ErrorCode::InvalidParams,
            format!("params failed validation: {e}"),
        )
    })
}

/// Snapshot `(workspace_root, store)` under the `DaemonState` mutexes in one
/// pass so each handler only holds the locks long enough to clone the `Arc`s.
fn snapshot(state: &Arc<DaemonState>) -> Result<(PathBuf, Arc<Store>), ProtocolError> {
    let root = {
        let g = state.workspace.lock().map_err(|e| {
            ProtocolError::new(ErrorCode::InternalError, format!("workspace poisoned: {e}"))
        })?;
        match g.as_ref() {
            Some(w) => w.canonical.path.clone(),
            None => {
                return Err(ProtocolError::new(
                    ErrorCode::IndexNotReady,
                    "no workspace mounted",
                ));
            }
        }
    };
    let store = {
        let g = state.store.lock().map_err(|e| {
            ProtocolError::new(ErrorCode::InternalError, format!("store poisoned: {e}"))
        })?;
        match g.as_ref() {
            Some(s) => s.clone(),
            None => {
                return Err(ProtocolError::new(
                    ErrorCode::IndexNotReady,
                    "no workspace mounted",
                ));
            }
        }
    };
    Ok((root, store))
}

/// Validate `token_budget` against the 50..=200_000 window when present.
fn check_budget(budget: Option<u64>) -> Result<u64, ProtocolError> {
    let b = budget.unwrap_or(4096);
    if b < TOKEN_BUDGET_MIN {
        return Err(ProtocolError::new(
            ErrorCode::BudgetTooSmall,
            format!("token_budget {b} < {TOKEN_BUDGET_MIN}"),
        ));
    }
    if b > TOKEN_BUDGET_MAX {
        return Err(ProtocolError::new(
            ErrorCode::BudgetTooLarge,
            format!("token_budget {b} > {TOKEN_BUDGET_MAX}"),
        ));
    }
    Ok(b)
}

/// Resolve a workspace-relative `file` argument to an absolute path inside
/// `root`. Enforces protocol-v0 §6.2 (per-read prefix check) + §6.3 (no `..`).
///
/// Absolute paths are accepted only if they already start with `root` (the
/// MCP server may forward absolute paths from agent-side editors); anything
/// else surfaces as `OUT_OF_ROOT`.
fn resolve_workspace_path(root: &Path, raw: &str) -> Result<(PathBuf, String), ProtocolError> {
    if raw.is_empty() {
        return Err(ProtocolError::new(
            ErrorCode::InvalidParams,
            "`file` must be non-empty",
        ));
    }
    let p = Path::new(raw);
    if p.components().any(|c| matches!(c, Component::ParentDir)) {
        return Err(ProtocolError::new(
            ErrorCode::PathTraversal,
            "`..` segment in path",
        ));
    }
    let abs = if p.is_absolute() {
        if !p.starts_with(root) {
            return Err(ProtocolError::new(
                ErrorCode::OutOfRoot,
                "absolute path is outside workspace root",
            ));
        }
        p.to_path_buf()
    } else {
        root.join(p)
    };
    let rel = match abs.strip_prefix(root) {
        Ok(r) => r.to_string_lossy().into_owned(),
        Err(_) => {
            return Err(ProtocolError::new(
                ErrorCode::OutOfRoot,
                "resolved path is outside workspace root",
            ));
        }
    };
    Ok((abs, rel))
}

/// Body-extension check per §13.4. Returns `OUT_OF_ALLOWED_BODY_EXTENSIONS` when
/// a body read is requested for a file whose extension isn't on the allowlist.
fn check_body_extension(path: &Path) -> Result<(), ProtocolError> {
    let ok = path
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_ascii_lowercase())
        .map(|e| BODY_ALLOWED_EXTENSIONS.contains(&e.as_str()))
        .unwrap_or(false);
    if !ok {
        return Err(ProtocolError::new(
            ErrorCode::OutOfAllowedBodyExtensions,
            "extension not in §13.4 body allowlist",
        ));
    }
    Ok(())
}

/// Approximate token count per protocol-v0 §11.1.
fn approx_tokens(byte_len: usize) -> u64 {
    (byte_len as u64).div_ceil(3)
}

/// Compose the `content_version` string per protocol-v0 §3.6:
/// `blake3(content)[:16]@mtime_ns+index_generation`. The blake3 prefix is the
/// first 16 hex chars (8 bytes) of the hash, matching the spec example.
fn content_version(content: &[u8], mtime_ns: i128, index_generation: u64) -> String {
    let hash = blake3::hash(content);
    let hex = hash.to_hex();
    let prefix = &hex.as_str()[..16];
    format!("{prefix}@{mtime_ns}+{index_generation}")
}

/// Bytewise truncate a UTF-8 buffer to at most `max_bytes` while keeping the
/// result valid UTF-8. Returns `(text, truncated)` where `truncated` is the
/// total bytes dropped.
fn truncate_utf8(buf: &str, max_bytes: usize) -> (&str, bool) {
    if buf.len() <= max_bytes {
        return (buf, false);
    }
    // walk back to the start of the previous UTF-8 boundary
    let mut end = max_bytes;
    while end > 0 && !buf.is_char_boundary(end) {
        end -= 1;
    }
    (&buf[..end], true)
}

/// Read a file from disk under tokio's blocking-pool. Returns the bytes plus
/// the mtime in ns-since-epoch (signed because `Duration::as_nanos` can be
/// shifted negative when computing relative offsets — not here, but the type
/// keeps it open for v2 if we move to a logical clock).
async fn read_file(abs: &Path) -> Result<(Vec<u8>, i128), ProtocolError> {
    let abs = abs.to_path_buf();
    let out = tokio::task::spawn_blocking(move || -> std::io::Result<(Vec<u8>, i128)> {
        let mut f = std::fs::File::open(&abs)?;
        let meta = f.metadata()?;
        let mtime = meta.modified().ok();
        let mut buf = Vec::with_capacity(meta.len() as usize);
        f.read_to_end(&mut buf)?;
        let ns: i128 = mtime
            .and_then(|m| m.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_nanos() as i128)
            .unwrap_or(0);
        Ok((buf, ns))
    })
    .await
    .map_err(|e| ProtocolError::new(ErrorCode::InternalError, format!("join error: {e}")))?;
    out.map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => {
            ProtocolError::new(ErrorCode::FileNotIndexed, format!("file not found: {e}"))
        }
        _ => ProtocolError::new(ErrorCode::InternalError, format!("read error: {e}")),
    })
}

/// Compute the byte range of `[start_line..=end_line]` (1-indexed, inclusive)
/// in a buffer that uses `\n` line terminators. Lines past EOF surface as
/// `RANGE_OUT_OF_BOUNDS`. The end byte is exclusive (points one past the
/// trailing `\n`).
fn line_range_bytes(
    buf: &[u8],
    start_line: u32,
    end_line: u32,
) -> Result<(usize, usize), ProtocolError> {
    if start_line == 0 || end_line == 0 {
        return Err(ProtocolError::new(
            ErrorCode::InvalidParams,
            "line numbers are 1-indexed",
        ));
    }
    if end_line < start_line {
        return Err(ProtocolError::new(
            ErrorCode::InvalidParams,
            "end_line < start_line",
        ));
    }
    let mut line: u32 = 1;
    let mut start_byte: Option<usize> = None;
    let mut end_byte: Option<usize> = None;
    if start_line == 1 {
        start_byte = Some(0);
    }
    for (i, b) in buf.iter().enumerate() {
        if *b == b'\n' {
            line += 1;
            if line == start_line && start_byte.is_none() {
                start_byte = Some(i + 1);
            }
            if line == end_line + 1 && end_byte.is_none() {
                end_byte = Some(i + 1);
                break;
            }
        }
    }
    let s = match start_byte {
        Some(b) => b,
        None => {
            return Err(ProtocolError::new(
                ErrorCode::RangeOutOfBounds,
                format!("start_line {start_line} past EOF"),
            ));
        }
    };
    let e = end_byte.unwrap_or(buf.len());
    Ok((s, e))
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

    let (_root, store_arc) = snapshot(state)?;
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

/// `Index.ReadRange` — protocol-v0 §7.8.
///
/// Reads an explicit `[start_line..=end_line]` slice (1-indexed, inclusive).
/// The file must be inside the workspace root, must not contain `..`
/// segments, and its extension must be in the §13.4 body allowlist.
pub async fn read_range(
    params: serde_json::Value,
    state: &Arc<DaemonState>,
) -> Result<serde_json::Value, ProtocolError> {
    let p: ReadRangeParams = parse_params(params)?;
    let budget = check_budget(p.token_budget)?;

    let (root, _store_arc) = snapshot(state)?;
    let (abs, rel) = resolve_workspace_path(&root, &p.file)?;
    check_body_extension(&abs)?;

    let (bytes, mtime_ns) = read_file(&abs).await?;
    let (start_byte, end_byte) = line_range_bytes(&bytes, p.start_line, p.end_line)?;

    let slice = &bytes[start_byte..end_byte];
    let text = std::str::from_utf8(slice).map_err(|e| {
        ProtocolError::new(
            ErrorCode::InternalError,
            format!("file is not valid UTF-8 in the requested range: {e}"),
        )
    })?;

    let (text_kept, byte_truncated) = truncate_utf8(text, MAX_TEXT_BYTES);
    let budget_bytes = budget.saturating_mul(3) as usize;
    let (text_kept, budget_truncated) = truncate_utf8(text_kept, budget_bytes);
    let truncated = byte_truncated || budget_truncated;
    let tokens_returned = approx_tokens(text_kept.len());

    let cv = content_version(
        &bytes,
        mtime_ns,
        state.index_generation.load(Ordering::Relaxed),
    );

    Ok(serde_json::json!({
        "qualified_name": serde_json::Value::Null,
        "kind":           serde_json::Value::Null,
        "file":           rel,
        "range": {
            "start_line": p.start_line,
            "end_line":   p.end_line,
            "start_byte": start_byte,
            "end_byte":   end_byte,
        },
        "shape":           "body",
        "text":            text_kept,
        "content_version": cv,
        "tokens_returned": tokens_returned,
        "token_counter":   TOKEN_COUNTER,
        "truncated":       truncated,
    }))
}

/// `Index.ReadSymbol` — protocol-v0 §7.7.
///
/// v0 ships `shape: "body"` (default). `signature`/`both` accept the param but
/// only return what the body slice carries until the P8 `SignatureRenderer`
/// lands. `include_dependencies` is accepted-and-inert (P8 closure walker is
/// what would populate it).
///
/// Disambiguation policy: when multiple defs match (and no `file`/`kind`
/// filter pins them), the daemon returns the first match plus
/// `truncated: true` and `truncated_symbols: [...other files]` rather than
/// erroring out with `AMBIGUOUS_SYMBOL` — per §7.7 the catalog says the
/// "top-K + truncated" path is preferred.
pub async fn read_symbol(
    params: serde_json::Value,
    state: &Arc<DaemonState>,
) -> Result<serde_json::Value, ProtocolError> {
    let p: ReadSymbolParams = parse_params(params)?;
    if p.name.is_empty() || p.name.len() > 256 {
        return Err(ProtocolError::new(
            ErrorCode::InvalidParams,
            "`name` must be 1..=256 characters",
        ));
    }
    let shape = p.shape.as_deref().unwrap_or("body");
    if !matches!(shape, "body" | "signature" | "both") {
        return Err(ProtocolError::new(
            ErrorCode::InvalidParams,
            "`shape` must be one of body, signature, both",
        ));
    }
    let _ = p.include_dependencies; // v1: closure walker, deferred to P8
    let budget = check_budget(p.token_budget)?;

    let (root, store_arc) = snapshot(state)?;
    let hits = store_arc.find_symbol(&p.name).map_err(|e| {
        ProtocolError::new(
            ErrorCode::InternalError,
            format!("find_symbol storage error: {e:#}"),
        )
    })?;

    let kind_filter = p.kind.as_deref().map(SymbolKind::from_str_loose);
    let file_filter = p.file.as_deref();

    let mut filtered: Vec<FoundSymbol> = hits
        .into_iter()
        .filter(|h| match kind_filter {
            Some(k) => h.kind == k,
            None => true,
        })
        .filter(|h| match file_filter {
            Some(f) => h.file == f,
            None => true,
        })
        .collect();
    if filtered.is_empty() {
        return Err(ProtocolError::new(
            ErrorCode::SymbolNotFound,
            format!("no symbol named `{}`", p.name),
        ));
    }
    // Stable order for "first match is the pin". File path is a reasonable
    // tiebreaker for v0 — once P8 PageRank lands the higher-rank match wins.
    filtered.sort_by(|a, b| a.file.cmp(&b.file).then(a.start_byte.cmp(&b.start_byte)));
    let chosen = filtered.remove(0);
    let extra: Vec<String> = filtered.iter().map(|h| h.file.clone()).collect();
    let ambiguous = !extra.is_empty();

    let (abs, _rel) = resolve_workspace_path(&root, &chosen.file)?;
    check_body_extension(&abs)?;

    let (bytes, mtime_ns) = read_file(&abs).await?;
    let start = chosen.start_byte as usize;
    let end = (chosen.end_byte as usize).min(bytes.len());
    if start > bytes.len() {
        return Err(ProtocolError::new(
            ErrorCode::RangeOutOfBounds,
            "symbol byte range past EOF",
        ));
    }
    let slice = &bytes[start..end];
    let body_text = std::str::from_utf8(slice).map_err(|e| {
        ProtocolError::new(
            ErrorCode::InternalError,
            format!("symbol body is not valid UTF-8: {e}"),
        )
    })?;

    // Render the signature when the file is in a language we support.
    // v0 ships Rust only (P8 SignatureRenderer first slice); other
    // languages return `signature: null` and the caller still gets the
    // body. Falls through gracefully when the slice doesn't parse as a
    // single top-level item.
    let signature: Option<String> = if matches!(shape, "signature" | "both") {
        render_signature_for_path(&chosen.file, body_text.as_bytes())
    } else {
        None
    };

    // `text` returned to the client depends on shape:
    //   body       → full body bytes
    //   signature  → signature only (or full body if renderer returned None)
    //   both       → full body bytes; `signature` field carries the cheap form
    let text_source: String = match shape {
        "signature" => signature.clone().unwrap_or_else(|| body_text.to_string()),
        _ => body_text.to_string(),
    };

    let (text_kept, byte_truncated) = truncate_utf8(&text_source, MAX_TEXT_BYTES);
    let budget_bytes = budget.saturating_mul(3) as usize;
    let (text_kept, budget_truncated) = truncate_utf8(text_kept, budget_bytes);
    let body_truncated = byte_truncated || budget_truncated;
    let tokens_returned = approx_tokens(text_kept.len());

    let cv = content_version(
        &bytes,
        mtime_ns,
        state.index_generation.load(Ordering::Relaxed),
    );

    let signature_value = match signature {
        Some(s) => Value::String(s),
        None => Value::Null,
    };

    Ok(serde_json::json!({
        "qualified_name": chosen.name,
        "kind":           chosen.kind.as_wire_str(),
        "file":           chosen.file,
        "range": {
            "start_line": chosen.start_line,
            "end_line":   chosen.end_line,
            "start_byte": chosen.start_byte,
            "end_byte":   chosen.end_byte,
        },
        "shape":           shape,
        "text":            text_kept,
        "signature":       signature_value,
        "visibility":      chosen.visibility.as_wire_str(),
        "content_version": cv,
        "tokens_returned": tokens_returned,
        "token_counter":   TOKEN_COUNTER,
        // v0: dependency walker is P8.
        "dependencies":      serde_json::Value::Array(vec![]),
        "closure_truncated": false,
        // Disambiguation surface per §7.7.
        "truncated":         ambiguous || body_truncated,
        "truncated_symbols": extra,
    }))
}

/// Dispatch to the right per-language signature renderer based on the
/// file extension. Returns `None` for languages without a renderer yet —
/// the caller falls back to the full body.
fn render_signature_for_path(rel_path: &str, body: &[u8]) -> Option<String> {
    let ext = std::path::Path::new(rel_path)
        .extension()
        .and_then(|e| e.to_str())
        .map(|s| s.to_ascii_lowercase());
    match ext.as_deref() {
        Some("rs") => rust_tree_sitter::signature::render_rust(body),
        // Python, TypeScript, and the other 8 grammars land in subsequent
        // P8 slices. Until then those agents get the body in `text` and
        // a `null` signature field.
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncate_utf8_keeps_char_boundary() {
        let s = "ééééé"; // 10 bytes (2 per é)
        let (kept, t) = truncate_utf8(s, 5);
        assert!(t);
        assert_eq!(kept, "éé"); // 4 bytes; 5 is mid-char so we walk back
    }

    #[test]
    fn line_range_basic() {
        let buf = b"one\ntwo\nthree\n";
        let (s, e) = line_range_bytes(buf, 1, 2).unwrap();
        assert_eq!(&buf[s..e], b"one\ntwo\n");
        let (s, e) = line_range_bytes(buf, 2, 2).unwrap();
        assert_eq!(&buf[s..e], b"two\n");
        let (s, e) = line_range_bytes(buf, 3, 3).unwrap();
        assert_eq!(&buf[s..e], b"three\n");
    }

    #[test]
    fn line_range_past_eof_errors() {
        let buf = b"one\ntwo\n";
        let err = line_range_bytes(buf, 10, 12).unwrap_err();
        assert_eq!(err.code, ErrorCode::RangeOutOfBounds);
    }

    #[test]
    fn line_range_invalid_args() {
        let buf = b"x";
        assert_eq!(
            line_range_bytes(buf, 0, 1).unwrap_err().code,
            ErrorCode::InvalidParams
        );
        assert_eq!(
            line_range_bytes(buf, 5, 2).unwrap_err().code,
            ErrorCode::InvalidParams
        );
    }

    #[test]
    fn content_version_shape() {
        let cv = content_version(b"hello", 1_700_000_000_000_000_000, 47);
        // 16 hex chars, '@', decimal mtime, '+', decimal gen.
        let parts: Vec<&str> = cv.split(['@', '+']).collect();
        assert_eq!(parts.len(), 3, "got {cv}");
        assert_eq!(parts[0].len(), 16);
        assert!(parts[0].chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(parts[1], "1700000000000000000");
        assert_eq!(parts[2], "47");
    }

    #[test]
    fn resolve_rejects_parent_dir() {
        let root = Path::new("/tmp/ws");
        let err = resolve_workspace_path(root, "../etc/passwd").unwrap_err();
        assert_eq!(err.code, ErrorCode::PathTraversal);
    }

    #[test]
    fn resolve_rejects_outside_absolute() {
        let root = Path::new("/tmp/ws");
        let err = resolve_workspace_path(root, "/etc/passwd").unwrap_err();
        assert_eq!(err.code, ErrorCode::OutOfRoot);
    }

    #[test]
    fn resolve_joins_relative() {
        let root = Path::new("/tmp/ws");
        let (abs, rel) = resolve_workspace_path(root, "src/lib.rs").unwrap();
        assert_eq!(abs, Path::new("/tmp/ws/src/lib.rs"));
        assert_eq!(rel, "src/lib.rs");
    }

    #[test]
    fn check_body_ext_allows_rust() {
        check_body_extension(Path::new("/x/foo.rs")).unwrap();
    }

    #[test]
    fn check_body_ext_rejects_unknown() {
        let err = check_body_extension(Path::new("/x/foo.bin")).unwrap_err();
        assert_eq!(err.code, ErrorCode::OutOfAllowedBodyExtensions);
    }
}
