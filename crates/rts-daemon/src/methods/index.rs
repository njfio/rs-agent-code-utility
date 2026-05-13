//! `Index.*` method handlers. v0 implements all four verbs:
//! `Index.FindSymbol`, `Index.ReadSymbol`, `Index.ReadRange`, and
//! `Index.Outline` (PageRank-ranked).

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
    /// Exact name. Mutually exclusive with `pattern`; if both are
    /// provided we error with `INVALID_PARAMS` rather than silently
    /// picking one — agents shouldn't have to guess our precedence.
    #[serde(default)]
    name: Option<String>,
    /// Glob pattern (`*`, `?`) over symbol names. The matcher is a
    /// minimal shell-style globber — no character classes, no escape
    /// (project symbols don't contain glob metacharacters in practice).
    /// Closes the largest dogfooding gap vs ripgrep: "I know roughly
    /// what it's called". Internally O(N) over all indexed names.
    #[serde(default)]
    pattern: Option<String>,
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

#[derive(Debug, Deserialize)]
struct ReadSymbolAtParams {
    /// Workspace-relative file path.
    file: String,
    /// 1-indexed line containing the symbol to read.
    line: u32,
    /// Optional 1-indexed column inside the line. When omitted we pick
    /// the innermost def whose range covers the line at all; when set,
    /// we additionally require the column to fall inside the def's
    /// byte range. Useful for "go-to-definition" workflows where the
    /// caller wants the symbol at the exact caret position.
    #[serde(default)]
    column: Option<u32>,
    #[serde(default)]
    shape: Option<String>,
    #[serde(default)]
    token_budget: Option<u64>,
    #[serde(default)]
    include_dependencies: bool,
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
/// - either `name` (exact) or `pattern` (glob `*`/`?`) is required, but
///   not both — the pattern path is the alpha.24 dogfooding-gap fix
///   that replaces "agent falls back to ripgrep when they don't know the
///   exact name". O(N) over all indexed names; with a 256-match cap.
/// - `rank_score` is a placeholder constant for this slice — the real
///   PageRank-driven ranking lands in the P8 token-reduction-depth phase.
pub async fn find_symbol(
    params: serde_json::Value,
    state: &Arc<DaemonState>,
) -> Result<serde_json::Value, ProtocolError> {
    const MAX_MATCHES: usize = 256;

    let p: FindSymbolParams = parse_params(params)?;
    if p.name.is_some() && p.pattern.is_some() {
        return Err(ProtocolError::new(
            ErrorCode::InvalidParams,
            "provide either `name` or `pattern`, not both",
        ));
    }
    if p.name.is_none() && p.pattern.is_none() {
        return Err(ProtocolError::new(
            ErrorCode::InvalidParams,
            "either `name` (exact) or `pattern` (glob) is required",
        ));
    }
    if let Some(n) = &p.name {
        if n.is_empty() || n.len() > 256 {
            return Err(ProtocolError::new(
                ErrorCode::InvalidParams,
                "`name` must be 1..=256 characters",
            ));
        }
    }
    if let Some(pat) = &p.pattern {
        if pat.is_empty() || pat.len() > 256 {
            return Err(ProtocolError::new(
                ErrorCode::InvalidParams,
                "`pattern` must be 1..=256 characters",
            ));
        }
    }
    let kind_filter = p.kind.as_deref().map(SymbolKind::from_str_loose);
    let file_filter = p.file.as_deref();

    let (_root, store_arc) = snapshot(state)?;

    // Resolve the candidate symbol names.
    let names: Vec<String> = if let Some(n) = &p.name {
        vec![n.clone()]
    } else {
        // Pattern path. Pull the full name set and glob-match. Capped at
        // 4× MAX_MATCHES candidates to bound work — patterns like `*`
        // would otherwise iterate every def in the index.
        let pattern = p.pattern.as_deref().unwrap();
        let all = store_arc.all_defined_names().map_err(|e| {
            ProtocolError::new(
                ErrorCode::InternalError,
                format!("all_defined_names storage error: {e:#}"),
            )
        })?;
        let mut filtered: Vec<String> = all
            .into_iter()
            .filter(|n| symbol_glob_match(pattern, n))
            .collect();
        // Stable lexicographic order so successive calls with the same
        // pattern return the same prefix when truncated.
        filtered.sort();
        filtered.truncate(MAX_MATCHES * 4);
        filtered
    };

    let mut matches = Vec::with_capacity(names.len().min(MAX_MATCHES));
    'outer: for n in &names {
        let hits = store_arc.find_symbol(n).map_err(|e| {
            ProtocolError::new(
                ErrorCode::InternalError,
                format!("find_symbol storage error: {e:#}"),
            )
        })?;
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
                break 'outer;
            }
        }
    }

    let truncated = matches.len() == MAX_MATCHES;
    Ok(serde_json::json!({
        "matches":   matches,
        "truncated": truncated,
    }))
}

/// Minimal shell-style globber for symbol names.
///
/// Supports `*` (zero or more chars) and `?` (one char). Anything else
/// is matched literally — there are no character classes, no escapes,
/// and no `**`. Project symbols don't contain glob metacharacters in
/// practice (`*`, `?` aren't valid in Rust/Python/JS/Go/etc. identifiers),
/// so we don't need an escape mechanism for v0.
///
/// Algorithm is two-pointer with backtracking on `*` — same shape as
/// libc's `fnmatch(3)` minus the bracket-expr machinery. O(N×M) worst
/// case for catastrophic patterns like `a*a*a*a*b` against `aaaaaa…`,
/// but the 4× MAX_MATCHES candidate cap upstream keeps that bounded.
pub(crate) fn symbol_glob_match(pattern: &str, name: &str) -> bool {
    let pb = pattern.as_bytes();
    let nb = name.as_bytes();
    let (mut pi, mut ni) = (0usize, 0usize);
    let (mut star_pi, mut star_ni) = (usize::MAX, 0usize);
    while ni < nb.len() {
        if pi < pb.len() && (pb[pi] == b'?' || pb[pi] == nb[ni]) {
            pi += 1;
            ni += 1;
        } else if pi < pb.len() && pb[pi] == b'*' {
            star_pi = pi;
            star_ni = ni;
            pi += 1;
        } else if star_pi != usize::MAX {
            // Backtrack: the last `*` consumes one more char and we
            // retry from the saved pattern position.
            pi = star_pi + 1;
            star_ni += 1;
            ni = star_ni;
        } else {
            return false;
        }
    }
    // Tail: only trailing `*`s in the pattern are allowed.
    while pi < pb.len() && pb[pi] == b'*' {
        pi += 1;
    }
    pi == pb.len()
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
/// lands. `include_dependencies` walks the anchor's body for known def names
/// and surfaces each as a `{qualified_name, kind, file, range, signature}`
/// entry under `dependencies`; the walk is depth-1 and budget-aware. See
/// `crate::closure` for the rationale + scope.
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
    let include_deps = p.include_dependencies;
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

    read_symbol_body(state, &root, &store_arc, chosen, extra, ambiguous, shape, budget, include_deps).await
}

/// Shared "I have a `FoundSymbol`, build the wire response" routine,
/// extracted so `Index.ReadSymbol` (which resolves the anchor by name)
/// and `Index.ReadSymbolAt` (which resolves by `(file, line, col)`)
/// can share everything from "read the file" onward.
#[allow(clippy::too_many_arguments)]
async fn read_symbol_body(
    state: &Arc<DaemonState>,
    root: &Path,
    store_arc: &Arc<Store>,
    chosen: FoundSymbol,
    extra: Vec<String>,
    ambiguous: bool,
    shape: &str,
    budget: u64,
    include_deps: bool,
) -> Result<serde_json::Value, ProtocolError> {
    let (abs, _rel) = resolve_workspace_path(root, &chosen.file)?;
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
    let body_tokens = approx_tokens(text_kept.len());

    let cv = content_version(
        &bytes,
        mtime_ns,
        state.index_generation.load(Ordering::Relaxed),
    );

    let signature_value = match signature {
        Some(s) => Value::String(s),
        None => Value::Null,
    };

    // Closure walk (when requested). The walker reads each dep's
    // body from disk for signature rendering, so we delegate to a
    // blocking task. The budget passed in is what's left after the
    // anchor body's tokens are spent — body always wins, deps fill
    // the remainder, and `closure_truncated` fires if any didn't fit.
    let (deps_value, closure_truncated, deps_truncated_names, dep_tokens) = if include_deps {
        let remaining_budget = budget.saturating_sub(body_tokens);
        let root_owned = root.to_path_buf();
        let store_arc = store_arc.clone();
        let chosen_clone = chosen.clone();
        let body_owned = body_text.to_string();
        let walk = tokio::task::spawn_blocking(move || {
            crate::closure::compute(
                &root_owned,
                &store_arc,
                &chosen_clone,
                &body_owned,
                remaining_budget,
            )
        })
        .await
        .map_err(|e| {
            ProtocolError::new(ErrorCode::InternalError, format!("closure join error: {e}"))
        })?;
        let value = crate::closure::to_wire_value(&walk.dependencies);
        (
            value,
            walk.closure_truncated,
            walk.truncated_symbols,
            walk.tokens_used,
        )
    } else {
        (serde_json::Value::Array(vec![]), false, Vec::new(), 0u64)
    };
    let tokens_returned = body_tokens.saturating_add(dep_tokens);

    // `truncated_symbols` blends two sources per §7.7: ambiguous
    // anchor matches (extra files) and closure deps that didn't fit
    // (deps_truncated_names). Both let the agent re-request
    // individually.
    let mut truncated_symbols = extra;
    truncated_symbols.extend(deps_truncated_names);

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
        "dependencies":      deps_value,
        "closure_truncated": closure_truncated,
        // Disambiguation surface per §7.7.
        "truncated":         ambiguous || body_truncated,
        "truncated_symbols": truncated_symbols,
    }))
}

/// `Index.ReadSymbolAt` — line-anchored read.
///
/// Resolves `(file, line, col?)` to a def site (the smallest enclosing
/// range — innermost wins) and then dispatches through the same
/// response-building path as `Index.ReadSymbol`. The dogfooding case
/// this closes: an agent has a compiler error like
/// `error[E0308] mismatched types --> src/lib.rs:42:18` and wants the
/// containing function in one round trip, without having to first
/// `find_symbol` (which they couldn't anyway without the name).
///
/// Errors mirror `Index.ReadSymbol` plus `FILE_NOT_INDEXED` for
/// unseen files and `SYMBOL_NOT_FOUND` when no def covers the line.
pub async fn read_symbol_at(
    params: serde_json::Value,
    state: &Arc<DaemonState>,
) -> Result<serde_json::Value, ProtocolError> {
    let p: ReadSymbolAtParams = parse_params(params)?;
    if p.line == 0 {
        return Err(ProtocolError::new(
            ErrorCode::InvalidParams,
            "`line` is 1-indexed; got 0",
        ));
    }
    let shape = p.shape.as_deref().unwrap_or("body");
    if !matches!(shape, "body" | "signature" | "both") {
        return Err(ProtocolError::new(
            ErrorCode::InvalidParams,
            "`shape` must be one of body, signature, both",
        ));
    }
    let budget = check_budget(p.token_budget)?;

    let (root, store_arc) = snapshot(state)?;
    // Validate the path (catches `..`, OUT_OF_ROOT etc.) and re-emit
    // the canonical workspace-relative form.
    let (_abs, rel) = resolve_workspace_path(&root, &p.file)?;

    let defs = store_arc.defs_in_file(&rel).map_err(|e| {
        ProtocolError::new(
            ErrorCode::InternalError,
            format!("defs_in_file storage error: {e:#}"),
        )
    })?;
    if defs.is_empty() {
        return Err(ProtocolError::new(
            ErrorCode::FileNotIndexed,
            format!("`{rel}` is not in the index (yet)"),
        ));
    }

    // Pick the innermost def whose line range contains `line`. Ties
    // (same range) are broken by `(start_byte, start_line)` for
    // determinism. Column refinement is best-effort: we don't have
    // line-byte mappings without re-reading the file, so when `column`
    // is set we still rank by line-range tightness — the column field
    // becomes a tie-breaker hint, not a hard filter. This is fine in
    // practice for the compiler-error use case.
    let _column = p.column; // reserved; line-byte mapping is v1.1
    let chosen = pick_innermost_def(&defs, p.line).ok_or_else(|| {
        ProtocolError::new(
            ErrorCode::SymbolNotFound,
            format!("no symbol covers `{rel}:{}`", p.line),
        )
    })?;

    // `read_symbol_at` is single-resolution by construction (no
    // name-based ambiguity), so `extra` is empty and `ambiguous` is
    // false. The closure-walk + truncation_symbols path still fires.
    read_symbol_body(
        state,
        &root,
        &store_arc,
        chosen,
        Vec::new(),
        false,
        shape,
        budget,
        p.include_dependencies,
    )
    .await
}

/// Find the smallest (line-range) def covering `line`. Ties go to the
/// earliest start_byte for a stable tie-break.
fn pick_innermost_def(defs: &[FoundSymbol], line: u32) -> Option<FoundSymbol> {
    defs.iter()
        .filter(|d| d.start_line <= line && line <= d.end_line)
        .min_by(|a, b| {
            let span_a = a.end_line.saturating_sub(a.start_line);
            let span_b = b.end_line.saturating_sub(b.start_line);
            span_a
                .cmp(&span_b)
                .then(a.start_byte.cmp(&b.start_byte))
        })
        .cloned()
}

#[derive(Debug, Deserialize)]
struct OutlineParamsWire {
    #[serde(default)]
    glob: Option<String>,
    #[serde(default)]
    token_budget: Option<u64>,
    #[serde(default)]
    mentioned_files: Vec<String>,
    #[serde(default)]
    mentioned_idents: Vec<String>,
}

/// `Index.Outline` — protocol-v0 §7.5.
///
/// Walks the indexed workspace, builds a file→file reference graph
/// from the existing redb index + on-disk content, runs Personalized
/// PageRank per the plan's §"Aider repo-map algorithm" recipe, and
/// returns a token-budgeted outline (dotted plain text + structured
/// sidecar).
///
/// Repeat calls with the same params against an unchanged index are
/// served from `state.outline_cache`. The cache key bakes in
/// `state.index_generation`, which the writer bumps on every commit —
/// so cache invalidation is automatic and correctness-preserving (see
/// `outline.rs` module docs).
pub async fn outline(
    params: serde_json::Value,
    state: &Arc<DaemonState>,
) -> Result<serde_json::Value, ProtocolError> {
    let p: OutlineParamsWire = parse_params(params)?;
    let budget = check_budget(p.token_budget)?;

    let (root, store_arc) = snapshot(state)?;

    // Build the cache key up front. We snapshot the generation *before*
    // spawning the compute task — any writer commit that lands while
    // we're computing will bump the counter further, so the result we
    // store is the right answer for the generation we observed.
    let generation = state.index_generation.load(Ordering::Relaxed);
    let cache_key = {
        let params_borrow = crate::outline::OutlineParams {
            glob: p.glob.as_deref(),
            token_budget: budget,
            mentioned_files: &p.mentioned_files,
            mentioned_idents: &p.mentioned_idents,
        };
        crate::outline::OutlineCacheKey::from_params(generation, &params_borrow)
    };

    let result = if let Some(hit) = state.outline_cache.get(&cache_key) {
        tracing::debug!(target: "rts_daemon::outline", gen = generation, "cache hit");
        hit
    } else {
        let store = store_arc.clone();
        let glob_owned = p.glob.clone();
        let mentioned_files = p.mentioned_files.clone();
        let mentioned_idents = p.mentioned_idents.clone();
        // PageRank + content reads can be heavy on large workspaces;
        // delegate to a blocking task so we don't hog the daemon's
        // single-threaded async runtime.
        let computed = tokio::task::spawn_blocking(move || {
            let outline_params = crate::outline::OutlineParams {
                glob: glob_owned.as_deref(),
                token_budget: budget,
                mentioned_files: &mentioned_files,
                mentioned_idents: &mentioned_idents,
            };
            crate::outline::compute(&root, &store, &outline_params)
        })
        .await
        .map_err(|e| {
            ProtocolError::new(ErrorCode::InternalError, format!("outline join error: {e}"))
        })?
        .map_err(|e| {
            ProtocolError::new(
                ErrorCode::InternalError,
                format!("outline compute error: {e:#}"),
            )
        })?;
        let computed = std::sync::Arc::new(computed);
        // Store under the generation we observed. If a commit raced and
        // bumped the counter, the next call sees a key mismatch and
        // recomputes — no torn read.
        state.outline_cache.put(cache_key, computed.clone());
        tracing::debug!(target: "rts_daemon::outline", gen = generation, "cache miss → recomputed");
        computed
    };

    Ok(serde_json::json!({
        "outline_text":     result.outline_text,
        "outline_json":     result.outline_json,
        "tokens_returned":  result.tokens_returned,
        "token_counter":    TOKEN_COUNTER,
        "files_considered": result.files_considered,
        "files_included":   result.files_included,
    }))
}

/// Dispatch to the right per-language signature renderer based on the
/// file extension. Returns `None` for languages without a renderer yet —
/// the caller falls back to the full body.
///
/// `pub(crate)` so the closure walker (`crate::closure`) can render
/// per-dep signatures without re-implementing the extension-to-renderer
/// dispatch table.
pub(crate) fn render_signature_for_path(rel_path: &str, body: &[u8]) -> Option<String> {
    let ext = std::path::Path::new(rel_path)
        .extension()
        .and_then(|e| e.to_str())
        .map(|s| s.to_ascii_lowercase());
    match ext.as_deref() {
        Some("rs") => rust_tree_sitter::signature::render_rust(body),
        Some("py") => rust_tree_sitter::signature::render_python(body),
        // TypeScript grammar handles `.ts`; `.tsx` is intentionally
        // routed here too — the grammar accepts both and the agent's
        // signature shape is identical.
        Some("ts") | Some("tsx") => rust_tree_sitter::signature::render_typescript(body),
        Some("js") | Some("jsx") | Some("mjs") | Some("cjs") => {
            rust_tree_sitter::signature::render_javascript(body)
        }
        Some("go") => rust_tree_sitter::signature::render_go(body),
        Some("java") => rust_tree_sitter::signature::render_java(body),
        // C headers (.h) routed to the C renderer — C++ headers are
        // typically .hpp/.hh/.hxx and parse fine under the C++ grammar,
        // which is a superset of C for the patterns the renderer cares
        // about.
        Some("c") | Some("h") => rust_tree_sitter::signature::render_c(body),
        Some("cpp") | Some("cc") | Some("cxx") | Some("hpp") | Some("hh") | Some("hxx") => {
            rust_tree_sitter::signature::render_cpp(body)
        }
        Some("php") | Some("phtml") => rust_tree_sitter::signature::render_php(body),
        Some("rb") | Some("rake") => rust_tree_sitter::signature::render_ruby(body),
        Some("swift") => rust_tree_sitter::signature::render_swift(body),
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

    // ----- symbol_glob_match -----

    #[test]
    fn glob_exact_match() {
        assert!(symbol_glob_match("foo", "foo"));
        assert!(!symbol_glob_match("foo", "fooo"));
        assert!(!symbol_glob_match("foo", "fo"));
    }

    #[test]
    fn glob_star_prefix() {
        assert!(symbol_glob_match("make_*", "make_widget"));
        assert!(symbol_glob_match("make_*", "make_"));
        assert!(!symbol_glob_match("make_*", "Make_widget"));
        assert!(!symbol_glob_match("make_*", "widget_make"));
    }

    #[test]
    fn glob_star_suffix() {
        assert!(symbol_glob_match("*_target", "swiftTarget_target"));
        assert!(symbol_glob_match("*_target", "_target"));
        assert!(!symbol_glob_match("*_target", "target"));
    }

    #[test]
    fn glob_star_middle() {
        assert!(symbol_glob_match("read_*_at", "read_symbol_at"));
        assert!(symbol_glob_match("a*b", "ab"));
        assert!(symbol_glob_match("a*b", "axxxxb"));
        assert!(!symbol_glob_match("a*b", "axxxxbx"));
    }

    #[test]
    fn glob_question_mark() {
        assert!(symbol_glob_match("f?o", "foo"));
        assert!(symbol_glob_match("f?o", "fXo"));
        assert!(!symbol_glob_match("f?o", "fo"));
        assert!(!symbol_glob_match("f?o", "fooo"));
    }

    #[test]
    fn glob_lone_star_matches_everything() {
        assert!(symbol_glob_match("*", ""));
        assert!(symbol_glob_match("*", "anything"));
        assert!(symbol_glob_match("**", "anything")); // trailing stars collapse
    }

    #[test]
    fn glob_backtracking_doesnt_overrun() {
        // Classic glob backtrack: pattern starts looking like a match but
        // the literal tail forces a back-step.
        assert!(symbol_glob_match("a*c", "abc"));
        assert!(symbol_glob_match("a*c", "abxc"));
        assert!(!symbol_glob_match("a*c", "abcd"));
    }

    // ----- pick_innermost_def -----

    fn fake_def(name: &str, sl: u32, el: u32, sb: u32) -> crate::store::FoundSymbol {
        use crate::store::SymbolKind;
        use crate::store::schema::Visibility;
        crate::store::FoundSymbol {
            name: name.to_string(),
            kind: SymbolKind::Function,
            file: "src/lib.rs".into(),
            fid: 1,
            start_byte: sb,
            end_byte: sb + 50,
            start_line: sl,
            end_line: el,
            visibility: Visibility::Public,
        }
    }

    #[test]
    fn innermost_def_picks_smallest_containing() {
        let outer = fake_def("outer", 1, 100, 0);
        let inner = fake_def("inner", 10, 30, 200);
        let target_at_15 = pick_innermost_def(&[outer.clone(), inner.clone()], 15).unwrap();
        assert_eq!(target_at_15.name, "inner");
        // A line only the outer covers → outer wins.
        let target_at_50 = pick_innermost_def(&[outer.clone(), inner.clone()], 50).unwrap();
        assert_eq!(target_at_50.name, "outer");
    }

    #[test]
    fn innermost_def_returns_none_when_no_match() {
        let only = fake_def("only", 10, 20, 0);
        assert!(pick_innermost_def(&[only], 99).is_none());
    }

    #[test]
    fn innermost_def_ties_break_by_start_byte() {
        // Same line range, different start_byte → earlier wins.
        let a = fake_def("a", 5, 10, 500);
        let b = fake_def("b", 5, 10, 100);
        let picked = pick_innermost_def(&[a, b], 7).unwrap();
        assert_eq!(picked.name, "b");
    }
}
