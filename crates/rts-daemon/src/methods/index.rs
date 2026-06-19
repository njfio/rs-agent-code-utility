//! `Index.*` method handlers. v0 implements all four verbs:
//! `Index.FindSymbol`, `Index.ReadSymbol`, `Index.ReadRange`, and
//! `Index.Outline` (PageRank-ranked).

use std::io::Read;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::Ordering;

use serde::Deserialize;
use serde_json::Value;

use crate::cancel::CancelToken;
use crate::error::{ErrorCode, ProtocolError};
use crate::filter::BODY_ALLOWED_EXTENSIONS;
use crate::state::DaemonState;
use crate::store::{FoundSymbol, Store, SymbolKind};
use crate::symbol_pagerank::{SymbolRanks, compute_symbol_ranks};

/// Shared error builder for cooperative-cancellation hits. Code
/// `CANCELLED` (custom JSON-RPC -32099); message stable so callers can
/// log/branch on it without fuzzy matching.
fn cancelled() -> ProtocolError {
    ProtocolError::new(ErrorCode::Cancelled, "cancelled")
}

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
    /// v0.7+ (cap: `parent_scope`) — exact-match filter on a def's
    /// nearest enclosing container name (`DefSite::parent`). Drops
    /// candidates whose `parent` is not exactly this value. Lets agents
    /// disambiguate same-named methods across types
    /// (`parent: "Foo"` keeps only `Foo::new`). Currently all defs
    /// carry `parent: None` (extraction unpopulated), so a `Some(_)`
    /// filter matches nothing until the extractor assigns parents.
    #[serde(default)]
    parent: Option<String>,
    /// v0.3 U4 (alpha.34+, cap: `pagerank_symbolwise`) — sort order
    /// for the `matches` array. Accepted values:
    /// - `"rank"` (default when the capability is advertised) —
    ///   descending `rank_score` (symbol-level PageRank). Use this
    ///   to get the top-K most central matches first.
    /// - `"lexical"` — back-compat alphabetical order by `file` then
    ///   `start_byte`. Opt out for tooling that pinned to v0.2's
    ///   insertion-shape ordering.
    /// Unknown values are accepted and treated as `"rank"`.
    #[serde(default)]
    sort: Option<String>,
    /// Maximum number of `matches` to return. Defaults to 256 (the
    /// agent-facing default — most LLM contexts can't usefully digest
    /// more). Range: 1..=4096. The 4096 ceiling is set for the
    /// `rts-bench semantic` eval harness, which needs the full ranked
    /// candidate set to score query relevance — values above that
    /// indicate a tooling problem (the daemon shouldn't be paginating
    /// thousands of symbols for an agent).
    ///
    /// When omitted (the common case for agent calls), behavior is
    /// identical to pre-v0.4.1 daemons.
    #[serde(default)]
    limit: Option<u32>,
    /// Filter the returned matches to those whose doc-comment text
    /// contains the given substring (case-insensitive). Applied
    /// AFTER rank-sorting but BEFORE the `limit` cap, so the
    /// filtered candidate population is what gets truncated.
    /// Symbols with no doc comment never match. Requires capability
    /// `find_symbol_doc_filter` (v0.5.2+). Useful for agents
    /// searching by behavior described in docs rather than by
    /// identifier name — "find the cache eviction logic" can hit
    /// any documented function whose comment mentions "evict".
    #[serde(default)]
    doc_contains: Option<String>,
    /// When `true`, populate the `signature` field on each match by
    /// invoking the `rts-core` per-language `SignatureRenderer` over
    /// the symbol's byte range. Default `false` (pre-v0.5.3 wire
    /// shape preserved — agents pay the rendering cost only when
    /// they ask for it).
    ///
    /// Each render is `O(parse(symbol_bytes))` but cached per
    /// `(path, byte_range, mtime)` in `DaemonState::signature_cache`,
    /// so repeated calls on the same workspace pay it once. Best for
    /// outline-style follow-ups where the agent wants signatures
    /// without paying for `read_symbol` per result.
    #[serde(default)]
    include_signature: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct ReadRangeParams {
    file: String,
    start_line: u32,
    end_line: u32,
    #[serde(default)]
    token_budget: Option<u64>,
}

/// v0.5.4: `Index.Grep` — literal-substring (or v0.5.5+ regex) search
/// over indexed file contents. Closes the agent-loop hole where the
/// daemon couldn't help find error messages, version strings, log
/// outputs, or any other non-symbol text.
///
/// v0.5.5 adds `regex: true` (opt-in regex syntax) and `file_glob`
/// (`*.rs`, `src/**/*.toml`, etc.) so agents can scope searches the
/// same way they would with `rg --type rust foo` without leaving the
/// daemon's already-indexed file set. `context_lines` and enclosing-
/// symbol resolution remain filed for follow-up.
#[derive(Debug, Deserialize)]
struct GrepParams {
    /// The pattern to search for. 1..=1024 chars. By default
    /// interpreted as a literal substring; set `regex: true` to
    /// interpret as a regex (Rust `regex` crate syntax, byte-level
    /// matching).
    ///
    /// v0.6: now `Option<String>` to allow `structural_query` alone
    /// (no literal/regex source). At least one of `text` or
    /// `structural_query` is required; absence of both returns
    /// `NO_SEARCH_SOURCE_PROVIDED`. v1 callers always set this
    /// field — backward compatibility is by construction.
    #[serde(default)]
    text: Option<String>,
    /// Maximum number of matches to return. Defaults to 256.
    /// Range: 1..=4096 (same shape as `find_symbol.limit`).
    #[serde(default)]
    limit: Option<u32>,
    /// Case-insensitive matching. Defaults to `true` — agent-friendly.
    /// Set explicitly to `false` for case-sensitive search. Applies
    /// to both literal and regex modes (regex mode uses
    /// `RegexBuilder::case_insensitive(true)`).
    #[serde(default)]
    case_insensitive: Option<bool>,
    /// v0.5.5+ opt-in regex mode. When `true`, `text` is compiled as
    /// a `regex::bytes::Regex` pattern. Compilation failures surface
    /// as `INVALID_PARAMS` with the compiler's error message so the
    /// agent can self-correct. Defaults to `false` (literal mode).
    #[serde(default)]
    regex: Option<bool>,
    /// v0.5.5+ file-path glob filter. When set, only files whose
    /// workspace-relative path matches this glob are scanned. Uses
    /// `globset::Glob` syntax: `*.rs`, `src/**/*.toml`,
    /// `crates/{rts-core,rts-daemon}/**/*.rs`. Invalid globs surface
    /// as `INVALID_PARAMS`. Defaults to scanning every indexed file.
    #[serde(default)]
    file_glob: Option<String>,
    /// v0.6 multi-line regex mode. See `GrepArgs::multiline` (MCP
    /// side) for the user-facing doc. Only meaningful when
    /// `regex: true`; rejected with `MULTILINE_REQUIRES_REGEX` on
    /// the literal `text` path.
    #[serde(default)]
    multiline: Option<bool>,
    /// v0.6 raw tree-sitter S-expression structural query. Requires
    /// `language`. Validated at request time via
    /// `rts_core::query::Query::new`. See `GrepArgs::structural_query`
    /// for the full contract and the predicate whitelist.
    #[serde(default)]
    structural_query: Option<String>,
    /// v0.6 within-symbol byte-range filter. See
    /// `GrepArgs::within_symbol` for the full contract.
    #[serde(default)]
    within_symbol: Option<String>,
    /// v0.6 opt-in to multi-def `within_symbol`.
    #[serde(default)]
    within_symbol_allow_overload: Option<bool>,
    /// v0.6 language filter. Required when `structural_query` is set.
    /// Accepted values match the indexed-language identifiers.
    #[serde(default)]
    language: Option<Vec<String>>,
}

/// Per-mode search strategy. Compiled once in `grep()` and reused
/// across every scanned file. Literal mode stays on the byte-windows
/// path that's been measured at GB/s on modern CPUs; regex mode
/// delegates to `regex::bytes::Regex::find_iter`.
enum GrepScanner {
    Literal {
        needle: String,
        case_insensitive: bool,
    },
    Regex(regex::bytes::Regex),
}

impl GrepScanner {
    /// Return every non-overlapping match in `bytes` as
    /// `(start_byte, end_byte)` pairs against the *original* buffer
    /// (not the lowercased copy in the case-insensitive literal
    /// path — the caller renders `line_text` from the original).
    fn scan_file(&self, bytes: &[u8]) -> Vec<(usize, usize)> {
        match self {
            GrepScanner::Literal {
                needle,
                case_insensitive,
            } => {
                let needle_bytes = needle.as_bytes();
                if needle_bytes.is_empty() {
                    return Vec::new();
                }
                let n = needle_bytes.len();
                if *case_insensitive {
                    // Allocate the lowercase haystack + needle once
                    // per file. ASCII fast-path matches v0.5.4
                    // behaviour byte-for-byte; non-ASCII content is
                    // still scanned correctly because the original
                    // byte windows are what we return.
                    let needle_lower: Vec<u8> = needle_bytes
                        .iter()
                        .map(|b| b.to_ascii_lowercase())
                        .collect();
                    let haystack_lower: Vec<u8> =
                        bytes.iter().map(|b| b.to_ascii_lowercase()).collect();
                    let mut out = Vec::new();
                    let mut from = 0usize;
                    while from + n <= haystack_lower.len() {
                        if &haystack_lower[from..from + n] == needle_lower.as_slice() {
                            out.push((from, from + n));
                            from += n;
                        } else {
                            from += 1;
                        }
                    }
                    out
                } else {
                    let mut out = Vec::new();
                    let mut from = 0usize;
                    while from + n <= bytes.len() {
                        if &bytes[from..from + n] == needle_bytes {
                            out.push((from, from + n));
                            from += n;
                        } else {
                            from += 1;
                        }
                    }
                    out
                }
            }
            GrepScanner::Regex(re) => {
                let mut out = Vec::new();
                // `find_iter` skips overlapping matches by advancing
                // past `m.end()`, matching the literal path's
                // semantics. Zero-width matches (e.g. `(?i)^`) are
                // dropped — we'd otherwise loop forever, and a
                // line-anchor regex without a body isn't a useful
                // grep query for the agent.
                for m in re.find_iter(bytes) {
                    if m.start() == m.end() {
                        continue;
                    }
                    out.push((m.start(), m.end()));
                }
                out
            }
        }
    }
}

#[derive(Debug, Deserialize)]
struct ReadSymbolParams {
    name: String,
    #[serde(default)]
    file: Option<String>,
    #[serde(default)]
    kind: Option<String>,
    /// v0.7+ (cap: `parent_scope`) — exact-match filter on the def's
    /// nearest enclosing container name (`DefSite::parent`). Drops
    /// candidates whose `parent` is not exactly this value before the
    /// "first match is the pin" selection, so `read_symbol name="new"
    /// parent="Foo"` resolves `Foo::new` past the ambiguity. All defs
    /// currently carry `parent: None`, so a `Some(_)` filter matches
    /// nothing until extraction populates parents.
    #[serde(default)]
    parent: Option<String>,
    #[serde(default)]
    shape: Option<String>,
    #[serde(default)]
    token_budget: Option<u64>,
    #[serde(default)]
    include_dependencies: bool,
    /// v0.3 U2' — when true, the response carries a `callers` array
    /// of direct callers (one redb lookup per anchor, same shape as
    /// `Index.FindCallers.callers[]`). Token budget is shared with
    /// body + deps; callers fill the remainder. Defaults to false to
    /// preserve v0.2 wire shape.
    #[serde(default)]
    include_callers: bool,
    /// v1.1 session-dedup override. Accepted but inert in v0.
    #[serde(default)]
    #[allow(dead_code)]
    force_resend: bool,
}

#[derive(Debug, Deserialize)]
struct FindCallersParams {
    /// Name of the symbol whose callers we want. Required.
    name: String,
    /// Optional filter: only return callers whose enclosing-def's
    /// `kind` matches. Accepts the same loose-string form as
    /// `Index.FindSymbol.kind`.
    #[serde(default)]
    kind: Option<String>,
    /// Optional filter: only return callers from this workspace-relative
    /// file. Useful for "who calls X in foo.rs?".
    #[serde(default)]
    file: Option<String>,
}

/// `Index.VerifySymbol` params (verify-v0 P1.U1). Answers "does this
/// symbol exist?" — `name` is required (bare or qualified, e.g.
/// `Store::commit_batch`); `kind`/`lang`/`file` are optional filters.
/// `content_version` is echoed back; U1 does not hard-fail on mismatch.
#[derive(Debug, Deserialize)]
struct VerifySymbolParams {
    /// Symbol name to verify. 1..=256 chars. Bare (`commit_batch`) or
    /// qualified (`Store::commit_batch`); the handler matches the
    /// stored bare name and, when the input is qualified, its final
    /// `::`-segment too.
    name: String,
    /// Optional `kind` filter (`fn`/`method`/`struct`/...). Loose
    /// string form, same as `Index.FindSymbol.kind`.
    #[serde(default)]
    kind: Option<String>,
    /// Optional language filter. Accepted but currently advisory —
    /// def kinds are language-agnostic in v0; reserved for U2+ where
    /// signature/import checks become language-specific.
    #[serde(default)]
    #[allow(dead_code)]
    lang: Option<String>,
    /// Optional workspace-relative file filter — scopes the match (and
    /// the ambiguity decision) to one file.
    #[serde(default)]
    file: Option<String>,
    /// Optional content-version echo. U1 echoes it back verbatim and
    /// does NOT hard-fail on mismatch (the writer's generation already
    /// guards staleness for the candidate pool).
    #[serde(default)]
    content_version: Option<String>,
}

/// `Index.VerifySignature` params (verify-v0 P1.U2). "Does a call match
/// the definition?" — `name` resolves the indexed def; `claimed` is the
/// shape the caller believes it has.
#[derive(Debug, Deserialize)]
struct VerifySignatureParams {
    /// Symbol name to resolve. 1..=256 chars. Bare or qualified, same
    /// resolution as `Index.VerifySymbol`.
    name: String,
    /// Optional `kind` filter (loose-string form), to disambiguate
    /// same-named defs of different kinds.
    #[serde(default)]
    kind: Option<String>,
    /// Optional language filter. Advisory in v0 (the def's file
    /// extension drives shape extraction).
    #[serde(default)]
    #[allow(dead_code)]
    lang: Option<String>,
    /// Optional workspace-relative file filter, to disambiguate
    /// overloaded names across files.
    #[serde(default)]
    file: Option<String>,
    /// The signature shape the caller claims the symbol has.
    claimed: ClaimedSignature,
}

/// The caller's claimed signature shape for `Index.VerifySignature`.
#[derive(Debug, Clone, Deserialize)]
struct ClaimedSignature {
    /// Claimed parameter count (excluding any receiver).
    arity: u32,
    /// Claimed parameter names, in order.
    #[serde(default)]
    params: Vec<String>,
    /// Claimed return type (string compared against the actual).
    #[serde(default)]
    returns: Option<String>,
}

/// `Index.VerifyImport` params (verify-v0 P1.U3). Thin: resolves the
/// FINAL segment of `path` against the index. Real cross-module path
/// resolution is deferred to its own plan.
#[derive(Debug, Deserialize)]
struct VerifyImportParams {
    /// The import path, e.g. `crate::store::CommitOptions`. The final
    /// `::`-segment is what's resolved against the index.
    path: String,
    /// Optional language hint. Advisory in v0.
    #[serde(default)]
    #[allow(dead_code)]
    lang: Option<String>,
}

/// `Index.VerifyClaims` params (verify-v0 P1.U4). Batch verification of
/// a heterogeneous claim list; composes U1/U2/U3 + a location check.
#[derive(Debug, Deserialize)]
struct VerifyClaimsParams {
    #[serde(default)]
    claims: Vec<ClaimItem>,
}

/// One claim in a `Index.VerifyClaims` batch. Tagged by `type`.
#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ClaimItem {
    /// "does this symbol exist?" — delegates to `verify_symbol_inner`.
    Symbol {
        name: String,
        #[serde(default)]
        kind: Option<String>,
        #[serde(default)]
        lang: Option<String>,
        #[serde(default)]
        file: Option<String>,
    },
    /// "does this call match the def?" — delegates to
    /// `verify_signature_inner`.
    Signature {
        name: String,
        #[serde(default)]
        kind: Option<String>,
        #[serde(default)]
        lang: Option<String>,
        #[serde(default)]
        file: Option<String>,
        claimed: ClaimedSignature,
    },
    /// "does the final segment resolve?" — delegates to
    /// `verify_import_inner`.
    Import {
        path: String,
        #[serde(default)]
        lang: Option<String>,
    },
    /// "is this symbol's def at file:line?" — local location check.
    Location {
        symbol: String,
        file: String,
        line: u32,
        #[serde(default)]
        kind: Option<String>,
    },
}

#[derive(Debug, Deserialize)]
struct ImpactOfParams {
    /// Name of the symbol whose transitive callers we want. Required.
    name: String,
    /// BFS depth cap. Default 2 per Deepening §E (JetBrains
    /// practitioner guidance for IntelliJ call-hierarchy). Hard
    /// max 4; values outside [1, 4] are clamped, not rejected.
    #[serde(default)]
    depth: Option<u32>,
    /// Token budget for the response. Default 4096; validated
    /// against the standard 50..=200000 §16 window.
    #[serde(default)]
    token_budget: Option<u64>,
    /// Max distinct caller entries. Default 200. Hard ceiling
    /// 10_000 — past that, the impact result is noise rather than
    /// signal.
    #[serde(default)]
    max_nodes: Option<u32>,
    /// Whether to filter callers whose enclosing file matches
    /// `is_test_path`. Default `true` (per Deepening §E:
    /// IntelliJ's exclude-tests filter is the biggest noise
    /// reducer on real find-usages flows).
    #[serde(default)]
    exclude_test_paths: Option<bool>,
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
    /// v0.3 U2' — direct callers. Mirrors `ReadSymbolParams.include_callers`.
    #[serde(default)]
    include_callers: bool,
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

use crate::path::resolve_workspace_path;

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

/// Sort modes for `Index.FindSymbol.matches`. v0.3 U4 (alpha.34+).
/// `Rank` is the default when the `pagerank_symbolwise` capability
/// is advertised; `Lexical` is opt-in for tooling pinned to v0.2's
/// insertion-shape ordering.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SortMode {
    Rank,
    Lexical,
}

impl SortMode {
    fn from_param(s: Option<&str>) -> Self {
        match s.map(|x| x.trim().to_ascii_lowercase()) {
            Some(ref v) if v == "lexical" => SortMode::Lexical,
            Some(ref v) if v == "rank" => SortMode::Rank,
            _ => SortMode::Rank, // unknown / unset → default
        }
    }
}

/// Fetch the symbol-level PageRank for the current generation. On a
/// cache hit (warm), returns the cached `Arc<SymbolRanks>` cheaply.
/// On a miss (cold or post-commit), runs `compute_symbol_ranks` on a
/// blocking thread (the compute is CPU-bound; spawn_blocking keeps
/// the tokio runtime responsive for other concurrent requests),
/// stores the result, and hands it back.
///
/// Returns `Ok(None)` only when no workspace symbols exist yet
/// (cold start). In that case `find_symbol` proceeds with all
/// `rank_score: 0.0` — the wire shape stays consistent.
///
/// **Cache TOCTOU invariant (Deepening §C):** the caller must read
/// `state.index_generation` *before* opening any read transaction
/// against the store. Passing `generation` in (rather than reading
/// it here) makes that ordering explicit.
fn symbol_ranks_lazy(
    state: &Arc<DaemonState>,
    store: &Arc<Store>,
    generation: u64,
) -> Result<Option<Arc<SymbolRanks>>, ProtocolError> {
    if let Some(hit) = state.symbol_pagerank_cache.get(generation) {
        return Ok(Some(hit));
    }
    // Miss: synchronously compute. First cut per the plan; the
    // stale-rank-during-recompute optimization from Deepening §C3 is
    // a follow-up if perf bench shows this dominates.
    let ranks = compute_symbol_ranks(store, generation).map_err(|e| {
        ProtocolError::new(
            ErrorCode::InternalError,
            format!("symbol_pagerank compute error: {e:#}"),
        )
    })?;
    if ranks.sid_to_rank.is_empty() {
        return Ok(None);
    }
    state.symbol_pagerank_cache.put(ranks.clone());
    // Re-fetch through the cache so callers get an `Arc<SymbolRanks>`
    // instead of cloning the map. The cache's mutex guarantees the
    // value we just put is the one we read back (no other writer
    // could race against this thread between put and get).
    Ok(state.symbol_pagerank_cache.get(generation))
}

/// `Index.FindSymbol` — protocol-v0 §7.6.
///
/// v0 contract:
/// - always returns a list (length ≥ 0), never errors with `SYMBOL_NOT_FOUND`
///   for empty results; the agent disambiguates via the list shape.
/// - `truncated: true` when the list was clipped to the effective `limit`.
/// - either `name` (exact) or `pattern` (glob `*`/`?`) is required, but
///   not both — the pattern path is the alpha.24 dogfooding-gap fix
///   that replaces "agent falls back to ripgrep when they don't know the
///   exact name". O(N) over all indexed names.
/// - **v0.3 U4** (alpha.34+, capability `pagerank_symbolwise`):
///   `rank_score` is filled with the symbol-level PageRank value
///   and results sort by descending rank. The `sort: "lexical"`
///   param opts out for tooling that pinned to v0.2's
///   insertion-order ordering.
/// - **v0.4.1+** (capability `find_symbol_limit_param`): `limit`
///   parameter sets the maximum number of returned matches.
///   Defaults to 256 (back-compat); range 1..=4096. The 4096 ceiling
///   exists for the `rts-bench semantic` eval; agents shouldn't go
///   above the default.
/// Uniform `::` join for code symbols. Markdown defs carry their own
/// hierarchical name and a `None` parent, so they are unaffected.
fn render_qualified_name(name: &str, parent: Option<&str>) -> String {
    match parent {
        Some(p) if !p.is_empty() => format!("{p}::{name}"),
        _ => name.to_string(),
    }
}

pub async fn find_symbol(
    params: serde_json::Value,
    state: &Arc<DaemonState>,
    token: CancelToken,
) -> Result<serde_json::Value, ProtocolError> {
    /// Default cap when no `limit` is supplied. Tuned for agent
    /// callers — most LLM contexts can't usefully digest more.
    const DEFAULT_LIMIT: usize = 256;
    /// Hard ceiling on `limit`. Set for the `rts-bench semantic`
    /// eval harness, which needs the full ranked candidate pool to
    /// score query relevance.
    const MAX_LIMIT: usize = 4096;

    if token.is_cancelled() {
        return Err(cancelled());
    }
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
    // Resolve effective limit. 0 → INVALID; >MAX_LIMIT → INVALID.
    // Absent → DEFAULT_LIMIT.
    let limit = match p.limit {
        None => DEFAULT_LIMIT,
        Some(0) => {
            return Err(ProtocolError::new(
                ErrorCode::InvalidParams,
                "`limit` must be >= 1",
            ));
        }
        Some(n) if (n as usize) > MAX_LIMIT => {
            return Err(ProtocolError::new(
                ErrorCode::InvalidParams,
                format!("`limit` must be <= {MAX_LIMIT}"),
            ));
        }
        Some(n) => n as usize,
    };
    let kind_filter = p.kind.as_deref().map(SymbolKind::from_str_loose);
    let file_filter = p.file.as_deref();
    let sort_mode = SortMode::from_param(p.sort.as_deref());
    // Auto-default for `include_signature` when not explicitly set.
    //
    // Heuristic: small-result queries are "browsing" queries where
    // signatures are nearly always wanted next (the agent's natural
    // follow-up is `read_symbol` for the top hit). Pre-v0.5.3 the
    // default was always `false` — cheaper, but every browsing flow
    // paid an extra round-trip.
    //
    // We auto-enable when:
    //   - the user asked by exact `name` (lookups land 0-3 results)
    //   - OR the user explicitly capped `limit` at 10 or less
    //
    // Pattern queries with the default 256 limit still default to
    // `false` — pattern-of-the-day workflows like
    // `find_symbol --pattern "*"` shouldn't auto-parse 256 symbols.
    //
    // Explicit `include_signature: false` always wins (escape hatch
    // for clients that want the pre-v0.5.3 wire shape on small
    // queries — useful for byte-count-tight clients).
    let want_signatures = match p.include_signature {
        Some(b) => b,
        None => match (p.name.as_ref(), p.limit) {
            (Some(_), _) => true,
            (None, Some(n)) if n <= 10 => true,
            _ => false,
        },
    };

    let (root, store_arc) = snapshot(state)?;

    // Read the index generation BEFORE opening any read transaction
    // for rank lookup. Deepening §C invariant: the cache key must be
    // observed *before* the data the cache describes, never after,
    // to avoid storing pre-commit ranks under a post-commit key.
    let generation = state.index_generation.load(Ordering::Relaxed);
    let ranks = symbol_ranks_lazy(state, &store_arc, generation)?;

    // Resolve the candidate symbol names.
    let names: Vec<String> = if let Some(n) = &p.name {
        vec![n.clone()]
    } else {
        // Pattern path. Pull the full name set and glob-match. Capped at
        // 4× the effective limit to bound work — patterns like `*`
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
        // When `doc_contains` is set the filter reduces the post-rank
        // candidate set significantly; expand the pre-filter pool to
        // MAX_LIMIT*4 so the filter has the full ranked universe to
        // pull matching docs from. Without this, a `--limit 5`
        // request would only ever see 20 candidate names — almost
        // none of which carry the queried doc-text in a large pool.
        let candidate_cap = if p.doc_contains.is_some() {
            MAX_LIMIT * 4
        } else {
            limit * 4
        };
        filtered.truncate(candidate_cap);
        filtered
    };

    // Collect typed `(FoundSymbol, rank_score)` tuples so we can sort
    // before building the wire JSON. The `limit` cap applies after
    // sorting (per Deepening §G: rank-then-truncate gives the
    // top-K-by-rank, not the top-K-by-encounter).
    //
    // Pre-fix: the loop called `store.find_symbol(name)` + `store.
    // sid_for_name(name)` per name — TWO read transactions per name,
    // both doing the same `NAME_TO_SID` lookup. For pattern mode
    // (up to 1024 candidate names), that's 2048 txn-opens. The
    // batched `find_symbols_batch_with_sids` shares one txn.
    // v0.5.4: pre-filter count covers ALL active filters
    // (`kind`, `file`, `doc_contains`), not just `doc_contains`. The
    // PR #78 surface was extended after dogfood found the same
    // silent-empty failure mode for the `file` filter — a query
    // like `pattern: "*" + file: "foo.rs"` could return `matches:
    // []` ambiguously between "no symbols matched the pattern"
    // and "the file filter rejected every candidate".
    //
    // Strategy: collect ALL hits (pre-filter), then apply kind+file
    // filter. Track the pre-filter count for emission only when at
    // least one filter is active (back-compat: unfiltered responses
    // keep the pre-v0.5.2 wire shape with no `pre_filter_count` field).
    let parent_filter = p.parent.as_deref();
    let any_local_filter = kind_filter.is_some()
        || file_filter.is_some()
        || p.doc_contains.is_some()
        || parent_filter.is_some();
    let mut typed_all: Vec<(crate::store::FoundSymbol, f64)> =
        Vec::with_capacity(names.len().min(limit));
    let mut batched = store_arc
        .find_symbols_batch_with_sids(&names)
        .map_err(|e| {
            ProtocolError::new(
                ErrorCode::InternalError,
                format!("find_symbols_batch_with_sids storage error: {e:#}"),
            )
        })?;
    for n in &names {
        let (sid, hits) = match batched.remove(n) {
            Some(t) => t,
            None => continue,
        };
        let rank_for_name = sid
            .and_then(|s| ranks.as_ref().map(|r| r.rank_for(s)))
            .unwrap_or(0.0);
        for h in hits.into_iter() {
            typed_all.push((h, rank_for_name));
        }
    }
    // Capture the unfiltered population before any kind/file/doc
    // filter runs. Emitted later iff any filter was active.
    let pre_filter_count_value: Option<usize> = if any_local_filter {
        Some(typed_all.len())
    } else {
        None
    };
    let mut typed: Vec<(crate::store::FoundSymbol, f64)> = typed_all
        .into_iter()
        .filter(|(h, _)| kind_filter.map(|k| h.kind == k).unwrap_or(true))
        .filter(|(h, _)| file_filter.map(|f| h.file == f).unwrap_or(true))
        // v0.7+ (cap: `parent_scope`): exact-match parent filter.
        // A candidate with `parent: None` never matches a `Some(_)`
        // filter, so an unpopulated index yields `matches: []` (the
        // `pre_filter_count` field disambiguates "filtered to empty").
        .filter(|(h, _)| {
            parent_filter
                .map(|pp| h.parent.as_deref() == Some(pp))
                .unwrap_or(true)
        })
        .collect();

    // Apply sort. Default = descending rank when ranks are available;
    // explicit "lexical" opts out. Stable secondary sort by
    // (file, start_byte) keeps the order deterministic across ties.
    match sort_mode {
        SortMode::Lexical => typed.sort_by(|a, b| {
            a.0.file
                .cmp(&b.0.file)
                .then(a.0.start_byte.cmp(&b.0.start_byte))
        }),
        SortMode::Rank => typed.sort_by(|a, b| {
            b.1.partial_cmp(&a.1)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then(a.0.file.cmp(&b.0.file))
                .then(a.0.start_byte.cmp(&b.0.start_byte))
        }),
    }

    // v0.5: batched doc-comment lookup. One read txn for all matches.
    // The result is parallel to `typed[i]`; positions with no doc
    // become JSON `null` (back-compat with pre-v0.5 wire shape).
    //
    // v0.5.2 (cap: `find_symbol_doc_filter`): when `doc_contains` is
    // set, we do the doc lookup BEFORE truncating so the filter is
    // applied to the full sorted pre-truncate set, and only matches
    // whose doc text contains the substring survive. Without the
    // filter the lookup remains post-truncate (only `limit` items).
    //
    // v0.5.2 (cap: `find_symbol_pre_filter_count`): when a filter is
    // active, record the pre-filter candidate count so agents can
    // distinguish "no matches against name/pattern" from "filter
    // rejected every candidate". Without this, a `matches: []`
    // response is ambiguous — PR #76's dogfood report flagged this
    // as an agent-hostile silent failure mode. The field is omitted
    // (serialized as JSON null when serde drops `Option::None`)
    // when no filter ran, preserving the pre-v0.5.2 wire shape.
    let mut docs: Vec<Option<String>>;
    if let Some(needle) = p.doc_contains.as_deref() {
        // Pre-truncate lookup so the filter sees every candidate.
        let names_for_docs: Vec<String> = typed.iter().map(|(h, _)| h.name.clone()).collect();
        let fids_for_docs: Vec<u32> = typed.iter().map(|(h, _)| h.fid).collect();
        // Note: `pre_filter_count_value` was already captured above
        // — it covers the full unfiltered population (before
        // kind/file/doc filters), so we don't need to capture it
        // again here.
        let all_docs = store_arc
            .docs_for_names_with_fid(&names_for_docs, &fids_for_docs)
            .map_err(|e| {
                ProtocolError::new(
                    ErrorCode::InternalError,
                    format!("docs_for_names_with_fid storage error: {e:#}"),
                )
            })?;
        let needle_lower = needle.to_lowercase();
        // Zip + filter: keep (typed, doc) pairs whose doc text
        // contains the needle (case-insensitive). Symbols with no
        // doc are dropped entirely (the filter is opt-in; agents
        // calling without it get the full behavior).
        let mut kept_typed: Vec<(crate::store::FoundSymbol, f64)> = Vec::with_capacity(typed.len());
        let mut kept_docs: Vec<Option<String>> = Vec::with_capacity(typed.len());
        for (entry, doc) in typed.into_iter().zip(all_docs) {
            if let Some(d) = doc {
                if d.to_lowercase().contains(&needle_lower) {
                    kept_typed.push(entry);
                    kept_docs.push(Some(d));
                }
            }
        }
        typed = kept_typed;
        docs = kept_docs;
    } else {
        docs = Vec::new();
    }

    let pre_truncate_len = typed.len();
    typed.truncate(limit);

    if p.doc_contains.is_none() {
        // No filter: do the doc lookup post-truncate (cheaper).
        let names_for_docs: Vec<String> = typed.iter().map(|(h, _)| h.name.clone()).collect();
        let fids_for_docs: Vec<u32> = typed.iter().map(|(h, _)| h.fid).collect();
        docs = store_arc
            .docs_for_names_with_fid(&names_for_docs, &fids_for_docs)
            .map_err(|e| {
                ProtocolError::new(
                    ErrorCode::InternalError,
                    format!("docs_for_names_with_fid storage error: {e:#}"),
                )
            })?;
    } else {
        // Filter active: docs already gathered above, truncate to match.
        docs.truncate(limit);
    }

    // v0.5.3 (cap: `find_symbol_signature_field`): when
    // `include_signature: true`, render each surviving match's
    // signature via `rts-core`'s per-language renderer. Default off
    // — agents pay the parse cost only when they ask for it.
    //
    // We share one file_cache across all matches in this call so a
    // pattern query that hits 50 symbols in the same file reads it
    // once. The `signature_cache` on `DaemonState` deduplicates
    // across calls as well (keyed on `(path, byte_range, mtime)`).
    //
    // Vec is parallel to `typed[i]`; `None` entries serialize to
    // JSON `null` (back-compat: a match with no renderer support
    // looks identical to the pre-v0.5.3 wire shape).
    let signatures: Vec<Option<String>> = if want_signatures {
        let mut file_cache: std::collections::HashMap<std::path::PathBuf, Option<(Vec<u8>, i128)>> =
            std::collections::HashMap::with_capacity(typed.len().min(8));
        let mut out: Vec<Option<String>> = Vec::with_capacity(typed.len());
        for (h, _) in typed.iter() {
            let abs = match crate::path::resolve_workspace_path(&root, &h.file) {
                Ok((abs, _)) => abs,
                Err(_) => {
                    out.push(None);
                    continue;
                }
            };
            let bytes_and_mtime: Option<(&[u8], i128)> = if let Some(c) = file_cache.get(&abs) {
                c.as_ref().map(|(b, m)| (b.as_slice(), *m))
            } else {
                let read_result = std::fs::read(&abs).and_then(|b| {
                    let meta = std::fs::metadata(&abs)?;
                    let mtime_ns = meta
                        .modified()
                        .ok()
                        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                        .map(|d| d.as_nanos() as i128)
                        .unwrap_or(0);
                    Ok((b, mtime_ns))
                });
                match read_result {
                    Ok((b, m)) => {
                        file_cache.insert(abs.clone(), Some((b, m)));
                        file_cache
                            .get(&abs)
                            .and_then(|c| c.as_ref())
                            .map(|(b, m)| (b.as_slice(), *m))
                    }
                    Err(_) => {
                        file_cache.insert(abs.clone(), None);
                        None
                    }
                }
            };
            let Some((body_bytes, mtime_ns)) = bytes_and_mtime else {
                out.push(None);
                continue;
            };
            let (start, end) = (h.start_byte as usize, h.end_byte as usize);
            let slice = if end > start && end <= body_bytes.len() {
                &body_bytes[start..end]
            } else {
                out.push(None);
                continue;
            };
            let rendered = state.signature_cache.get_or_compute(
                &abs,
                h.start_byte,
                h.end_byte,
                mtime_ns,
                || {
                    crate::language::info_for_path(&h.file)
                        .and_then(|info| info.signature_renderer)
                        .and_then(|render| render(slice))
                },
            );
            out.push(rendered);
        }
        out
    } else {
        Vec::new()
    };

    let matches: Vec<serde_json::Value> = typed
        .into_iter()
        .zip(docs)
        .enumerate()
        .map(|(i, ((h, rank), doc))| {
            let signature_value = if want_signatures {
                match signatures.get(i).and_then(|s| s.clone()) {
                    Some(s) => serde_json::Value::String(s),
                    None => serde_json::Value::Null,
                }
            } else {
                serde_json::Value::Null
            };
            serde_json::json!({
                "qualified_name": render_qualified_name(&h.name, h.parent.as_deref()),
                // v0.7+ (cap: `parent_scope`): nearest enclosing
                // container name, or null for top-level / unpopulated.
                "parent":         h.parent,
                "kind":           h.kind.as_wire_str(),
                "file":           h.file,
                "range": {
                    "start_line": h.start_line,
                    "end_line":   h.end_line,
                    "start_byte": h.start_byte,
                    "end_byte":   h.end_byte,
                },
                // v0.5.3 (cap: `find_symbol_signature_field`):
                // populated when params.include_signature=true; null
                // otherwise (preserves pre-v0.5.3 wire shape).
                "signature": signature_value,
                // v0.5: real doc text when the writer extracted any;
                // null when the symbol has no doc comment. Capability
                // `find_symbol_doc_field` advertises that the daemon
                // populates this field rather than leaving the
                // pre-v0.5 placeholder.
                "doc":       match doc {
                    Some(t) => serde_json::Value::String(t),
                    None    => serde_json::Value::Null,
                },
                "visibility": h.visibility.as_wire_str(),
                // v0.3 U4: real PageRank score when ranks are loaded;
                // 0.0 fallback during cold start / torn read.
                "rank_score": rank,
            })
        })
        .collect();

    let truncated = pre_truncate_len > limit;
    let mut response = serde_json::json!({
        "matches":   matches,
        "truncated": truncated,
    });
    // v0.5.2+: emit `pre_filter_count` only when at least one filter
    // (`kind`, `file`, `doc_contains`) was active. Omitted otherwise
    // so pre-v0.5.2 callers see the original wire shape unchanged.
    // When present, an empty `matches[]` array accompanied by
    // `pre_filter_count: N > 0` tells the agent N candidates matched
    // the base name/pattern but the active filters rejected all of
    // them — distinguishing "nothing matched" from "filters dropped
    // every candidate".
    //
    // v0.5.4 extension: the field now fires for `kind` and `file`
    // filter rejections too, not just `doc_contains`. Same
    // silent-empty failure mode, same remedy.
    if let Some(count) = pre_filter_count_value {
        response["pre_filter_count"] = serde_json::Value::Number(count.into());
    }
    Ok(response)
}

/// `Index.Grep(text)` — literal-substring search across all
/// indexed file bytes. v0.5.4+, capability `index_grep`.
///
/// Closes the agent-loop hole where `find_symbol` / `find_callers`
/// couldn't help find non-symbol content: error message text, log
/// strings, version literals, configuration values, doc-comment
/// passages too long to surface through `doc_contains`.
///
/// **Wire shape:**
/// ```jsonc
/// {
///   "matches": [
///     {
///       "file": "crates/rts-bench/src/mcp_runner.rs",
///       "range": { "start_line": 165, "end_line": 165,
///                  "start_byte": 4892, "end_byte": 4925 },
///       "line_text": "        .map_err(|_| anyhow!(\"timeout reading MCP response\"))??;"
///     }
///   ],
///   "truncated": false,
///   "files_scanned": 245,
///   "files_with_matches": 1
/// }
/// ```
///
/// MVP: literal substring, case-insensitive default, no regex, no
/// `file_glob`, no `context_lines`, no enclosing-symbol resolution.
/// Each of those is a separate iteration filed in the CHANGELOG.
///
/// Errors: `INVALID_PARAMS` for empty `text`, `text` over 1024
/// chars, `limit` outside `1..=4096`.
pub async fn grep(
    params: serde_json::Value,
    state: &Arc<DaemonState>,
    token: CancelToken,
) -> Result<serde_json::Value, ProtocolError> {
    /// Default cap on returned matches when `limit` is unset.
    /// Matches `find_symbol`'s default — same agent-context budget.
    const DEFAULT_LIMIT: usize = 256;
    /// Hard ceiling on `limit`. Same shape as `find_symbol`.
    const MAX_LIMIT: usize = 4096;
    /// Max body bytes we'll scan per file. Above this, the file is
    /// skipped and counted toward `files_scanned` but contributes
    /// no matches. Caps an individual oversized file's CPU cost
    /// without rejecting the whole query.
    const MAX_FILE_BYTES: usize = 4 * 1024 * 1024;
    /// Max line-text length we surface in the response. Long lines
    /// (minified JS, generated tables) get truncated with an
    /// ellipsis suffix so the response stays parseable.
    const MAX_LINE_BYTES: usize = 512;

    if token.is_cancelled() {
        return Err(cancelled());
    }
    let p: GrepParams = parse_params(params)?;

    // v0.6 composition matrix: validate the param shape first, then
    // dispatch to the matching scanner. v1 callers (just `text`, no
    // new fields) take the same Literal/Regex branches they did
    // before; the validator returns a `ValidatedGrepCall::Literal`
    // or `ValidatedGrepCall::Regex` that maps 1:1 to v1 semantics.
    //
    // Structural calls land in U5; for U2 we recognize the variant
    // but report it as `NOT_YET_IMPLEMENTED` so the wire shape is
    // observable without committing to a half-built scanner.
    let validation_input = super::grep_v2::compose::ValidationInput {
        text: p.text.clone(),
        limit: p.limit,
        case_insensitive: p.case_insensitive,
        regex: p.regex,
        file_glob: p.file_glob.clone(),
        multiline: p.multiline,
        structural_query: p.structural_query.clone(),
        within_symbol: p.within_symbol.clone(),
        within_symbol_allow_overload: p.within_symbol_allow_overload,
        language: p.language.clone(),
    };
    let (validated, shared_filters) =
        super::grep_v2::validate(&validation_input).map_err(|e| e.into_protocol_error())?;

    // U7: bump grep_v2 sub-counters based on which v2 params were
    // actually active in this call. The parent `index_grep` counter
    // is bumped by the dispatcher (`methods/mod.rs`) — DO NOT bump it
    // again here. Sub-counters fire after validation but before the
    // heavy work, so e.g. a structural call that later times out
    // still counts toward `Index.Grep.structural`, giving operators
    // visibility into rejection vs failure rates. Bump-policy spec:
    // a call with `multiline + structural + within_symbol` bumps four
    // counters total (parent + three sub).
    {
        use std::sync::atomic::Ordering::Relaxed;
        if matches!(
            validated,
            super::grep_v2::ValidatedGrepCall::Regex {
                multiline: true,
                ..
            }
        ) {
            state
                .call_counters
                .index_grep_multiline
                .fetch_add(1, Relaxed);
        }
        if matches!(
            validated,
            super::grep_v2::ValidatedGrepCall::Structural { .. }
        ) {
            state
                .call_counters
                .index_grep_structural
                .fetch_add(1, Relaxed);
        }
        if shared_filters.within_symbol.is_some() {
            state
                .call_counters
                .index_grep_within_symbol
                .fetch_add(1, Relaxed);
        }
    }

    if (shared_filters.limit as usize) > MAX_LIMIT {
        return Err(ProtocolError::new(
            ErrorCode::InvalidParams,
            format!("`limit` must be <= {MAX_LIMIT}"),
        ));
    }
    if shared_filters.limit == 0 {
        return Err(ProtocolError::new(
            ErrorCode::InvalidParams,
            "`limit` must be >= 1",
        ));
    }
    let limit = shared_filters.limit as usize;

    let (text_for_response, case_insensitive, multiline, scanner) = match validated {
        super::grep_v2::ValidatedGrepCall::Literal {
            text,
            case_insensitive,
        } => {
            let scanner = GrepScanner::Literal {
                needle: text.clone(),
                case_insensitive,
            };
            (text, case_insensitive, false, scanner)
        }
        super::grep_v2::ValidatedGrepCall::Regex {
            pattern,
            case_insensitive,
            multiline,
        } => {
            // U3: multiline path runs through `grep_v2::multiline` so
            // the DFA/NFA size budgets are explicit and compile
            // failures surface as `REGEX_TOO_COMPLEX` rather than a
            // generic INVALID_PARAMS envelope. Single-line path keeps
            // v1 semantics (regex crate defaults; INVALID_PARAMS on
            // syntax errors) so v1 callers see byte-identical errors.
            let re = if multiline {
                super::grep_v2::multiline::compile_multiline_regex(&pattern, case_insensitive)
                    .map_err(|e| e.into_protocol_error())?
            } else {
                let mut builder = regex::bytes::RegexBuilder::new(&pattern);
                builder.case_insensitive(case_insensitive);
                builder.build().map_err(|e| {
                    ProtocolError::new(
                        ErrorCode::InvalidParams,
                        format!("`text` failed to compile as regex: {e}"),
                    )
                })?
            };
            (pattern, case_insensitive, multiline, GrepScanner::Regex(re))
        }
        super::grep_v2::ValidatedGrepCall::Structural {
            query,
            languages,
            combine,
        } => {
            // Structural mode owns its own response builder — the
            // shape is a superset of the v1 grep response with
            // per-match `captures` plus top-level truncation /
            // partial-failure metadata. Early-return after running
            // structural::run; do not thread through the literal/
            // regex scan accumulation below.
            //
            // `combine` carries the optional literal/regex filter the
            // caller asked to intersect with structural matches. The
            // protocol matrix in compose.rs defines `structural + text`
            // and `structural + regex` as INTERSECTION semantics —
            // every returned match must satisfy *both* the structural
            // query AND the literal/regex filter. Applied as a
            // post-pass over `result.matches` below.
            super::grep_v2::validate_predicates(&query).map_err(|e| e.into_protocol_error())?;

            // Compile the file_glob early so a bad glob fails fast
            // before snapshotting the store.
            let glob = match p.file_glob.as_deref() {
                Some(g) if g.is_empty() => {
                    return Err(ProtocolError::new(
                        ErrorCode::InvalidParams,
                        "`file_glob` must be non-empty when provided",
                    ));
                }
                Some(g) => {
                    let glob = globset::Glob::new(g).map_err(|e| {
                        ProtocolError::new(
                            ErrorCode::InvalidParams,
                            format!("`file_glob` failed to compile: {e}"),
                        )
                    })?;
                    Some(glob.compile_matcher())
                }
                None => None,
            };

            let (root, store_arc) = snapshot(state)?;
            let files = store_arc.list_indexed_files().map_err(|e| {
                ProtocolError::new(
                    ErrorCode::InternalError,
                    format!("list_indexed_files failed: {e}"),
                )
            })?;

            // v0.6 cancellation: the structural scanner is CPU-bound
            // (tree-sitter parse + node-visit + capture extraction per
            // file). Running it directly on a tokio worker thread
            // blocks that worker for the scan duration, which on
            // wide-fanout queries delays *every* concurrent task
            // assigned to the same worker — including the
            // `Daemon.Cancel` handler that's supposed to flip the
            // cancel flag this scanner polls.
            //
            // Move the scan to a dedicated blocking thread so the
            // tokio runtime stays responsive: the cancel handler
            // runs promptly on its own worker, sets the flag, and
            // the next per-match poll inside the scanner sees it.
            // This matches the existing `Index.Outline` /
            // `Index.ImpactOf` pattern (both already `spawn_blocking`
            // their CPU-bound compute) — see the v0.3.x comments
            // around `read_symbol_body`'s closure walk for the
            // rationale.
            // Build the intersection (`combine`) filter once, up-front, so
            // a bad regex fails before the scan. It is applied INLINE in
            // `structural::run` (issue #152) so the row cap counts only
            // matches that satisfy BOTH the structural query and the
            // literal/regex filter — a post-pass let the cap truncate raw
            // structural nodes before filtering on large scopes (#147 fixed
            // the user-`limit` case; this fixes the hard-cap case).
            use super::grep_v2::compose::StructuralCombine;
            use super::grep_v2::structural::CombineFilter;
            let combine_filter: Option<CombineFilter> = match &combine {
                StructuralCombine::None => None,
                StructuralCombine::Literal {
                    text,
                    case_insensitive,
                } => Some(CombineFilter::Literal {
                    needle: text.clone().into_bytes(),
                    case_insensitive: *case_insensitive,
                }),
                StructuralCombine::Regex {
                    pattern,
                    case_insensitive,
                    multiline,
                } => {
                    let mut builder = regex::bytes::RegexBuilder::new(pattern);
                    builder.case_insensitive(*case_insensitive);
                    if *multiline {
                        builder.dot_matches_new_line(true).multi_line(true);
                    }
                    let re = builder.build().map_err(|e| {
                        ProtocolError::new(
                            ErrorCode::InvalidParams,
                            format!("`text` failed to compile as regex: {e}"),
                        )
                    })?;
                    Some(CombineFilter::Regex(re))
                }
            };

            // The user's `limit` bounds RETURNED matches. `combine` now
            // runs inline, so the only remaining post-scan filter is
            // `within_symbol`: give the scan headroom (the hard cap,
            // wall-clock bounded) when it's present and truncate to `limit`
            // afterward. Otherwise cap directly at `limit`.
            let scan_limit = if shared_filters.within_symbol.is_some() {
                super::grep_v2::limits::STRUCTURAL_MAX_ROWS
            } else {
                limit
            };

            let state_clone = state.clone();
            let root_owned = root.clone();
            let query_owned = query.clone();
            let languages_owned = languages.clone();
            let glob_owned = glob.clone();
            let files_owned = files.clone();
            let token_owned = token.clone();
            let combine_owned = combine_filter;
            let result = tokio::task::spawn_blocking(move || {
                super::grep_v2::structural::run(
                    &state_clone,
                    &root_owned,
                    &files_owned,
                    &query_owned,
                    &languages_owned,
                    glob_owned.as_ref(),
                    scan_limit,
                    combine_owned.as_ref(),
                    &token_owned,
                )
            })
            .await
            .map_err(|e| {
                ProtocolError::new(
                    ErrorCode::InternalError,
                    format!("structural::run join error: {e}"),
                )
            })?
            .map_err(|e| match e {
                super::grep_v2::structural::StructuralError::Cancelled => cancelled(),
                super::grep_v2::structural::StructuralError::AllLanguagesFailed(pfs) => {
                    let first = pfs
                        .first()
                        .map(|pf| format!("{}: {}", pf.language, pf.error))
                        .unwrap_or_else(|| "no languages compiled".to_string());
                    let pfs_json: Vec<_> = pfs
                        .iter()
                        .map(|pf| {
                            serde_json::json!({
                                "language": pf.language,
                                "error": pf.error,
                            })
                        })
                        .collect();
                    ProtocolError::new(
                        ErrorCode::InvalidParams,
                        format!(
                            "structural query failed to compile for any requested language: {first}"
                        ),
                    )
                    .with_data(serde_json::json!({
                        "code": super::grep_v2::GrepValidationCode::StructuralQueryInvalid.as_str(),
                        "partial_failures": pfs_json,
                    }))
                }
                super::grep_v2::structural::StructuralError::Timeout => ProtocolError::new(
                    ErrorCode::InvalidParams,
                    "structural query exceeded the wall-clock budget",
                )
                .with_data(serde_json::json!({
                    "code": super::grep_v2::GrepValidationCode::StructuralQueryTimeout.as_str(),
                    "budget_ms": super::grep_v2::limits::STRUCTURAL_WALL_CLOCK_MS,
                })),
            })?;

            // The `combine` (literal/regex) intersection filter is applied
            // inline during the scan (see `combine_filter` above and
            // issue #152), so `result.matches` already satisfies both the
            // structural query and the filter — no post-pass needed.
            let combine_filtered: Vec<_> = result.matches;

            // Apply within_symbol filter post-scan if requested.
            // Mirrors the literal/regex path's filter ordering.
            let mut final_matches: Vec<_> = if let Some(name) = &shared_filters.within_symbol {
                let defs = match store_arc.find_symbol(name) {
                    Ok(v) => v,
                    Err(e) => {
                        return Err(ProtocolError::new(
                            ErrorCode::InternalError,
                            format!("within_symbol lookup failed: {e}"),
                        ));
                    }
                };
                if defs.is_empty() {
                    return Err(super::grep_v2::GrepValidationError::new(
                        super::grep_v2::GrepValidationCode::WithinSymbolNotFound,
                        format!("`within_symbol`={name} resolved to zero defs"),
                    )
                    .into_protocol_error());
                }
                if defs.len() > super::grep_v2::WITHIN_SYMBOL_MAX_DEFS
                    && !shared_filters.within_symbol_allow_overload
                {
                    return Err(super::grep_v2::GrepValidationError::new(
                        super::grep_v2::GrepValidationCode::WithinSymbolTooManyDefs,
                        format!(
                            "`within_symbol`={name} resolved to {} defs (cap {}); set `within_symbol_allow_overload: true` to opt in",
                            defs.len(),
                            super::grep_v2::WITHIN_SYMBOL_MAX_DEFS
                        ),
                    )
                    .with_data("def_count", serde_json::Value::from(defs.len()))
                    .into_protocol_error());
                }
                // Filter: keep matches whose byte range lies inside
                // any resolved def's byte range AND in the same file.
                combine_filtered
                    .into_iter()
                    .filter(|m| {
                        defs.iter().any(|d| {
                            d.file == m.file
                                && m.start_byte >= d.start_byte
                                && m.end_byte <= d.end_byte
                        })
                    })
                    .collect()
            } else {
                combine_filtered
            };

            // Now that all post-scan filters have run, enforce the
            // user's `limit` on the RETURNED set (issue #147). When a
            // filter was applied the scan ran up to STRUCTURAL_MAX_ROWS,
            // so the filtered set may exceed `limit`; truncate here and
            // flag it. files_with_matches is recomputed from the final
            // set so it reflects what the caller actually receives.
            let post_filter_truncated = final_matches.len() > limit;
            if post_filter_truncated {
                final_matches.truncate(limit);
            }
            let truncated = result.truncated || post_filter_truncated;
            let files_with_matches = {
                let mut seen = std::collections::HashSet::new();
                final_matches
                    .iter()
                    .filter(|m| seen.insert(m.file.as_str()))
                    .count()
            };

            // Serialize structural matches to JSON.
            let match_records: Vec<serde_json::Value> = final_matches
                .iter()
                .map(|m| {
                    let captures_obj: serde_json::Map<String, serde_json::Value> = m
                        .captures
                        .iter()
                        .map(|(name, payloads)| {
                            let arr: Vec<serde_json::Value> = payloads
                                .iter()
                                .map(|p| {
                                    let mut obj = serde_json::Map::new();
                                    obj.insert(
                                        "start".into(),
                                        serde_json::json!({"line": p.start.line, "col": p.start.col}),
                                    );
                                    obj.insert(
                                        "end".into(),
                                        serde_json::json!({"line": p.end.line, "col": p.end.col}),
                                    );
                                    obj.insert(
                                        "text".into(),
                                        serde_json::Value::String(p.text.clone()),
                                    );
                                    if p.truncated {
                                        obj.insert(
                                            "truncated".into(),
                                            serde_json::Value::Bool(true),
                                        );
                                    }
                                    serde_json::Value::Object(obj)
                                })
                                .collect();
                            (name.clone(), serde_json::Value::Array(arr))
                        })
                        .collect();
                    serde_json::json!({
                        "file": m.file,
                        "range": {
                            "start_line": m.start_line,
                            "end_line":   m.end_line,
                            "start_byte": m.start_byte,
                            "end_byte":   m.end_byte,
                        },
                        "captures": captures_obj,
                    })
                })
                .collect();

            let pfs_json: Vec<_> = result
                .partial_failures
                .iter()
                .map(|pf| {
                    serde_json::json!({
                        "language": pf.language,
                        "error": pf.error,
                    })
                })
                .collect();

            return Ok(serde_json::json!({
                "matches": match_records,
                "truncated": truncated,
                "rows_seen": result.rows_seen,
                "rows_returned": final_matches.len(),
                "files_scanned": result.files_scanned,
                "files_with_matches": files_with_matches,
                "partial_failures": pfs_json,
            }));
        }
    };
    // Make the v1 unused-variables guard happy for the new fields
    // until U4-U7 consume them. Keeps the v1 hot path untouched.
    // `multiline` is consumed below to compute `end_line` for matches
    // that span newlines; `case_insensitive` is folded into the
    // scanner already.
    let _ = (
        &text_for_response,
        case_insensitive,
        &shared_filters.language,
    );

    // Compile `file_glob` (workspace-relative path matcher) before
    // mounting the index, same reason as the regex precompile above.
    let glob = match p.file_glob.as_deref() {
        Some(g) if g.is_empty() => {
            return Err(ProtocolError::new(
                ErrorCode::InvalidParams,
                "`file_glob` must be non-empty when provided",
            ));
        }
        Some(g) => {
            let glob = globset::Glob::new(g).map_err(|e| {
                ProtocolError::new(
                    ErrorCode::InvalidParams,
                    format!("`file_glob` failed to compile: {e}"),
                )
            })?;
            Some(glob.compile_matcher())
        }
        None => None,
    };

    let (root, store_arc) = snapshot(state)?;

    // v0.5.5: PageRank-based ranking. Same lazy-fetch shape
    // `find_callers` uses — `symbol_ranks_lazy` hits the cache
    // when warm and runs `compute_symbol_ranks` only on a generation
    // miss. Reading `index_generation` here (before the file walk)
    // upholds the Deepening §C TOCTOU invariant: cache lookups
    // observe a generation that's no newer than what the file walk
    // sees in subsequent `defs_in_file` reads.
    let generation = state.index_generation.load(Ordering::Relaxed);
    let ranks: Option<Arc<SymbolRanks>> = symbol_ranks_lazy(state, &store_arc, generation)?;

    // Pull the workspace-relative paths the writer has committed.
    let files = store_arc.list_indexed_files().map_err(|e| {
        ProtocolError::new(
            ErrorCode::InternalError,
            format!("list_indexed_files storage error: {e:#}"),
        )
    })?;

    let mut matches: Vec<serde_json::Value> = Vec::new();
    let mut files_scanned: usize = 0;
    let mut files_with_matches: usize = 0;
    let mut total_pre_truncate: usize = 0;
    let mut truncated_hit_cap = false;

    'files: for rel in &files {
        // Cooperative cancellation: per-file boundary. Covers both the
        // multiline-regex path (where a single file's scan is the
        // smallest interruptible unit — the `regex` DFA can't be
        // pre-empted mid-find) and the literal/single-line-regex paths
        // (where per-match checks below add a sub-millisecond ceiling).
        if token.is_cancelled() {
            return Err(cancelled());
        }
        // file_glob filter is path-only — applied before file read so
        // a tight glob (`crates/rts-core/**/*.rs`) keeps `files_scanned`
        // honest: we don't claim to have scanned files the user asked
        // us to skip.
        if let Some(g) = &glob {
            if !g.is_match(rel) {
                continue;
            }
        }

        // Resolve workspace-relative → absolute. Skip the file
        // silently if resolution fails (e.g. file deleted after
        // index but before this scan); the writer will catch up.
        let abs = match crate::path::resolve_workspace_path(&root, rel) {
            Ok((abs, _)) => abs,
            Err(_) => continue,
        };
        let bytes = match std::fs::read(&abs) {
            Ok(b) => b,
            Err(_) => continue,
        };
        files_scanned += 1;
        if bytes.len() > MAX_FILE_BYTES {
            continue;
        }

        // Per-file match collection. `scan_file` is `_ -> Vec<(byte_start, byte_end)>`
        // — both modes return concrete byte ranges into the original
        // `bytes` buffer so line-bounds resolution + line_text
        // extraction is identical.
        let hits = scanner.scan_file(&bytes);
        if hits.is_empty() {
            continue;
        }

        // v0.5.5: enclosing-symbol resolution. For each match, surface
        // the innermost def whose line range contains the match line
        // — same `pick_innermost_def` lookup `read_symbol_at` uses.
        // One redb txn per file with matches (not per match) keeps the
        // hot path O(files_with_matches), not O(matches). Files with
        // no indexed defs (yet — torn read, or a file the writer
        // hasn't extracted symbols from) return an empty Vec; matches
        // in those files surface with `enclosing_*: null`, same shape
        // as a match at file scope (top-level comment, module-level
        // statement).
        let defs = match store_arc.defs_in_file(rel) {
            Ok(v) => v,
            // Storage errors at this layer shouldn't fail the whole
            // query — the match data is still valid and the agent
            // can re-issue if needed. Log + continue with empty defs.
            Err(e) => {
                tracing::warn!(
                    target: "rts_daemon::grep",
                    error = %e,
                    file = %rel,
                    "defs_in_file failed; surfacing matches without enclosing"
                );
                Vec::new()
            }
        };

        let mut file_recorded = false;
        for (m_start, m_end) in hits {
            // Per-match cancellation check. For the multiline regex
            // path this is what bounds the abort latency *within* a
            // file (the per-file check at the top of the outer loop
            // only fires once per file). Literal-mode scans are fast
            // enough that the per-file check usually wins; the extra
            // load here is a relaxed atomic, ~1ns.
            if token.is_cancelled() {
                return Err(cancelled());
            }
            total_pre_truncate += 1;

            if matches.len() < limit {
                let (line_no, line_start, line_end) = find_line_bounds(&bytes, m_start);
                let raw_line = &bytes[line_start..line_end];
                let line_text = bytes_to_truncated_utf8(raw_line, MAX_LINE_BYTES);
                let one_based_line = (line_no + 1) as u32;
                // U3: when the regex spans newlines (`multiline: true`
                // with `.` matching `\n`), the match's end byte may
                // sit on a later line than the start. Compute the
                // end line from `m_end`; v1 single-line matches (and
                // every literal match) collapse `end_line` back to
                // `start_line` because `m_end` is inside the same
                // line as `m_start`.
                let one_based_end_line = if multiline && m_end > line_end {
                    let (end_line_no, _, _) = find_line_bounds(&bytes, m_end.saturating_sub(1));
                    (end_line_no + 1) as u32
                } else {
                    one_based_line
                };

                // Resolve enclosing def. `pick_innermost_def` returns
                // the smallest line-range def covering `one_based_line`,
                // breaking ties by `(span, start_byte)` for stable
                // output across calls. Matches at file scope (no def
                // covers them — module-level statements, top-of-file
                // comments) return `None` here, surfacing as nulls in
                // the wire response.
                let (enc_name, enc_kind, enc_def_range, rank_score) =
                    match pick_innermost_def(&defs, one_based_line) {
                        Some(d) => {
                            // v0.5.5: PageRank of the enclosing def.
                            // File-scope matches and cold-start (no
                            // ranks yet) collapse to 0.0 — same
                            // convention as `find_callers.rank_score`.
                            let r = match ranks.as_ref() {
                                Some(r) => r.rank_for(d.sid),
                                None => 0.0,
                            };
                            (
                                serde_json::Value::String(d.name.clone()),
                                serde_json::Value::String(d.kind.as_wire_str().to_string()),
                                serde_json::json!({
                                    "start_byte": d.start_byte,
                                    "end_byte":   d.end_byte,
                                    "start_line": d.start_line,
                                    "end_line":   d.end_line,
                                }),
                                r,
                            )
                        }
                        None => (
                            serde_json::Value::Null,
                            serde_json::Value::Null,
                            serde_json::Value::Null,
                            0.0,
                        ),
                    };

                matches.push(serde_json::json!({
                    "file": rel,
                    "range": {
                        "start_line": one_based_line,
                        "end_line":   one_based_end_line,
                        "start_byte": m_start as u32,
                        "end_byte":   m_end as u32,
                    },
                    "line_text": line_text,
                    // v0.5.5: enclosing-symbol fields. Same shape as
                    // `Index.FindCallers.callers[]` (modulo the rename
                    // from `kind` → `enclosing_kind` for clarity in a
                    // grep-result context, where bare `kind` would
                    // confuse the reader: "kind of what, the match?").
                    "enclosing_qualified_name": enc_name,
                    "enclosing_kind":           enc_kind,
                    "enclosing_def_range":      enc_def_range,
                    // v0.5.5: PageRank of the enclosing def. File-scope
                    // matches surface 0.0; same convention as
                    // `Index.FindCallers.callers[].rank_score`.
                    "rank_score":               rank_score,
                }));
                file_recorded = true;
            } else {
                truncated_hit_cap = true;
                // We've filled `matches`; further hits in this file
                // count toward `total_pre_truncate` (so `truncated`
                // reflects reality) but contribute no payload.
                // Stop scanning entirely — agents should narrow the
                // search instead of asking for more pages.
                break 'files;
            }
        }
        if file_recorded {
            files_with_matches += 1;
        }
    }

    // U4: within_symbol post-filter. Runs after collection (so the
    // store lookup is paid at most once per call, not per match) and
    // before the rank-score sort (so the response ordering remains
    // the documented "PageRank descending" shape). Strict containment
    // semantics — see `grep_v2::within_symbol` for the policy.
    //
    // Cardinality failures (`WITHIN_SYMBOL_NOT_FOUND`,
    // `WITHIN_SYMBOL_TOO_MANY_DEFS`) are surfaced as INVALID_PARAMS
    // envelopes per the plan; the filter never produces a partial
    // result on a name resolution failure.
    if let Some(name) = shared_filters.within_symbol.as_deref() {
        let ranges: Vec<super::grep_v2::WithinSymbolMatchRange> = matches
            .iter()
            .map(|m| super::grep_v2::WithinSymbolMatchRange {
                file: m["file"].as_str().unwrap_or("").to_string(),
                start_byte: m["range"]["start_byte"].as_u64().unwrap_or(0) as u32,
                end_byte: m["range"]["end_byte"].as_u64().unwrap_or(0) as u32,
            })
            .collect();
        let kept = super::grep_v2::resolve_and_filter_within_symbol(
            &store_arc,
            name,
            shared_filters.within_symbol_allow_overload,
            ranges,
        )
        .map_err(|e| e.into_protocol_error())?;
        // Re-index `matches` to only those whose (file, start_byte,
        // end_byte) survived the filter. Build a lookup set keyed on
        // (file, start_byte, end_byte) — matches are unique on that
        // tuple within a single response (a match is a concrete
        // byte slice).
        use std::collections::HashSet;
        let keep_keys: HashSet<(String, u32, u32)> = kept
            .into_iter()
            .map(|r| (r.file, r.start_byte, r.end_byte))
            .collect();
        let dropped_count = matches.len();
        matches.retain(|m| {
            let f = m["file"].as_str().unwrap_or("").to_string();
            let s = m["range"]["start_byte"].as_u64().unwrap_or(0) as u32;
            let e = m["range"]["end_byte"].as_u64().unwrap_or(0) as u32;
            keep_keys.contains(&(f, s, e))
        });
        // `files_with_matches` was computed during collection and is
        // now stale (a file may have contributed matches all of which
        // got filtered out). Recompute from the surviving matches.
        let surviving_files: HashSet<&str> =
            matches.iter().filter_map(|m| m["file"].as_str()).collect();
        files_with_matches = surviving_files.len();
        // Reflect the post-filter drop in the `truncated` accounting:
        // `total_pre_truncate` was counted pre-filter, so if the
        // filter dropped any rows we want the existing
        // `total_pre_truncate > matches.len()` clause to keep firing.
        // No mutation needed; just note the invariant.
        let _ = dropped_count;
    }

    let truncated = truncated_hit_cap || total_pre_truncate > matches.len();

    // v0.5.5: sort by enclosing-def PageRank, descending. Ties broken
    // by `(file, start_byte)` for stable cross-call ordering — same
    // shape `find_callers` uses. Matches without enclosing (file-scope
    // or cold-start) carry `rank_score == 0.0` and fall to the bottom.
    matches.sort_by(|a, b| {
        let ra = a["rank_score"].as_f64().unwrap_or(0.0);
        let rb = b["rank_score"].as_f64().unwrap_or(0.0);
        // total_cmp handles NaN safely; partial_cmp would panic on
        // NaN inputs (which shouldn't happen here, but defending in
        // depth is cheap).
        rb.total_cmp(&ra).then_with(|| {
            let af = a["file"].as_str().unwrap_or("");
            let bf = b["file"].as_str().unwrap_or("");
            let ab = a["range"]["start_byte"].as_u64().unwrap_or(0);
            let bb = b["range"]["start_byte"].as_u64().unwrap_or(0);
            af.cmp(bf).then(ab.cmp(&bb))
        })
    });

    Ok(serde_json::json!({
        "matches":            matches,
        "truncated":          truncated,
        "files_scanned":      files_scanned,
        "files_with_matches": files_with_matches,
    }))
}

// ---- v0.6 Index.Grep v2 structural × literal/regex intersection
// helpers (PR #110 Codex review C5). The structural scanner returns
// matches as byte-range coordinates; intersection with the literal
// or regex filter requires reading the file bytes at each match's
// range and testing the substring/pattern against that slice.

/// Helper: given byte offset `pos` into `bytes`, return
/// `(line_index_0_based, line_start_byte, line_end_byte_exclusive)`.
/// Stops the end at the newline or EOF, whichever comes first.
fn find_line_bounds(bytes: &[u8], pos: usize) -> (usize, usize, usize) {
    let pos = pos.min(bytes.len());
    // Count newlines in [0, pos) for the line number.
    let mut line_no = 0usize;
    let mut line_start = 0usize;
    for (i, b) in bytes[..pos].iter().enumerate() {
        if *b == b'\n' {
            line_no += 1;
            line_start = i + 1;
        }
    }
    // Find the end of the current line.
    let mut line_end = pos;
    while line_end < bytes.len() && bytes[line_end] != b'\n' {
        line_end += 1;
    }
    (line_no, line_start, line_end)
}

/// Helper: lossy-UTF8 a slice with truncation to `max_bytes`. The
/// truncation respects char boundaries via `String::from_utf8_lossy`
/// (replaces invalid sequences with U+FFFD).
fn bytes_to_truncated_utf8(bytes: &[u8], max_bytes: usize) -> String {
    let slice = if bytes.len() > max_bytes {
        &bytes[..max_bytes]
    } else {
        bytes
    };
    let mut s = String::from_utf8_lossy(slice).into_owned();
    if bytes.len() > max_bytes {
        s.push_str("…");
    }
    s
}

/// `Index.FindCallers(name)` — direct callers of a symbol. v0.3 U2'.
///
/// Wire shape:
/// ```jsonc
/// {
///   "callers": [
///     {
///       "enclosing_qualified_name": "rts_core::index::build_index", // null when caller_sid is None (file-scope ref)
///       "kind":  "fn",                                                // null when caller_sid is None
///       "file":  "src/index/mod.rs",
///       "range": { "start_line": 142, "end_line": 142,
///                  "start_byte": 4520, "end_byte": 4540 },           // the call site
///       "enclosing_def_range": {                                      // the caller's def range (null when caller_sid is None)
///         "start_line": 138, "end_line": 160,
///         "start_byte": 4400, "end_byte": 5200
///       },
///       "rank_score": 0.0                                             // placeholder until v0.3 U4
///     }
///   ],
///   "truncated": false
/// }
/// ```
///
/// Errors: `SYMBOL_NOT_FOUND` when no `NAME_TO_SID` entry; mirrors
/// `Index.FindSymbol`'s shape. Result is sorted by `(file, start_byte)`
/// for stable output across calls. The 256-entry cap (`MAX_CALLERS`)
/// matches `find_symbol`'s default `limit`.
///
/// Capability: `find_callers` (advertised in `Daemon.Ping` from
/// alpha.32 onward).
pub async fn find_callers(
    params: serde_json::Value,
    state: &Arc<DaemonState>,
    token: CancelToken,
) -> Result<serde_json::Value, ProtocolError> {
    const MAX_CALLERS: usize = 256;

    if token.is_cancelled() {
        return Err(cancelled());
    }
    let p: FindCallersParams = parse_params(params)?;
    if p.name.is_empty() || p.name.len() > 256 {
        return Err(ProtocolError::new(
            ErrorCode::InvalidParams,
            "`name` must be 1..=256 characters",
        ));
    }
    let kind_filter = p.kind.as_deref().map(SymbolKind::from_str_loose);
    let file_filter = p.file.as_deref();

    let (_root, store_arc) = snapshot(state)?;

    // v0.3 U4: read generation BEFORE any redb txn (Deepening §C).
    let generation = state.index_generation.load(Ordering::Relaxed);
    let ranks = symbol_ranks_lazy(state, &store_arc, generation)?;

    let callee_sid = match store_arc.sid_for_name(&p.name).map_err(|e| {
        ProtocolError::new(
            ErrorCode::InternalError,
            format!("sid_for_name storage error: {e:#}"),
        )
    })? {
        Some(s) => s,
        None => {
            return Err(ProtocolError::new(
                ErrorCode::SymbolNotFound,
                format!("no symbol named `{}` is indexed", p.name),
            ));
        }
    };

    let sites = store_arc.refs_to_symbol(callee_sid).map_err(|e| {
        ProtocolError::new(
            ErrorCode::InternalError,
            format!("refs_to_symbol storage error: {e:#}"),
        )
    })?;

    let mut callers: Vec<serde_json::Value> = Vec::with_capacity(sites.len().min(MAX_CALLERS));
    for site in &sites {
        let entry = match build_caller_entry(&store_arc, site, ranks.as_deref())? {
            Some(e) => e,
            None => continue, // path lookup failed (torn read); skip
        };

        // Filter by file (workspace-relative match).
        if let Some(filter) = file_filter {
            if entry.file != filter {
                continue;
            }
        }
        // Filter by kind. File-scope refs (caller_sid==None) have no
        // kind and are excluded when a kind filter is set.
        if let Some(filter) = kind_filter {
            if entry.kind != Some(filter) {
                continue;
            }
        }
        callers.push(entry.to_wire_value());
    }

    // Stable order: (file, start_byte). Matches the FindSymbol
    // convention of "predictable wire ordering across calls."
    callers.sort_by(|a, b| {
        let (af, ab) = (
            a["file"].as_str().unwrap_or(""),
            a["range"]["start_byte"].as_u64().unwrap_or(0),
        );
        let (bf, bb) = (
            b["file"].as_str().unwrap_or(""),
            b["range"]["start_byte"].as_u64().unwrap_or(0),
        );
        (af, ab).cmp(&(bf, bb))
    });

    let truncated = callers.len() > MAX_CALLERS;
    callers.truncate(MAX_CALLERS);

    Ok(serde_json::json!({
        "callers":   callers,
        "truncated": truncated,
    }))
}

/// Render the signature for a single resolved def, reusing the
/// shared `DaemonState::signature_cache` (keyed on `(path, byte
/// range, mtime)`). Returns `None` when the file can't be read, the
/// byte range is degenerate, or the language has no renderer.
///
/// Factored out of `find_symbol`'s inline loop so the verify-family
/// handlers (`verify_symbol` here; signature/import siblings next)
/// render a `matches[].signature` the same way `find_symbol`'s
/// `include_signature` path does — one rendering policy, one cache.
fn render_signature_for(
    state: &Arc<DaemonState>,
    root: &Path,
    found: &FoundSymbol,
) -> Option<String> {
    let abs = match crate::path::resolve_workspace_path(root, &found.file) {
        Ok((abs, _)) => abs,
        Err(_) => return None,
    };
    let (body_bytes, mtime_ns) = match std::fs::read(&abs).and_then(|b| {
        let meta = std::fs::metadata(&abs)?;
        let mtime_ns = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_nanos() as i128)
            .unwrap_or(0);
        Ok((b, mtime_ns))
    }) {
        Ok(v) => v,
        Err(_) => return None,
    };
    let (start, end) = (found.start_byte as usize, found.end_byte as usize);
    if !(end > start && end <= body_bytes.len()) {
        return None;
    }
    let slice = &body_bytes[start..end];
    state
        .signature_cache
        .get_or_compute(&abs, found.start_byte, found.end_byte, mtime_ns, || {
            crate::language::info_for_path(&found.file)
                .and_then(|info| info.signature_renderer)
                .and_then(|render| render(slice))
        })
}

/// Build the `(qualified_name, pagerank)` name pool that
/// `rust_tree_sitter::rank_candidates` consumes for "did you mean…"
/// near-miss ranking. Enumerates every indexed def name via the same
/// `find_symbols_batch_with_sids` path `find_symbol` uses (one read
/// txn, shared fid→path cache), renders each def's qualified name
/// (`parent::name`), and attaches its symbol-level PageRank from the
/// already-loaded `SymbolRanks` (0.0 when ranks are cold).
///
/// One entry per *def site*, not per name — an overloaded name shows
/// up once per def so a candidate in the right module/type can win the
/// PageRank tie-break. The verify-family siblings (import/claims)
/// reuse this verbatim for their own miss paths.
fn verify_candidate_pool(
    store: &Arc<Store>,
    ranks: Option<&Arc<SymbolRanks>>,
) -> Result<Vec<(String, f64)>, ProtocolError> {
    let all: Vec<String> = store
        .all_defined_names()
        .map_err(|e| {
            ProtocolError::new(
                ErrorCode::InternalError,
                format!("all_defined_names storage error: {e:#}"),
            )
        })?
        .into_iter()
        .collect();
    let batched = store.find_symbols_batch_with_sids(&all).map_err(|e| {
        ProtocolError::new(
            ErrorCode::InternalError,
            format!("find_symbols_batch_with_sids storage error: {e:#}"),
        )
    })?;
    let mut pool: Vec<(String, f64)> = Vec::with_capacity(batched.len());
    for (_name, (sid, hits)) in batched {
        let rank = sid
            .and_then(|s| ranks.map(|r| r.rank_for(s)))
            .unwrap_or(0.0);
        for h in hits {
            pool.push((render_qualified_name(&h.name, h.parent.as_deref()), rank));
        }
    }
    Ok(pool)
}

/// `Index.VerifySymbol(name, kind?, lang?, file?, content_version?)`
/// — verify-v0 P1.U1, capability `verify_symbol`.
///
/// Answers "does this symbol exist?" with precision over recall:
/// never a confident wrong answer. A miss is a RESULT, not an error —
/// the handler returns `exists:false` and a ranked `candidates[]`
/// shortlist so the agent can self-correct an invented name.
///
/// Wire shape:
/// ```jsonc
/// {
///   "exists": true,
///   "resolution": "exact",            // exact | not_found | indeterminate
///   "reason": "ambiguous_overload",   // present ONLY on indeterminate
///   "matches": [ { "qualified_name": "...", "kind": "method",
///                  "file": "...", "line": 242,
///                  "signature": "fn ...", "pagerank": 0.0143 } ],
///   "candidates": [ { "qualified_name": "...", "edit_distance": 2,
///                     "pagerank": 0.0102 } ],   // miss only
///   "content_version": "…"
/// }
/// ```
///
/// Resolution rules:
/// - ≥1 def after filters → `exists:true, "exact"`.
/// - filters leave multiple defs and neither `file` nor `kind`
///   disambiguates → `exists:true, "indeterminate",
///   reason:"ambiguous_overload"` (still lists all `matches`).
/// - no def → `exists:false, "not_found"`, ranked `candidates[]`.
///
/// `content_version` always echoes: the matched file's version on a
/// hit, else the index generation. `INVALID_PARAMS` on empty/oversize
/// `name`. Walks the full name pool on a miss → cancellable.
pub async fn verify_symbol(
    params: serde_json::Value,
    state: &Arc<DaemonState>,
    token: CancelToken,
) -> Result<serde_json::Value, ProtocolError> {
    if token.is_cancelled() {
        return Err(cancelled());
    }
    let p: VerifySymbolParams = parse_params(params)?;
    if p.name.is_empty() || p.name.len() > 256 {
        return Err(ProtocolError::new(
            ErrorCode::InvalidParams,
            "`name` must be 1..=256 characters",
        ));
    }

    let (root, store_arc) = snapshot(state)?;
    // Read generation BEFORE any read txn (Deepening §C cache invariant).
    let generation = state.index_generation.load(Ordering::Relaxed);
    let ranks = symbol_ranks_lazy(state, &store_arc, generation)?;
    let ctx = VerifyCtx {
        root: &root,
        store: &store_arc,
        generation,
        ranks: ranks.as_ref(),
    };
    verify_symbol_inner(&p, state, &ctx, &token)
}

/// Resolved per-call context shared by the verify-family inner fns.
/// Snapshotted once by each JSON-RPC entrypoint (and once per batch by
/// `verify_claims`), then threaded into the reusable inner logic so
/// U4 composes U1–U3 without re-dispatching through the wire layer.
struct VerifyCtx<'a> {
    root: &'a Path,
    store: &'a Arc<Store>,
    generation: u64,
    ranks: Option<&'a Arc<SymbolRanks>>,
}

/// Reusable core of `Index.VerifySymbol`. Assumes `p.name` is already
/// validated (1..=256 chars). Pure resolution logic over the resolved
/// `ctx`; the public handler owns snapshot + validation, `verify_claims`
/// calls this directly per `{type:"symbol"}` claim.
fn verify_symbol_inner(
    p: &VerifySymbolParams,
    state: &Arc<DaemonState>,
    ctx: &VerifyCtx<'_>,
    token: &CancelToken,
) -> Result<serde_json::Value, ProtocolError> {
    /// Near-miss candidate count surfaced on a `not_found`.
    const CANDIDATE_LIMIT: usize = 5;

    let root = ctx.root;
    let store_arc = ctx.store;
    let generation = ctx.generation;
    let ranks = ctx.ranks.cloned();

    let kind_filter = p.kind.as_deref().map(SymbolKind::from_str_loose);
    let file_filter = p.file.as_deref();

    // Resolve the name. The stored key is the bare name; when the
    // caller passes a qualified name (`Store::commit_batch`) we also
    // try its final `::`-segment so qualified inputs resolve.
    let bare = p.name.rsplit("::").next().unwrap_or(&p.name).to_string();
    let mut lookup_names: Vec<String> = vec![p.name.clone()];
    if bare != p.name {
        lookup_names.push(bare.clone());
    }
    let mut batched = store_arc
        .find_symbols_batch_with_sids(&lookup_names)
        .map_err(|e| {
            ProtocolError::new(
                ErrorCode::InternalError,
                format!("find_symbols_batch_with_sids storage error: {e:#}"),
            )
        })?;
    // Take the first lookup name that resolved to ≥1 def.
    let mut hits: Vec<FoundSymbol> = Vec::new();
    for n in &lookup_names {
        if let Some((_sid, found)) = batched.remove(n) {
            if !found.is_empty() {
                hits = found;
                break;
            }
        }
    }

    // When the caller passed a QUALIFIED name (`Foo::new`), the bare-segment
    // fallback above resolved every `new` in the index — so we must narrow to
    // hits whose immediate container actually matches the qualifier, or we'd
    // confirm `Foo::new` exists when only `Bar::new` does (a false positive).
    // The store tracks only the immediate parent, so we match that segment; a
    // free function (`parent: None`) never satisfies a qualified claim.
    let qualifier: Option<String> = if p.name.contains("::") {
        let mut segs: Vec<&str> = p.name.split("::").collect();
        segs.pop(); // drop the final (bare) segment
        segs.into_iter()
            .rev()
            .find(|s| !s.is_empty())
            .map(str::to_string)
    } else {
        None
    };

    // Apply optional kind/file filters plus the qualifier narrowing above.
    let filtered: Vec<FoundSymbol> = hits
        .into_iter()
        .filter(|h| kind_filter.map(|k| h.kind == k).unwrap_or(true))
        .filter(|h| file_filter.map(|f| h.file == f).unwrap_or(true))
        .filter(|h| match &qualifier {
            Some(q) => h.parent.as_deref() == Some(q.as_str()),
            None => true,
        })
        .collect();

    // Echo `content_version`: the matched file's version on a hit
    // (first match's file), else the index generation. We keep the
    // caller's echoed value out of the response unless we have nothing
    // better — the wire field is the daemon's view, not the agent's.
    let content_version_for = |found: Option<&FoundSymbol>| -> String {
        match found {
            Some(h) => match crate::path::resolve_workspace_path(root, &h.file) {
                Ok((abs, _)) => match std::fs::read(&abs).ok().and_then(|bytes| {
                    let meta = std::fs::metadata(&abs).ok()?;
                    let mtime_ns = meta
                        .modified()
                        .ok()
                        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                        .map(|d| d.as_nanos() as i128)
                        .unwrap_or(0);
                    Some(content_version(&bytes, mtime_ns, generation))
                }) {
                    Some(cv) => cv,
                    None => format!("@{generation}"),
                },
                Err(_) => format!("@{generation}"),
            },
            None => p
                .content_version
                .clone()
                .unwrap_or_else(|| format!("@{generation}")),
        }
    };

    if filtered.is_empty() {
        // MISS. Build the ranked near-miss shortlist. This walks the
        // whole name pool, so poll the cancel token first.
        if token.is_cancelled() {
            return Err(cancelled());
        }
        let pool = verify_candidate_pool(store_arc, ranks.as_ref())?;
        let candidates =
            rust_tree_sitter::rank_candidates(&bare, pool.into_iter(), CANDIDATE_LIMIT);
        let candidates_json: Vec<serde_json::Value> = candidates
            .into_iter()
            .map(|c| {
                serde_json::json!({
                    "qualified_name": c.qualified_name,
                    "edit_distance":  c.edit_distance,
                    "pagerank":       c.pagerank,
                })
            })
            .collect();
        return Ok(serde_json::json!({
            "exists":          false,
            "resolution":      rust_tree_sitter::Resolution::NotFound,
            "matches":         [],
            "candidates":      candidates_json,
            "content_version": content_version_for(None),
        }));
    }

    // HIT (one or more defs survived the filters). Render each as a
    // `matches[]` entry. Stable order: (file, start_byte).
    let mut survivors = filtered;
    survivors.sort_by(|a, b| a.file.cmp(&b.file).then(a.start_byte.cmp(&b.start_byte)));

    let matches: Vec<serde_json::Value> = survivors
        .iter()
        .map(|h| {
            let pagerank = ranks.as_ref().map(|r| r.rank_for(h.sid)).unwrap_or(0.0);
            let signature = render_signature_for(state, root, h);
            serde_json::json!({
                "qualified_name": render_qualified_name(&h.name, h.parent.as_deref()),
                "kind":           h.kind.as_wire_str(),
                "file":           h.file,
                "line":           h.start_line,
                "signature":      signature,
                "pagerank":       pagerank,
            })
        })
        .collect();

    let content_version = content_version_for(survivors.first());

    // Ambiguous when multiple defs survive AND no filter narrowed to
    // one. With a `file` or `kind` filter that already selected a
    // single def we'd be in the single-match branch; if multiple defs
    // share the same file+kind, that's still genuinely ambiguous.
    if survivors.len() > 1 {
        return Ok(serde_json::json!({
            "exists":          true,
            "resolution":      rust_tree_sitter::Resolution::Indeterminate,
            "reason":          rust_tree_sitter::IndeterminateReason::AmbiguousOverload,
            "matches":         matches,
            "candidates":      [],
            "content_version": content_version,
        }));
    }

    Ok(serde_json::json!({
        "exists":          true,
        "resolution":      rust_tree_sitter::Resolution::Exact,
        "matches":         matches,
        "candidates":      [],
        "content_version": content_version,
    }))
}

/// Find the indexed def's ACTUAL `SignatureShape` by reading its file,
/// parsing it, locating the function/method node that covers the def's
/// byte range, and running `signature_shape`.
///
/// Returns `Ok(Some(shape))` on a decided shape, `Ok(None)` when the
/// language is unsupported, the file can't be read/parsed, no def node
/// covers the range, or the shape is undecidable (variadics) — every
/// one of those collapses to an `indeterminate` verify result. The
/// language is mapped from the def's file path via `info_for_path`
/// (the same registry the writer and `find_symbol` use).
fn actual_signature_shape(
    root: &Path,
    found: &FoundSymbol,
) -> Option<rust_tree_sitter::SignatureShape> {
    use rust_tree_sitter::Parser;

    let info = crate::language::info_for_path(&found.file)?;
    let lang = info.language;

    let abs = crate::path::resolve_workspace_path(root, &found.file)
        .ok()
        .map(|(abs, _)| abs)?;
    let src = std::fs::read(&abs).ok()?;

    // Parse the whole file (the def's byte offsets are file-relative).
    let src_str = std::str::from_utf8(&src).ok()?;
    let parser = Parser::new(lang).ok()?;
    let tree = parser.parse(src_str, None).ok()?;

    // Locate the def node: the deepest function/method node whose byte
    // range contains the def's start byte. The writer's def range can
    // be slightly wider/narrower than tree-sitter's node (attributes,
    // doc comments), so we anchor on `start_byte` containment and pick
    // the innermost recognised def kind.
    let target = found.start_byte as usize;
    let root_node = tree.root_node().inner();
    let def_node = find_def_node(root_node, target)?;
    rust_tree_sitter::signature_shape(def_node, &src, lang)
}

/// Depth-first search for the innermost tree-sitter node of a
/// recognised function/method-definition kind whose byte range covers
/// `offset`. Returns the deepest such node so a method inside an impl
/// wins over its enclosing item.
fn find_def_node(
    node: rust_tree_sitter::tree_sitter::Node<'_>,
    offset: usize,
) -> Option<rust_tree_sitter::tree_sitter::Node<'_>> {
    /// Kinds `signature_shape` recognises across Rust / TS / Python.
    const DEF_KINDS: &[&str] = &[
        "function_item",
        "function_signature_item",
        "function_declaration",
        "function_signature",
        "method_definition",
        "method_signature",
        "generator_function_declaration",
        "function_definition",
    ];

    if offset < node.start_byte() || offset >= node.end_byte() {
        return None;
    }
    // Recurse first so a nested def (deeper) is preferred over `node`.
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if let Some(found) = find_def_node(child, offset) {
            return Some(found);
        }
    }
    if DEF_KINDS.contains(&node.kind()) {
        return Some(node);
    }
    None
}

/// `Index.VerifySignature(name, kind?, lang?, file?, claimed{arity,
/// params, returns?})` — verify-v0 P1.U2, capability `verify_signature`.
///
/// Resolves the indexed def (same lookup as `Index.VerifySymbol`), reads
/// the def's actual `SignatureShape`, and reports whether the claim
/// matches plus a structured `diff[]`.
///
/// Wire shape (hit, decidable):
/// ```jsonc
/// { "match": false, "resolution": "exact",
///   "actual": { "arity": 1, "params": ["entries"], "returns": "Result<()>" },
///   "diff": [ { "issue": "arity", "claimed": 2, "actual": 1 },
///             { "issue": "unknown_param", "name": "flush" } ],
///   "content_version": "…" }
/// ```
/// `diff[]` issue kinds: `arity`, `unknown_param`, `param_order`,
/// `return_shape`. When `signature_shape` can't decide (variadics /
/// unsupported language) → `resolution:"indeterminate"`, `reason` set,
/// `match` OMITTED. When the symbol doesn't exist → `resolution:
/// "not_found"`, `exists:false`, ranked `candidates[]`.
pub async fn verify_signature(
    params: serde_json::Value,
    state: &Arc<DaemonState>,
    token: CancelToken,
) -> Result<serde_json::Value, ProtocolError> {
    if token.is_cancelled() {
        return Err(cancelled());
    }
    let p: VerifySignatureParams = parse_params(params)?;
    if p.name.is_empty() || p.name.len() > 256 {
        return Err(ProtocolError::new(
            ErrorCode::InvalidParams,
            "`name` must be 1..=256 characters",
        ));
    }

    let (root, store_arc) = snapshot(state)?;
    let generation = state.index_generation.load(Ordering::Relaxed);
    let ranks = symbol_ranks_lazy(state, &store_arc, generation)?;
    let ctx = VerifyCtx {
        root: &root,
        store: &store_arc,
        generation,
        ranks: ranks.as_ref(),
    };
    verify_signature_inner(&p, &ctx, &token)
}

/// Reusable core of `Index.VerifySignature`. Assumes `p.name` validated.
fn verify_signature_inner(
    p: &VerifySignatureParams,
    ctx: &VerifyCtx<'_>,
    token: &CancelToken,
) -> Result<serde_json::Value, ProtocolError> {
    /// Near-miss candidate count surfaced on a `not_found`.
    const CANDIDATE_LIMIT: usize = 5;

    let root = ctx.root;
    let store_arc = ctx.store;

    let kind_filter = p.kind.as_deref().map(SymbolKind::from_str_loose);
    let file_filter = p.file.as_deref();

    // Resolve the def (reuse U1's bare/qualified lookup).
    let bare = p.name.rsplit("::").next().unwrap_or(&p.name).to_string();
    let mut lookup_names: Vec<String> = vec![p.name.clone()];
    if bare != p.name {
        lookup_names.push(bare.clone());
    }
    let mut batched = store_arc
        .find_symbols_batch_with_sids(&lookup_names)
        .map_err(|e| {
            ProtocolError::new(
                ErrorCode::InternalError,
                format!("find_symbols_batch_with_sids storage error: {e:#}"),
            )
        })?;
    let mut hits: Vec<FoundSymbol> = Vec::new();
    for n in &lookup_names {
        if let Some((_sid, found)) = batched.remove(n) {
            if !found.is_empty() {
                hits = found;
                break;
            }
        }
    }
    let filtered: Vec<FoundSymbol> = hits
        .into_iter()
        .filter(|h| kind_filter.map(|k| h.kind == k).unwrap_or(true))
        .filter(|h| file_filter.map(|f| h.file == f).unwrap_or(true))
        .collect();

    // MISS → not_found + candidates (reuse U1's pool).
    if filtered.is_empty() {
        if token.is_cancelled() {
            return Err(cancelled());
        }
        let pool = verify_candidate_pool(store_arc, ctx.ranks)?;
        let candidates =
            rust_tree_sitter::rank_candidates(&bare, pool.into_iter(), CANDIDATE_LIMIT);
        let candidates_json: Vec<serde_json::Value> = candidates
            .into_iter()
            .map(|c| {
                serde_json::json!({
                    "qualified_name": c.qualified_name,
                    "edit_distance":  c.edit_distance,
                    "pagerank":       c.pagerank,
                })
            })
            .collect();
        return Ok(serde_json::json!({
            "exists":     false,
            "resolution": rust_tree_sitter::Resolution::NotFound,
            "candidates": candidates_json,
        }));
    }

    // Multiple surviving defs with no disambiguating filter → we can't
    // decide WHICH def the claim is about. Honest answer: indeterminate.
    if filtered.len() > 1 {
        return Ok(serde_json::json!({
            "resolution": rust_tree_sitter::Resolution::Indeterminate,
            "reason":     rust_tree_sitter::IndeterminateReason::AmbiguousOverload,
        }));
    }

    let def = &filtered[0];

    // Get the ACTUAL shape. `None` (unsupported lang / unparseable /
    // variadic) → indeterminate, `match` omitted.
    let actual = match actual_signature_shape(root, def) {
        Some(s) => s,
        None => {
            return Ok(serde_json::json!({
                "resolution": rust_tree_sitter::Resolution::Indeterminate,
                "reason":     rust_tree_sitter::IndeterminateReason::UndecidableSignature,
            }));
        }
    };

    // Build the structured diff.
    let claimed = &p.claimed;
    let mut diff: Vec<serde_json::Value> = Vec::new();

    if claimed.arity != actual.arity {
        diff.push(serde_json::json!({
            "issue":   "arity",
            "claimed": claimed.arity,
            "actual":  actual.arity,
        }));
    }

    // `unknown_param`: a claimed param name not present in the actual
    // param set. One diff entry per offending name.
    for cp in &claimed.params {
        if !actual.params.contains(cp) {
            diff.push(serde_json::json!({
                "issue": "unknown_param",
                "name":  cp,
            }));
        }
    }

    // `param_order`: same SET of names, different order. Only meaningful
    // when neither side has an unknown param (the sets are equal) and
    // the ordered lists differ.
    {
        use std::collections::BTreeSet;
        let claimed_set: BTreeSet<&String> = claimed.params.iter().collect();
        let actual_set: BTreeSet<&String> = actual.params.iter().collect();
        if claimed_set == actual_set && claimed.params != actual.params {
            diff.push(serde_json::json!({
                "issue":   "param_order",
                "claimed": claimed.params,
                "actual":  actual.params,
            }));
        }
    }

    // `return_shape`: the caller asserted a return type, so flag it if the
    // actual differs OR the actual has none at all (claiming `-> u32` for a
    // `-> ()` fn is a mismatch, not a match). A caller that omits `returns`
    // asserts nothing about it, so claimed-None is never a mismatch.
    if let Some(cr) = claimed.returns.as_ref() {
        if actual.returns.as_deref() != Some(cr.as_str()) {
            diff.push(serde_json::json!({
                "issue":   "return_shape",
                "claimed": cr,
                "actual":  actual.returns,  // null when the def declares no return
            }));
        }
    }

    let matched = diff.is_empty();
    Ok(serde_json::json!({
        "match":      matched,
        "resolution": rust_tree_sitter::Resolution::Exact,
        "actual": {
            "arity":   actual.arity,
            "params":  actual.params,
            "returns": actual.returns,
        },
        "diff":       diff,
    }))
}

/// `Index.VerifyImport(path, lang?)` — verify-v0 P1.U3, capability
/// `verify_import`. THIN: resolves only the FINAL `::`-segment of `path`
/// against the index. Real cross-module path resolution (validating
/// each intermediate segment forms a real module chain) is deferred to
/// its own plan — this tool never claims a confident `not_found` for a
/// path whose intermediate segments it cannot decide.
///
/// Wire shape:
/// ```jsonc
/// { "resolves": true, "resolution": "exact" }              // final seg present
/// { "resolves": false, "resolution": "not_found",
///   "candidates": [ … ] }                                   // decidably absent
/// { "resolution": "indeterminate", "reason": "unresolved_ref" } // can't decide
/// ```
pub async fn verify_import(
    params: serde_json::Value,
    state: &Arc<DaemonState>,
    token: CancelToken,
) -> Result<serde_json::Value, ProtocolError> {
    if token.is_cancelled() {
        return Err(cancelled());
    }
    let p: VerifyImportParams = parse_params(params)?;
    if p.path.is_empty() || p.path.len() > 1024 {
        return Err(ProtocolError::new(
            ErrorCode::InvalidParams,
            "`path` must be 1..=1024 characters",
        ));
    }

    let (root, store_arc) = snapshot(state)?;
    let generation = state.index_generation.load(Ordering::Relaxed);
    let ranks = symbol_ranks_lazy(state, &store_arc, generation)?;
    let ctx = VerifyCtx {
        root: &root,
        store: &store_arc,
        generation,
        ranks: ranks.as_ref(),
    };
    verify_import_inner(&p, &ctx, &token)
}

/// Reusable core of `Index.VerifyImport`. Assumes `p.path` validated.
fn verify_import_inner(
    p: &VerifyImportParams,
    ctx: &VerifyCtx<'_>,
    token: &CancelToken,
) -> Result<serde_json::Value, ProtocolError> {
    /// Near-miss candidate count surfaced on a `not_found`.
    const CANDIDATE_LIMIT: usize = 5;

    let store_arc = ctx.store;

    // Split on `::` (Rust) AND `.` (TS/Python dotted paths) so the
    // "final segment" notion holds across the languages we index.
    let final_seg = p
        .path
        .rsplit([':', '.'])
        .find(|s| !s.is_empty())
        .unwrap_or(p.path.as_str())
        .to_string();

    if final_seg.is_empty() {
        return Ok(serde_json::json!({
            "resolution": rust_tree_sitter::Resolution::Indeterminate,
            "reason":     rust_tree_sitter::IndeterminateReason::UnresolvedRef,
        }));
    }

    // Is the final segment present as a def (module/type/symbol)?
    let sid = store_arc.sid_for_name(&final_seg).map_err(|e| {
        ProtocolError::new(
            ErrorCode::InternalError,
            format!("sid_for_name storage error: {e:#}"),
        )
    })?;

    if sid.is_some() {
        return Ok(serde_json::json!({
            "resolves":   true,
            "resolution": rust_tree_sitter::Resolution::Exact,
        }));
    }

    // The final segment is absent. We can only confidently report
    // `not_found` for a SINGLE-segment path (no intermediates to
    // resolve) — a bare name that simply isn't indexed. For a
    // multi-segment path, the intermediates might name an external
    // crate / module we never indexed, so deciding `not_found` would
    // risk a confident false negative: report `indeterminate` instead
    // and defer real path resolution.
    let segments: Vec<&str> = p.path.split([':', '.']).filter(|s| !s.is_empty()).collect();

    if segments.len() <= 1 {
        // Single segment, decidably absent → not_found + candidates.
        if token.is_cancelled() {
            return Err(cancelled());
        }
        let pool = verify_candidate_pool(store_arc, ctx.ranks)?;
        let candidates =
            rust_tree_sitter::rank_candidates(&final_seg, pool.into_iter(), CANDIDATE_LIMIT);
        let candidates_json: Vec<serde_json::Value> = candidates
            .into_iter()
            .map(|c| {
                serde_json::json!({
                    "qualified_name": c.qualified_name,
                    "edit_distance":  c.edit_distance,
                    "pagerank":       c.pagerank,
                })
            })
            .collect();
        return Ok(serde_json::json!({
            "resolves":   false,
            "resolution": rust_tree_sitter::Resolution::NotFound,
            "candidates": candidates_json,
        }));
    }

    // Multi-segment path whose final segment is absent. We still offer
    // a candidate shortlist (the agent may have a typo) but DO NOT
    // claim `not_found` — the path may cross into un-indexed modules.
    if token.is_cancelled() {
        return Err(cancelled());
    }
    let pool = verify_candidate_pool(store_arc, ctx.ranks)?;
    let candidates =
        rust_tree_sitter::rank_candidates(&final_seg, pool.into_iter(), CANDIDATE_LIMIT);
    let candidates_json: Vec<serde_json::Value> = candidates
        .into_iter()
        .map(|c| {
            serde_json::json!({
                "qualified_name": c.qualified_name,
                "edit_distance":  c.edit_distance,
                "pagerank":       c.pagerank,
            })
        })
        .collect();
    Ok(serde_json::json!({
        "resolution": rust_tree_sitter::Resolution::Indeterminate,
        "reason":     rust_tree_sitter::IndeterminateReason::UnresolvedRef,
        "candidates": candidates_json,
    }))
}

/// `Index.VerifyClaims(claims[])` — verify-v0 P1.U4, capability
/// `verify_claims`. Batch verification of a heterogeneous claim list,
/// composing U1/U2/U3 inner logic + a local location check.
///
/// Wire shape:
/// ```jsonc
/// { "results": [ { "ok": true, … }, { "ok": false, … } ],
///   "grounded": 2, "total": 3, "grounding_rate": 0.667 }
/// ```
///
/// **Decidability rule:** `indeterminate` results are EXCLUDED from both
/// `grounded` and `total` (the denominator is decidable claims only).
/// `grounding_rate = grounded/total`, and is `null` (not NaN) when
/// `total == 0`.
pub async fn verify_claims(
    params: serde_json::Value,
    state: &Arc<DaemonState>,
    token: CancelToken,
) -> Result<serde_json::Value, ProtocolError> {
    /// Hard cap on batch size — a runaway claim list is a tooling bug.
    const MAX_CLAIMS: usize = 256;

    if token.is_cancelled() {
        return Err(cancelled());
    }
    let p: VerifyClaimsParams = parse_params(params)?;
    if p.claims.len() > MAX_CLAIMS {
        return Err(ProtocolError::new(
            ErrorCode::InvalidParams,
            format!("`claims` length {} exceeds {MAX_CLAIMS}", p.claims.len()),
        ));
    }

    // Snapshot ONCE for the whole batch (Deepening §C: read generation
    // before any read txn). Every inner call reuses this context.
    let (root, store_arc) = snapshot(state)?;
    let generation = state.index_generation.load(Ordering::Relaxed);
    let ranks = symbol_ranks_lazy(state, &store_arc, generation)?;
    let ctx = VerifyCtx {
        root: &root,
        store: &store_arc,
        generation,
        ranks: ranks.as_ref(),
    };

    let mut results: Vec<serde_json::Value> = Vec::with_capacity(p.claims.len());
    let mut grounded: u64 = 0;
    let mut total: u64 = 0;

    for claim in &p.claims {
        if token.is_cancelled() {
            return Err(cancelled());
        }
        // Run the matching inner verifier, then map its resolution to
        // an `ok` / decidability verdict. `indeterminate` results are
        // excluded from BOTH numerator and denominator.
        let (inner, ok): (serde_json::Value, ClaimVerdict) = match claim {
            ClaimItem::Symbol {
                name,
                kind,
                lang,
                file,
            } => {
                if name.is_empty() || name.len() > 256 {
                    (
                        serde_json::json!({ "error": "`name` must be 1..=256 characters" }),
                        ClaimVerdict::Indeterminate,
                    )
                } else {
                    let sp = VerifySymbolParams {
                        name: name.clone(),
                        kind: kind.clone(),
                        lang: lang.clone(),
                        file: file.clone(),
                        content_version: None,
                    };
                    let v = verify_symbol_inner(&sp, state, &ctx, &token)?;
                    let verdict = verdict_from_resolution(
                        &v,
                        v.get("exists").and_then(|e| e.as_bool()).unwrap_or(false),
                    );
                    (v, verdict)
                }
            }
            ClaimItem::Signature {
                name,
                kind,
                lang,
                file,
                claimed,
            } => {
                if name.is_empty() || name.len() > 256 {
                    (
                        serde_json::json!({ "error": "`name` must be 1..=256 characters" }),
                        ClaimVerdict::Indeterminate,
                    )
                } else {
                    let sp = VerifySignatureParams {
                        name: name.clone(),
                        kind: kind.clone(),
                        lang: lang.clone(),
                        file: file.clone(),
                        claimed: claimed.clone(),
                    };
                    let v = verify_signature_inner(&sp, &ctx, &token)?;
                    // A signature claim is grounded iff `match: true`.
                    let matched = v.get("match").and_then(|m| m.as_bool()).unwrap_or(false);
                    let verdict = verdict_from_resolution(&v, matched);
                    (v, verdict)
                }
            }
            ClaimItem::Import { path, lang } => {
                if path.is_empty() || path.len() > 1024 {
                    (
                        serde_json::json!({ "error": "`path` must be 1..=1024 characters" }),
                        ClaimVerdict::Indeterminate,
                    )
                } else {
                    let ip = VerifyImportParams {
                        path: path.clone(),
                        lang: lang.clone(),
                    };
                    let v = verify_import_inner(&ip, &ctx, &token)?;
                    let resolves = v.get("resolves").and_then(|r| r.as_bool()).unwrap_or(false);
                    let verdict = verdict_from_resolution(&v, resolves);
                    (v, verdict)
                }
            }
            ClaimItem::Location {
                symbol,
                file,
                line,
                kind,
            } => verify_location(&ctx, symbol, file, *line, kind.as_deref())?,
        };

        let (ok_field, counts_toward_total): (serde_json::Value, bool) = match ok {
            ClaimVerdict::Grounded => {
                grounded += 1;
                total += 1;
                (serde_json::Value::Bool(true), true)
            }
            ClaimVerdict::NotGrounded => {
                total += 1;
                (serde_json::Value::Bool(false), true)
            }
            // Indeterminate: excluded from BOTH grounded and total.
            ClaimVerdict::Indeterminate => (serde_json::Value::Null, false),
        };
        let _ = counts_toward_total;

        let mut entry = serde_json::Map::new();
        entry.insert("ok".into(), ok_field);
        if let serde_json::Value::Object(map) = inner {
            for (k, v) in map {
                entry.insert(k, v);
            }
        } else {
            entry.insert("detail".into(), inner);
        }
        results.push(serde_json::Value::Object(entry));
    }

    // `grounding_rate` is `null` (not NaN) when the denominator is 0.
    let grounding_rate: serde_json::Value = if total == 0 {
        serde_json::Value::Null
    } else {
        serde_json::json!((grounded as f64) / (total as f64))
    };

    Ok(serde_json::json!({
        "results":        results,
        "grounded":       grounded,
        "total":          total,
        "grounding_rate": grounding_rate,
    }))
}

/// Decidability verdict for one claim in a `verify_claims` batch.
enum ClaimVerdict {
    /// Decidable AND the claim held (counts toward `grounded` + `total`).
    Grounded,
    /// Decidable AND the claim failed (counts toward `total` only).
    NotGrounded,
    /// Undecidable — excluded from both `grounded` and `total`.
    Indeterminate,
}

/// Map an inner verify result's `resolution` (+ a pre-computed
/// "claim held?" boolean) to a `ClaimVerdict`. `indeterminate` always
/// wins (excluded from the denominator); otherwise the verdict follows
/// the held flag.
fn verdict_from_resolution(v: &serde_json::Value, held: bool) -> ClaimVerdict {
    match v.get("resolution").and_then(|r| r.as_str()) {
        Some("indeterminate") => ClaimVerdict::Indeterminate,
        _ if held => ClaimVerdict::Grounded,
        _ => ClaimVerdict::NotGrounded,
    }
}

/// `location` claim check (verify-v0 P1.U4): the symbol's indexed def is
/// at the claimed `file` AND the claimed `line` falls within the def's
/// line range. Resolution mirrors the other verifiers: a missing symbol
/// is `not_found` (decidable miss); an ambiguous overload that no
/// `file`/`kind` filter narrows is `indeterminate`.
fn verify_location(
    ctx: &VerifyCtx<'_>,
    symbol: &str,
    file: &str,
    line: u32,
    kind: Option<&str>,
) -> Result<(serde_json::Value, ClaimVerdict), ProtocolError> {
    let store_arc = ctx.store;
    let kind_filter = kind.map(SymbolKind::from_str_loose);

    let bare = symbol.rsplit("::").next().unwrap_or(symbol).to_string();
    let mut lookup_names: Vec<String> = vec![symbol.to_string()];
    if bare != symbol {
        lookup_names.push(bare.clone());
    }
    let mut batched = store_arc
        .find_symbols_batch_with_sids(&lookup_names)
        .map_err(|e| {
            ProtocolError::new(
                ErrorCode::InternalError,
                format!("find_symbols_batch_with_sids storage error: {e:#}"),
            )
        })?;
    let mut hits: Vec<FoundSymbol> = Vec::new();
    for n in &lookup_names {
        if let Some((_sid, found)) = batched.remove(n) {
            if !found.is_empty() {
                hits = found;
                break;
            }
        }
    }
    // Narrow by the claimed file first (a location claim always names a
    // file), then optional kind.
    let filtered: Vec<FoundSymbol> = hits
        .into_iter()
        .filter(|h| kind_filter.map(|k| h.kind == k).unwrap_or(true))
        .collect();

    if filtered.is_empty() {
        return Ok((
            serde_json::json!({
                "symbol":     symbol,
                "resolution": rust_tree_sitter::Resolution::NotFound,
            }),
            ClaimVerdict::NotGrounded,
        ));
    }

    // Defs that live in the claimed file.
    let in_file: Vec<&FoundSymbol> = filtered.iter().filter(|h| h.file == file).collect();
    if in_file.is_empty() {
        // The symbol exists, but not in the claimed file → decidably
        // wrong location.
        return Ok((
            serde_json::json!({
                "symbol":     symbol,
                "resolution": rust_tree_sitter::Resolution::NotFound,
                "actual_files": filtered.iter().map(|h| h.file.clone()).collect::<Vec<_>>(),
            }),
            ClaimVerdict::NotGrounded,
        ));
    }

    // If several defs sit in the same file and none contains the line,
    // it's still a decidable miss. A line that falls in ANY of them is
    // a hit.
    let hit = in_file
        .iter()
        .find(|h| line >= h.start_line && line <= h.end_line);
    match hit {
        Some(h) => Ok((
            serde_json::json!({
                "symbol":     symbol,
                "resolution": rust_tree_sitter::Resolution::Exact,
                "file":       h.file,
                "range":      { "start_line": h.start_line, "end_line": h.end_line },
            }),
            ClaimVerdict::Grounded,
        )),
        None => Ok((
            serde_json::json!({
                "symbol":     symbol,
                "resolution": rust_tree_sitter::Resolution::NotFound,
                "file":       file,
                "actual_ranges": in_file
                    .iter()
                    .map(|h| serde_json::json!({ "start_line": h.start_line, "end_line": h.end_line }))
                    .collect::<Vec<_>>(),
            }),
            ClaimVerdict::NotGrounded,
        )),
    }
}

/// `Index.ImpactOf(name, depth?, token_budget?, max_nodes?, exclude_test_paths?)`
/// — v0.3 U5 transitive caller closure. BFS over the reverse
/// reference graph (`REFS`/`SID_REFS_OUT` populated by U1) to
/// enumerate every symbol that directly or indirectly calls `name`,
/// bounded by depth + token + node-count + wall-clock.
///
/// Wire shape (per Deepening §F3 trim):
/// ```jsonc
/// {
///   "impact": [
///     { "qualified_name": "...", "kind": "fn", "file": "...",
///       "range": { ... }, "depth": 1, "rank_score": 0.012 }
///   ],
///   "closure_truncated":    false,
///   "wall_clock_truncated": false,
///   "depth_truncated":      false,
///   "node_count_truncated": false,
///   "tokens_returned":      1247,
///   "token_counter":        "bytes_div_3"
/// }
/// ```
///
/// Each truncation flag is independent so agents can tell *why*
/// the result is partial (and pick a mitigation: deeper depth,
/// bigger budget, raise max_nodes, accept the wall-clock wins).
///
/// Errors: `SYMBOL_NOT_FOUND` when no `NAME_TO_SID` entry, mirrors
/// `Index.FindCallers`. `BUDGET_TOO_SMALL`/`BUDGET_TOO_LARGE` per
/// the standard §16 window. `INVALID_PARAMS` on empty/oversize
/// name.
///
/// Capability: `impact_of` (advertised from alpha.35).
pub async fn impact_of(
    params: serde_json::Value,
    state: &Arc<DaemonState>,
    token: CancelToken,
) -> Result<serde_json::Value, ProtocolError> {
    if token.is_cancelled() {
        return Err(cancelled());
    }
    let p: ImpactOfParams = parse_params(params)?;
    if p.name.is_empty() || p.name.len() > 256 {
        return Err(ProtocolError::new(
            ErrorCode::InvalidParams,
            "`name` must be 1..=256 characters",
        ));
    }
    let token_budget = check_budget(p.token_budget)?;

    let bounds = crate::impact::ImpactBounds {
        max_depth: p.depth.unwrap_or(crate::impact::DEFAULT_DEPTH),
        max_nodes: p.max_nodes.unwrap_or(crate::impact::DEFAULT_MAX_NODES),
        token_budget,
        exclude_test_paths: p.exclude_test_paths.unwrap_or(true),
    };

    let (_root, store_arc) = snapshot(state)?;

    // v0.3 U4 invariant: read generation BEFORE any read txn.
    let generation = state.index_generation.load(Ordering::Relaxed);
    let ranks = symbol_ranks_lazy(state, &store_arc, generation)?;

    let anchor_sid = match store_arc.sid_for_name(&p.name).map_err(|e| {
        ProtocolError::new(
            ErrorCode::InternalError,
            format!("sid_for_name storage error: {e:#}"),
        )
    })? {
        Some(s) => s,
        None => {
            return Err(ProtocolError::new(
                ErrorCode::SymbolNotFound,
                format!("no symbol named `{}` is indexed", p.name),
            ));
        }
    };

    // Delegate to the spawn_blocking-friendly compute function. BFS
    // is CPU-bound (multiple redb reads), so we run it on a blocking
    // thread to keep the tokio runtime responsive — matches the
    // alpha.22 closure walker's posture.
    let store_clone = store_arc.clone();
    let ranks_clone = ranks.clone();
    // Move a clone of the token into the blocking BFS so it can poll
    // at each frontier dequeue — a per-request deadline (or explicit
    // Daemon.Cancel) interrupts the walk mid-flight instead of waiting
    // out the 50ms wall-clock budget.
    let token_clone = token.clone();
    let walk = tokio::task::spawn_blocking(move || {
        crate::impact::compute(
            &store_clone,
            anchor_sid,
            bounds,
            ranks_clone.as_deref(),
            &token_clone,
        )
    })
    .await
    .map_err(|e| ProtocolError::new(ErrorCode::InternalError, format!("impact join error: {e}")))?
    .map_err(|e| {
        ProtocolError::new(
            ErrorCode::InternalError,
            format!("impact compute error: {e:#}"),
        )
    })?;
    // The BFS polls the token at its frontier loop head and breaks on
    // cancel. Surface that as CANCELLED so dispatch can rewrite it to
    // DEADLINE_EXCEEDED when a deadline fired.
    if token.is_cancelled() {
        return Err(cancelled());
    }

    let impact_value = crate::impact::to_wire_value(&walk.impact);

    Ok(serde_json::json!({
        "impact":               impact_value,
        "closure_truncated":    walk.closure_truncated,
        "wall_clock_truncated": walk.wall_clock_truncated,
        "depth_truncated":      walk.depth_truncated,
        "node_count_truncated": walk.node_count_truncated,
        "tokens_returned":      walk.tokens_used,
        "token_counter":        TOKEN_COUNTER,
    }))
}

/// Internal struct used by `find_callers` (and U2's `read_symbol`
/// `include_callers` branch) to build the wire-level caller entry.
/// Filter steps run against the typed form before serialization.
struct CallerEntry {
    enclosing_qualified_name: Option<String>,
    kind: Option<SymbolKind>,
    file: String,
    /// Call-site range — the RefSite.
    call_start_byte: u32,
    call_end_byte: u32,
    call_start_line: u32,
    call_end_line: u32,
    /// Enclosing def's range — present when caller_sid is Some.
    def_range: Option<(u32, u32, u32, u32)>, // (start_byte, end_byte, start_line, end_line)
    /// v0.3 U4: rank of the enclosing caller fn. `0.0` for
    /// file-scope refs (no caller_sid) and on cold-start before
    /// ranks have been computed.
    rank_score: f64,
}

impl CallerEntry {
    fn to_wire_value(&self) -> serde_json::Value {
        let enclosing_def_range = match self.def_range {
            Some((sb, eb, sl, el)) => serde_json::json!({
                "start_byte": sb,
                "end_byte":   eb,
                "start_line": sl,
                "end_line":   el,
            }),
            None => serde_json::Value::Null,
        };
        serde_json::json!({
            "enclosing_qualified_name": match &self.enclosing_qualified_name {
                Some(n) => serde_json::Value::String(n.clone()),
                None => serde_json::Value::Null,
            },
            "kind": match self.kind {
                Some(k) => serde_json::Value::String(k.as_wire_str().to_string()),
                None => serde_json::Value::Null,
            },
            "file": self.file,
            "range": {
                "start_byte": self.call_start_byte,
                "end_byte":   self.call_end_byte,
                "start_line": self.call_start_line,
                "end_line":   self.call_end_line,
            },
            "enclosing_def_range": enclosing_def_range,
            // v0.3 U4: PageRank of the enclosing caller fn.
            "rank_score": self.rank_score,
        })
    }
}

/// Resolve a `RefSite` into a `CallerEntry`. Joins `path_for_fid` and
/// `caller_def_info`. Returns `Ok(None)` only when the fid path lookup
/// fails (torn read or stale fid) — file-scope refs (caller_sid==None)
/// return a `CallerEntry` with the caller fields cleared.
///
/// `ranks` is `None` during cold-start (no PageRank computed yet) or
/// for empty workspaces; in that case every entry gets `rank_score = 0.0`.
fn build_caller_entry(
    store: &Arc<Store>,
    site: &crate::store::RefSite,
    ranks: Option<&SymbolRanks>,
) -> Result<Option<CallerEntry>, ProtocolError> {
    let file = match store.path_for_fid(site.fid).map_err(|e| {
        ProtocolError::new(
            ErrorCode::InternalError,
            format!("path_for_fid storage error: {e:#}"),
        )
    })? {
        Some(p) => p,
        None => return Ok(None),
    };
    let (enclosing_qualified_name, kind, def_range) = match site.caller_sid {
        Some(sid) => match store.caller_def_info(sid, site.fid).map_err(|e| {
            ProtocolError::new(
                ErrorCode::InternalError,
                format!("caller_def_info storage error: {e:#}"),
            )
        })? {
            Some(info) => (
                Some(info.name),
                Some(info.kind),
                Some((
                    info.def_start_byte,
                    info.def_end_byte,
                    info.def_start_line,
                    info.def_end_line,
                )),
            ),
            None => (None, None, None),
        },
        None => (None, None, None),
    };
    // Caller rank: use the enclosing fn's sid → ranks lookup. File-scope
    // refs (no caller_sid) get 0.0; cold-start (ranks is None) also gets 0.0.
    let rank_score = match (site.caller_sid, ranks) {
        (Some(sid), Some(r)) => r.rank_for(sid),
        _ => 0.0,
    };
    Ok(Some(CallerEntry {
        enclosing_qualified_name,
        kind,
        file,
        call_start_byte: site.start,
        call_end_byte: site.end,
        call_start_line: site.start_line,
        call_end_line: site.end_line,
        def_range,
        rank_score,
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
/// but the 4× `limit` candidate cap upstream keeps that bounded.
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

    let generation = state.index_generation.load(Ordering::Relaxed);
    let cv = state
        .content_version_cache
        .get_or_compute(&abs, mtime_ns, generation, || {
            content_version(&bytes, mtime_ns, generation)
        });

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
    token: CancelToken,
) -> Result<serde_json::Value, ProtocolError> {
    if token.is_cancelled() {
        return Err(cancelled());
    }
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
    let include_callers = p.include_callers;
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
    let parent_filter = p.parent.as_deref();

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
        // v0.7+ (cap: `parent_scope`): exact-match parent filter. A
        // candidate with `parent: None` never matches a `Some(_)`
        // filter, so an unpopulated index resolves to SymbolNotFound
        // when a parent is requested.
        .filter(|h| match parent_filter {
            Some(pp) => h.parent.as_deref() == Some(pp),
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

    read_symbol_body(
        state,
        &root,
        &store_arc,
        chosen,
        extra,
        ambiguous,
        shape,
        budget,
        include_deps,
        include_callers,
        &token,
    )
    .await
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
    include_callers: bool,
    token: &CancelToken,
) -> Result<serde_json::Value, ProtocolError> {
    // Timing harness (RTS_PROFILE_READ_SYMBOL=1) — prints µs per
    // section to stderr. Useful for chasing the v0.3 deps-mode
    // regression filed in v0.3.2; the env var lives long enough to
    // root-cause then comes back out.
    let profile = std::env::var("RTS_PROFILE_READ_SYMBOL")
        .map(|v| !v.is_empty() && v != "0")
        .unwrap_or(false);
    macro_rules! mark {
        ($t:ident, $label:literal) => {
            if profile {
                eprintln!(
                    "read_symbol:{:>22} = {:>6} µs",
                    $label,
                    $t.elapsed().as_micros()
                );
                #[allow(unused_assignments)]
                {
                    $t = std::time::Instant::now();
                }
            }
        };
    }
    let mut t_section = std::time::Instant::now();

    let (abs, _rel) = resolve_workspace_path(root, &chosen.file)?;
    check_body_extension(&abs)?;
    mark!(t_section, "path_resolve+check");

    let (bytes, mtime_ns) = read_file(&abs).await?;
    mark!(t_section, "read_file");
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
        // Cache key is (path, byte range, mtime). The bench's seeded
        // RNG picks the same anchor many times across queries; without
        // this cache, tree-sitter re-parses the slice every call.
        state.signature_cache.get_or_compute(
            &abs,
            chosen.start_byte,
            chosen.end_byte,
            mtime_ns,
            || {
                crate::language::info_for_path(&chosen.file)
                    .and_then(|info| info.signature_renderer)
                    .and_then(|render| render(body_text.as_bytes()))
            },
        )
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

    let generation = state.index_generation.load(Ordering::Relaxed);
    let cv = state
        .content_version_cache
        .get_or_compute(&abs, mtime_ns, generation, || {
            content_version(&bytes, mtime_ns, generation)
        });
    mark!(t_section, "content_version");

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
        // v0.3.x perf fix: removed `spawn_blocking` for the closure
        // walk. The walk does redb reads (single-digit µs each), at
        // most a few `std::fs::metadata` + `std::fs::read` calls
        // (cached after the file_cache hit on first read in this
        // call), and tree-sitter signature renders (CPU-bound but
        // short — and now signature-cached across calls).
        //
        // Pre-fix: each call cost ~50-100 µs of spawn_blocking
        // handoff (thread pool scheduling + Arc<JoinHandle> setup +
        // await). On the warm path (bench measures), that's pure
        // overhead — the underlying work doesn't block long enough
        // to justify moving off the runtime. For a 200 µs closure
        // walk, 50 µs of overhead is 25%.
        //
        // The trade-off: a true cold-disk read on the first call
        // for a file could in principle block the runtime worker.
        // In practice the OS page cache + the file_cache + the
        // signature cache keep this rare; the daemon's other
        // concurrent work (writer task) runs on its own task and
        // doesn't share this thread's scheduler frame anyway.
        let walk = crate::closure::compute(
            root,
            store_arc,
            &chosen,
            remaining_budget,
            &state.signature_cache,
            token,
        );
        mark!(t_section, "closure_walk");
        // The walker polls the token at the head of its per-dep render
        // loop and `break`s on cancel. Surface that as CANCELLED so a
        // per-request deadline (or explicit Daemon.Cancel) interrupts
        // a large dependency-closure read instead of returning a
        // partial result that looks complete.
        if token.is_cancelled() {
            return Err(cancelled());
        }
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

    // v0.3 U2': callers branch. Parallel to the dep walk above.
    // Budget priority: body wins first, deps fill the remainder,
    // callers fill what's left after deps. Callers use a separate
    // truncation flag (`callers_truncated`) to keep the v0.2
    // `closure_truncated` semantics intact (Deepening §C4 — silent
    // overload of the existing flag was rejected).
    //
    // Per-entry budget cost is `bytes_div_3` of the JSON entry size;
    // we approximate this as a constant 60 tokens per entry (matches
    // the average CallerEntry serialization with all string fields
    // populated). Cheaper than serializing each entry to measure
    // exactly; agents have the `tokens_returned` field for precision.
    let (callers_value, callers_truncated, caller_tokens) = if include_callers {
        const APPROX_TOKENS_PER_CALLER: u64 = 60;
        let remaining_budget = budget
            .saturating_sub(body_tokens)
            .saturating_sub(dep_tokens);
        let max_callers_by_budget = remaining_budget / APPROX_TOKENS_PER_CALLER;

        // v0.3 U4: rank lookup for the caller entries' rank_score
        // field. Read generation BEFORE the read txn (Deepening §C).
        let generation = state.index_generation.load(Ordering::Relaxed);
        let ranks = symbol_ranks_lazy(state, store_arc, generation)?;

        // Anchor is workspace-defined (we just read its body) so a
        // sid is virtually guaranteed; if it's missing (torn read on
        // a just-removed file), surface an empty callers list rather
        // than failing the whole call.
        let callee_sid_opt = store_arc.sid_for_name(&chosen.name).map_err(|e| {
            ProtocolError::new(
                ErrorCode::InternalError,
                format!("sid_for_name storage error: {e:#}"),
            )
        })?;
        if let Some(callee_sid) = callee_sid_opt {
            let sites = store_arc.refs_to_symbol(callee_sid).map_err(|e| {
                ProtocolError::new(
                    ErrorCode::InternalError,
                    format!("refs_to_symbol storage error: {e:#}"),
                )
            })?;
            let total_sites = sites.len() as u64;
            let kept_sites: Vec<_> = sites
                .into_iter()
                .take(max_callers_by_budget as usize)
                .collect();
            let truncated = (kept_sites.len() as u64) < total_sites;

            let mut entries: Vec<serde_json::Value> = Vec::with_capacity(kept_sites.len());
            for site in &kept_sites {
                if let Some(entry) = build_caller_entry(store_arc, site, ranks.as_deref())? {
                    entries.push(entry.to_wire_value());
                }
            }
            // Stable order: (file, start_byte). Same as Index.FindCallers.
            entries.sort_by(|a, b| {
                let (af, ab) = (
                    a["file"].as_str().unwrap_or(""),
                    a["range"]["start_byte"].as_u64().unwrap_or(0),
                );
                let (bf, bb) = (
                    b["file"].as_str().unwrap_or(""),
                    b["range"]["start_byte"].as_u64().unwrap_or(0),
                );
                (af, ab).cmp(&(bf, bb))
            });
            let tokens = (entries.len() as u64).saturating_mul(APPROX_TOKENS_PER_CALLER);
            (serde_json::Value::Array(entries), truncated, tokens)
        } else {
            (serde_json::Value::Array(vec![]), false, 0u64)
        }
    } else {
        (serde_json::Value::Array(vec![]), false, 0u64)
    };

    let tokens_returned = body_tokens
        .saturating_add(dep_tokens)
        .saturating_add(caller_tokens);

    // `truncated_symbols` blends two sources per §7.7: ambiguous
    // anchor matches (extra files) and closure deps that didn't fit
    // (deps_truncated_names). Both let the agent re-request
    // individually. Callers truncation is signalled separately via
    // `callers_truncated` per Deepening §C4 (separate flag rather
    // than overloading `closure_truncated`).
    let mut truncated_symbols = extra;
    truncated_symbols.extend(deps_truncated_names);

    Ok(serde_json::json!({
        "qualified_name": render_qualified_name(&chosen.name, chosen.parent.as_deref()),
        // v0.7+ (cap: `parent_scope`): nearest enclosing container
        // name, or null for top-level / unpopulated.
        "parent":         chosen.parent,
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
        "callers":           callers_value,
        "callers_truncated": callers_truncated,
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
    //
    // `Index.ReadSymbolAt` isn't in the dispatcher's cancellable set
    // (it resolves a single def, no large fan-out), so hand the shared
    // body builder a fresh, never-tripped token — the closure poll
    // becomes a no-op for this caller.
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
        p.include_callers,
        &CancelToken::new(),
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
            span_a.cmp(&span_b).then(a.start_byte.cmp(&b.start_byte))
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
    token: CancelToken,
) -> Result<serde_json::Value, ProtocolError> {
    if token.is_cancelled() {
        return Err(cancelled());
    }
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
        // Move a clone of the token into the blocking compute so its
        // per-file ref-graph walk can poll it and break mid-flight — a
        // per-request deadline (or explicit Daemon.Cancel) interrupts
        // the heavy walk instead of running it to completion. Matches
        // the impact/closure walkers' posture.
        let token_clone = token.clone();
        // PageRank + content reads can be heavy on large workspaces;
        // delegate to a blocking task so we don't hog the daemon's
        // single-threaded async runtime.
        let compute_result = tokio::task::spawn_blocking(move || {
            let outline_params = crate::outline::OutlineParams {
                glob: glob_owned.as_deref(),
                token_budget: budget,
                mentioned_files: &mentioned_files,
                mentioned_idents: &mentioned_idents,
            };
            crate::outline::compute(&root, &store, &outline_params, &token_clone)
        })
        .await
        .map_err(|e| {
            ProtocolError::new(ErrorCode::InternalError, format!("outline join error: {e}"))
        })?;
        // The walk polls the token at its per-file loop head and bails
        // with a cancellation-shaped error on cancel. Check the token
        // BEFORE mapping a compute error so a deadline/Daemon.Cancel
        // surfaces as CANCELLED (rewritten to DEADLINE_EXCEEDED by
        // dispatch when a deadline fired) — NOT InternalError.
        if token.is_cancelled() {
            return Err(cancelled());
        }
        let computed = compute_result.map_err(|e| {
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

    // `resolve_workspace_path` tests moved to `crate::path::tests` in
    // alpha.29 when the fn was extracted. The richer suite there covers
    // these cases plus the M2 symlink-rejection contract.
    #[test]
    #[allow(dead_code)]
    fn resolve_smoke() {
        let root = Path::new("/tmp/ws");
        // Quick smoke; full coverage lives in path::tests.
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
            sid: 0,
            start_byte: sb,
            end_byte: sb + 50,
            start_line: sl,
            end_line: el,
            visibility: Visibility::Public,
            parent: None,
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
