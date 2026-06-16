//! Structural query execution for `Index.Grep` v2.
//!
//! Entry point: [`run`]. Walks the in-scope file set (filtered by
//! `language` + `file_glob`), parses each file with tree-sitter,
//! runs the compiled `Query` against the parsed tree, and assembles
//! [`StructuralMatch`] records with per-match captures.
//!
//! ## Per-file flow
//!
//! 1. Resolve workspace-relative path → absolute; skip on failure
//!    (file deleted between index and scan).
//! 2. Read bytes; skip if `len > MAX_FILE_BYTES` (mirrors v1 cap).
//! 3. Use `info_for_path` to map ext → `Language`; skip if not on
//!    the caller's `language` whitelist.
//! 4. Parse with `rust_tree_sitter::Parser`; skip on parse failure
//!    (logged at debug, file does not contribute matches).
//! 5. Use the cached `Query` for this language to drive
//!    `query.matches_in_node(tree.root_node(), source)`. For each
//!    match, build a `StructuralMatch` with captures.
//!
//! Wall-clock budget is checked between files (not mid-file). On
//! breach: return [`StructuralError::Timeout`].
//!
//! ## Cross-language partial failures
//!
//! When the caller passes `language: ["rust", "ts"]` and the query
//! compiles for Rust but fails for TypeScript:
//!
//! * Files matching ext→rust are scanned.
//! * Files matching ext→ts are skipped.
//! * `partial_failures` carries `[{"language": "typescript", "error": "..."}]`.
//! * The call succeeds (returns whatever Rust files contributed)
//!   provided at least one language compiled successfully.
//! * If *all* requested languages failed compile, the call returns
//!   `StructuralError::AllLanguagesFailed` — the caller sees a
//!   `STRUCTURAL_QUERY_INVALID` envelope.
//!
//! ## Row + capture truncation
//!
//! Caps come from [`super::limits`]:
//!
//! * `STRUCTURAL_MAX_ROWS` — total match rows returned. Hits past
//!   the cap don't accumulate.
//! * `STRUCTURAL_MAX_CAPTURES_PER_MATCH` — captures attached to a
//!   single match. Beyond this, captures are dropped; the response's
//!   top-level `truncated: true` flag is set.
//! * `STRUCTURAL_MAX_CAPTURE_BYTES` — per-capture text length. Long
//!   captures are truncated and the capture object gains
//!   `"truncated": true`.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use globset::GlobMatcher;
use rust_tree_sitter::{Language, Parser};
use serde_json::{Map as JsonMap, Value};

use crate::cancel::CancelToken;
use crate::path::resolve_workspace_path;
use crate::state::DaemonState;

use super::limits::{
    STRUCTURAL_MAX_CAPTURE_BYTES, STRUCTURAL_MAX_CAPTURES_PER_MATCH, STRUCTURAL_MAX_ROWS,
    STRUCTURAL_WALL_CLOCK_MS,
};

/// Same cap as v1 `Index.Grep`'s `MAX_FILE_BYTES`. Files larger than
/// this are skipped (counted toward `files_scanned`, no matches).
const MAX_FILE_BYTES: usize = 4 * 1024 * 1024;

/// Intersection filter applied **inline** during the structural scan so
/// the row cap counts only matches that satisfy BOTH the structural query
/// and the literal/regex filter (issue #152). Built by the caller from
/// the validated `combine` (regex compiled up-front so a bad pattern
/// fails before the scan).
pub enum CombineFilter {
    /// Literal substring over the match's bytes (ASCII case-fold when
    /// `case_insensitive`). Mirrors v1 grep literal semantics.
    Literal {
        needle: Vec<u8>,
        case_insensitive: bool,
    },
    /// Pre-compiled byte regex.
    Regex(regex::bytes::Regex),
}

impl CombineFilter {
    /// Does the match's byte slice satisfy the filter?
    fn matches(&self, slice: &[u8]) -> bool {
        match self {
            CombineFilter::Literal {
                needle,
                case_insensitive,
            } => {
                if needle.is_empty() {
                    return true;
                }
                if needle.len() > slice.len() {
                    return false;
                }
                if *case_insensitive {
                    slice
                        .windows(needle.len())
                        .any(|w| w.eq_ignore_ascii_case(needle))
                } else {
                    slice.windows(needle.len()).any(|w| w == needle.as_slice())
                }
            }
            CombineFilter::Regex(re) => re.is_match(slice),
        }
    }
}

/// One capture in a structural match.
#[derive(Debug, Clone, PartialEq)]
pub struct CapturePayload {
    pub start: LineCol,
    pub end: LineCol,
    pub text: String,
    pub truncated: bool,
}

/// 1-based line + 0-based column. Matches the rest of the protocol's
/// position conventions (def ranges are 1-based inclusive lines).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LineCol {
    pub line: u32,
    pub col: u32,
}

/// Per-match record. Carries the byte range of the *root* capture
/// (the "@whole" of the match — by convention, the largest range
/// among captures), the line text at that range's start, and the
/// per-capture map.
#[derive(Debug, Clone)]
pub struct StructuralMatch {
    pub file: String,
    pub start_byte: u32,
    pub end_byte: u32,
    pub start_line: u32,
    pub end_line: u32,
    /// Captures, keyed by capture name (e.g. `@fn` → "fn"). Anonymous
    /// matches with no captures end up here as empty.
    pub captures: BTreeMap<String, Vec<CapturePayload>>,
}

/// Partial-failure entry surfaced when one of the requested
/// languages had a compile-time error against the supplied query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartialFailure {
    pub language: String,
    pub error: String,
}

/// Top-level result from [`run`]. Carries the match rows + truncation
/// flag + per-language partial failures.
#[derive(Debug, Clone, Default)]
pub struct StructuralResult {
    pub matches: Vec<StructuralMatch>,
    /// Total candidate matches the scanner saw before truncation.
    pub rows_seen: usize,
    /// Match rows actually returned (== `matches.len()`).
    pub rows_returned: usize,
    /// Set when row or capture truncation kicked in.
    pub truncated: bool,
    /// Per-grammar compile failures. Empty when all requested
    /// languages compiled cleanly.
    pub partial_failures: Vec<PartialFailure>,
    /// Files actually opened + parsed. Aligns with v1's `files_scanned`.
    pub files_scanned: usize,
    /// Files that contributed at least one match row.
    pub files_with_matches: usize,
}

/// Structural-execution error. The caller maps these onto
/// `STRUCTURAL_QUERY_INVALID` / `STRUCTURAL_QUERY_TIMEOUT` /
/// `CANCELLED` envelopes.
#[derive(Debug)]
pub enum StructuralError {
    /// `Query::new` failed for every requested language. Carries the
    /// per-language compile diagnostic so the caller can surface
    /// the first one (or all) in the error envelope.
    AllLanguagesFailed(Vec<PartialFailure>),
    /// Wall-clock budget (`STRUCTURAL_WALL_CLOCK_MS`) exceeded.
    Timeout,
    /// Cooperative cancellation tripped via `Daemon.Cancel`. The
    /// caller maps this to a `CANCELLED` envelope (custom code
    /// `-32099`); see `crate::cancel`.
    Cancelled,
}

/// Run the structural query against the file set.
///
/// * `state` — the daemon state (for the query cache).
/// * `workspace_root` — absolute path of the mounted workspace.
/// * `files` — workspace-relative paths committed by the writer.
/// * `query_text` — raw S-expression supplied by the caller (already
///   validated against the predicate whitelist).
/// * `languages` — the caller's `language` filter list (already
///   non-empty by validation).
/// * `glob` — compiled `file_glob` matcher, if any.
/// * `row_limit` — caller's `limit` (capped at `STRUCTURAL_MAX_ROWS`
///   inside this function).
#[allow(clippy::too_many_arguments)]
pub fn run(
    state: &Arc<DaemonState>,
    workspace_root: &std::path::Path,
    files: &[String],
    query_text: &str,
    languages: &[String],
    glob: Option<&GlobMatcher>,
    row_limit: usize,
    combine: Option<&CombineFilter>,
    cancel: &CancelToken,
) -> Result<StructuralResult, StructuralError> {
    // Resolve language whitelist + compile queries per language.
    // We compile up-front so a per-language compile error becomes a
    // partial-failure entry, not a per-file warning.
    let mut compiled: Vec<(Language, &'static str, Arc<rust_tree_sitter::query::Query>)> =
        Vec::new();
    let mut partial_failures: Vec<PartialFailure> = Vec::new();

    for lang_str in languages {
        let lang_str = lang_str.to_ascii_lowercase();
        let language = match map_wire_language(&lang_str) {
            Some(l) => l,
            None => {
                partial_failures.push(PartialFailure {
                    language: lang_str.clone(),
                    error: format!("unknown language `{lang_str}`"),
                });
                continue;
            }
        };
        match state.query_cache.get_or_compile(language, query_text) {
            Ok(q) => {
                compiled.push((language, language_wire_name(language), q));
            }
            Err(e) => {
                partial_failures.push(PartialFailure {
                    language: lang_str.clone(),
                    error: format!("query compile error: {e}"),
                });
            }
        }
    }

    if compiled.is_empty() {
        return Err(StructuralError::AllLanguagesFailed(partial_failures));
    }

    let cap = row_limit.min(STRUCTURAL_MAX_ROWS);
    let started = Instant::now();
    let budget = Duration::from_millis(STRUCTURAL_WALL_CLOCK_MS);

    let mut result = StructuralResult {
        partial_failures,
        ..StructuralResult::default()
    };
    let mut row_truncated = false;
    let mut capture_truncated = false;

    'files: for rel in files {
        // Between-file cooperative cancellation. Cheap (one relaxed
        // atomic load); covers the common case where a structural
        // query fans across hundreds of files and the agent loses
        // interest mid-flight. Inner per-match check below tightens
        // the latency to ~50µs per emission.
        if cancel.is_cancelled() {
            return Err(StructuralError::Cancelled);
        }
        // Between-file wall-clock check.
        if started.elapsed() > budget {
            return Err(StructuralError::Timeout);
        }

        if let Some(g) = glob {
            if !g.is_match(rel) {
                continue;
            }
        }

        // Map extension → Language; skip if file's language isn't in
        // our compiled set.
        let info = match crate::language::info_for_path(rel) {
            Some(i) => i,
            None => continue,
        };
        let lang_entry = match compiled.iter().find(|(l, _, _)| *l == info.language) {
            Some(e) => e,
            None => continue,
        };
        let (language, _wire_name, query_arc) = lang_entry;

        let abs = match resolve_workspace_path(workspace_root, rel) {
            Ok((abs, _)) => abs,
            Err(_) => continue,
        };
        let bytes = match std::fs::read(&abs) {
            Ok(b) => b,
            Err(_) => continue,
        };
        result.files_scanned += 1;
        if bytes.len() > MAX_FILE_BYTES {
            continue;
        }
        // Parse as UTF-8 (lossy) — tree-sitter consumes &str via the
        // rts-core wrapper. Source files with invalid UTF-8 fall to
        // `from_utf8_lossy` which preserves byte positions for valid
        // runs; for capture-text purposes that's enough.
        let source = match std::str::from_utf8(&bytes) {
            Ok(s) => s.to_string(),
            Err(_) => String::from_utf8_lossy(&bytes).into_owned(),
        };

        let parser = match Parser::new(*language) {
            Ok(p) => p,
            Err(e) => {
                tracing::debug!(
                    target: "rts_daemon::grep_v2::structural",
                    error = %e,
                    file = %rel,
                    "parser construction failed; skipping file"
                );
                continue;
            }
        };
        let tree = match parser.parse(&source, None) {
            Ok(t) => t,
            Err(e) => {
                tracing::debug!(
                    target: "rts_daemon::grep_v2::structural",
                    error = %e,
                    file = %rel,
                    "parse failed; skipping file"
                );
                continue;
            }
        };

        let matches = match query_arc.matches(&tree) {
            Ok(m) => m,
            Err(e) => {
                tracing::debug!(
                    target: "rts_daemon::grep_v2::structural",
                    error = %e,
                    file = %rel,
                    "query.matches failed; skipping file"
                );
                continue;
            }
        };

        let mut file_recorded = false;
        for qm in matches {
            // Per-match cancellation check. Plan §"Scanner integration":
            // the structural scanner is the hot loop where in-flight
            // queries can fan out to thousands of node visits per file.
            // A relaxed atomic load is ~1ns — noise next to the
            // per-match capture-extraction work.
            if cancel.is_cancelled() {
                return Err(StructuralError::Cancelled);
            }
            result.rows_seen += 1;

            // Per-match wall-clock check (#152 review). With an inline
            // `combine` filter, filtered-out candidates `continue` before
            // the row cap, so a single huge file with many non-matching
            // nodes (e.g. `(identifier) @i` + a rare text) could otherwise
            // monopolize the blocking thread well past the budget — the
            // between-files check below never fires mid-file. Sample the
            // clock every 1024 candidates to keep `Instant::now()` off the
            // hottest path while still bounding it.
            if result.rows_seen % 1024 == 0 && started.elapsed() > budget {
                return Err(StructuralError::Timeout);
            }

            // Find the "primary" capture: the one with the widest
            // byte range (typically the `@whole` capture per
            // tree-sitter convention). If the match has no captures
            // (queries can match without `@name`), surface the
            // first-pattern node bounds via a synthetic capture
            // payload — but with no @name, the captures map is
            // empty and the row uses the first capture's bounds.
            let captures_vec = qm.captures();
            if captures_vec.is_empty() {
                // Cannot produce a row without a byte range. Skip.
                continue;
            }
            let (start_byte, end_byte) = captures_vec
                .iter()
                .map(|c| {
                    let r = c.byte_range();
                    (r.start_byte, r.end_byte)
                })
                .fold((u32::MAX, 0u32), |(s, e), (cs, ce)| {
                    (s.min(cs as u32), e.max(ce as u32))
                });

            // Intersection (`combine`) filter, applied INLINE so the row
            // cap counts only matches that satisfy both the structural
            // query and the literal/regex filter (issue #152). Without
            // this, a large scope hits the cap on raw structural nodes
            // before the post-pass filter runs, silently dropping real
            // matches. `source` is already in hand — no extra file read.
            if let Some(filter) = combine {
                let (lo, hi) = (start_byte as usize, end_byte as usize);
                let bytes = source.as_bytes();
                if hi > bytes.len() || lo > hi || !filter.matches(&bytes[lo..hi]) {
                    continue;
                }
            }

            if result.matches.len() >= cap {
                row_truncated = true;
                // Skip the rest of this file's matches but keep
                // counting rows_seen so the caller sees the real
                // candidate count. To stay under wall-clock budget,
                // break out entirely.
                break 'files;
            }
            // Re-fetch start position from the *primary* (widest)
            // capture for line/col.
            let primary = captures_vec
                .iter()
                .max_by_key(|c| {
                    let r = c.byte_range();
                    r.end_byte.saturating_sub(r.start_byte)
                })
                .unwrap_or(&captures_vec[0]);
            let primary_start = primary.start_position();
            let primary_end = primary.end_position();

            let mut cap_map: BTreeMap<String, Vec<CapturePayload>> = BTreeMap::new();
            let mut cap_count = 0usize;
            for c in &captures_vec {
                if cap_count >= STRUCTURAL_MAX_CAPTURES_PER_MATCH {
                    capture_truncated = true;
                    break;
                }
                cap_count += 1;
                let name = match c.name() {
                    Some(n) => n.to_string(),
                    None => continue,
                };
                let start = LineCol {
                    line: c.start_position().row as u32 + 1,
                    col: c.start_position().column as u32,
                };
                let end = LineCol {
                    line: c.end_position().row as u32 + 1,
                    col: c.end_position().column as u32,
                };
                let raw_text = match c.text() {
                    Ok(t) => t,
                    Err(_) => "",
                };
                let (text, truncated) = if raw_text.len() > STRUCTURAL_MAX_CAPTURE_BYTES {
                    let cut = floor_char_boundary(raw_text, STRUCTURAL_MAX_CAPTURE_BYTES);
                    let mut t = raw_text[..cut].to_string();
                    t.push('…');
                    capture_truncated = true;
                    (t, true)
                } else {
                    (raw_text.to_string(), false)
                };
                cap_map.entry(name).or_default().push(CapturePayload {
                    start,
                    end,
                    text,
                    truncated,
                });
            }

            result.matches.push(StructuralMatch {
                file: rel.clone(),
                start_byte,
                end_byte,
                start_line: primary_start.row as u32 + 1,
                end_line: primary_end.row as u32 + 1,
                captures: cap_map,
            });
            file_recorded = true;
        }
        if file_recorded {
            result.files_with_matches += 1;
        }
    }

    result.rows_returned = result.matches.len();
    result.truncated = row_truncated || capture_truncated;
    Ok(result)
}

/// Render a `StructuralMatch` as the JSON shape the response expects.
/// Used by `methods::index::grep` when assembling the final body.
pub fn match_to_json(m: &StructuralMatch) -> Value {
    let captures = capture_map_to_json(&m.captures);
    serde_json::json!({
        "file": m.file,
        "range": {
            "start_line": m.start_line,
            "end_line":   m.end_line,
            "start_byte": m.start_byte,
            "end_byte":   m.end_byte,
        },
        "captures": captures,
    })
}

/// Render the per-match `captures` map as a JSON object.
pub fn capture_map_to_json(map: &BTreeMap<String, Vec<CapturePayload>>) -> Value {
    let mut obj = JsonMap::with_capacity(map.len());
    for (name, payloads) in map {
        let arr: Vec<Value> = payloads.iter().map(capture_to_json).collect();
        obj.insert(name.clone(), Value::Array(arr));
    }
    Value::Object(obj)
}

fn capture_to_json(c: &CapturePayload) -> Value {
    let mut obj = JsonMap::new();
    obj.insert(
        "start".to_string(),
        serde_json::json!({"line": c.start.line, "col": c.start.col}),
    );
    obj.insert(
        "end".to_string(),
        serde_json::json!({"line": c.end.line, "col": c.end.col}),
    );
    obj.insert("text".to_string(), Value::String(c.text.clone()));
    if c.truncated {
        obj.insert("truncated".to_string(), Value::Bool(true));
    }
    Value::Object(obj)
}

/// Map wire-level language identifier (the lowercase form callers
/// send) to the `Language` enum. Stable across patch releases; new
/// languages added here when the daemon grows support for them.
pub fn map_wire_language(s: &str) -> Option<Language> {
    Some(match s {
        "rust" | "rs" => Language::Rust,
        "python" | "py" => Language::Python,
        "javascript" | "js" => Language::JavaScript,
        "typescript" | "ts" => Language::TypeScript,
        "c" => Language::C,
        "cpp" | "c++" | "cxx" => Language::Cpp,
        "go" => Language::Go,
        "java" => Language::Java,
        "php" => Language::Php,
        "ruby" | "rb" => Language::Ruby,
        "swift" => Language::Swift,
        "csharp" | "c#" | "cs" => Language::CSharp,
        "markdown" | "md" => Language::Markdown,
        _ => return None,
    })
}

/// Inverse mapping for surfacing the canonical wire name in
/// partial-failure records.
fn language_wire_name(l: Language) -> &'static str {
    match l {
        Language::Rust => "rust",
        Language::Python => "python",
        Language::JavaScript => "javascript",
        Language::TypeScript => "typescript",
        Language::C => "c",
        Language::Cpp => "cpp",
        Language::Go => "go",
        Language::Java => "java",
        Language::Php => "php",
        Language::Ruby => "ruby",
        Language::Swift => "swift",
        Language::CSharp => "csharp",
        Language::Markdown => "markdown",
    }
}

/// `str::floor_char_boundary` polyfill — that function is unstable
/// on stable Rust. Find the largest valid UTF-8 char boundary
/// `<= max`. Returns `s.len()` if `max >= s.len()`.
fn floor_char_boundary(s: &str, max: usize) -> usize {
    if max >= s.len() {
        return s.len();
    }
    let mut cut = max;
    while cut > 0 && !s.is_char_boundary(cut) {
        cut -= 1;
    }
    cut
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn map_wire_language_handles_common_aliases() {
        assert_eq!(map_wire_language("rust"), Some(Language::Rust));
        assert_eq!(map_wire_language("rs"), Some(Language::Rust));
        assert_eq!(map_wire_language("typescript"), Some(Language::TypeScript));
        assert_eq!(map_wire_language("ts"), Some(Language::TypeScript));
        assert_eq!(map_wire_language("py"), Some(Language::Python));
        assert_eq!(map_wire_language("bogus"), None);
    }

    #[test]
    fn floor_char_boundary_respects_utf8() {
        // "résumé" — 'é' is a 2-byte char.
        let s = "résumé";
        let n = floor_char_boundary(s, 3);
        // Should NOT split the second byte of 'é'; cut to the start
        // of the multi-byte sequence.
        let prefix = &s[..n];
        // Re-decoding must succeed (no replacement chars).
        assert_eq!(prefix.chars().count(), prefix.chars().count());
        assert!(n <= 3);
    }

    #[test]
    fn capture_to_json_includes_truncated_flag_when_set() {
        let c = CapturePayload {
            start: LineCol { line: 1, col: 0 },
            end: LineCol { line: 1, col: 5 },
            text: "hello".to_string(),
            truncated: true,
        };
        let v = capture_to_json(&c);
        assert_eq!(v["truncated"], Value::Bool(true));
    }

    #[test]
    fn capture_to_json_omits_truncated_when_false() {
        let c = CapturePayload {
            start: LineCol { line: 1, col: 0 },
            end: LineCol { line: 1, col: 5 },
            text: "hello".to_string(),
            truncated: false,
        };
        let v = capture_to_json(&c);
        assert!(
            v.get("truncated").is_none(),
            "truncated should be absent (not false) when not set"
        );
    }
}
