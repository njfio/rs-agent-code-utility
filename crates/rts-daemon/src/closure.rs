//! `Index.ReadSymbol` closure walker — implements the
//! `include_dependencies: true` branch of protocol-v0 §7.7.
//!
//! ### What this does
//!
//! Given an anchor symbol the agent asked for, walk its body for
//! identifier references and surface each referenced symbol as a
//! lightweight dep entry: `qualified_name`, `kind`, `file`, `range`,
//! and a rendered `signature`. This lets agents do their work in one
//! round trip instead of N `Index.FindSymbol` + `Index.ReadSymbol`
//! follow-ups — a measurable token-reduction win on the §P9 baseline
//! tasks (`get_body`, `find_callers`, `summarize_module`).
//!
//! ### Scope (v0)
//!
//! - **Depth 1.** We extract identifiers from the anchor body, filter
//!   to known def names, and return one entry per unique referenced
//!   symbol. We do not recursively walk the deps' bodies. Agents that
//!   want depth > 1 can re-call `Index.ReadSymbol` on each entry.
//! - **First-match disambiguation.** When a name has multiple defs,
//!   we pick the first by `(file, start_byte)` — same policy as the
//!   anchor in `read_symbol`. The caller can re-resolve with a
//!   `file:` filter if they need a specific definition.
//! - **Budget-aware.** The caller passes a token budget (what's left
//!   after the anchor body's tokens are spent). We greedy-pack deps
//!   in tokenized-cost order, smallest first — this maximizes the
//!   number of useful entries that fit. Anything that didn't fit
//!   surfaces in `truncated_symbols` and flips `closure_truncated`.
//!
//! Push-flow / multi-hop / type-graph walking is deferred to v1.1.

use std::collections::BTreeSet;
use std::path::Path;

use serde::Serialize;

use crate::store::{FoundSymbol, Store};

/// One dep entry, ready for the wire shape. Fields mirror
/// protocol-v0 §7.7 example: `qualified_name`, `kind`, `file`,
/// `range`, `signature`.
#[derive(Debug, Clone, Serialize)]
pub struct DependencyEntry {
    pub qualified_name: String,
    /// Wire-stable kind string ("fn", "type", ...).
    pub kind: String,
    pub file: String,
    pub start_line: u32,
    pub end_line: u32,
    pub start_byte: u32,
    pub end_byte: u32,
    /// Best-effort rendered signature. `None` when the language has no
    /// renderer or the body didn't parse cleanly — the agent still
    /// gets the range and can re-request the body via
    /// `Index.ReadRange`.
    pub signature: Option<String>,
}

/// Result of one closure walk.
#[derive(Debug, Clone)]
pub struct ClosureResult {
    pub dependencies: Vec<DependencyEntry>,
    /// True when at least one referenced symbol was dropped because it
    /// didn't fit in `remaining_budget`. Mirrors the protocol field of
    /// the same name.
    pub closure_truncated: bool,
    /// Names that were resolved but didn't fit in the budget. The agent
    /// can re-request these individually. Sorted for stable wire shape.
    pub truncated_symbols: Vec<String>,
    /// Approximate token cost of the entries we did include (bytes / 3,
    /// matching the daemon's `bytes_div_3` counter). The handler sums
    /// this into the response's `tokens_returned`.
    pub tokens_used: u64,
}

impl ClosureResult {
    pub fn empty() -> Self {
        Self {
            dependencies: Vec::new(),
            closure_truncated: false,
            truncated_symbols: Vec::new(),
            tokens_used: 0,
        }
    }
}

/// Walk the closure of `anchor` against `anchor_body` and return the
/// dep entries that fit in `remaining_budget_tokens`.
///
/// `workspace_root` is needed to read each dep's file contents for
/// signature rendering. I/O failures on a single dep don't fail the
/// whole call — that dep just gets `signature: None` and we move on.
pub fn compute(
    workspace_root: &Path,
    store: &Store,
    anchor: &FoundSymbol,
    anchor_body: &str,
    remaining_budget_tokens: u64,
) -> ClosureResult {
    // Build the set of identifiers referenced by the anchor body
    // that look like *symbols* (filtered against the workspace-wide
    // def name set). This piggybacks on the same heuristic
    // `crate::outline` uses for its PageRank graph, so behaviour is
    // consistent across the two surfaces.
    let all_def_names = match store.all_defined_names() {
        Ok(s) => s,
        Err(_) => return ClosureResult::empty(),
    };
    // Pull references via tags.scm where available (Rust/Python/Go/Ruby
    // as of alpha.27); fall through to the regex tokenizer for other
    // languages. Tags.scm precision eliminates false positives from
    // local-variable shadowing + identifier mentions in comments. The
    // call-site filter (`@reference.call`) drops trait/type-position
    // identifiers too, which the regex would have surfaced as deps.
    let refs = crate::refs::references_for_path(&anchor.file, anchor_body);
    let mut candidates: BTreeSet<String> = BTreeSet::new();
    for ident in refs {
        if ident == anchor.name {
            continue; // skip self-reference
        }
        if all_def_names.contains(&ident) {
            candidates.insert(ident);
        }
    }
    if candidates.is_empty() {
        return ClosureResult::empty();
    }

    // Resolve each candidate to a def site (first match wins, same as
    // `read_symbol`). Skip names that resolve to the anchor itself
    // (e.g. via overload — defensive; same name + same file id).
    let mut resolved: Vec<(String, FoundSymbol)> = Vec::with_capacity(candidates.len());
    for name in &candidates {
        let hits = match store.find_symbol(name) {
            Ok(h) => h,
            Err(_) => continue,
        };
        if hits.is_empty() {
            continue;
        }
        // First-match policy: lowest (file, start_byte). Avoids
        // anchor-self when the anchor's name was somehow still in
        // play.
        let mut hits = hits;
        hits.sort_by(|a, b| a.file.cmp(&b.file).then(a.start_byte.cmp(&b.start_byte)));
        // Don't surface the anchor as its own dep.
        let chosen = match hits
            .into_iter()
            .find(|h| !(h.fid == anchor.fid && h.start_byte == anchor.start_byte))
        {
            Some(h) => h,
            None => continue,
        };
        resolved.push((name.clone(), chosen));
    }

    // Render each entry (read body bytes + dispatch the per-language
    // signature renderer). I/O or render failures degrade gracefully
    // to `signature: None`.
    //
    // alpha.29 M1: route dep file reads through the same
    // `path::resolve_workspace_path` gate the read handlers use.
    // Today this is defense-in-depth (the writer always stores
    // workspace-relative paths, so `def.file` couldn't be malicious
    // in practice). But the security review flagged that closure was
    // the one file-read surface that didn't share the gate, and a
    // future writer bug or stale db.redb could surface garbage. M2's
    // symlink rejection rides for free now.
    let mut rendered: Vec<DependencyEntry> = Vec::with_capacity(resolved.len());
    for (_name, def) in &resolved {
        let abs = match crate::path::resolve_workspace_path(workspace_root, &def.file) {
            Ok((abs, _rel)) => abs,
            Err(_) => {
                rendered.push(entry_without_signature(def));
                continue;
            }
        };
        let (start, end) = (def.start_byte as usize, def.end_byte as usize);
        let body_bytes = match std::fs::read(&abs) {
            Ok(b) => b,
            Err(_) => {
                rendered.push(entry_without_signature(def));
                continue;
            }
        };
        let slice = if end > start && end <= body_bytes.len() {
            &body_bytes[start..end]
        } else {
            &body_bytes[..]
        };
        let signature = crate::language::info_for_path(&def.file)
            .and_then(|info| info.signature_renderer)
            .and_then(|render| render(slice));
        rendered.push(DependencyEntry {
            qualified_name: def.name.clone(),
            kind: def.kind.as_wire_str().to_string(),
            file: def.file.clone(),
            start_line: def.start_line,
            end_line: def.end_line,
            start_byte: def.start_byte,
            end_byte: def.end_byte,
            signature,
        });
    }

    // Greedy-pack by ascending cost. The protocol cares about
    // *getting useful work done in one call*, so showing 20 short
    // signature deps beats showing 3 full-bodied ones.
    rendered.sort_by_key(entry_cost_bytes);

    // Convert budget to a bytes ceiling (the daemon counts
    // `bytes / 3`, so `tokens * 3` is the bytes a budget admits).
    let mut bytes_remaining: u64 = remaining_budget_tokens.saturating_mul(3);
    let mut dependencies: Vec<DependencyEntry> = Vec::new();
    let mut truncated: BTreeSet<String> = BTreeSet::new();
    let mut bytes_used: u64 = 0;
    for e in rendered {
        let cost = entry_cost_bytes(&e) as u64;
        if cost > bytes_remaining && !dependencies.is_empty() {
            truncated.insert(e.qualified_name.clone());
            continue;
        }
        // Always admit at least one entry — if the very first dep is
        // too big for the budget, we still surface it (the agent can
        // make a follow-up call with a bigger budget). The
        // `closure_truncated` flag will fire below if any others were
        // dropped.
        bytes_remaining = bytes_remaining.saturating_sub(cost);
        bytes_used = bytes_used.saturating_add(cost);
        dependencies.push(e);
    }

    // Also surface any *resolved* names that weren't rendered — e.g.
    // I/O errors that produced an entry but we still want the agent
    // to know about. (Currently they get pushed to `dependencies`
    // with `signature: None`, so this branch only fires for the
    // truncated-by-budget case.)
    let closure_truncated = !truncated.is_empty();
    let truncated_symbols: Vec<String> = truncated.into_iter().collect();
    ClosureResult {
        dependencies,
        closure_truncated,
        truncated_symbols,
        tokens_used: bytes_used.div_ceil(3), // mirrors approx_tokens() in methods/index.rs
    }
}

/// Build a `DependencyEntry` with `signature: None` when we couldn't
/// read or render. Helper to keep `compute` linear.
fn entry_without_signature(def: &FoundSymbol) -> DependencyEntry {
    DependencyEntry {
        qualified_name: def.name.clone(),
        kind: def.kind.as_wire_str().to_string(),
        file: def.file.clone(),
        start_line: def.start_line,
        end_line: def.end_line,
        start_byte: def.start_byte,
        end_byte: def.end_byte,
        signature: None,
    }
}

/// Approximate the byte footprint of one entry in the JSON response.
/// Includes the rendered signature plus a fudge for the JSON envelope
/// (field names, punctuation) — overestimating by a bit is safer than
/// underestimating, since the wire response is hard-capped at 16 MiB
/// per §3.3.
fn entry_cost_bytes(e: &DependencyEntry) -> usize {
    // Per-field envelope overhead. Empirically ~180 bytes for the
    // mandatory fields (qualified_name + kind + file + range) plus
    // JSON delimiters. We use a constant rather than computing it
    // exactly — the budget is approximate anyway.
    const ENVELOPE_BYTES: usize = 180;
    let sig_bytes = e.signature.as_deref().map(|s| s.len()).unwrap_or(0);
    e.qualified_name.len() + e.file.len() + sig_bytes + ENVELOPE_BYTES
}

/// Render a closure result into the wire-shaped JSON array the
/// `Index.ReadSymbol` handler embeds under `dependencies`.
///
/// Returned alongside `closure_truncated` and `truncated_symbols`
/// via the parent function's `ClosureResult`.
pub fn to_wire_value(deps: &[DependencyEntry]) -> serde_json::Value {
    serde_json::Value::Array(
        deps.iter()
            .map(|e| {
                serde_json::json!({
                    "qualified_name": e.qualified_name,
                    "kind":           e.kind,
                    "file":           e.file,
                    "range": {
                        "start_line": e.start_line,
                        "end_line":   e.end_line,
                        "start_byte": e.start_byte,
                        "end_byte":   e.end_byte,
                    },
                    "signature": match e.signature.as_deref() {
                        Some(s) => serde_json::Value::String(s.to_string()),
                        None => serde_json::Value::Null,
                    },
                })
            })
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dep(name: &str, sig: Option<&str>) -> DependencyEntry {
        DependencyEntry {
            qualified_name: name.to_string(),
            kind: "fn".to_string(),
            file: "src/lib.rs".to_string(),
            start_line: 1,
            end_line: 2,
            start_byte: 0,
            end_byte: 10,
            signature: sig.map(|s| s.to_string()),
        }
    }

    #[test]
    fn entry_cost_includes_signature() {
        let a = dep("foo", None);
        let b = dep("foo", Some("pub fn foo() -> u32"));
        assert!(entry_cost_bytes(&b) > entry_cost_bytes(&a));
    }

    #[test]
    fn empty_result_is_clean() {
        let r = ClosureResult::empty();
        assert!(r.dependencies.is_empty());
        assert!(!r.closure_truncated);
        assert!(r.truncated_symbols.is_empty());
        assert_eq!(r.tokens_used, 0);
    }

    #[test]
    fn to_wire_value_has_expected_shape() {
        let entries = vec![dep("foo", Some("pub fn foo() -> u32")), dep("bar", None)];
        let v = to_wire_value(&entries);
        let arr = v.as_array().expect("array");
        assert_eq!(arr.len(), 2);
        assert_eq!(arr[0]["qualified_name"], "foo");
        assert_eq!(arr[0]["kind"], "fn");
        assert_eq!(arr[0]["signature"], "pub fn foo() -> u32");
        assert!(arr[1]["signature"].is_null());
        assert!(arr[0]["range"].is_object());
    }

    #[test]
    fn extracted_identifiers_round_trip() {
        // The closure walker piggybacks on outline::extract_identifiers
        // for the regex fallback path; this test pins the tokenizer's
        // shape against the patterns closure needs (Rust-style paths,
        // calls, type names).
        let ids: std::collections::HashSet<String> =
            crate::outline::extract_identifiers("fn foo(x: u32) -> bar::Baz { call() }")
                .map(|s| s.to_string())
                .collect();
        assert!(ids.contains("foo"));
        assert!(ids.contains("bar"));
        assert!(ids.contains("Baz"));
        assert!(ids.contains("call"));
    }
}
