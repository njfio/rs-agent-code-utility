//! `Index.ReadSymbol` closure walker — implements the
//! `include_dependencies: true` branch of protocol-v0 §7.7.
//!
//! ### What this does
//!
//! Given an anchor symbol the agent asked for, look up its outgoing
//! references via the persistent ref graph (alpha.31 U1) and surface
//! each referenced symbol as a lightweight dep entry:
//! `qualified_name`, `kind`, `file`, `range`, and a rendered
//! `signature`. This lets agents do their work in one round trip
//! instead of N `Index.FindSymbol` + `Index.ReadSymbol` follow-ups —
//! a measurable token-reduction win on the §P9 baseline tasks
//! (`get_body`, `summarize_module`, etc.).
//!
//! ### v0.3 U3 — indexed-edge swap
//!
//! Before alpha.33, this module re-parsed the anchor body on every
//! call via `crate::refs::references_for_path` and filtered against
//! the workspace-wide def-name set. The U1 ref graph means we can
//! now read the outgoing edges from `SID_REFS_OUT` directly — one
//! redb lookup instead of a tree-sitter parse + filter. Same
//! external behavior; the `closure_round_trip` + `closure_precision`
//! integration tests pass unchanged.
//!
//! ### Scope (v0)
//!
//! - **Depth 1.** We enumerate the anchor's outgoing edges from the
//!   indexed graph and return one entry per unique referenced
//!   symbol. We do not recursively walk the deps' edges. Agents that
//!   want depth > 1 can re-call `Index.ReadSymbol` on each entry, or
//!   use `Index.ImpactOf` (v0.3 U5) for the transitive *caller*
//!   direction.
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
//! Index.ImpactOf (v0.3 U5) provides multi-hop in the caller
//! direction; multi-hop in the dependency direction would re-call
//! `compute` recursively.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

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

/// Walk the closure of `anchor` and return the dep entries that fit
/// in `remaining_budget_tokens`.
///
/// `workspace_root` is needed to read each dep's file contents for
/// signature rendering. I/O failures on a single dep don't fail the
/// whole call — that dep just gets `signature: None` and we move on.
///
/// v0.3 U3 (alpha.33): outgoing refs now come from the indexed
/// `SID_REFS_OUT` table (populated by the writer in U1). No more
/// re-parsing the anchor body. The candidate set is implicitly
/// filtered to workspace-defined names because the writer's
/// commit-time external-symbol filter (§F1) only interns
/// workspace-defined callees into NAME_TO_SID.
pub fn compute(
    workspace_root: &Path,
    store: &Store,
    anchor: &FoundSymbol,
    remaining_budget_tokens: u64,
    signature_cache: &crate::state::SignatureCache,
) -> ClosureResult {
    // Fine-grained timing — same env-var gate as the outer
    // `RTS_PROFILE_READ_SYMBOL`. Lets us see WHICH sub-section of
    // closure_walk dominates on the regression tail.
    let profile = std::env::var("RTS_PROFILE_READ_SYMBOL")
        .map(|v| !v.is_empty() && v != "0")
        .unwrap_or(false);
    macro_rules! cmark {
        ($t:ident, $label:literal, $count:expr) => {
            if profile {
                eprintln!(
                    "closure:{:>26} = {:>6} µs  (n={})",
                    $label,
                    $t.elapsed().as_micros(),
                    $count,
                );
                #[allow(unused_assignments)]
                {
                    $t = std::time::Instant::now();
                }
            }
        };
    }
    let mut t = std::time::Instant::now();

    // Resolve the anchor's sid so we can look up its outgoing edges.
    // The anchor came from `Store::find_symbol(name)` or
    // `Store::defs_in_file(path)`, so by construction the name has a
    // NAME_TO_SID entry — but bail gracefully on a torn read.
    let anchor_sid = match store.sid_for_name(&anchor.name) {
        Ok(Some(s)) => s,
        _ => return ClosureResult::empty(),
    };
    cmark!(t, "anchor_sid_lookup", 1);
    // Pull outgoing edges from the indexed graph. The writer's
    // smallest-enclosing-def resolution at commit time (U1) means
    // each edge's caller_sid is the def whose byte range covers the
    // call site — so `refs_from_symbol(anchor_sid)` returns exactly
    // the callees of the anchor's body, deduplicated by callee sid.
    //
    // File-scope refs (caller_sid == None) within the anchor's file
    // are correctly excluded — they have no caller to key the
    // SID_REFS_OUT edge on, so they wouldn't be in the closure even
    // under the v0.2 behavior (which extracted from the anchor body
    // alone, not the whole file).
    let callee_sids = match store.refs_from_symbol(anchor_sid) {
        Ok(v) => v,
        Err(_) => return ClosureResult::empty(),
    };
    let callee_count = callee_sids.len();
    cmark!(t, "refs_from_symbol", callee_count);
    let mut candidates: BTreeSet<String> = BTreeSet::new();
    for callee_sid in callee_sids {
        if callee_sid == anchor_sid {
            continue; // skip self-reference (mutual recursion would land here too)
        }
        let name = match store.name_for_sid(callee_sid) {
            Ok(Some(n)) => n,
            _ => continue, // torn read or unknown sid; skip
        };
        candidates.insert(name);
    }
    cmark!(t, "name_for_sid_loop", candidates.len());
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
    cmark!(t, "find_symbol_resolve_loop", resolved.len());

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
    // Per-call file cache: multiple deps frequently live in the same
    // file (e.g. tree-sitter wrapper methods on `SyntaxTree` all live
    // in `tree.rs`). Reading the file once and reusing the buffer
    // across deps avoids N full `read()` syscalls when the resolved
    // set has N deps in 1-2 files. On `crates/rts-core` reads where
    // deps cluster, this is the per-call hot path. Sized to
    // `resolved.len()` upper bound; in practice files-per-call is much
    // smaller (typically 1-5 distinct files).
    // Each cache value is `(bytes, mtime_ns)` — mtime is the
    // signature cache's invalidation key, fetched once per file
    // via `std::fs::metadata` alongside the read.
    let mut file_cache: std::collections::HashMap<PathBuf, Option<(Vec<u8>, i128)>> =
        std::collections::HashMap::with_capacity(resolved.len().min(8));
    let mut rendered: Vec<DependencyEntry> = Vec::with_capacity(resolved.len());
    for (_name, def) in &resolved {
        let abs = match crate::path::resolve_workspace_path(workspace_root, &def.file) {
            Ok((abs, _rel)) => abs,
            Err(_) => {
                rendered.push(entry_without_signature(def));
                continue;
            }
        };
        // Reuse cached bytes when this dep's file has already been
        // read for an earlier dep in this same call. `None` cached
        // values flag an earlier I/O failure so we don't retry per dep.
        let body_with_mtime: Option<(&[u8], i128)> = if let Some(cached) = file_cache.get(&abs) {
            cached.as_ref().map(|(b, m)| (b.as_slice(), *m))
        } else {
            let result = std::fs::read(&abs).and_then(|b| {
                let m = std::fs::metadata(&abs)?;
                let mtime_ns = m
                    .modified()
                    .ok()
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|d| d.as_nanos() as i128)
                    .unwrap_or(0);
                Ok((b, mtime_ns))
            });
            match result {
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
        let Some((body_bytes, mtime_ns)) = body_with_mtime else {
            rendered.push(entry_without_signature(def));
            continue;
        };
        let (start, end) = (def.start_byte as usize, def.end_byte as usize);
        let slice = if end > start && end <= body_bytes.len() {
            &body_bytes[start..end]
        } else {
            body_bytes
        };
        // Tree-sitter signature renders are expensive (1248 µs avg
        // per-call on `crates/rts-core` deps walks); cache per
        // `(path, byte_range, mtime)`.
        let signature =
            signature_cache.get_or_compute(&abs, def.start_byte, def.end_byte, mtime_ns, || {
                crate::language::info_for_path(&def.file)
                    .and_then(|info| info.signature_renderer)
                    .and_then(|render| render(slice))
            });
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
    cmark!(t, "render_loop_total", rendered.len());

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
        // Sanity test for the regex tokenizer used by
        // `refs::references_with_ranges` for languages without a
        // tags.scm query (C, C++, Java, PHP, Swift). v0.3 U3 no
        // longer routes the closure walker through this path —
        // the walker now reads `store.refs_from_symbol` directly
        // (which itself is fed by the same regex fallback at
        // write time for those languages). The test stays because
        // `extract_identifiers` is still the underlying tokenizer.
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
