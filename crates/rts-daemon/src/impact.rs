//! `Index.ImpactOf` transitive caller closure — v0.3 U5.
//!
//! ## What this does
//!
//! Given an anchor symbol (e.g. a function the agent is about to
//! refactor), BFS the *reverse* reference graph to enumerate every
//! transitive caller — direct callers + the callers' callers, up to
//! a configurable depth. The result is the refactor-blast-radius:
//! "if I change X, what touches it (transitively)?"
//!
//! Where U2' `Index.FindCallers` is **depth-1, no body** and the
//! v0.3 U3 closure walker is **depth-1 outgoing** (X's deps),
//! `Index.ImpactOf` is **depth-N incoming** (transitively who
//! depends on X).
//!
//! ## Bounds (from plan + Deepening §E)
//!
//! All four bounds are belt-and-suspenders — any one triggering
//! flips a truncation flag:
//!
//! - **`max_depth`** (default 2, hard cap 4). JetBrains IntelliJ
//!   call-hierarchy guidance: 2-3 is the sweet spot; past 4 the
//!   result is noise.
//! - **`max_nodes`** (default 200). Token budgets alone aren't
//!   enough — a hub fn at depth 4 can produce 10⁴+ nodes before any
//!   token cap fires.
//! - **`token_budget`** (default 4096). Standard protocol-v0 §11
//!   `bytes_div_3` accounting. Hard ceiling 200000 per §16.
//! - **`wall_clock_budget`** (default 50 ms, fixed). Last-resort
//!   defense against pathological graphs that pass the other three
//!   bounds but somehow still take seconds.
//!
//! Each bound surfaces a separate truncation flag on the wire so
//! agents can tell *why* the result is partial (and pick a
//! mitigation: deeper depth, bigger budget, exclude tests, etc.).
//!
//! ## Cycle break
//!
//! `HashSet<sid>` visited-set; mutual recursion (A→B and B→A) lands
//! both at the appropriate depths without an infinite loop. Self-
//! loops are skipped at the seed step.
//!
//! ## Test-path exclusion (Deepening §E)
//!
//! When `exclude_test_paths: true` (default), callers whose
//! enclosing-def file matches the test-path heuristic are skipped.
//! IntelliJ's exclude-tests filter is the single biggest noise
//! reducer on real "find usages" results. See
//! [`is_test_path`].
//!
//! ## Wire shape (trimmed per Deepening §F3)
//!
//! Per Deepening §F3, the v0.3 plan's original 9-field per-entry
//! wire shape was trimmed to 6 (drop `signature` and nested
//! `callers` arrays — agents follow up with `find_callers` per
//! interesting entry):
//!
//! ```jsonc
//! {
//!   "impact": [
//!     { "qualified_name": "...", "kind": "fn", "file": "...",
//!       "range": { ... }, "depth": 1, "rank_score": 0.012 }
//!   ],
//!   "closure_truncated": false,
//!   "wall_clock_truncated": false,
//!   "depth_truncated": false,
//!   "node_count_truncated": false,
//!   "tokens_returned": 1247,
//!   "token_counter": "bytes_div_3"
//! }
//! ```

use std::collections::{HashSet, VecDeque};
use std::time::{Duration, Instant};

use serde::Serialize;

use crate::cancel::CancelToken;
use crate::store::{CallerDefInfo, RefSite, Store, SymbolKind};
use crate::symbol_pagerank::SymbolRanks;

/// Defaults — kept as `pub const` so callers and tests share one
/// source of truth. Wire layer applies these when the request omits
/// the param.
pub const DEFAULT_DEPTH: u32 = 2;
pub const MAX_DEPTH: u32 = 4;
pub const DEFAULT_MAX_NODES: u32 = 200;
pub const HARD_MAX_NODES: u32 = 10_000;
pub const DEFAULT_TOKEN_BUDGET: u64 = 4096;
pub const WALL_CLOCK_BUDGET: Duration = Duration::from_millis(50);

/// One impact entry in the response. Trimmed from the original
/// 9-field shape (plan §Phase 6) to 6 per Deepening §F3 —
/// `signature` and nested `callers` arrays were YAGNI'd. Agents
/// can re-issue `find_callers` per interesting entry if they want
/// to drill down.
#[derive(Debug, Clone, Serialize)]
pub struct ImpactEntry {
    pub qualified_name: String,
    /// Wire-stable kind string ("fn", "method", "module"). Drawn
    /// from the enclosing-def lookup; file-scope refs would have
    /// `kind: null`, but those are excluded at the BFS step
    /// (impact only walks fn-shaped callers).
    pub kind: String,
    pub file: String,
    pub start_line: u32,
    pub end_line: u32,
    pub start_byte: u32,
    pub end_byte: u32,
    /// 1-based BFS depth — the number of edges from the anchor.
    /// Direct callers are depth=1; their callers are depth=2; etc.
    pub depth: u32,
    /// Caller's symbol-level PageRank (alpha.34+). `0.0` on cold
    /// start before ranks are computed.
    pub rank_score: f64,
}

/// Result of one `Index.ImpactOf` call.
#[derive(Debug, Clone)]
pub struct ImpactResult {
    pub impact: Vec<ImpactEntry>,
    /// Token-budget truncation. Set when `max_nodes`+`tokens_per_entry`
    /// would have exceeded the caller's budget and we stopped
    /// adding entries.
    pub closure_truncated: bool,
    /// Wall-clock truncation. Set when `WALL_CLOCK_BUDGET` elapsed
    /// before BFS completed. Hard cap; non-configurable.
    pub wall_clock_truncated: bool,
    /// Depth-cap truncation. Set when at least one BFS frontier
    /// hit `max_depth` while there were still unvisited callers.
    pub depth_truncated: bool,
    /// Node-count truncation. Set when the `max_nodes` cap fired
    /// before BFS could enumerate all transitive callers.
    pub node_count_truncated: bool,
    /// Approximate token cost of the response body. Mirrors
    /// `closure::ClosureResult.tokens_used`'s shape.
    pub tokens_used: u64,
}

impl ImpactResult {
    pub fn empty() -> Self {
        Self {
            impact: Vec::new(),
            closure_truncated: false,
            wall_clock_truncated: false,
            depth_truncated: false,
            node_count_truncated: false,
            tokens_used: 0,
        }
    }
}

/// Per-call bounds, exposed for the handler to normalize from wire
/// params. All fields have safe defaults; values out of range are
/// clamped (not rejected) so old clients don't get `INVALID_PARAMS`
/// when a future server tightens a default.
#[derive(Debug, Clone, Copy)]
pub struct ImpactBounds {
    pub max_depth: u32,
    pub max_nodes: u32,
    pub token_budget: u64,
    pub exclude_test_paths: bool,
}

impl Default for ImpactBounds {
    fn default() -> Self {
        Self {
            max_depth: DEFAULT_DEPTH,
            max_nodes: DEFAULT_MAX_NODES,
            token_budget: DEFAULT_TOKEN_BUDGET,
            exclude_test_paths: true,
        }
    }
}

impl ImpactBounds {
    /// Clamp user-supplied bounds to safe values.
    pub fn clamp(mut self) -> Self {
        self.max_depth = self.max_depth.clamp(1, MAX_DEPTH);
        self.max_nodes = self.max_nodes.clamp(1, HARD_MAX_NODES);
        // token_budget validated by the wire layer's existing
        // 50..=200000 window; we just guard against absurd values.
        if self.token_budget == 0 {
            self.token_budget = DEFAULT_TOKEN_BUDGET;
        }
        self
    }
}

/// Heuristic: is this workspace-relative path a test file? Used by
/// the `exclude_test_paths` filter. The heuristic is intentionally
/// conservative — it errs toward filtering things that *look* like
/// tests, since the alternative (an over-broad impact result) is
/// noisier than missing a real production caller.
///
/// Matched patterns (case-insensitive substring):
/// - `tests/` or `test/` anywhere in the path
/// - `__tests__/` (JS convention)
/// - filename ends with `_test.<ext>`, `_tests.<ext>`, `_spec.<ext>`,
///   or `.test.<ext>` (JS / TS convention)
/// - filename ends with `.spec.<ext>` (JS / Rust integration convention)
pub fn is_test_path(rel_path: &str) -> bool {
    let lower = rel_path.to_ascii_lowercase();
    // Directory-shaped patterns.
    if lower.contains("/tests/")
        || lower.contains("/test/")
        || lower.contains("/__tests__/")
        || lower.starts_with("tests/")
        || lower.starts_with("test/")
    {
        return true;
    }
    // Filename-shaped patterns. Pull the basename without
    // extension(s) since `_test.rs` and `_test.py` both qualify.
    let basename = lower.rsplit('/').next().unwrap_or(&lower);
    // Strip everything after the first '.' to handle multi-extension
    // forms (`foo.spec.ts` → "foo"+"spec.ts" → check "spec").
    let parts: Vec<&str> = basename.split('.').collect();
    if parts.len() < 2 {
        return false;
    }
    let stem = parts[0];
    let after_first_dot = parts[1];
    // `_test.rs`, `_tests.rs`, `_spec.rs`
    if stem.ends_with("_test") || stem.ends_with("_tests") || stem.ends_with("_spec") {
        return true;
    }
    // `.test.ts` / `.spec.ts` (JS convention)
    if after_first_dot == "test" || after_first_dot == "spec" {
        return true;
    }
    false
}

/// Compute the transitive caller closure of `anchor_sid`. BFS over
/// the reverse reference graph (`REFS` table) with the four bounds
/// applied at the frontier-walking step.
///
/// `ranks` is `None` during cold-start (before symbol-level
/// PageRank has been computed); entries get `rank_score: 0.0` in
/// that case.
pub fn compute(
    store: &Store,
    anchor_sid: u32,
    bounds: ImpactBounds,
    ranks: Option<&SymbolRanks>,
    token: &CancelToken,
) -> anyhow::Result<ImpactResult> {
    let bounds = bounds.clamp();
    let started = Instant::now();

    // BFS state. The visited set holds sids we've enqueued (not
    // necessarily emitted — bound checks may drop a sid before it
    // lands in `impact`). The depth map records the first-seen
    // depth so subsequent enqueues at deeper layers are skipped.
    let mut visited: HashSet<u32> = HashSet::new();
    let mut queue: VecDeque<(u32, u32)> = VecDeque::new(); // (sid, depth)
    visited.insert(anchor_sid);
    queue.push_back((anchor_sid, 0));

    let mut impact: Vec<ImpactEntry> = Vec::new();
    let mut closure_truncated = false;
    let mut wall_clock_truncated = false;
    let mut depth_truncated = false;
    let mut node_count_truncated = false;

    // Approx per-entry token cost — matches the constant used in
    // read_symbol_body's include_callers branch. ImpactEntries don't
    // carry signature/text, so they're cheaper than CallerEntries;
    // 50 is a reasonable approximation of `qualified_name + file +
    // range + depth + rank_score` JSON envelope size / 3.
    const APPROX_TOKENS_PER_ENTRY: u64 = 50;
    let mut bytes_used: u64 = 0;
    let budget_bytes: u64 = bounds.token_budget.saturating_mul(3);

    while let Some((sid, depth)) = queue.pop_front() {
        // Cooperative cancellation: poll at every frontier dequeue so a
        // per-request deadline (or explicit Daemon.Cancel) interrupts
        // the BFS mid-walk. We `break` with whatever we've gathered;
        // the handler checks `token.is_cancelled()` after `compute`
        // returns and surfaces CANCELLED (rewritten to
        // DEADLINE_EXCEEDED by dispatch when a deadline fired).
        if token.is_cancelled() {
            break;
        }
        // Wall-clock check on every dequeue — keeps the worst-case
        // bounded at "constant work per node + wall-clock check".
        if started.elapsed() >= WALL_CLOCK_BUDGET {
            wall_clock_truncated = true;
            break;
        }

        if depth >= bounds.max_depth {
            // We've reached the depth cap. Any callers of this sid
            // would be at `depth + 1 > max_depth` — out of scope.
            // Don't flip `depth_truncated` from this branch alone:
            // we need to confirm there *were* unvisited callers.
            // Cheap probe below.
            if !depth_truncated {
                let sites = store.refs_to_symbol(sid)?;
                if sites
                    .iter()
                    .any(|s| s.caller_sid.is_some_and(|c| !visited.contains(&c)))
                {
                    depth_truncated = true;
                }
            }
            continue;
        }

        // Walk the callers of `sid` (one redb lookup).
        let sites = store.refs_to_symbol(sid)?;
        for site in sites {
            let caller_sid = match site.caller_sid {
                Some(c) => c,
                None => continue, // file-scope call; no enclosing def to surface
            };
            if !visited.insert(caller_sid) {
                continue; // already visited (cycle break)
            }

            // Resolve the caller's def info.
            let info = match store.caller_def_info(caller_sid, site.fid)? {
                Some(i) => i,
                None => continue,
            };

            // Path resolution — needed for both `file` field and
            // test-path exclusion.
            let file = match store.path_for_fid(site.fid)? {
                Some(p) => p,
                None => continue,
            };

            // Test-path filter.
            if bounds.exclude_test_paths && is_test_path(&file) {
                continue;
            }

            // Filter out non-call-bearing kinds at the wire level
            // too (defensive — the writer should already only set
            // caller_sid to Function/Method/Module per U3's
            // is_call_bearing_kind filter).
            if !matches!(
                info.kind,
                SymbolKind::Function | SymbolKind::Method | SymbolKind::Module
            ) {
                continue;
            }

            let entry_depth = depth + 1;
            let entry = build_entry(caller_sid, entry_depth, &file, &info, &site, ranks);
            let entry_bytes = APPROX_TOKENS_PER_ENTRY.saturating_mul(3);

            // Node-count bound.
            if (impact.len() as u32) >= bounds.max_nodes {
                node_count_truncated = true;
                break;
            }
            // Token-budget bound.
            if bytes_used.saturating_add(entry_bytes) > budget_bytes && !impact.is_empty() {
                closure_truncated = true;
                break;
            }
            bytes_used = bytes_used.saturating_add(entry_bytes);
            impact.push(entry);

            // Enqueue for further BFS.
            queue.push_back((caller_sid, entry_depth));
        }

        // Outer-loop bail-out — if either node or budget cap hit
        // during the inner iteration, stop the whole BFS (don't
        // process the next dequeued sid).
        if node_count_truncated || closure_truncated {
            break;
        }
    }

    // Sort: depth ASC (direct callers first) then rank_score DESC
    // (most-central callers first within each depth tier). Per
    // Deepening §E "re-rank transitive callers by PageRank
    // descending" — once node count > 50, unranked results are
    // noise.
    impact.sort_by(|a, b| {
        a.depth
            .cmp(&b.depth)
            .then(
                b.rank_score
                    .partial_cmp(&a.rank_score)
                    .unwrap_or(std::cmp::Ordering::Equal),
            )
            .then(a.file.cmp(&b.file))
            .then(a.start_byte.cmp(&b.start_byte))
    });

    let tokens_used = (impact.len() as u64).saturating_mul(APPROX_TOKENS_PER_ENTRY);

    Ok(ImpactResult {
        impact,
        closure_truncated,
        wall_clock_truncated,
        depth_truncated,
        node_count_truncated,
        tokens_used,
    })
}

fn build_entry(
    caller_sid: u32,
    depth: u32,
    file: &str,
    info: &CallerDefInfo,
    _site: &RefSite,
    ranks: Option<&SymbolRanks>,
) -> ImpactEntry {
    let rank_score = ranks.map(|r| r.rank_for(caller_sid)).unwrap_or(0.0);
    ImpactEntry {
        qualified_name: info.name.clone(),
        kind: info.kind.as_wire_str().to_string(),
        file: file.to_string(),
        start_line: info.def_start_line,
        end_line: info.def_end_line,
        start_byte: info.def_start_byte,
        end_byte: info.def_end_byte,
        depth,
        rank_score,
    }
}

/// Render an `ImpactResult` into the wire-shaped JSON the
/// `Index.ImpactOf` handler embeds under `impact`.
pub fn to_wire_value(impact: &[ImpactEntry]) -> serde_json::Value {
    serde_json::Value::Array(
        impact
            .iter()
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
                    "depth":      e.depth,
                    "rank_score": e.rank_score,
                })
            })
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_result_is_clean() {
        let r = ImpactResult::empty();
        assert!(r.impact.is_empty());
        assert!(!r.closure_truncated);
        assert!(!r.wall_clock_truncated);
        assert!(!r.depth_truncated);
        assert!(!r.node_count_truncated);
        assert_eq!(r.tokens_used, 0);
    }

    #[test]
    fn bounds_clamp_to_safe_window() {
        let b = ImpactBounds {
            max_depth: 100,
            max_nodes: 1_000_000,
            token_budget: 0,
            exclude_test_paths: true,
        }
        .clamp();
        assert_eq!(b.max_depth, MAX_DEPTH, "depth clamped to MAX_DEPTH");
        assert_eq!(
            b.max_nodes, HARD_MAX_NODES,
            "max_nodes clamped to HARD_MAX_NODES"
        );
        assert_eq!(b.token_budget, DEFAULT_TOKEN_BUDGET, "zero budget reset");

        let b = ImpactBounds {
            max_depth: 0,
            max_nodes: 0,
            token_budget: 1024,
            exclude_test_paths: false,
        }
        .clamp();
        assert_eq!(b.max_depth, 1, "zero depth clamped up to 1");
        assert_eq!(b.max_nodes, 1, "zero max_nodes clamped up to 1");
        assert_eq!(b.token_budget, 1024, "non-zero budget preserved");
    }

    #[test]
    fn is_test_path_matches_common_conventions() {
        // Directory-shaped patterns.
        assert!(is_test_path("crates/rts-daemon/tests/wire_round_trip.rs"));
        assert!(is_test_path("src/foo/test/bar.py"));
        assert!(is_test_path("packages/ui/__tests__/Button.test.tsx"));
        assert!(is_test_path("tests/integration.rs"));
        // Filename-shaped patterns.
        assert!(is_test_path("src/lib_test.rs"));
        assert!(is_test_path("src/utils_tests.go"));
        assert!(is_test_path("src/parser_spec.rb"));
        assert!(is_test_path("packages/ui/Button.test.ts"));
        assert!(is_test_path("packages/ui/Button.spec.tsx"));
        // Non-test paths.
        assert!(!is_test_path("src/lib.rs"));
        assert!(!is_test_path("src/foo/bar.py"));
        assert!(!is_test_path("packages/ui/Button.tsx"));
        // Edge: filename containing "test" but not in a test-shaped position.
        assert!(!is_test_path("src/contestant.rs"));
        assert!(!is_test_path("src/protest_handler.rs"));
    }

    #[test]
    fn to_wire_value_has_trimmed_shape() {
        // The Deepening §F3 trim: 6 fields per entry, no signature
        // or nested callers.
        let entries = vec![ImpactEntry {
            qualified_name: "foo".into(),
            kind: "fn".into(),
            file: "src/lib.rs".into(),
            start_line: 1,
            end_line: 2,
            start_byte: 0,
            end_byte: 10,
            depth: 1,
            rank_score: 0.123,
        }];
        let v = to_wire_value(&entries);
        let arr = v.as_array().expect("array");
        assert_eq!(arr.len(), 1);
        let e = &arr[0];
        assert_eq!(e["qualified_name"], "foo");
        assert_eq!(e["kind"], "fn");
        assert_eq!(e["depth"], 1);
        assert!((e["rank_score"].as_f64().unwrap() - 0.123).abs() < 1e-9);
        assert!(e["range"].is_object());
        // Trimmed: no signature, no nested callers array.
        assert!(e.get("signature").is_none(), "signature should be trimmed");
        assert!(
            e.get("callers").is_none(),
            "nested callers should be trimmed"
        );
    }

    #[test]
    fn empty_workspace_returns_empty_impact() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("db.redb");
        let store = Store::open(&path).unwrap();
        // Anchor sid that doesn't exist — BFS from an unvisited
        // sid degenerates to "no callers found."
        let r = compute(
            &store,
            999,
            ImpactBounds::default(),
            None,
            &CancelToken::new(),
        )
        .unwrap();
        assert!(r.impact.is_empty());
        assert!(!r.closure_truncated);
        assert!(!r.wall_clock_truncated);
    }

    /// A BFS handed an already-tripped token returns immediately with
    /// an empty result — the cooperative poll at the frontier loop head
    /// breaks before any caller is enqueued. This is the unit-level
    /// guarantee behind `Index.ImpactOf`'s deadline interruptibility
    /// (the e2e path is gated by the 50ms wall-clock budget, which
    /// makes a reliably-slow fixture impractical).
    #[test]
    fn impact_bfs_breaks_on_pretripped_token() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("db.redb");
        let store = Store::open(&path).unwrap();
        let token = CancelToken::new();
        token.cancel();
        let r = compute(&store, 0, ImpactBounds::default(), None, &token).unwrap();
        assert!(
            r.impact.is_empty(),
            "a pre-cancelled token must short-circuit the BFS before emitting entries"
        );
    }
}
