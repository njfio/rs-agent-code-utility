//! Symbol-level PageRank — v0.3 U4 of the code-graph KB plan.
//!
//! ## What this does
//!
//! Computes a PageRank score over the workspace-defined symbol set,
//! using the persistent reference graph (`SID_REFS_OUT` populated by
//! U1's writer) as the edge structure. The result fills the
//! `rank_score` field in `Index.FindSymbol` and `Index.FindCallers`
//! responses — which v0.2 left as a `0.0` placeholder.
//!
//! `find_symbol(pattern="*")` becomes the de-facto "top symbols in
//! this workspace" query: results sort by descending rank, with the
//! 256-entry cap surfacing the most-central symbols.
//!
//! ## Algorithm
//!
//! - **Nodes**: workspace-defined `sid`s (have ≥ 1 DEFS entry).
//!   External symbols (referenced but not workspace-defined) are
//!   filtered at commit time by U1's writer, so they have no
//!   NAME_TO_SID entry and are naturally absent here.
//! - **Edges**: `(caller_sid, callee_sid)` pairs from
//!   `SID_REFS_OUT`. Multimap dedup means each `(caller, callee)`
//!   pair contributes once even if there are multiple call sites in
//!   the same caller's body.
//! - **Weights**: Aider's recipe via
//!   [`rust_tree_sitter::pagerank::edge_weight`] — ×10 for compound
//!   well-named symbols (≥ 8 chars), ×0.1 for leading-underscore
//!   privates, ×0.1 for ubiquitous symbols (>5 defs across the
//!   workspace). `num_refs` is the call-site count (i.e. how often
//!   the caller references the callee), summed across all edges.
//! - **PageRank**: [`rust_tree_sitter::pagerank::compute`] with
//!   NetworkX defaults (α=0.85, max_iter=100, tol=1e-6). Returns
//!   ranks summing to 1.
//!
//! ## Caching
//!
//! Single-slot mutex cache keyed on `index_generation`, mirroring
//! alpha.20's [`crate::outline::OutlineCache`]. The first
//! `find_symbol` call after a generation bump pays the compute cost
//! (estimated 150–450ms on 100k LOC per plan §G3 / Deepening §C3);
//! subsequent calls at the same generation are O(1).
//!
//! ## Deferred (planned for follow-up)
//!
//! - **Stale-rank serving during recompute** (Deepening §C3): on
//!   cold compute, return v0.2 insertion-order results immediately
//!   while the recompute runs in the background. Subsequent calls
//!   pick up the new ranks. Not landed in U4 — first cut is
//!   synchronous compute (matches alpha.20's outline cache pattern).
//! - **Sorted-edge-vec collapse** instead of `HashMap<(u32,u32),f64>`
//!   in `pagerank::compute` (Deepening §C3): defer until perf bench
//!   confirms the cold-call latency target needs it. The existing
//!   compute path is shared with file-level PageRank.
//! - **Loosened TOL / capped iters** for symbol-level: ditto; defer
//!   until measured.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;

use anyhow::Context;
use rust_tree_sitter::pagerank::{Edge, compute as pagerank_compute, edge_weight};

use crate::store::Store;

/// Cached PageRank scores for a single `index_generation`.
#[derive(Debug, Clone)]
pub struct SymbolRanks {
    /// `index_generation` at the time the ranks were computed. The
    /// cache only hands these out when the daemon's current generation
    /// matches; stale entries are recomputed on the next lookup.
    pub generation: u64,
    /// `sid` → rank score. `0.0..=1.0`; the full sid set sums to 1.
    /// Lookups via the wire-level name go through `Store::sid_for_name`.
    pub sid_to_rank: HashMap<u32, f64>,
}

impl SymbolRanks {
    /// Returns the rank for a given `sid`, or `0.0` when the sid is
    /// not in the workspace-defined set (e.g. an external symbol
    /// that snuck through, or a torn read).
    pub fn rank_for(&self, sid: u32) -> f64 {
        self.sid_to_rank.get(&sid).copied().unwrap_or(0.0)
    }
}

/// Single-slot cache. Same shape as [`crate::outline::OutlineCache`]:
/// one entry, generation-keyed. The cache slot is `None` on cold
/// start (before the first commit) and after a generation mismatch
/// triggers a recompute.
#[derive(Default)]
pub struct SymbolPagerankCache {
    inner: Mutex<Option<Arc<SymbolRanks>>>,
}

impl SymbolPagerankCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Return the cached ranks if they match `generation`. Cheap:
    /// one mutex acquire + one Arc clone. Returns `None` when the
    /// cache is empty or stale; the caller invokes [`Self::put`] to
    /// fill the slot after a recompute.
    pub fn get(&self, generation: u64) -> Option<Arc<SymbolRanks>> {
        let g = self.inner.lock().ok()?;
        let entry = g.as_ref()?;
        if entry.generation == generation {
            Some(entry.clone())
        } else {
            None
        }
    }

    /// Replace the cache slot. The stored ranks are wrapped in `Arc`
    /// so cache hits hand out cheap clones — the caller only reads.
    pub fn put(&self, ranks: SymbolRanks) {
        if let Ok(mut g) = self.inner.lock() {
            *g = Some(Arc::new(ranks));
        }
    }

    /// Test-only: whether the slot is currently populated. Used by
    /// the integration tests to verify cache invalidation behavior.
    #[cfg(test)]
    pub fn is_occupied(&self) -> bool {
        self.inner.lock().map(|g| g.is_some()).unwrap_or(false)
    }
}

impl std::fmt::Debug for SymbolPagerankCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (occupied, gen_str) = match self.inner.lock() {
            Ok(g) => match g.as_ref() {
                Some(r) => (true, r.generation.to_string()),
                None => (false, "-".to_string()),
            },
            Err(_) => (false, "poisoned".to_string()),
        };
        f.debug_struct("SymbolPagerankCache")
            .field("occupied", &occupied)
            .field("generation", &gen_str)
            .finish()
    }
}

/// Compute symbol-level PageRank by enumerating workspace-defined
/// sids, building the edge set from `SID_REFS_OUT`, applying Aider's
/// edge-weight recipe, and running [`pagerank_compute`].
///
/// Returns the ranks keyed by sid; sids absent from this map have
/// rank 0 by convention (e.g. they're external, unindexed, or
/// belong to a future generation). Empty workspaces return an empty
/// map without error.
///
/// `generation` is folded into the result so cache writers can pair
/// the ranks with the generation they were computed against. The
/// invariant per Deepening §C: read the generation *before* opening
/// the read transaction below, never after — that's the caller's
/// responsibility (see `find_symbol` handler in `methods/index.rs`).
pub fn compute_symbol_ranks(store: &Store, generation: u64) -> anyhow::Result<SymbolRanks> {
    // Enumerate workspace-defined sids and their per-sid def counts.
    // The def count drives the "ubiquitous" edge-weight multiplier
    // (>5 defs across the workspace → ×0.1 dampening).
    let sid_info = collect_workspace_sids(store).context("collect_workspace_sids")?;
    if sid_info.is_empty() {
        return Ok(SymbolRanks {
            generation,
            sid_to_rank: HashMap::new(),
        });
    }

    // Assign dense indices [0..n) to sids — pagerank::compute uses
    // u32 node ids in that space.
    let mut sid_to_idx: HashMap<u32, u32> = HashMap::with_capacity(sid_info.len());
    let mut idx_to_sid: Vec<u32> = Vec::with_capacity(sid_info.len());
    for (sid, _name, _def_count) in &sid_info {
        sid_to_idx.insert(*sid, idx_to_sid.len() as u32);
        idx_to_sid.push(*sid);
    }

    // Build edges from SID_REFS_OUT, scoped to workspace-defined
    // callees (external sids would have no `sid_to_idx` entry and
    // are skipped — Deepening §F1 already filters them at commit
    // time, this is belt-and-suspenders).
    let edges = build_edges(store, &sid_info, &sid_to_idx).context("build_edges")?;

    // Run PageRank. Default uniform teleport (no personalization for
    // v0.3 U4; mentioned-files-style biasing is a v0.4+ concern).
    let n = idx_to_sid.len();
    let raw = pagerank_compute(n, &edges, None);

    // Translate dense ranks back to sid-keyed scores.
    let mut sid_to_rank: HashMap<u32, f64> = HashMap::with_capacity(n);
    for (i, r) in raw.iter().enumerate() {
        sid_to_rank.insert(idx_to_sid[i], *r);
    }

    Ok(SymbolRanks {
        generation,
        sid_to_rank,
    })
}

/// Collect every workspace-defined sid plus its `(name, def_count)`.
/// `def_count` is the number of DEFS rows for this sid (= how many
/// files define the symbol). Used by `build_edges` to compute the
/// "ubiquitous" multiplier per Aider's recipe.
fn collect_workspace_sids(store: &Store) -> anyhow::Result<Vec<(u32, String, u32)>> {
    let out = store
        .iter_workspace_sids()
        .context("iter_workspace_sids storage error")?;
    Ok(out)
}

/// Build the weighted edge set. Each `(caller_sid, callee_sid)` pair
/// in `SID_REFS_OUT` contributes one `Edge`. Weight applies Aider's
/// recipe to the *callee's* name (the symbol whose rank we're
/// computing inbound flow for) — well-named compound names attract
/// more rank; leading-underscore privates and ubiquitous names get
/// dampened.
fn build_edges(
    store: &Store,
    sid_info: &[(u32, String, u32)],
    sid_to_idx: &HashMap<u32, u32>,
) -> anyhow::Result<Vec<Edge>> {
    // Index callee names + ubiquity for fast lookup.
    let mut callee_meta: HashMap<u32, (&str, bool)> = HashMap::with_capacity(sid_info.len());
    for (sid, name, def_count) in sid_info {
        callee_meta.insert(*sid, (name.as_str(), *def_count > 5));
    }

    // Walk SID_REFS_OUT for each caller sid. The store helper returns
    // the deduplicated callee set per caller; we count parallel call
    // sites separately via REFS for the `num_refs` factor in the
    // edge weight.
    let mut edges: Vec<Edge> = Vec::with_capacity(sid_info.len() * 4);
    for (caller_sid, _name, _def_count) in sid_info {
        let callees = store.refs_from_symbol(*caller_sid)?;
        if callees.is_empty() {
            continue;
        }
        for callee_sid in callees {
            // Self-loops shouldn't exist in well-formed graphs but
            // skip defensively. Mutual recursion lands as two edges
            // (A→B and B→A) which PageRank handles natively via
            // teleportation.
            if callee_sid == *caller_sid {
                continue;
            }
            let (callee_name, is_ubiquitous) = match callee_meta.get(&callee_sid) {
                Some(&(n, u)) => (n, u),
                None => continue, // callee not in workspace-defined set
            };
            let src_idx = match sid_to_idx.get(caller_sid) {
                Some(&i) => i,
                None => continue,
            };
            let dst_idx = match sid_to_idx.get(&callee_sid) {
                Some(&i) => i,
                None => continue,
            };

            // num_refs is the per-(caller, callee) call-site count.
            // SID_REFS_OUT is dedup'd by multimap semantics, so we
            // join with REFS[callee_sid] filtered by caller-side
            // RefSites whose caller_sid matches.
            let num_refs = count_calls_between(store, *caller_sid, callee_sid)?;
            if num_refs == 0 {
                continue;
            }

            let w = edge_weight(callee_name, num_refs, false, false, is_ubiquitous);
            edges.push(Edge {
                src: src_idx,
                dst: dst_idx,
                weight: w,
            });
        }
    }
    Ok(edges)
}

/// Per-(caller, callee) call-site count. Walks `REFS[callee_sid]`
/// and counts RefSites whose `caller_sid == Some(caller)`. O(N)
/// per-callee scan — fine for v0.3 first cut; future optimization
/// is to cache per-batch counts at commit time if perf bench shows
/// this dominates.
fn count_calls_between(store: &Store, caller_sid: u32, callee_sid: u32) -> anyhow::Result<u32> {
    let sites = store.refs_to_symbol(callee_sid)?;
    let mut count = 0u32;
    for s in sites {
        if s.caller_sid == Some(caller_sid) {
            count = count.saturating_add(1);
        }
    }
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_workspace_returns_empty_ranks() {
        // Build a tempfile-backed store with no files committed; the
        // graph builder should return an empty rank map.
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("db.redb");
        let store = Store::open(&path).unwrap();
        let ranks = compute_symbol_ranks(&store, 0).unwrap();
        assert_eq!(ranks.generation, 0);
        assert!(ranks.sid_to_rank.is_empty());
    }

    #[test]
    fn cache_stores_and_invalidates_by_generation() {
        let cache = SymbolPagerankCache::new();
        assert!(cache.get(0).is_none(), "cold cache should miss");

        cache.put(SymbolRanks {
            generation: 7,
            sid_to_rank: [(1, 0.5), (2, 0.5)].into_iter().collect(),
        });
        let hit = cache.get(7).expect("hit at gen=7");
        assert_eq!(hit.generation, 7);
        assert!((hit.rank_for(1) - 0.5).abs() < 1e-9);
        assert!((hit.rank_for(2) - 0.5).abs() < 1e-9);
        assert_eq!(hit.rank_for(999), 0.0, "unknown sid → 0 rank");

        // Stale generation → miss (caller must recompute).
        assert!(cache.get(8).is_none(), "gen=8 should not hit gen=7 slot");

        // Re-putting at a new generation replaces the slot.
        cache.put(SymbolRanks {
            generation: 8,
            sid_to_rank: [(3, 1.0)].into_iter().collect(),
        });
        assert!(cache.get(7).is_none(), "gen=7 should now miss");
        let hit = cache.get(8).expect("hit at gen=8");
        assert!((hit.rank_for(3) - 1.0).abs() < 1e-9);
    }
}
