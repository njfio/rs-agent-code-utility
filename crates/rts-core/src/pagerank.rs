//! Personalised PageRank over a file→file reference graph.
//!
//! Per plan §"Aider repo-map algorithm (concrete recipe)": NetworkX
//! defaults (α=0.85, max_iter=100, tol=1e-6), power iteration with
//! row-stochastic transition. Graph type is a MultiDiGraph collapsed
//! to summed edge weights for ~5–10× speedup with identical scores.
//!
//! This is the v0 naïve implementation: full recompute on every
//! `Index.Outline` call. P8's incremental-update path (push-flow
//! local PageRank, Andersen et al. 2006) is a later slice when the
//! S1 latency budget says it's needed.

use std::collections::HashMap;

/// Damping factor — NetworkX default. The probability that the
/// random walker follows an edge rather than teleporting.
pub const DAMPING: f64 = 0.85;
/// Maximum power-iteration count — NetworkX default.
pub const MAX_ITER: u32 = 100;
/// Convergence tolerance (L1 norm of delta) — NetworkX default.
pub const TOL: f64 = 1e-6;

/// A directed weighted edge from `src` (referencer) to `dst` (definer).
/// Multiple edges between the same pair are summed by `compute`.
#[derive(Debug, Clone, Copy)]
pub struct Edge {
    pub src: u32,
    pub dst: u32,
    pub weight: f64,
}

/// Run PageRank over `n` nodes given a list of weighted directed
/// edges and an optional personalization vector. Returns the rank of
/// each node — non-negative, summing to 1.
///
/// `personalization[i]` biases the random walker's restart toward
/// node `i`. When `None`, uniform restart is used. Per Aider, the
/// caller should retry with `None` if the personalized run produces
/// a degenerate result.
pub fn compute(n: usize, edges: &[Edge], personalization: Option<&[f64]>) -> Vec<f64> {
    if n == 0 {
        return Vec::new();
    }

    // Collapse parallel edges by (src, dst) → summed weight.
    let mut collapsed: HashMap<(u32, u32), f64> = HashMap::new();
    for e in edges {
        *collapsed.entry((e.src, e.dst)).or_insert(0.0) += e.weight;
    }

    // Outgoing weight per source — denominator for the transition matrix.
    let mut out_weight: Vec<f64> = vec![0.0; n];
    for (&(src, _), &w) in &collapsed {
        out_weight[src as usize] += w;
    }

    // Reverse adjacency for efficient PR update: for each `dst`, list of
    // (src, weight). Power iteration walks "what flows INTO this node".
    let mut in_edges: Vec<Vec<(u32, f64)>> = vec![Vec::new(); n];
    for (&(src, dst), &w) in &collapsed {
        in_edges[dst as usize].push((src, w));
    }

    // Personalization vector. Default: uniform 1/n.
    let teleport: Vec<f64> = match personalization {
        Some(p) if p.len() == n => {
            let sum: f64 = p.iter().sum();
            if sum > 0.0 {
                p.iter().map(|x| x / sum).collect()
            } else {
                vec![1.0 / n as f64; n]
            }
        }
        _ => vec![1.0 / n as f64; n],
    };

    // Initial rank — uniform.
    let mut rank: Vec<f64> = vec![1.0 / n as f64; n];

    for _iter in 0..MAX_ITER {
        let mut next: Vec<f64> = teleport.iter().map(|t| (1.0 - DAMPING) * t).collect();

        // Dangling-node mass: nodes with no outgoing edges contribute
        // their entire rank to the teleport set.
        let mut dangling_mass = 0.0;
        for i in 0..n {
            if out_weight[i] == 0.0 {
                dangling_mass += rank[i];
            }
        }
        for i in 0..n {
            next[i] += DAMPING * dangling_mass * teleport[i];
        }

        // Inbound contributions.
        for i in 0..n {
            for &(src, w) in &in_edges[i] {
                let src_out = out_weight[src as usize];
                if src_out > 0.0 {
                    next[i] += DAMPING * rank[src as usize] * (w / src_out);
                }
            }
        }

        // Convergence check.
        let delta: f64 = rank.iter().zip(&next).map(|(a, b)| (a - b).abs()).sum();
        rank = next;
        if delta < TOL {
            break;
        }
    }

    rank
}

/// Edge weight per the Aider recipe. `mul = 1.0 × …`:
/// - `× 10`  if ident in `mentioned_idents`
/// - `× 10`  if compound name && len >= 8
/// - `× 0.1` if ident starts with `_`
/// - `× 0.1` if ident is ubiquitous (defined in > 5 files)
/// - `× 50`  if referencer is in chat_files
///
/// Weight = `mul × sqrt(num_refs)`.
pub fn edge_weight(
    ident: &str,
    num_refs: u32,
    in_mentioned_idents: bool,
    in_chat_files: bool,
    is_ubiquitous: bool,
) -> f64 {
    let mut mul = 1.0;
    if in_mentioned_idents {
        mul *= 10.0;
    }
    if ident.len() >= 8 && is_compound(ident) {
        mul *= 10.0;
    }
    if ident.starts_with('_') {
        mul *= 0.1;
    }
    if is_ubiquitous {
        mul *= 0.1;
    }
    if in_chat_files {
        mul *= 50.0;
    }
    mul * (num_refs as f64).sqrt()
}

/// Compound identifier heuristic: contains `_`, `-`, or has a
/// camelCase transition (any pair of adjacent lower→upper letters).
fn is_compound(s: &str) -> bool {
    if s.contains('_') || s.contains('-') {
        return true;
    }
    let bytes = s.as_bytes();
    for w in bytes.windows(2) {
        if w[0].is_ascii_lowercase() && w[1].is_ascii_uppercase() {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_ranks_sum_to_one(rank: &[f64]) {
        let sum: f64 = rank.iter().sum();
        assert!(
            (sum - 1.0).abs() < 1e-6,
            "ranks should sum to 1; got {sum} ({rank:?})"
        );
    }

    #[test]
    fn empty_graph_returns_empty() {
        assert!(compute(0, &[], None).is_empty());
    }

    #[test]
    fn single_node_no_edges() {
        let r = compute(1, &[], None);
        assert_eq!(r.len(), 1);
        assert!((r[0] - 1.0).abs() < 1e-9);
    }

    #[test]
    fn two_node_chain_dst_outranks_src() {
        // 0 → 1: node 1 should have higher rank than 0.
        let edges = vec![Edge {
            src: 0,
            dst: 1,
            weight: 1.0,
        }];
        let r = compute(2, &edges, None);
        assert!(r[1] > r[0], "dst should outrank src; got {r:?}");
        assert_ranks_sum_to_one(&r);
    }

    #[test]
    fn hub_outranks_leaf() {
        // 0,1,2,3 all point to 4. Node 4 should rank highest.
        let edges: Vec<Edge> = (0..4)
            .map(|i| Edge {
                src: i,
                dst: 4,
                weight: 1.0,
            })
            .collect();
        let r = compute(5, &edges, None);
        let max_idx = r
            .iter()
            .enumerate()
            .max_by(|a, b| a.1.partial_cmp(b.1).unwrap())
            .unwrap()
            .0;
        assert_eq!(max_idx, 4, "node 4 should rank highest; got {r:?}");
        assert_ranks_sum_to_one(&r);
    }

    #[test]
    fn personalization_biases_rank() {
        let edges = vec![
            Edge {
                src: 0,
                dst: 1,
                weight: 1.0,
            },
            Edge {
                src: 1,
                dst: 2,
                weight: 1.0,
            },
        ];
        // Bias teleport toward node 0 — it should outrank where it
        // would otherwise lose to the chain.
        let p = vec![1.0, 0.0, 0.0];
        let r = compute(3, &edges, Some(&p));
        // Without personalization, dst-of-chain (node 2) ranks highest.
        // With teleport pinned to node 0, node 0 should be at least
        // competitive.
        assert_ranks_sum_to_one(&r);
        let r_none = compute(3, &edges, None);
        assert!(
            r[0] > r_none[0],
            "personalization should boost node 0; got pers={r:?} vs uniform={r_none:?}"
        );
    }

    #[test]
    fn edge_weight_recipe() {
        // Plain ident, 1 ref → mul=1.0, weight = sqrt(1) = 1.0.
        assert!((edge_weight("foo", 1, false, false, false) - 1.0).abs() < 1e-9);
        // mentioned_idents → ×10.
        assert!((edge_weight("foo", 1, true, false, false) - 10.0).abs() < 1e-9);
        // Compound name + len ≥ 8 → ×10.
        let w = edge_weight("build_index", 1, false, false, false);
        assert!((w - 10.0).abs() < 1e-9, "got {w}");
        // Leading underscore → ×0.1.
        assert!((edge_weight("_priv", 1, false, false, false) - 0.1).abs() < 1e-9);
        // Multiple multipliers stack.
        let w = edge_weight("BuildIndex", 4, true, true, false);
        // mentioned (×10) × compound (×10) × chat (×50) × sqrt(4)=2 → 10000
        assert!((w - 10_000.0).abs() < 1e-6, "got {w}");
    }

    #[test]
    fn is_compound_recognises_camelcase_underscore_kebab() {
        assert!(is_compound("snake_case"));
        assert!(is_compound("kebab-case"));
        assert!(is_compound("camelCase"));
        assert!(!is_compound("flat"));
        assert!(!is_compound("UPPERCASE"));
    }
}
