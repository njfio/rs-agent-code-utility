//! Fuzzy candidate ranking for the verification layer (Phase F, F2).
//!
//! When a reference fails to resolve exactly, [`rank_candidates`] offers
//! a "did you mean…" shortlist: it ranks a pool of qualified names by
//! Damerau-Levenshtein edit distance against a target, comparing only the
//! FINAL path segment of each (so `a::b::commit_batch` matches the target
//! `commit_batch` at distance 0). Ties break on PageRank descending so the
//! more central symbol surfaces first.
//!
//! Pure: no I/O, no parsing.

use serde::Serialize;

/// A ranked fuzzy-match candidate for a failed-to-resolve reference.
#[derive(Debug, Clone, Serialize)]
pub struct Candidate {
    /// Fully-qualified name of the candidate definition.
    pub qualified_name: String,
    /// Damerau-Levenshtein distance between the candidate's final path
    /// segment and the target's final segment.
    pub edit_distance: u32,
    /// PageRank of the candidate (centrality); used as the tie-breaker.
    pub pagerank: f64,
}

/// Rank `pool` (each `(qualified_name, pagerank)`) against `target`.
///
/// Matching is on the FINAL path segment of each candidate vs `target`'s
/// final segment, using Damerau-Levenshtein. Candidates with
/// `edit_distance > max(2, target_final_len / 3)` are dropped (too far to
/// be a plausible typo). The survivors are sorted by `edit_distance`
/// ascending, breaking ties by `pagerank` descending, and truncated to
/// `limit`.
pub fn rank_candidates(
    target: &str,
    pool: impl Iterator<Item = (String, f64)>,
    limit: usize,
) -> Vec<Candidate> {
    let target_final = final_segment(target);
    let target_final_len = target_final.chars().count();
    // Distance cap: at least 2, or a third of the target length for longer
    // names (a 12-char name tolerates a distance of 4).
    let max_distance = 2.max(target_final_len / 3) as u32;

    let mut candidates: Vec<Candidate> = pool
        .filter_map(|(qualified_name, pagerank)| {
            let cand_final = final_segment(&qualified_name);
            let edit_distance = damerau_levenshtein(target_final, cand_final);
            if edit_distance > max_distance {
                return None;
            }
            Some(Candidate {
                qualified_name,
                edit_distance,
                pagerank,
            })
        })
        .collect();

    candidates.sort_by(|a, b| {
        a.edit_distance.cmp(&b.edit_distance).then_with(|| {
            // pagerank descending; NaN-safe (treat unordered as Equal).
            b.pagerank
                .partial_cmp(&a.pagerank)
                .unwrap_or(std::cmp::Ordering::Equal)
        })
    });

    candidates.truncate(limit);
    candidates
}

/// The final `::`-delimited segment of a qualified name. `commit_batch`
/// (no separator) returns itself; `a::b::commit` returns `commit`.
fn final_segment(qualified: &str) -> &str {
    qualified.rsplit("::").next().unwrap_or(qualified)
}

/// Iterative Damerau-Levenshtein distance (optimal string alignment
/// variant) over Unicode scalar values. O(a*b) time, O(a*b) space.
///
/// Counts insertions, deletions, substitutions, and transpositions of two
/// adjacent characters as unit-cost edits.
fn damerau_levenshtein(a: &str, b: &str) -> u32 {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let (n, m) = (a.len(), b.len());
    if n == 0 {
        return m as u32;
    }
    if m == 0 {
        return n as u32;
    }

    // d[i][j] = distance between a[..i] and b[..j].
    let cols = m + 1;
    let mut d = vec![0u32; (n + 1) * cols];
    let idx = |i: usize, j: usize| i * cols + j;

    for (i, slot) in d.iter_mut().step_by(cols).enumerate() {
        *slot = i as u32;
    }
    for j in 0..=m {
        d[idx(0, j)] = j as u32;
    }

    for i in 1..=n {
        for j in 1..=m {
            let cost = if a[i - 1] == b[j - 1] { 0 } else { 1 };
            let mut value = (d[idx(i - 1, j)] + 1) // deletion
                .min(d[idx(i, j - 1)] + 1) // insertion
                .min(d[idx(i - 1, j - 1)] + cost); // substitution
            // Transposition of two adjacent characters.
            if i > 1 && j > 1 && a[i - 1] == b[j - 2] && a[i - 2] == b[j - 1] {
                value = value.min(d[idx(i - 2, j - 2)] + 1);
            }
            d[idx(i, j)] = value;
        }
    }

    d[idx(n, m)]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn damerau_basic_distances() {
        assert_eq!(damerau_levenshtein("commit_batch", "commit_batch"), 0);
        // "commit_batch" -> "commit_batches": insert 'e','s' = 2? Actually
        // "commit_batch" + "es" is two insertions -> distance 2.
        assert_eq!(damerau_levenshtein("commit_batch", "commit_batches"), 2);
        // transposition counts as 1
        assert_eq!(damerau_levenshtein("ab", "ba"), 1);
        assert_eq!(damerau_levenshtein("", "abc"), 3);
        assert_eq!(damerau_levenshtein("abc", ""), 3);
    }

    #[test]
    fn ranks_closer_match_first_and_drops_far() {
        let pool = vec![
            ("store::Store::commit_batches".to_string(), 0.01),
            ("store::Store::commit".to_string(), 0.02),
            ("totally_unrelated_name".to_string(), 0.9),
        ];
        let ranked = rank_candidates("commit_batch", pool.into_iter(), 10);

        // commit_batches (dist 2) ranks before commit (dist 6); unrelated
        // is dropped by the distance cap.
        let names: Vec<&str> = ranked.iter().map(|c| c.qualified_name.as_str()).collect();
        assert_eq!(names, vec!["store::Store::commit_batches"]);
        assert_eq!(ranked[0].edit_distance, 2);
    }

    #[test]
    fn far_candidate_dropped_by_cap() {
        let pool = vec![("totally_unrelated_name".to_string(), 0.9)];
        let ranked = rank_candidates("commit_batch", pool.into_iter(), 10);
        assert!(ranked.is_empty());
    }

    #[test]
    fn final_segment_matching_distance_zero() {
        // A fully-qualified candidate matches the bare target at dist 0
        // because only the final segment is compared.
        let pool = vec![("a::b::commit_batch".to_string(), 0.5)];
        let ranked = rank_candidates("commit_batch", pool.into_iter(), 10);
        assert_eq!(ranked.len(), 1);
        assert_eq!(ranked[0].edit_distance, 0);
        assert_eq!(ranked[0].qualified_name, "a::b::commit_batch");
    }

    #[test]
    fn identical_yields_zero() {
        let pool = vec![("commit_batch".to_string(), 0.5)];
        let ranked = rank_candidates("commit_batch", pool.into_iter(), 10);
        assert_eq!(ranked[0].edit_distance, 0);
    }

    #[test]
    fn empty_pool_yields_empty() {
        let ranked = rank_candidates("commit_batch", std::iter::empty(), 10);
        assert!(ranked.is_empty());
    }

    #[test]
    fn limit_is_honored() {
        let pool = vec![
            ("a::commit_batch".to_string(), 0.1),
            ("b::commit_batch".to_string(), 0.2),
            ("c::commit_batch".to_string(), 0.3),
        ];
        let ranked = rank_candidates("commit_batch", pool.into_iter(), 2);
        assert_eq!(ranked.len(), 2);
        // All dist 0, so tie-break is pagerank desc: 0.3 then 0.2.
        assert_eq!(ranked[0].qualified_name, "c::commit_batch");
        assert_eq!(ranked[1].qualified_name, "b::commit_batch");
    }

    #[test]
    fn tie_break_is_pagerank_descending() {
        let pool = vec![
            ("low::commit_batch".to_string(), 0.01),
            ("high::commit_batch".to_string(), 0.99),
        ];
        let ranked = rank_candidates("commit_batch", pool.into_iter(), 10);
        assert_eq!(ranked[0].qualified_name, "high::commit_batch");
        assert_eq!(ranked[1].qualified_name, "low::commit_batch");
    }
}
