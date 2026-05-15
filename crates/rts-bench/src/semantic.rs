//! Semantic-search evaluation harness.
//!
//! Runs a TOML corpus of labelled queries against a workspace,
//! reports precision@K + MRR + coverage of a **graph-only baseline
//! ranker** (no embeddings, no LLM). The deliverable is a measurable
//! comparison point for ANY future ranker — without this, every
//! "semantic search would help" claim is speculation.
//!
//! ## Why a graph-only baseline?
//!
//! Today the daemon answers structurally-connected queries
//! ("who calls X", "find symbol named X") via PageRank + the call
//! graph. It does NOT answer "find code conceptually similar to X."
//! The hypothesis is that embeddings would close that gap.
//!
//! Before building embeddings, we need to know: how much of the gap
//! does the EXISTING graph already cover? If `find_symbol`,
//! `outline_workspace`, and PageRank already surface relevant
//! symbols for natural-language queries (via name matching + doc
//! comments + structural centrality), embeddings have less work
//! to do. If they DON'T surface them, embeddings have measurable
//! headroom.
//!
//! This module measures that.
//!
//! ## Baseline ranker design
//!
//! For each query, the baseline:
//!
//! 1. Extracts content-bearing tokens from the query text
//!    (drops stopwords + question words; lowercases; splits on
//!    word boundaries).
//! 2. Issues `find_symbol(pattern="*")` against the daemon to
//!    pull the top-256 by PageRank.
//! 3. Scores each candidate symbol against the query tokens:
//!    - exact-name match: +10.0
//!    - substring match in qualified_name: +3.0
//!    - substring match in file path: +1.0
//!    - + the candidate's own rank_score (already 0..1, normalize)
//! 4. Returns the top-K by combined score.
//!
//! This is intentionally a simple ranker — its job is to be a
//! *reproducible baseline*, not a state-of-the-art system. The
//! embedding ranker (if it ever lands) should beat this by an
//! amount that justifies the model dependency.
//!
//! ## Wire shape
//!
//! Input corpus (TOML):
//! ```toml
//! version = 1
//!
//! [[query]]
//! text = "where is workspace mounting handled?"
//! # Symbols that should appear in the top-K. The scorer counts a
//! # query as "hit at rank N" if the top-K result at position N is
//! # in this list. Hand-graded; iterate as the baseline ranker
//! # evolves.
//! expected_top_k = ["mount", "mount_inner", "prewarm_mount"]
//! ```
//!
//! Output report (JSON): per-query rank of first correct answer +
//! aggregate precision@K, MRR, coverage.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::mcp_runner::McpSession;

/// Parsed corpus file. Pinned format-version field so future
/// breaking changes can be detected at load time.
#[derive(Debug, Deserialize)]
pub struct Corpus {
    #[allow(dead_code)]
    pub version: u32,
    #[serde(rename = "query")]
    pub queries: Vec<CorpusQuery>,
}

#[derive(Debug, Deserialize)]
pub struct CorpusQuery {
    pub text: String,
    /// Hand-graded list of symbol qualified_names that should appear
    /// in the top-K. Order doesn't matter — the scorer just checks
    /// membership.
    pub expected_top_k: Vec<String>,
}

/// One query's evaluation result.
#[derive(Debug, Clone, Serialize)]
pub struct QueryResult {
    pub query: String,
    pub expected_top_k: Vec<String>,
    pub returned_top_k: Vec<String>,
    /// Position (0-indexed) of the first expected name in the
    /// returned top-K, or `None` if none of the expected names
    /// appeared.
    pub first_hit_rank: Option<usize>,
    /// Count of expected names that appeared anywhere in the
    /// returned top-K.
    pub hits_in_top_k: usize,
    /// `1.0 / (first_hit_rank + 1)` if any hit, else `0.0`. This
    /// is the per-query reciprocal rank; MRR is the mean across
    /// all queries.
    pub reciprocal_rank: f64,
}

/// Aggregate report.
#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub version: u32,
    pub rts_bench_version: String,
    pub workspace_path: String,
    pub corpus_path: String,
    pub top_k: usize,
    pub query_count: usize,
    /// Mean reciprocal rank across queries.
    pub mrr: f64,
    /// Fraction of queries with at least one expected name in top-K.
    pub coverage: f64,
    /// Mean precision@K: average of `hits_in_top_k / top_k` per query.
    pub mean_precision_at_k: f64,
    pub queries: Vec<QueryResult>,
}

/// Stopword + question-word set dropped before scoring. Kept small
/// and English-only — corpora can use full natural-language phrases
/// but the scorer reduces to content tokens.
const STOPWORDS: &[&str] = &[
    "a",
    "an",
    "the",
    "is",
    "are",
    "was",
    "were",
    "be",
    "been",
    "being",
    "do",
    "does",
    "did",
    "have",
    "has",
    "had",
    "in",
    "on",
    "at",
    "by",
    "for",
    "with",
    "to",
    "from",
    "of",
    "and",
    "or",
    "but",
    "if",
    "then",
    "than",
    "so",
    "as",
    "this",
    "that",
    "these",
    "those",
    // Question words
    "what",
    "where",
    "when",
    "who",
    "why",
    "how",
    "which",
    "whom",
    "whose",
    "does",
    "do",
    "did",
    "can",
    "could",
    "should",
    "would",
    "will",
    "shall",
    "may",
    "might",
    "must",
    // Common code-discussion fillers
    "code",
    "function",
    "method",
    "symbol",
    "logic",
    "handles",
    "handle",
    "handled",
    "handling",
    "happens",
    "happen",
    "happening",
    "look",
    "looking",
    "find",
    "show",
    "tell",
    "exists",
    "exist",
    "me",
    "i",
    "you",
    "we",
    "they",
    "it",
    "its",
    "their",
    "there",
    "here",
    "thing",
    "things",
    "stuff",
];

/// Token-ize a query: lowercase, split on non-alphanumeric, drop
/// empties + stopwords + tokens of length 1.
pub fn tokens_of(query: &str) -> Vec<String> {
    query
        .to_lowercase()
        .split(|c: char| !c.is_alphanumeric() && c != '_')
        .filter(|t| !t.is_empty())
        .filter(|t| t.len() > 1)
        .filter(|t| !STOPWORDS.contains(t))
        .map(|t| t.to_string())
        .collect()
}

/// Score one candidate symbol against a token set.
pub fn score_candidate(
    candidate_name: &str,
    candidate_file: &str,
    candidate_rank: f64,
    tokens: &[String],
) -> f64 {
    let name_lower = candidate_name.to_lowercase();
    let file_lower = candidate_file.to_lowercase();
    let mut score = candidate_rank; // baseline: PageRank already 0..1
    for tok in tokens {
        if name_lower == *tok {
            score += 10.0; // exact-name match dominates
        } else if name_lower.contains(tok) {
            score += 3.0;
        }
        if file_lower.contains(tok) {
            score += 1.0;
        }
    }
    score
}

/// Run the eval harness end-to-end.
pub async fn run(
    session: &mut McpSession,
    corpus: &Corpus,
    top_k: usize,
) -> Result<Vec<QueryResult>> {
    // Pull the workspace's top symbols once via find_symbol(pattern="*").
    // 256 is the daemon's MAX_MATCHES; that's the full set we have
    // to score against.
    let candidates = fetch_candidates(session).await?;
    let mut out: Vec<QueryResult> = Vec::with_capacity(corpus.queries.len());
    for q in &corpus.queries {
        let tokens = tokens_of(&q.text);
        let mut scored: Vec<(String, String, f64)> = candidates
            .iter()
            .map(|c| {
                let score = score_candidate(&c.name, &c.file, c.rank, &tokens);
                (c.name.clone(), c.file.clone(), score)
            })
            .collect();
        // Sort descending by score; stable tie-break by name for
        // reproducibility.
        scored.sort_by(|a, b| {
            b.2.partial_cmp(&a.2)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then(a.0.cmp(&b.0))
        });
        let returned: Vec<String> = scored
            .into_iter()
            .take(top_k)
            .map(|(name, _, _)| name)
            .collect();
        let first_hit_rank = returned
            .iter()
            .position(|name| q.expected_top_k.contains(name));
        let hits_in_top_k = returned
            .iter()
            .filter(|name| q.expected_top_k.contains(name))
            .count();
        let reciprocal_rank = match first_hit_rank {
            Some(r) => 1.0 / (r as f64 + 1.0),
            None => 0.0,
        };
        out.push(QueryResult {
            query: q.text.clone(),
            expected_top_k: q.expected_top_k.clone(),
            returned_top_k: returned,
            first_hit_rank,
            hits_in_top_k,
            reciprocal_rank,
        });
    }
    Ok(out)
}

#[derive(Debug, Clone)]
pub struct Candidate {
    pub name: String,
    pub file: String,
    pub rank: f64,
}

/// Pull the top-256 by PageRank as the candidate set the baseline
/// ranker will re-score. This is the entire universe of "things the
/// graph thinks are central."
pub async fn fetch_candidates(session: &mut McpSession) -> Result<Vec<Candidate>> {
    let resp = session
        .tools_call("find_symbol", json!({ "pattern": "*" }), 5)
        .await
        .context("fetch candidates via find_symbol(pattern='*')")?;
    if resp.is_error {
        anyhow::bail!("find_symbol(pattern='*') errored");
    }
    let body = resp
        .result_body
        .ok_or_else(|| anyhow::anyhow!("find_symbol returned no body"))?;
    let matches = body
        .get("matches")
        .and_then(|m| m.as_array())
        .ok_or_else(|| anyhow::anyhow!("find_symbol response missing matches array"))?;
    Ok(matches
        .iter()
        .filter_map(|m| {
            let name = m.get("qualified_name")?.as_str()?.to_string();
            let file = m
                .get("file")
                .and_then(|f| f.as_str())
                .unwrap_or("")
                .to_string();
            let rank = m.get("rank_score").and_then(|r| r.as_f64()).unwrap_or(0.0);
            Some(Candidate { name, file, rank })
        })
        .collect())
}

/// Load and parse a TOML corpus.
pub fn load_corpus(path: &Path) -> Result<Corpus> {
    let bytes =
        std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let parsed: Corpus = toml::from_str(&bytes)
        .with_context(|| format!("parse {} as semantic corpus TOML", path.display()))?;
    Ok(parsed)
}

/// Compute aggregate report from per-query results.
pub fn build_report(
    workspace_path: &Path,
    corpus_path: &Path,
    top_k: usize,
    results: Vec<QueryResult>,
) -> Report {
    let n = results.len() as f64;
    let mrr = if n > 0.0 {
        results.iter().map(|r| r.reciprocal_rank).sum::<f64>() / n
    } else {
        0.0
    };
    let coverage = if n > 0.0 {
        results
            .iter()
            .filter(|r| r.first_hit_rank.is_some())
            .count() as f64
            / n
    } else {
        0.0
    };
    let mean_precision_at_k = if n > 0.0 && top_k > 0 {
        results
            .iter()
            .map(|r| r.hits_in_top_k as f64 / top_k as f64)
            .sum::<f64>()
            / n
    } else {
        0.0
    };
    Report {
        version: 1,
        rts_bench_version: env!("CARGO_PKG_VERSION").to_string(),
        workspace_path: workspace_path.display().to_string(),
        corpus_path: corpus_path.display().to_string(),
        top_k,
        query_count: results.len(),
        mrr,
        coverage,
        mean_precision_at_k,
        queries: results,
    }
}

/// Write a report to disk as pretty JSON.
pub fn write_report(path: &Path, report: &Report) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(report).context("encode semantic report")?;
    std::fs::write(path, bytes).with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

#[allow(dead_code)]
fn _val_unused(_: Value, _: PathBuf) {} // keep imports tidy on no-op shifts

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_drop_stopwords_and_short_tokens() {
        let toks = tokens_of("Where is the workspace mounting handled?");
        assert!(!toks.contains(&"where".to_string()));
        assert!(!toks.contains(&"is".to_string()));
        assert!(!toks.contains(&"the".to_string()));
        assert!(!toks.contains(&"handled".to_string()));
        // Content tokens survive.
        assert!(toks.contains(&"workspace".to_string()));
        assert!(toks.contains(&"mounting".to_string()));
    }

    #[test]
    fn tokens_normalize_case_and_punctuation() {
        let toks = tokens_of("PageRank's compute_symbol_ranks!");
        // Lowercased, underscores preserved (single token), apostrophes stripped.
        assert!(toks.contains(&"pagerank".to_string()));
        assert!(toks.contains(&"compute_symbol_ranks".to_string()));
    }

    #[test]
    fn score_candidate_exact_name_dominates_substring() {
        let toks = vec!["mount".to_string()];
        let exact = score_candidate("mount", "src/lib.rs", 0.001, &toks);
        let substring = score_candidate("workspace_mount", "src/lib.rs", 0.001, &toks);
        assert!(
            exact > substring,
            "exact name match should outrank substring match (+10 vs +3)"
        );
    }

    #[test]
    fn score_candidate_pagerank_breaks_ties_on_no_keyword_match() {
        let toks = vec!["unrelated_keyword_xyz".to_string()];
        let high = score_candidate("foo", "src/lib.rs", 0.5, &toks);
        let low = score_candidate("bar", "src/lib.rs", 0.001, &toks);
        assert!(
            high > low,
            "with no keyword hits, PageRank determines the order"
        );
    }

    #[test]
    fn build_report_computes_mrr_and_coverage() {
        let queries = vec![
            QueryResult {
                query: "q1".into(),
                expected_top_k: vec!["a".into()],
                returned_top_k: vec!["a".into(), "b".into()],
                first_hit_rank: Some(0),
                hits_in_top_k: 1,
                reciprocal_rank: 1.0,
            },
            QueryResult {
                query: "q2".into(),
                expected_top_k: vec!["x".into()],
                returned_top_k: vec!["b".into(), "x".into()],
                first_hit_rank: Some(1),
                hits_in_top_k: 1,
                reciprocal_rank: 0.5,
            },
            QueryResult {
                query: "q3".into(),
                expected_top_k: vec!["nothing".into()],
                returned_top_k: vec!["b".into(), "c".into()],
                first_hit_rank: None,
                hits_in_top_k: 0,
                reciprocal_rank: 0.0,
            },
        ];
        let report = build_report(Path::new("/tmp"), Path::new("/tmp/c.toml"), 10, queries);
        // MRR = (1.0 + 0.5 + 0.0) / 3 = 0.5
        assert!((report.mrr - 0.5).abs() < 1e-9);
        // Coverage = 2 / 3 (two queries had a hit)
        assert!((report.coverage - 2.0 / 3.0).abs() < 1e-9);
    }

    #[test]
    fn load_corpus_round_trips_via_toml() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("corpus.toml");
        std::fs::write(
            &path,
            r#"
version = 1

[[query]]
text = "where is X handled?"
expected_top_k = ["foo", "bar"]

[[query]]
text = "what does Y do?"
expected_top_k = ["baz"]
"#,
        )
        .unwrap();
        let corpus = load_corpus(&path).unwrap();
        assert_eq!(corpus.queries.len(), 2);
        assert_eq!(corpus.queries[0].text, "where is X handled?");
        assert_eq!(corpus.queries[0].expected_top_k, vec!["foo", "bar"]);
        assert_eq!(corpus.queries[1].expected_top_k, vec!["baz"]);
    }
}
