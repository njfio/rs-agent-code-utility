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
//! 2. Issues `find_symbol(pattern="*", limit=4096)` against the
//!    daemon to pull the full ranked candidate pool (capability
//!    `find_symbol_limit_param`, v0.4.1+). On workspaces with fewer
//!    than 4096 distinct symbols this returns the entire universe.
//! 3. Decomposes each candidate's qualified_name into sub-tokens
//!    on snake_case / kebab-case / camelCase boundaries, and applies
//!    naive English stemming (drops common suffixes, normalizes
//!    trailing `e`) so `parsing`/`parse`/`parsed` collapse to the
//!    same stem.
//! 4. Scores each candidate symbol against the query tokens:
//!    - exact-name match (raw or stemmed): +10.0
//!    - exact sub-token match (stemmed): +6.0
//!    - substring match in qualified_name: +3.0
//!    - substring match in file path: +1.0
//!    - + the candidate's own rank_score (already 0..1, normalize)
//! 5. Returns the top-K by combined score.
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
    /// Fraction of queries with at least one expected name in top-K
    /// (denominator = all queries, including negative controls).
    pub coverage: f64,
    /// Fraction of *answerable* queries (non-empty expected_top_k)
    /// with at least one expected name in top-K. Negative-control
    /// queries are excluded from both numerator and denominator.
    /// This is the metric to track when comparing ranker variants.
    pub answerable_coverage: f64,
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

/// Split an identifier into its component words.
///
/// Handles `snake_case`, `kebab-case`, and `camelCase` boundaries.
/// Returns lowercased components; drops empties and 1-char fragments
/// (they're noise — almost always loop counters or generic params).
///
/// Examples:
/// - `find_nodes_by_kind` → `["find", "nodes", "by", "kind"]`
/// - `findNodesByKind`    → `["find", "nodes", "by", "kind"]`
/// - `MyClass`            → `["my", "class"]`
/// - `parse_v2`           → `["parse", "v2"]`
pub fn decompose_name(name: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut current = String::new();
    let mut prev_lower = false;
    for c in name.chars() {
        if c.is_alphanumeric() {
            if c.is_uppercase() && prev_lower {
                // camelCase boundary.
                if !current.is_empty() {
                    out.push(current.clone());
                    current.clear();
                }
            }
            current.push(c.to_ascii_lowercase());
            prev_lower = c.is_lowercase();
        } else {
            // Separator: `_`, `-`, `:`, `.`, etc.
            if !current.is_empty() {
                out.push(current.clone());
                current.clear();
            }
            prev_lower = false;
        }
    }
    if !current.is_empty() {
        out.push(current);
    }
    out.into_iter().filter(|s| s.len() > 1).collect()
}

/// Greek-origin noun/verb pairs the naive suffix stemmer can't
/// unify on its own. `analysis` and `analyze` look completely
/// different to a rule-based stripper (one ends in `-is`, the
/// other in `-ize`), but they share the same semantic root.
///
/// Each entry maps a token to the stem its sibling form would
/// produce under the regular suffix/e logic. e.g. `stem("analyze")`
/// naturally lands on `analyz` (no suffix match, trailing-e strip);
/// we map `analysis` → `analyz` so they meet.
///
/// Keep this list small and well-justified — it's a workaround for
/// stemmer limitations, not a synonym dictionary.
const LEMMA_OVERRIDES: &[(&str, &str)] = &[
    // analysis ↔ analyze ↔ analyser ↔ analytical
    ("analysis", "analyz"),
    ("analyses", "analyz"),
    ("analytic", "analyz"),
    ("analytical", "analyz"),
    // synthesis ↔ synthesize
    ("synthesis", "synthesiz"),
    ("syntheses", "synthesiz"),
    // hypothesis ↔ hypothesize
    ("hypothesis", "hypothesiz"),
    ("hypotheses", "hypothesiz"),
    // diagnosis ↔ diagnose
    ("diagnosis", "diagnos"),
    ("diagnoses", "diagnos"),
    // ─── Code-domain synonym pairs (v0.5+) ───
    //
    // These are NOT lemma-equivalent — they're distinct words that
    // refer to the same operation in agent-coding queries. The
    // blind-v2 corpus exposed the gap: a query for "what cleans up
    // after analysis?" misses `clear_cache` because the doc says
    // "Clear" but the corpus says "clean".
    //
    // Each entry maps a query-side word to the stem its code-side
    // synonym already produces. Keep this list short and audited;
    // it's a curated bridge, not a thesaurus.
    //
    // clean ↔ clear: cleanup, cleans, cleaning all → "clear"
    ("clean", "clear"),
    ("cleans", "clear"),
    ("cleanup", "clear"),
    ("cleaning", "clear"),
    ("cleaned", "clear"),
    // remove ↔ delete: rts-core uses both. The choice between them
    // is rarely meaningful at the call-site granularity; agent
    // queries phrased either way should hit either symbol.
    ("delete", "remov"),
    ("deletes", "remov"),
    ("deleting", "remov"),
    ("deleted", "remov"),
    ("deletion", "remov"),
    // begin ↔ start: same pattern.
    ("begin", "start"),
    ("begins", "start"),
    ("beginning", "start"),
    // finish ↔ end ↔ complete: tighter cluster. Agent queries about
    // "when does X finish/complete?" should hit code that uses "end"
    // or "done" or "finish" interchangeably.
    ("finish", "end"),
    ("finishes", "end"),
    ("finishing", "end"),
    ("finished", "end"),
    ("complete", "end"),
    ("completes", "end"),
    ("completed", "end"),
    ("completion", "end"),
    // -y/-ies inflections the suffix stemmer doesn't unify on its
    // own. The English rule "y → ies in plural" is regular, but
    // catching it generically would over-strip nouns whose lemma
    // ends in -y (city, story). Hand-curated for common code-domain
    // words instead.
    ("query", "queri"),
    ("queries", "queri"),
    ("dependency", "dependenci"),
    ("dependencies", "dependenci"),
    ("entity", "entiti"),
    ("entities", "entiti"),
    ("entry", "entri"),
    ("entries", "entri"),
];

/// Drop common English suffixes so different inflections collapse
/// to the same root. Intentionally simple — not a Porter stemmer,
/// just enough to map `parsing`/`parse`/`parsed`/`parses` →`pars` and
/// `nodes`/`node` → `nod`.
///
/// Three passes:
/// 1. Lemma override: a small table of noun/verb pairs the rule-
///    based stripper can't unify (`analysis` ↔ `analyze`). Checked
///    first; if the lowercased input matches an entry, return its
///    override.
/// 2. Strip the first matching suffix from a fixed list (if the
///    resulting stem is still ≥ 3 chars).
/// 3. Drop a final trailing `e` (so `parse` after the no-suffix path
///    still lands on `pars`).
pub fn stem(token: &str) -> String {
    let lower = token.to_lowercase();
    for (from, to) in LEMMA_OVERRIDES {
        if lower == *from {
            return (*to).to_string();
        }
    }
    let mut t = lower;
    // Longest first so e.g. `connection` matches `tion` before `s`.
    let suffixes: &[&str] = &[
        "ations", "ization", "tions", "sions", "ation", "tion", "sion", "ings", "ers", "ies",
        "ing", "ed", "er", "es", "ly", "s",
    ];
    for suf in suffixes {
        if t.ends_with(suf) {
            let stem_len = t.len() - suf.len();
            if stem_len >= 3 {
                t.truncate(stem_len);
                break;
            }
        }
    }
    if t.ends_with('e') && t.len() > 3 {
        t.pop();
    }
    t
}

/// Inverse-document-frequency weights over stemmed sub-tokens for
/// the candidate pool. Used by `score_candidate` to down-weight
/// matches against very-common terms (`symbol` in a code-analysis
/// crate, `file` in a filesystem-walker crate) and up-weight rare
/// terms (`public`, `visibility`, `cache`).
///
/// Formula: `log((N + 1) / (df + 1)) + 1.0` — a smoothed IDF that
/// stays positive for any term and avoids zero/negative weights.
/// Pre-computed once per eval over the entire candidate pool.
#[derive(Debug, Clone, Default)]
pub struct IdfWeights {
    /// Map: stemmed sub-token → IDF weight in [~0.5, ~ln(N)+1].
    pub weights: std::collections::HashMap<String, f64>,
    /// Default weight applied to any token absent from `weights`
    /// (treated as maximally rare).
    pub default: f64,
}

impl IdfWeights {
    /// Compute IDF weights from a candidate pool. Each sub-token's
    /// document frequency is the number of distinct candidates whose
    /// decomposed-stemmed name contains it.
    pub fn from_candidates(candidates: &[Candidate]) -> Self {
        use std::collections::HashMap;
        let n = candidates.len() as f64;
        let mut df: HashMap<String, usize> = HashMap::new();
        for c in candidates {
            let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
            for t in decompose_name(&c.name) {
                let s = stem(&t);
                if seen.insert(s.clone()) {
                    *df.entry(s).or_insert(0) += 1;
                }
            }
        }
        let weights = df
            .into_iter()
            .map(|(tok, dfc)| {
                let idf = ((n + 1.0) / (dfc as f64 + 1.0)).ln() + 1.0;
                (tok, idf)
            })
            .collect();
        let default = ((n + 1.0) / 1.0_f64).ln() + 1.0;
        IdfWeights { weights, default }
    }

    /// Compute IDF weights from the *doc-comment* text in the
    /// candidate pool. Same smoothed formula as `from_candidates`
    /// but the "documents" are the doc-comment bodies, tokenized
    /// + stemmed via the same query-token pipeline.
    ///
    /// Computing this separately from name-IDF matters because the
    /// two text universes have different term distributions. In a
    /// code-analysis crate, `symbol` is everywhere in names (low
    /// name-IDF) but moderately common in docs (moderate doc-IDF).
    /// `cleanup` may appear in only 2 docs but never as a sub-token
    /// — name-IDF returns the default (treat as rare) while doc-IDF
    /// correctly gives it high but bounded weight.
    ///
    /// Candidates with no doc (`doc.is_none()`) contribute nothing
    /// to df counts; their candidate-count IS included in N (the
    /// total candidate corpus size) so doc-IDF stays calibrated to
    /// the full pool.
    pub fn from_candidate_docs(candidates: &[Candidate]) -> Self {
        use std::collections::HashMap;
        let n = candidates.len() as f64;
        let mut df: HashMap<String, usize> = HashMap::new();
        for c in candidates {
            let Some(doc) = c.doc.as_deref() else {
                continue;
            };
            let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
            for t in tokens_of(doc) {
                let s = stem(&t);
                if seen.insert(s.clone()) {
                    *df.entry(s).or_insert(0) += 1;
                }
            }
        }
        let weights = df
            .into_iter()
            .map(|(tok, dfc)| {
                let idf = ((n + 1.0) / (dfc as f64 + 1.0)).ln() + 1.0;
                (tok, idf)
            })
            .collect();
        let default = ((n + 1.0) / 1.0_f64).ln() + 1.0;
        IdfWeights { weights, default }
    }

    /// Look up the weight for a stemmed token; missing tokens get
    /// `default` (treated as "never seen, maximally rare").
    pub fn weight(&self, stemmed_token: &str) -> f64 {
        self.weights
            .get(stemmed_token)
            .copied()
            .unwrap_or(self.default)
    }
}

/// Score one candidate symbol against a token set.
///
/// The candidate's qualified_name is decomposed into sub-tokens and
/// stemmed up front; each query token is stemmed once and tested
/// against (a) the full name, (b) the stemmed full name, (c) the
/// stemmed sub-token set, (d) raw substring fallback. File-path
/// substring stays unchanged.
///
/// Sub-token matches are weighted by IDF — matching a rare term
/// like `public` is worth more than matching a workspace-common term
/// like `symbol` in a code-analysis crate. This is what breaks the
/// "common single-word symbol dominates" failure mode (`Symbol`
/// outranking `is_public` for "where are symbols public?").
///
/// When `doc` is `Some`, query tokens are also matched against the
/// doc-comment text (raw + stemmed substring). Awards `+4.0 * IDF`
/// per matching token — between the sub-token tier (+6) and the
/// raw-name-substring tier (+3). Doc text bridges behavior queries
/// ("what cleans up...?") that identifier names alone can't answer.
pub fn score_candidate(
    candidate_name: &str,
    candidate_file: &str,
    candidate_rank: f64,
    candidate_doc: Option<&str>,
    tokens: &[String],
    idf: &IdfWeights,
    doc_idf: &IdfWeights,
) -> f64 {
    let name_lower = candidate_name.to_lowercase();
    let file_lower = candidate_file.to_lowercase();
    let name_stem = stem(&name_lower);
    // Decompose + stem the candidate once per scoring call.
    let sub_stems: Vec<String> = decompose_name(candidate_name)
        .into_iter()
        .map(|t| stem(&t))
        .collect();
    // Doc-comment: tokenize → stem → set. Word-level matching avoids
    // substring noise (an early `doc.contains(stem)` version matched
    // `analyz` against the unrelated word `analyzable`, inflating
    // every `*Analyzer` candidate on queries about "analysis").
    let doc_word_stems: std::collections::HashSet<String> = candidate_doc
        .map(|d| {
            tokens_of(d) // re-uses the query tokenizer: lowercase,
                .into_iter() // splits on non-alnum, drops stopwords.
                .map(|w| stem(&w))
                .collect()
        })
        .unwrap_or_default();
    let mut score = candidate_rank; // baseline: PageRank already 0..1
    // Diminishing-returns counter — applies ONLY when the candidate
    // has many sub-tokens (≥4). For short/compound names with 1-3
    // sub-tokens, every sub-token match earns the full +6 bonus.
    // Long compound names (4+ sub-tokens) like
    // `get_language_specific_complexity` start to look like noise
    // when multiple query tokens hit, so additional matches earn
    // diminishing weight to prevent them outranking shorter,
    // semantically-tighter candidates.
    let apply_diminishing = sub_stems.len() >= 4;
    let mut sub_token_match_idx: u32 = 0;
    for tok in tokens {
        let tok_stem = stem(tok);
        let w = idf.weight(&tok_stem);
        if name_lower == *tok || name_stem == tok_stem {
            // Exact full-name match (raw or stemmed) dominates.
            // Weighted by IDF so a query against `Symbol` in a
            // symbol-heavy codebase doesn't crush more-specific hits.
            score += 10.0 * w;
        } else if sub_stems.contains(&tok_stem) {
            // Exact stemmed sub-token match — bridges the natural-
            // language ↔ identifier gap (`parsing` ↔ `parse_file`).
            let bonus = if apply_diminishing {
                6.0 / 2.0_f64.powi(sub_token_match_idx as i32)
            } else {
                6.0
            };
            score += bonus * w;
            sub_token_match_idx += 1;
        } else if name_lower.contains(tok) {
            score += 3.0 * w;
        }
        if file_lower.contains(tok) {
            score += 1.0 * w;
        }
        // v0.5 doc-comment matching. Conservative — weight matches
        // the file-path bonus (+1). Doc text uses full natural-
        // language vocabulary, so it's noisy by nature; we award
        // a small bonus when a query token's stem also appears as
        // a word stem in the doc text, but don't let it dominate
        // identifier-shaped matches. Future ranker iterations
        // (synonym tables, doc-IDF computed separately from name-
        // IDF) could earn a higher weight by being more selective.
        if doc_word_stems.contains(&tok_stem) {
            // Use the doc-IDF table here so rare doc-specific terms
            // ("rollback", "retry", "validate") earn higher weight
            // than common ones ("the", "returns") even though the
            // candidate's NAME doesn't contain them. Capped via a
            // 0.8 coefficient so doc matches don't overwhelm
            // identifier matches even at maximum doc-IDF.
            score += 0.8 * doc_idf.weight(&tok_stem);
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
    // After dedupe by qualified_name this is ~141 unique symbols on
    // rts-core — the entire universe of "things the PageRank graph
    // considers central." A known limitation: niche symbols whose
    // PageRank ranks below the daemon's MAX_MATCHES (256) cap won't
    // appear here. Per-token retrieval expansion was tried; it grew
    // the pool but introduced scoring noise (bare matches like
    // `cache` and `pool` outranked specific names like
    // `calculate_cache_key`). Filed for a follow-up that pairs
    // expansion with name-specificity scoring.
    let candidates = fetch_candidates(session).await?;
    // Pre-compute IDF over the full candidate pool — the same
    // weights apply to every query.
    let idf = IdfWeights::from_candidates(&candidates);
    let doc_idf = IdfWeights::from_candidate_docs(&candidates);
    let mut out: Vec<QueryResult> = Vec::with_capacity(corpus.queries.len());
    for q in &corpus.queries {
        let tokens = tokens_of(&q.text);
        let mut scored: Vec<(String, String, f64)> = candidates
            .iter()
            .map(|c| {
                let score = score_candidate(
                    &c.name,
                    &c.file,
                    c.rank,
                    c.doc.as_deref(),
                    &tokens,
                    &idf,
                    &doc_idf,
                );
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
    /// Doc-comment text attached to the symbol, when the daemon
    /// advertises `find_symbol_doc_field` and the symbol actually
    /// has docs. Pre-v0.5 daemons always return `null`, which
    /// shows up here as `None` — the scorer falls back to
    /// identifier-only matching for those.
    pub doc: Option<String>,
}

/// Pull the workspace's full ranked candidate set via
/// `find_symbol(pattern="*", limit=4096)`. The 4096 cap is the
/// daemon's MAX_LIMIT (v0.4.1+); on workspaces smaller than that
/// it returns everything. Dedupes by qualified_name — the daemon
/// returns one row per occurrence, so popular names show up many
/// times without dedupe and crowd the top-K.
///
/// Note: pre-v0.4.1 daemons silently ignored the `limit` parameter
/// and capped at 256. Running the bench against an older daemon
/// will work but the pool size limits coverage.
pub async fn fetch_candidates(session: &mut McpSession) -> Result<Vec<Candidate>> {
    let resp = session
        .tools_call("find_symbol", json!({ "pattern": "*", "limit": 4096 }), 5)
        .await
        .context("fetch candidates via find_symbol(pattern='*', limit=4096)")?;
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
    // Dedupe by qualified_name. `find_symbol` returns one row per
    // occurrence, so popular names show up many times — without
    // dedupe, a single symbol can monopolize the top-K and crowd
    // out genuinely-relevant alternatives. Keep the first (highest-
    // rank, since the daemon returns by descending rank) occurrence.
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut out: Vec<Candidate> = Vec::new();
    for m in matches.iter() {
        let Some(name) = m.get("qualified_name").and_then(|n| n.as_str()) else {
            continue;
        };
        if !seen.insert(name.to_string()) {
            continue;
        }
        let file = m
            .get("file")
            .and_then(|f| f.as_str())
            .unwrap_or("")
            .to_string();
        let rank = m.get("rank_score").and_then(|r| r.as_f64()).unwrap_or(0.0);
        let doc = m
            .get("doc")
            .and_then(|d| d.as_str())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string());
        out.push(Candidate {
            name: name.to_string(),
            file,
            rank,
            doc,
        });
    }
    Ok(out)
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
    let answerable: Vec<&QueryResult> = results
        .iter()
        .filter(|r| !r.expected_top_k.is_empty())
        .collect();
    let answerable_coverage = if !answerable.is_empty() {
        answerable
            .iter()
            .filter(|r| r.first_hit_rank.is_some())
            .count() as f64
            / answerable.len() as f64
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
        answerable_coverage,
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

    /// Default IDF for tests: every token gets weight 1.0. Test the
    /// score-tier ordering without IDF noise.
    fn flat_idf() -> IdfWeights {
        IdfWeights {
            weights: std::collections::HashMap::new(),
            default: 1.0,
        }
    }

    #[test]
    fn score_candidate_exact_name_dominates_substring() {
        let toks = vec!["mount".to_string()];
        let idf = flat_idf();
        let exact = score_candidate("mount", "src/lib.rs", 0.001, None, &toks, &idf, &idf);
        let sub_token = score_candidate(
            "workspace_mount",
            "src/lib.rs",
            0.001,
            None,
            &toks,
            &idf,
            &idf,
        );
        assert!(
            exact > sub_token,
            "exact full-name match should outrank sub-token match (+10 vs +6)"
        );
        // And sub-token match should outrank mere substring (which
        // is what `workspacemount` would have been before decompose).
        let raw_substring = score_candidate(
            "workspacemount",
            "src/lib.rs",
            0.001,
            None,
            &toks,
            &idf,
            &idf,
        );
        assert!(
            sub_token > raw_substring,
            "stemmed sub-token match should outrank raw substring match (+6 vs +3)"
        );
    }

    #[test]
    fn idf_weights_down_weight_common_tokens() {
        // 10 candidates; 9 contain "symbol", 1 contains "public".
        // IDF for "symbol" should be much smaller than for "public".
        let mut cands = Vec::new();
        for i in 0..9 {
            cands.push(Candidate {
                name: format!("symbol_thing_{i}"),
                file: String::new(),
                rank: 0.0,
                doc: None,
            });
        }
        cands.push(Candidate {
            name: "is_public".into(),
            file: String::new(),
            rank: 0.0,
            doc: None,
        });
        let idf = IdfWeights::from_candidates(&cands);
        let w_symbol = idf.weight(&stem("symbol"));
        let w_public = idf.weight(&stem("public"));
        assert!(
            w_public > w_symbol,
            "rare term should outweigh common term: public={w_public}, symbol={w_symbol}"
        );
    }

    #[test]
    fn idf_breaks_single_word_vs_compound_match() {
        // The "symbols public" failure mode: `Symbol` (single-word
        // exact match against common term) shouldn't beat `is_public`
        // (sub-token match against rare term) when IDF is in play.
        let mut cands = Vec::new();
        for i in 0..15 {
            cands.push(Candidate {
                name: format!("symbol_var_{i}"),
                file: String::new(),
                rank: 0.0,
                doc: None,
            });
        }
        cands.push(Candidate {
            name: "Symbol".into(),
            file: "src/symbol_table.rs".into(),
            rank: 0.001,
            doc: None,
        });
        cands.push(Candidate {
            name: "is_public".into(),
            file: "src/symbol_table.rs".into(),
            rank: 0.001,
            doc: None,
        });
        let idf = IdfWeights::from_candidates(&cands);
        let toks = vec!["symbols".to_string(), "public".to_string()];
        let symbol_score = score_candidate(
            "Symbol",
            "src/symbol_table.rs",
            0.001,
            None,
            &toks,
            &idf,
            &idf,
        );
        let is_public_score = score_candidate(
            "is_public",
            "src/symbol_table.rs",
            0.001,
            None,
            &toks,
            &idf,
            &idf,
        );
        assert!(
            is_public_score > symbol_score,
            "with IDF, sub-token match against rare term should outrank exact-name match against common term: \
             is_public={is_public_score}, Symbol={symbol_score}"
        );
    }

    #[test]
    fn decompose_name_handles_snake_camel_and_kebab() {
        assert_eq!(
            decompose_name("find_nodes_by_kind"),
            vec!["find", "nodes", "by", "kind"]
        );
        assert_eq!(
            decompose_name("findNodesByKind"),
            vec!["find", "nodes", "by", "kind"]
        );
        assert_eq!(decompose_name("MyClass"), vec!["my", "class"]);
        assert_eq!(
            decompose_name("kebab-case-thing"),
            vec!["kebab", "case", "thing"]
        );
        // 1-char fragments dropped.
        assert_eq!(decompose_name("a_useful_name"), vec!["useful", "name"]);
    }

    #[test]
    fn stem_synonym_overrides_unify_code_domain_pairs() {
        // The blind-v2 corpus exposed the gap directly: "what cleans
        // up after analysis?" should hit `clear_cache`, but
        // clean*/clear* are different roots to a suffix stemmer.
        // The synonym overrides bridge each pair.
        let clear_stem = stem("clear");
        assert_eq!(stem("clean"), clear_stem);
        assert_eq!(stem("cleans"), clear_stem);
        assert_eq!(stem("cleanup"), clear_stem);
        assert_eq!(stem("cleaning"), clear_stem);
        assert_eq!(stem("cleaned"), clear_stem);
        // remove ↔ delete
        let remove_stem = stem("remove");
        assert_eq!(stem("delete"), remove_stem);
        assert_eq!(stem("deletes"), remove_stem);
        assert_eq!(stem("deleting"), remove_stem);
        // begin ↔ start
        let start_stem = stem("start");
        assert_eq!(stem("begin"), start_stem);
        // finish ↔ end ↔ complete
        let end_stem = stem("end");
        assert_eq!(stem("finish"), end_stem);
        assert_eq!(stem("complete"), end_stem);
        assert_eq!(stem("completion"), end_stem);
    }

    #[test]
    fn stem_lemma_overrides_unify_greek_origin_pairs() {
        // The classic case: `analysis` and `analyze` look totally
        // different to a suffix-strip stemmer (one ends in -is, the
        // other in -ize) but share a semantic root. The lemma table
        // forces them to meet on `analyz`.
        let analyze_stem = stem("analyze");
        assert_eq!(stem("analysis"), analyze_stem);
        assert_eq!(stem("analyses"), analyze_stem);
        assert_eq!(stem("analyzes"), analyze_stem); // suffix-strip path
        assert_eq!(stem("analyzed"), analyze_stem); // suffix-strip path
        // Synthesis family.
        assert_eq!(stem("synthesis"), stem("synthesize"));
        // Diagnosis family — pre-stem comparison; `diagnose` runs
        // through the trailing-e path to "diagnos" and `diagnosis`
        // uses the override to land on the same root.
        assert_eq!(stem("diagnosis"), "diagnos");
        assert_eq!(stem("diagnose"), "diagnos");
    }

    #[test]
    fn stem_collapses_common_inflections() {
        // All four forms of `parse` should land on the same root so a
        // query like "parsing" can match a symbol called `parse_*`.
        let root = stem("parsing");
        assert_eq!(stem("parse"), root, "parse should match parsing");
        assert_eq!(stem("parsed"), root, "parsed should match parsing");
        assert_eq!(stem("parser"), root, "parser should match parsing");
        // Plurals.
        assert_eq!(stem("node"), stem("nodes"));
        assert_eq!(stem("symbol"), stem("symbols"));
        // -tion gets stripped, even though our naive stemmer can't
        // reunite `connection` with `connect` (Porter handles that;
        // we don't). The point of this assertion is just to verify
        // the suffix fires.
        assert_ne!(stem("connection"), "connection");
        assert!(stem("connection").len() < "connection".len());
        // Short words don't get over-stripped.
        assert_eq!(stem("is"), "is");
        assert_eq!(stem("do"), "do");
    }

    #[test]
    fn score_candidate_sub_token_match_after_stemming() {
        // "parsing" query should hit candidate `parse_file_content`
        // even though there's no substring/exact overlap.
        let toks = vec!["parsing".to_string()];
        let idf = flat_idf();
        let hit = score_candidate(
            "parse_file_content",
            "src/parser.rs",
            0.001,
            None,
            &toks,
            &idf,
            &idf,
        );
        let miss = score_candidate(
            "unrelated_function",
            "src/other.rs",
            0.001,
            None,
            &toks,
            &idf,
            &idf,
        );
        // Hit gets at least the +6 sub-token bonus plus a file-path
        // +1 (the file is "parser.rs" which contains "parsing"? no it
        // doesn't, but stemming isn't applied to the path). The
        // important assertion is that hit > miss by a wide margin.
        assert!(
            hit > miss + 5.0,
            "stemmed sub-token match should fire (`parsing` → `pars` matches `parse`): \
             hit={hit}, miss={miss}"
        );
    }

    #[test]
    fn score_candidate_diminishing_subtoken_returns() {
        // The blind-v2 failure mode: a compound name matching MANY
        // sub-tokens used to beat a short name with one exact-name
        // hit. With diminishing returns on sub-token matches, the
        // short name wins.
        //
        // Query: "language specific queries"
        // - `Query` exact-name matches "queries" → +10
        // - `get_language_specific_complexity` matches `language` (+6)
        //   + `specific` (+3, halved) = +9 total — beats `Query`
        //   only if IDF tips it, which doesn't fire under flat IDF.
        let toks = vec![
            "language".to_string(),
            "specific".to_string(),
            "queries".to_string(),
        ];
        let idf = flat_idf();
        let query_score =
            score_candidate("Query", "src/queries.rs", 0.001, None, &toks, &idf, &idf);
        let compound_score = score_candidate(
            "get_language_specific_complexity",
            "src/complexity.rs",
            0.001,
            None,
            &toks,
            &idf,
            &idf,
        );
        assert!(
            query_score > compound_score,
            "Query (exact-name +10) should beat get_language_specific_complexity \
             (two diminishing sub-token matches): query={query_score}, compound={compound_score}"
        );
    }

    #[test]
    fn score_candidate_pagerank_breaks_ties_on_no_keyword_match() {
        let toks = vec!["unrelated_keyword_xyz".to_string()];
        let idf = flat_idf();
        let high = score_candidate("foo", "src/lib.rs", 0.5, None, &toks, &idf, &idf);
        let low = score_candidate("bar", "src/lib.rs", 0.001, None, &toks, &idf, &idf);
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
        // All three queries have non-empty expected_top_k, so
        // answerable_coverage equals coverage.
        assert!((report.answerable_coverage - 2.0 / 3.0).abs() < 1e-9);
    }

    #[test]
    fn answerable_coverage_excludes_negative_controls() {
        // 2 answerable queries (1 hit, 1 miss) + 1 negative control.
        // Plain coverage = 1/3; answerable coverage = 1/2.
        let queries = vec![
            QueryResult {
                query: "answerable hit".into(),
                expected_top_k: vec!["a".into()],
                returned_top_k: vec!["a".into()],
                first_hit_rank: Some(0),
                hits_in_top_k: 1,
                reciprocal_rank: 1.0,
            },
            QueryResult {
                query: "answerable miss".into(),
                expected_top_k: vec!["x".into()],
                returned_top_k: vec!["b".into()],
                first_hit_rank: None,
                hits_in_top_k: 0,
                reciprocal_rank: 0.0,
            },
            QueryResult {
                query: "negative control".into(),
                expected_top_k: vec![],
                returned_top_k: vec!["b".into()],
                first_hit_rank: None,
                hits_in_top_k: 0,
                reciprocal_rank: 0.0,
            },
        ];
        let report = build_report(Path::new("/tmp"), Path::new("/tmp/c.toml"), 10, queries);
        assert!((report.coverage - 1.0 / 3.0).abs() < 1e-9);
        assert!((report.answerable_coverage - 0.5).abs() < 1e-9);
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
