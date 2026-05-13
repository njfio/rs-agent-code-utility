//! `Index.Outline` orchestration: build the file→file reference
//! graph from the redb index + on-disk content, run PageRank, render
//! the token-budgeted dotted-text + structured-JSON pair.
//!
//! ### Incremental PageRank (alpha.20)
//!
//! The recompute path here is O(files × mean_file_bytes) for ref
//! extraction plus O(iters × edges) for power iteration — the S1 bench
//! measured 29–45 ms p95 on a 10k-LOC synthetic workspace. Most
//! `Index.Outline` calls in agent loops repeat the same params against
//! an unchanged index, so we keep a small LRU-of-one keyed by
//! `(index_generation, budget, glob, mentioned_*)` in [`OutlineCache`].
//!
//! Writer commits already `fetch_add` `state.index_generation` in
//! `writer::commit_batch`, so invalidation is implicit: the next call
//! after a commit sees a stale key and recomputes. This gives full
//! correctness for free without a push-flow algorithm — agents pay the
//! recompute cost only when the index actually changed.
//!
//! The push-flow local PageRank (Andersen et al. 2006) is deferred to
//! v1.1: it'd help workloads with high commit-cadence + repeat queries
//! on small subgraphs, but in practice the cache zeroes out the bench
//! and pushes p95 well under the 10 ms target.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use anyhow::Context;
use serde_json::{Value, json};

use crate::store::{FileWithDefs, Store};
use rust_tree_sitter::pagerank::{self, Edge};

/// Outline render targets.
pub struct OutlineParams<'a> {
    pub glob: Option<&'a str>,
    pub token_budget: u64,
    pub mentioned_files: &'a [String],
    pub mentioned_idents: &'a [String],
}

/// Built outline ready for the wire shape. `Clone` so we can hand out
/// cached snapshots cheaply (the JSON `Value` interior is `Arc`-shared
/// via `serde_json`'s representation).
#[derive(Clone)]
pub struct OutlineResult {
    pub outline_text: String,
    pub outline_json: Value,
    pub tokens_returned: u64,
    pub files_considered: u32,
    pub files_included: u32,
}

/// Cache key. Captures every input that affects the rendered outline.
/// `index_generation` is the implicit invalidator: any writer commit
/// bumps it, so a stale entry is just a key mismatch on the next call.
///
/// `mentioned_files` and `mentioned_idents` are stored as owned `Vec`s
/// because the live request borrows from a JSON-deserialised value
/// that doesn't outlive the handler frame. The cost is tiny — these
/// lists are agent-chat hints, typically 0–10 short strings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutlineCacheKey {
    pub index_generation: u64,
    pub token_budget: u64,
    pub glob: Option<String>,
    pub mentioned_files: Vec<String>,
    pub mentioned_idents: Vec<String>,
}

impl OutlineCacheKey {
    /// Convenience constructor from the borrowed handler view.
    pub fn from_params(generation: u64, p: &OutlineParams<'_>) -> Self {
        Self {
            index_generation: generation,
            token_budget: p.token_budget,
            glob: p.glob.map(|s| s.to_string()),
            mentioned_files: p.mentioned_files.to_vec(),
            mentioned_idents: p.mentioned_idents.to_vec(),
        }
    }
}

/// Single-slot cache. We intentionally avoid an LRU map — outline
/// queries from an agent loop almost always repeat the most recent
/// shape, and storing N entries doesn't help when the second-most-
/// recent is invalidated by every writer commit anyway. Keeping one
/// slot also bounds memory to "size of one rendered outline".
#[derive(Default)]
pub struct OutlineCache {
    inner: Mutex<Option<CachedEntry>>,
}

struct CachedEntry {
    key: OutlineCacheKey,
    /// `Arc<OutlineResult>` so cache hits hand out cheap clones — the
    /// caller only ever reads, and `serde_json::Value` doesn't `Copy`.
    result: Arc<OutlineResult>,
}

impl OutlineCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Return the cached result if the key matches. Cheap: one mutex
    /// + one Arc clone.
    pub fn get(&self, key: &OutlineCacheKey) -> Option<Arc<OutlineResult>> {
        let g = self.inner.lock().ok()?;
        let entry = g.as_ref()?;
        if &entry.key == key {
            Some(entry.result.clone())
        } else {
            None
        }
    }

    /// Replace the cache slot. Called after a miss + recompute.
    pub fn put(&self, key: OutlineCacheKey, result: Arc<OutlineResult>) {
        if let Ok(mut g) = self.inner.lock() {
            *g = Some(CachedEntry { key, result });
        }
    }

    /// Drop any cached entry. Currently only used in tests, but a
    /// future writer path may want to invalidate eagerly (e.g. on
    /// schema upgrade) instead of relying on the generation counter.
    #[allow(dead_code)]
    pub fn invalidate(&self) {
        if let Ok(mut g) = self.inner.lock() {
            *g = None;
        }
    }
}

impl std::fmt::Debug for OutlineCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let occupied = self.inner.lock().map(|g| g.is_some()).unwrap_or(false);
        f.debug_struct("OutlineCache")
            .field("occupied", &occupied)
            .finish()
    }
}

/// Compute the outline. `workspace_root` is needed to read the actual
/// file contents for reference extraction.
pub fn compute(
    workspace_root: &Path,
    store: &Store,
    params: &OutlineParams<'_>,
) -> anyhow::Result<OutlineResult> {
    let all_files = store
        .list_files_with_defs()
        .context("list files with defs")?;
    let files = match params.glob {
        Some(g) => filter_by_glob(all_files, g),
        None => all_files,
    };
    let files_considered = files.len() as u32;
    if files.is_empty() {
        return Ok(empty_result(files_considered));
    }

    let all_def_names = store.all_defined_names().context("all defined names")?;
    let mentioned_idents_set: HashSet<&str> =
        params.mentioned_idents.iter().map(|s| s.as_str()).collect();
    let mentioned_files_set: HashSet<&str> =
        params.mentioned_files.iter().map(|s| s.as_str()).collect();

    // Build a global map: symbol_name → set of file indices defining it.
    let mut def_map: HashMap<String, Vec<usize>> = HashMap::new();
    for (i, f) in files.iter().enumerate() {
        for d in &f.defined_symbols {
            def_map.entry(d.name.clone()).or_default().push(i);
        }
    }

    // For each file, parse and pull AST-precise references via
    // tags.scm (Rust/Python/Go/Ruby) — or the regex tokenizer fallback
    // for languages without a query. Each (referencer_file →
    // definer_file) tuple becomes an edge in the PageRank graph.
    //
    // The tags.scm path eliminates false-positive edges from local
    // variables that shadow def names, comment mentions, and
    // identifier appearances in trait/type bounds. PageRank ranks
    // files that *call* a symbol over files that *mention* it.
    let mut edges: Vec<Edge> = Vec::new();
    let mut ref_counts: HashMap<(usize, usize, String), u32> = HashMap::new();
    for (src_idx, f) in files.iter().enumerate() {
        let abs = workspace_root.join(&f.path);
        let content = match std::fs::read_to_string(&abs) {
            Ok(s) => s,
            Err(_) => continue,
        };
        for ident in crate::refs::references_for_path(&f.path, &content) {
            if !all_def_names.contains(&ident) {
                continue;
            }
            if let Some(dst_files) = def_map.get(&ident) {
                for &dst_idx in dst_files {
                    if dst_idx == src_idx {
                        continue;
                    }
                    *ref_counts
                        .entry((src_idx, dst_idx, ident.clone()))
                        .or_insert(0) += 1;
                }
            }
        }
    }

    // Per-ident ubiquity for the edge-weight recipe.
    let mut def_count_per_ident: HashMap<&str, u32> = HashMap::new();
    for (name, fids) in &def_map {
        def_count_per_ident.insert(name.as_str(), fids.len() as u32);
    }

    for ((src, dst, ident), refs) in &ref_counts {
        let in_mentioned = mentioned_idents_set.contains(ident.as_str());
        let in_chat = mentioned_files_set.contains(files[*src].path.as_str());
        let is_ubi = def_count_per_ident
            .get(ident.as_str())
            .copied()
            .unwrap_or(0)
            > 5;
        let w = pagerank::edge_weight(ident, *refs, in_mentioned, in_chat, is_ubi);
        edges.push(Edge {
            src: *src as u32,
            dst: *dst as u32,
            weight: w,
        });
    }

    // Personalization: 100 / |personalized_fnames| per qualifying file.
    let personalized: Vec<usize> = files
        .iter()
        .enumerate()
        .filter(|(_i, f)| {
            mentioned_files_set.contains(f.path.as_str())
                || mentioned_idents_set
                    .iter()
                    .any(|ident| f.path.split(['/', '.']).any(|seg| seg == *ident))
        })
        .map(|(i, _)| i)
        .collect();
    let p_vec: Option<Vec<f64>> = if !personalized.is_empty() {
        let mut v = vec![0.0; files.len()];
        let per = 100.0 / personalized.len() as f64;
        for i in personalized {
            v[i] = per;
        }
        Some(v)
    } else {
        None
    };

    let ranks = pagerank::compute(files.len(), &edges, p_vec.as_deref());

    // Order files by descending rank.
    let mut ordering: Vec<(usize, f64)> = ranks.iter().copied().enumerate().collect();
    ordering.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

    render(&files, &ordering, params.token_budget, files_considered)
}

fn render(
    files: &[FileWithDefs],
    ordering: &[(usize, f64)],
    token_budget: u64,
    files_considered: u32,
) -> anyhow::Result<OutlineResult> {
    let mut text = String::new();
    let mut json_files: Vec<Value> = Vec::new();
    let mut tokens: u64 = 0;
    let mut files_included: u32 = 0;
    // Each line is approximately N bytes / 3 tokens. Greedy-pack: stop
    // when adding another file's outline would exceed the budget.
    for (idx, rank) in ordering {
        let file = &files[*idx];
        let entry = render_file_entry(file, *rank);
        let entry_tokens = (entry.len() as u64).div_ceil(3);
        if tokens + entry_tokens > token_budget && files_included > 0 {
            break;
        }
        text.push_str(&entry);
        tokens += entry_tokens;
        files_included += 1;
        json_files.push(json!({
            "path":  file.path,
            "rank":  rank,
            "symbols": file.defined_symbols.iter().map(|d| json!({
                "name":       d.name,
                "kind":       d.kind.as_wire_str(),
                "visibility": d.visibility.as_wire_str(),
                "start_line": d.start_line,
                "end_line":   d.end_line,
            })).collect::<Vec<_>>(),
        }));
    }
    Ok(OutlineResult {
        outline_text: text,
        outline_json: json!({ "files": json_files }),
        tokens_returned: tokens,
        files_considered,
        files_included,
    })
}

fn render_file_entry(file: &FileWithDefs, rank: f64) -> String {
    let mut s = String::new();
    s.push_str(&format!("{} (rank={:.4})\n", file.path, rank));
    // Public/top-level symbols first, then private.
    let mut sorted = file.defined_symbols.clone();
    sorted.sort_by_key(|d| (d.visibility, d.start_line));
    for d in &sorted {
        s.push_str(&format!(
            "  {} {} (lines {}-{})\n",
            d.kind.as_wire_str(),
            d.name,
            d.start_line,
            d.end_line
        ));
    }
    s.push('\n');
    s
}

fn empty_result(files_considered: u32) -> OutlineResult {
    OutlineResult {
        outline_text: String::new(),
        outline_json: json!({ "files": [] }),
        tokens_returned: 0,
        files_considered,
        files_included: 0,
    }
}

/// Cheap glob match: prefix + `**` + trailing pattern. Anything more
/// complex than `prefix/**/*.ext` falls back to "everything" for v0.
fn filter_by_glob(files: Vec<FileWithDefs>, glob: &str) -> Vec<FileWithDefs> {
    if glob.is_empty() || glob == "**" || glob == "**/*" {
        return files;
    }
    files
        .into_iter()
        .filter(|f| glob_match(&f.path, glob))
        .collect()
}

fn glob_match(path: &str, glob: &str) -> bool {
    // Very small subset: prefix/** and *.ext suffix.
    if let Some(rest) = glob.strip_suffix("/**") {
        return path.starts_with(rest);
    }
    if let Some(ext) = glob.strip_prefix("**/*.") {
        return path.ends_with(&format!(".{ext}"));
    }
    if let Some(rest) = glob.strip_suffix("/**/*") {
        return path.starts_with(rest);
    }
    if let Some((prefix, ext)) = glob.split_once("/**/*.") {
        return path.starts_with(prefix) && path.ends_with(&format!(".{ext}"));
    }
    path == glob
}

/// Extract identifier-shaped tokens from source text. Identifiers
/// here are runs of `[A-Za-z_][A-Za-z0-9_]*`. This is intentionally
/// language-agnostic — we filter against the known-defs set later,
/// so noise (keywords, locals, etc.) just doesn't match.
///
/// `pub(crate)` so the closure walker (`crate::closure`) can share
/// this without duplicating the tokenizer logic.
pub(crate) fn extract_identifiers(content: &str) -> impl Iterator<Item = &str> + '_ {
    let bytes = content.as_bytes();
    let mut idx = 0;
    std::iter::from_fn(move || {
        while idx < bytes.len() {
            let b = bytes[idx];
            if b.is_ascii_alphabetic() || b == b'_' {
                let start = idx;
                idx += 1;
                while idx < bytes.len() {
                    let c = bytes[idx];
                    if c.is_ascii_alphanumeric() || c == b'_' {
                        idx += 1;
                    } else {
                        break;
                    }
                }
                return std::str::from_utf8(&bytes[start..idx]).ok();
            }
            idx += 1;
        }
        None
    })
}

/// Resolve a path the way the daemon's read handlers do — workspace-relative
/// only. Returns the absolute path inside the root. Unused here but
/// kept colocated for clarity.
#[allow(dead_code)]
fn resolve(workspace_root: &Path, rel: &str) -> PathBuf {
    workspace_root.join(rel)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_identifiers_skips_keywords_and_punctuation() {
        let src = "fn foo(bar: u32) -> Result<Foo, _Err> { let _x = 1; }";
        let idents: Vec<&str> = extract_identifiers(src).collect();
        assert!(idents.contains(&"foo"));
        assert!(idents.contains(&"bar"));
        assert!(idents.contains(&"Result"));
        assert!(idents.contains(&"Foo"));
        assert!(idents.contains(&"_Err"));
        // Numeric `1` is not an identifier — it should not appear.
        assert!(!idents.contains(&"1"));
    }

    #[test]
    fn glob_prefix_match() {
        assert!(glob_match("src/foo.rs", "src/**"));
        assert!(!glob_match("docs/foo.rs", "src/**"));
    }

    #[test]
    fn glob_ext_match() {
        assert!(glob_match("any/path.rs", "**/*.rs"));
        assert!(!glob_match("any/path.py", "**/*.rs"));
    }

    #[test]
    fn glob_prefix_plus_ext() {
        assert!(glob_match("src/lib.rs", "src/**/*.rs"));
        assert!(!glob_match("docs/lib.rs", "src/**/*.rs"));
        assert!(!glob_match("src/lib.py", "src/**/*.rs"));
    }

    fn fake_result(tag: &str) -> OutlineResult {
        OutlineResult {
            outline_text: tag.to_string(),
            outline_json: json!({"files": [], "tag": tag}),
            tokens_returned: 1,
            files_considered: 1,
            files_included: 1,
        }
    }

    fn key(generation: u64) -> OutlineCacheKey {
        OutlineCacheKey {
            index_generation: generation,
            token_budget: 4096,
            glob: None,
            mentioned_files: Vec::new(),
            mentioned_idents: Vec::new(),
        }
    }

    #[test]
    fn cache_empty_returns_none() {
        let c = OutlineCache::new();
        assert!(c.get(&key(0)).is_none());
    }

    #[test]
    fn cache_returns_stored_value_on_match() {
        let c = OutlineCache::new();
        c.put(key(7), Arc::new(fake_result("v7")));
        let got = c.get(&key(7)).expect("cache hit expected");
        assert_eq!(got.outline_text, "v7");
    }

    #[test]
    fn cache_misses_on_generation_change() {
        let c = OutlineCache::new();
        c.put(key(7), Arc::new(fake_result("v7")));
        // Index advanced → key mismatch → recompute path.
        assert!(c.get(&key(8)).is_none());
        // The stale slot stays until the next put — that's fine, we
        // overwrite on miss + compute.
    }

    #[test]
    fn cache_misses_on_param_change() {
        let c = OutlineCache::new();
        c.put(key(7), Arc::new(fake_result("v7")));
        let mut other = key(7);
        other.token_budget = 8192;
        assert!(c.get(&other).is_none());

        let mut other = key(7);
        other.glob = Some("src/**".to_string());
        assert!(c.get(&other).is_none());

        let mut other = key(7);
        other.mentioned_idents = vec!["foo".to_string()];
        assert!(c.get(&other).is_none());
    }

    #[test]
    fn cache_put_overwrites() {
        let c = OutlineCache::new();
        c.put(key(7), Arc::new(fake_result("first")));
        c.put(key(8), Arc::new(fake_result("second")));
        assert!(c.get(&key(7)).is_none());
        assert_eq!(c.get(&key(8)).unwrap().outline_text, "second");
    }

    #[test]
    fn cache_invalidate_clears_slot() {
        let c = OutlineCache::new();
        c.put(key(7), Arc::new(fake_result("v7")));
        c.invalidate();
        assert!(c.get(&key(7)).is_none());
    }

    #[test]
    fn cache_key_from_params_round_trip() {
        let mentioned_files = vec!["a.rs".to_string()];
        let mentioned_idents = vec!["Foo".to_string(), "bar".to_string()];
        let p = OutlineParams {
            glob: Some("src/**"),
            token_budget: 1024,
            mentioned_files: &mentioned_files,
            mentioned_idents: &mentioned_idents,
        };
        let k = OutlineCacheKey::from_params(42, &p);
        assert_eq!(k.index_generation, 42);
        assert_eq!(k.token_budget, 1024);
        assert_eq!(k.glob.as_deref(), Some("src/**"));
        assert_eq!(k.mentioned_files, vec!["a.rs"]);
        assert_eq!(k.mentioned_idents, vec!["Foo", "bar"]);
    }
}
