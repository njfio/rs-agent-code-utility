//! `Index.Outline` orchestration: build the file→file reference
//! graph from the redb index + on-disk content, run PageRank, render
//! the token-budgeted dotted-text + structured-JSON pair.
//!
//! v0 is the naïve recompute path: each call walks the workspace.
//! P8's incremental-update flow (push-flow local PageRank) lands when
//! S1 latency forces it.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use anyhow::Context;
use serde_json::{Value, json};

use crate::store::{DefinedSymbol, FileWithDefs, Store};
use rust_tree_sitter::pagerank::{self, Edge};

/// Outline render targets.
pub struct OutlineParams<'a> {
    pub glob: Option<&'a str>,
    pub token_budget: u64,
    pub mentioned_files: &'a [String],
    pub mentioned_idents: &'a [String],
}

/// Built outline ready for the wire shape.
pub struct OutlineResult {
    pub outline_text: String,
    pub outline_json: Value,
    pub tokens_returned: u64,
    pub files_considered: u32,
    pub files_included: u32,
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

    // For each file, parse-light: walk its source text and collect
    // identifier-shaped tokens that match a known def name. Each
    // (referencer_file → definer_file) becomes an edge.
    let mut edges: Vec<Edge> = Vec::new();
    let mut ref_counts: HashMap<(usize, usize, String), u32> = HashMap::new();
    for (src_idx, f) in files.iter().enumerate() {
        let abs = workspace_root.join(&f.path);
        let content = match std::fs::read_to_string(&abs) {
            Ok(s) => s,
            Err(_) => continue,
        };
        for ident in extract_identifiers(&content) {
            if !all_def_names.contains(ident) {
                continue;
            }
            if let Some(dst_files) = def_map.get(ident) {
                for &dst_idx in dst_files {
                    if dst_idx == src_idx {
                        continue;
                    }
                    *ref_counts
                        .entry((src_idx, dst_idx, ident.to_string()))
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
fn extract_identifiers(content: &str) -> impl Iterator<Item = &str> + '_ {
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
}
