//! Entropy-v0 contract subcommands: `rts context --format hook-json`,
//! `rts clones`, and `rts snapshot`.
//!
//! These run **in-process** over `rust_tree_sitter` (rts-core) rather than
//! round-tripping through the daemon: all three are whole-workspace batch
//! scans (rank every symbol / hash every subtree), which the daemon's
//! per-symbol RPC surface doesn't expose, and they must work headless in CI
//! hooks with a `timeout 2` wrapper — no socket, no auto-spawn.
//!
//! Output shapes are frozen by the golden fixtures in the entropy starter
//! repo (`fixtures/rts/*.json`); see `docs/entropy/rts-brief.md` there.
//! Experimental surface (see AGENTS.md "Experimental surface gate").

use std::collections::HashMap;
use std::path::Path;
use std::process::Command;

use serde_json::{Value, json};

use rust_tree_sitter::{Language, detect_language_from_path, parse_content, signature};

// ---------- workspace scan ----------

/// One parsed source file.
struct FileEntry {
    /// Workspace-relative path.
    path: String,
    content: String,
    language: Language,
}

/// Enumerate tracked source files (respects .gitignore via `git ls-files`;
/// falls back to a bounded directory walk when the workspace isn't a git
/// checkout) and keep the ones rts can parse.
fn scan_files(workspace: &Path) -> Vec<FileEntry> {
    let paths = git_ls_files(workspace).unwrap_or_else(|| walk_files(workspace));
    let mut out = Vec::new();
    for rel in paths {
        let Some(language) = detect_language_from_path(&rel) else {
            continue;
        };
        let abs = workspace.join(&rel);
        // Skip anything unreadable or non-UTF-8; a telemetry scan must
        // never fail the whole run over one file.
        let Ok(content) = std::fs::read_to_string(&abs) else {
            continue;
        };
        // 1 MiB cap: generated / vendored blobs distort clone mass and
        // dup_pct far more than they inform them.
        if content.len() > 1_048_576 {
            continue;
        }
        out.push(FileEntry {
            path: rel,
            content,
            language,
        });
    }
    out
}

fn git_ls_files(workspace: &Path) -> Option<Vec<String>> {
    let output = Command::new("git")
        .arg("-C")
        .arg(workspace)
        .args([
            "ls-files",
            "-z",
            "--cached",
            "--others",
            "--exclude-standard",
        ])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    Some(
        output
            .stdout
            .split(|b| *b == 0)
            .filter(|s| !s.is_empty())
            .filter_map(|s| String::from_utf8(s.to_vec()).ok())
            .collect(),
    )
}

fn walk_files(workspace: &Path) -> Vec<String> {
    const SKIP: &[&str] = &[".git", "target", "node_modules", "dist", "vendor"];
    let mut out = Vec::new();
    let mut stack = vec![workspace.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().into_owned();
            if path.is_dir() {
                if !SKIP.contains(&name.as_str()) && !name.starts_with('.') {
                    stack.push(path);
                }
            } else if let Ok(rel) = path.strip_prefix(workspace) {
                out.push(rel.to_string_lossy().into_owned());
            }
        }
    }
    out
}

// ---------- context (hook-json) ----------

/// Symbol kinds worth offering as reusable abstractions.
const OFFERABLE_KINDS: &[&str] = &[
    "function",
    "method",
    "struct",
    "enum",
    "trait",
    "class",
    "interface",
    "type",
    "type_alias",
    "module",
    "macro",
];

struct RankedSymbol {
    symbol_id: String,
    name: String,
    kind: String,
    path: String,
    line: usize,
    signature: String,
    doc_first_line: String,
    score: f64,
}

/// `rts context --for <text> --k <n> --token-budget <budget> --format hook-json`
pub fn run_context(workspace: &Path, query: &str, k: usize, token_budget: usize) -> i32 {
    let files = scan_files(workspace);
    let query_tokens = lex_tokens(query);

    let mut ranked: Vec<RankedSymbol> = Vec::new();
    for file in &files {
        let Ok(outcome) = parse_content(&file.content, file.language) else {
            continue;
        };
        let lines: Vec<&str> = file.content.lines().collect();
        for sym in &outcome.symbols {
            if sym.name.is_empty() || sym.start_line == 0 || sym.start_line > lines.len() {
                continue;
            }
            // Offer definitions an agent could call or reuse — not local
            // variables, imports, or markdown headings.
            if !OFFERABLE_KINDS.contains(&sym.kind.as_str()) {
                continue;
            }
            let doc_first_line = sym
                .documentation
                .as_deref()
                .and_then(|d| d.lines().next())
                .unwrap_or("")
                .trim()
                .to_string();
            let score = lexical_score(&query_tokens, &sym.name, &doc_first_line, &file.path);
            if score <= 0.0 {
                continue;
            }
            let qualified = match &sym.parent {
                Some(p) => format!("{p}::{}", sym.name),
                None => sym.name.clone(),
            };
            ranked.push(RankedSymbol {
                symbol_id: format!("crate::{qualified}@{}#L{}", file.path, sym.start_line),
                name: sym.name.clone(),
                kind: short_kind(&sym.kind),
                path: file.path.clone(),
                line: sym.start_line,
                signature: render_signature(&lines, sym.start_line, sym.end_line, file.language),
                doc_first_line,
                score,
            });
        }
    }

    // Deterministic order: score desc, then symbol_id for stable ties.
    ranked.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.symbol_id.cmp(&b.symbol_id))
    });
    ranked.truncate(k.max(1));

    // Render offered signatures + doc first lines, budget-capped: drop the
    // lowest-ranked symbols first until the estimate fits.
    let header = "## Existing abstractions relevant to this task\n\n";
    let footer = "\n\nPrefer calling these over reimplementing. If none fit, proceed.";
    let mut kept = ranked.len();
    let rendered = loop {
        let body: Vec<String> = ranked[..kept]
            .iter()
            .map(|s| {
                let doc = if s.doc_first_line.is_empty() {
                    s.signature.clone()
                } else {
                    s.doc_first_line.clone()
                };
                format!("`{}` — {}:{} — {}", s.name, s.path, s.line, doc)
            })
            .collect();
        let text = format!("{header}{}{footer}", body.join("\n"));
        if kept <= 1 || estimate_tokens(&text) <= token_budget {
            break text;
        }
        kept -= 1;
    };

    let offered: Vec<Value> = ranked
        .iter()
        .enumerate()
        .map(|(i, s)| {
            json!({
                "symbol_id": s.symbol_id,
                "name": s.name,
                "kind": s.kind,
                "path": s.path,
                "line": s.line,
                "signature": s.signature,
                "doc_first_line": s.doc_first_line,
                "rank": i + 1,
                "score": round2(s.score),
            })
        })
        .collect();

    print_json(&json!({ "offered": offered, "rendered": rendered }));
    0
}

/// Whitespace/word tokens, lowercased, deduplicated, stopwords dropped.
fn lex_tokens(text: &str) -> Vec<String> {
    const STOP: &[&str] = &[
        "the", "a", "an", "of", "to", "in", "for", "and", "or", "with", "on", "is",
    ];
    let mut out: Vec<String> = Vec::new();
    for raw in text.split(|c: char| !c.is_alphanumeric()) {
        for word in split_ident(raw) {
            if word.len() >= 2 && !STOP.contains(&word.as_str()) && !out.contains(&word) {
                out.push(word);
            }
        }
    }
    out
}

/// Split an identifier on snake_case / camelCase boundaries, lowercase.
fn split_ident(ident: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut cur = String::new();
    for c in ident.chars() {
        if c == '_' || c == '-' {
            if !cur.is_empty() {
                words.push(std::mem::take(&mut cur));
            }
        } else if c.is_uppercase()
            && !cur.is_empty()
            && cur.chars().last().is_some_and(char::is_lowercase)
        {
            words.push(std::mem::take(&mut cur));
            cur.push(c.to_ascii_lowercase());
        } else {
            cur.push(c.to_ascii_lowercase());
        }
    }
    if !cur.is_empty() {
        words.push(cur);
    }
    words
}

/// Hybrid lexical score in (0, 1]: fraction of query tokens matched, with
/// name hits weighted over doc hits over path hits.
fn lexical_score(query_tokens: &[String], name: &str, doc: &str, path: &str) -> f64 {
    if query_tokens.is_empty() {
        return 0.0;
    }
    let name_tokens = lex_tokens(name);
    let doc_tokens = lex_tokens(doc);
    let path_tokens = lex_tokens(path);
    let mut hit = 0.0;
    for q in query_tokens {
        if name_tokens.contains(q) {
            hit += 1.0;
        } else if doc_tokens.contains(q) {
            hit += 0.6;
        } else if path_tokens.contains(q) {
            hit += 0.3;
        }
    }
    hit / query_tokens.len() as f64
}

fn short_kind(kind: &str) -> String {
    match kind {
        "function" | "method" => "fn".to_string(),
        "class" => "class".to_string(),
        other => other.to_string(),
    }
}

/// Signature = declaration line(s) with the body stripped. Uses the core
/// per-language renderers when they succeed, else falls back to the first
/// source line trimmed of a trailing `{`.
fn render_signature(
    lines: &[&str],
    start_line: usize,
    end_line: usize,
    language: Language,
) -> String {
    let end = end_line.min(lines.len());
    let slice = lines[start_line - 1..end].join("\n");
    let rendered = match language {
        Language::Rust => signature::render_rust(slice.as_bytes()),
        Language::Python => signature::render_python(slice.as_bytes()),
        Language::TypeScript => signature::render_typescript(slice.as_bytes()),
        Language::JavaScript => signature::render_javascript(slice.as_bytes()),
        Language::Go => signature::render_go(slice.as_bytes()),
        _ => None,
    };
    let sig = rendered.unwrap_or_else(|| {
        lines[start_line - 1]
            .trim()
            .trim_end_matches('{')
            .trim_end()
            .to_string()
    });
    // One line, doc/attribute prefix lines dropped (docs travel separately
    // in `doc_first_line`).
    sig.lines()
        .map(str::trim)
        .filter(|l| !l.starts_with("///") && !l.starts_with("//!") && !l.starts_with("#["))
        .collect::<Vec<_>>()
        .join(" ")
        .trim_end_matches('{')
        .trim_end()
        .to_string()
}

/// Rough token estimate (~4 chars per token), matching the budget's spirit
/// without shipping a tokenizer.
fn estimate_tokens(text: &str) -> usize {
    text.len().div_ceil(4)
}

// ---------- clones ----------

struct CloneSite {
    path: String,
    start_line: usize,
    end_line: usize,
}

struct CloneCluster {
    cluster_id: String,
    mass_tokens: usize,
    sites: Vec<CloneSite>,
    spread_files: usize,
    score: usize,
}

struct CloneReport {
    clusters: Vec<CloneCluster>,
    total_tokens: usize,
}

/// `rts clones [--min-mass-tokens N] --format json|summary`
pub fn run_clones(workspace: &Path, min_mass_tokens: usize, summary: bool) -> i32 {
    let report = detect_clones(workspace, min_mass_tokens);
    if summary {
        let dup_tokens: usize = report
            .clusters
            .iter()
            .map(|c| c.mass_tokens * c.sites.len())
            .sum();
        let dup_pct = if report.total_tokens == 0 {
            0.0
        } else {
            100.0 * dup_tokens as f64 / report.total_tokens as f64
        };
        print_json(&json!({ "dup_pct": round2(dup_pct), "clusters": report.clusters.len() }));
    } else {
        let clusters: Vec<Value> = report
            .clusters
            .iter()
            .map(|c| {
                json!({
                    "cluster_id": c.cluster_id,
                    "mass_tokens": c.mass_tokens,
                    "sites": c.sites.iter().map(|s| json!({
                        "path": s.path,
                        "start_line": s.start_line,
                        "end_line": s.end_line,
                    })).collect::<Vec<_>>(),
                    "spread_files": c.spread_files,
                    "score": c.score,
                })
            })
            .collect();
        print_json(&json!({ "clusters": clusters }));
    }
    0
}

/// A candidate subtree: normalized hash + token mass + location.
struct Candidate {
    hash: [u8; 8],
    mass: usize,
    site: CloneSite,
}

/// Type-1/Type-2 clone detection: post-order normalized AST-subtree
/// hashing. Identifier leaves normalize to `ID`, literal leaves to `LIT`,
/// comments are dropped, so renamed variables / retyped literals still
/// collide (Type-2). Only maximal clusters are reported — a subtree whose
/// sites all sit inside an already-reported cluster's sites is noise.
fn detect_clones(workspace: &Path, min_mass_tokens: usize) -> CloneReport {
    let files = scan_files(workspace);
    let mut candidates: Vec<Candidate> = Vec::new();
    let mut total_tokens = 0usize;

    for file in &files {
        let Ok(parser) = rust_tree_sitter::Parser::new(file.language) else {
            continue;
        };
        let Ok(tree) = parser.parse(&file.content, None) else {
            continue;
        };
        let root = tree.root_node();
        let (_, _, tokens) = hash_subtree(&root, &file.path, min_mass_tokens, &mut candidates);
        total_tokens += tokens;
    }

    // Group by normalized hash; a cluster needs >= 2 sites and identical
    // mass (hash collisions across different masses are theoretical, but
    // keep the invariant explicit).
    let mut groups: HashMap<[u8; 8], Vec<usize>> = HashMap::new();
    for (i, c) in candidates.iter().enumerate() {
        groups.entry(c.hash).or_default().push(i);
    }

    let mut clusters: Vec<CloneCluster> = Vec::new();
    let mut group_list: Vec<(&[u8; 8], &Vec<usize>)> =
        groups.iter().filter(|(_, idxs)| idxs.len() >= 2).collect();
    // Largest mass first so containment filtering keeps maximal clones.
    group_list.sort_by_key(|(_, idxs)| std::cmp::Reverse(candidates[idxs[0]].mass));

    // Sites already claimed by an accepted (larger) cluster, per file.
    let mut claimed: HashMap<String, Vec<(usize, usize)>> = HashMap::new();
    for (hash, idxs) in group_list {
        let sites: Vec<&Candidate> = idxs
            .iter()
            .map(|&i| &candidates[i])
            .filter(|c| {
                !claimed.get(&c.site.path).is_some_and(|ivs| {
                    ivs.iter()
                        .any(|&(s, e)| s <= c.site.start_line && c.site.end_line <= e)
                })
            })
            .collect();
        if sites.len() < 2 {
            continue;
        }
        let mass = sites[0].mass;
        let mut paths: Vec<&str> = sites.iter().map(|c| c.site.path.as_str()).collect();
        paths.sort_unstable();
        paths.dedup();
        let spread_files = paths.len();
        for c in &sites {
            claimed
                .entry(c.site.path.clone())
                .or_default()
                .push((c.site.start_line, c.site.end_line));
        }
        clusters.push(CloneCluster {
            cluster_id: hex8(hash),
            mass_tokens: mass,
            sites: sites
                .iter()
                .map(|c| CloneSite {
                    path: c.site.path.clone(),
                    start_line: c.site.start_line,
                    end_line: c.site.end_line,
                })
                .collect(),
            spread_files,
            score: mass * spread_files,
        });
    }

    clusters.sort_by(|a, b| {
        b.score
            .cmp(&a.score)
            .then_with(|| a.cluster_id.cmp(&b.cluster_id))
    });
    CloneReport {
        clusters,
        total_tokens,
    }
}

/// Post-order walk: returns (structural fingerprint bytes fed upward,
/// subtree token mass, total leaf tokens under this node). Pushes a
/// candidate for every named subtree whose mass clears the threshold.
fn hash_subtree(
    node: &rust_tree_sitter::Node<'_>,
    path: &str,
    min_mass_tokens: usize,
    candidates: &mut Vec<Candidate>,
) -> (blake3::Hash, usize, usize) {
    let kind = node.kind();
    if kind.contains("comment") {
        return (blake3::hash(b""), 0, 0);
    }

    let mut hasher = blake3::Hasher::new();
    let mut mass = 0usize;

    if node.child_count() == 0 {
        // Leaf token: normalize identifiers and literals (Type-2).
        mass = 1;
        let norm = normalize_leaf(kind);
        hasher.update(norm.as_bytes());
    } else {
        hasher.update(kind.as_bytes());
        hasher.update(b"(");
        for child in node.children() {
            let (child_hash, child_mass, _) =
                hash_subtree(&child, path, min_mass_tokens, candidates);
            if child_mass > 0 {
                hasher.update(child_hash.as_bytes());
                mass += child_mass;
            }
        }
        hasher.update(b")");
    }

    let hash = hasher.finalize();
    if node.is_named() && node.child_count() > 0 && mass >= min_mass_tokens {
        let start = node.start_position();
        let end = node.end_position();
        let mut h8 = [0u8; 8];
        h8.copy_from_slice(&hash.as_bytes()[..8]);
        candidates.push(Candidate {
            hash: h8,
            mass,
            site: CloneSite {
                path: path.to_string(),
                start_line: start.row + 1,
                end_line: end.row + 1,
            },
        });
    }
    (hash, mass, mass)
}

/// Leaf normalization for Type-2 matching: any identifier-flavored kind
/// becomes `ID`, any literal-flavored kind becomes `LIT`; punctuation and
/// keywords hash as themselves.
fn normalize_leaf(kind: &str) -> &str {
    if kind.contains("identifier") || kind == "field_identifier" || kind == "type_identifier" {
        "ID"
    } else if kind.contains("literal")
        || kind.contains("string")
        || kind.contains("number")
        || kind.contains("integer")
        || kind.contains("float")
        || kind.contains("char")
        || kind == "true"
        || kind == "false"
    {
        "LIT"
    } else {
        kind
    }
}

fn hex8(bytes: &[u8; 8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// ---------- snapshot ----------

/// `rts snapshot --format json` — repo-level entropy stats. The four
/// dependency/fan metrics are nullable per the contract and rts doesn't
/// compute them yet, so they're emitted as `null`.
pub fn run_snapshot(workspace: &Path, min_mass_tokens: usize) -> i32 {
    let files = scan_files(workspace);
    let loc: usize = files.iter().map(|f| f.content.lines().count()).sum();
    let symbols: usize = files
        .iter()
        .filter_map(|f| parse_content(&f.content, f.language).ok())
        .map(|o| o.symbols.len())
        .sum();

    let report = detect_clones(workspace, min_mass_tokens);
    let dup_tokens: usize = report
        .clusters
        .iter()
        .map(|c| c.mass_tokens * c.sites.len())
        .sum();
    let dup_pct = if report.total_tokens == 0 {
        0.0
    } else {
        100.0 * dup_tokens as f64 / report.total_tokens as f64
    };

    let rev = Command::new("git")
        .arg("-C")
        .arg(workspace)
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    print_json(&json!({
        "rev": rev,
        "loc": loc,
        "symbols": symbols,
        "dup_pct": round2(dup_pct),
        "clone_clusters": report.clusters.len(),
        "mean_fan_in": Value::Null,
        "mean_fan_out": Value::Null,
        "deps_direct": Value::Null,
        "deps_transitive": Value::Null,
    }));
    0
}

// ---------- shared ----------

fn round2(x: f64) -> f64 {
    (x * 100.0).round() / 100.0
}

fn print_json(value: &Value) {
    println!(
        "{}",
        serde_json::to_string_pretty(value).unwrap_or_default()
    );
}
