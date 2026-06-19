//! verify-v0 P3 — `Index.VerifyEdit` engine.
//!
//! Validates a PROPOSED patch against the live code index *before it is
//! written*, returning a structured pass/warn/fail verdict. The approach
//! is a **scoped in-memory delta** (a spike settled this over a
//! copy-on-write shadow index): re-parse the patched files, diff their
//! defs against the on-disk version, and query the LIVE index for the
//! callers of any def the edit removes or whose arity it changes.
//!
//! Strictly **read-only** — this module never opens a write txn and never
//! mutates the live [`Store`]. It reads `OLD` content from disk and takes
//! `NEW` content from the caller's proposed edit.
//!
//! ## What each edit contributes
//! For every [`ProposedEdit`] (capped at `max_files`):
//! 1. Read `OLD` = `root/file` (missing → treated as a new file with no
//!    old defs). `NEW` = `edit.content`. The language is resolved from the
//!    path; an unsupported language **skips** the file (no fabricated
//!    findings — it simply contributes nothing, and its name lands in
//!    `files_skipped`).
//! 2. `parse_content(OLD)` → old defs; `parse_content(NEW)` → new defs;
//!    `extract_references(NEW)` → new use-sites (currently unused for the
//!    cross-file checks but parsed so the contract is stable).
//! 3. Diff defs keyed by `(parent, name)`: **removed** (old ∖ new),
//!    **added** (new ∖ old), **sig-changed** (in both, F4
//!    `signature_shape` differs).
//! 4. Run the checks below, **excluding** any caller that lives inside the
//!    patched fileset — those files are themselves being edited, so
//!    flagging them against the stale index would be a false positive.
//!
//! ## Checks
//! - **new_symbols** (`Info`): an added def whose name is absent from the
//!   live `NAME_TO_SID` table (`sid_for_name` → `None`).
//! - **dangling_refs** (`Warning`): a removed def that still has live
//!   callers *outside* the patch.
//! - **broken_callers / signature_breaks** (`Critical`): for a sig-changed
//!   def whose F4 arity changed, each live caller outside the patch is a
//!   `SignatureBreak`. For a removed def, every live caller outside the
//!   patch is a `BrokenCaller`.
//!
//! ## Verdict
//! Any `Critical` → `Fail`; else any `Warning` → `Warn`; else `Pass`.
//! **Important:** if `files_skipped` is non-empty the result must NOT read
//! as a bare clean `Pass` — the verdict is bumped to at least `Warn` so a
//! caller never mistakes "we couldn't analyze part of your edit" for "your
//! edit is safe".

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use rust_tree_sitter::languages::Language;
use rust_tree_sitter::{
    Parser, SignatureShape, extract_references, parse_content, signature_shape, supports_references,
};

use crate::store::Store;

/// Default cap on the number of files analyzed in one call. The spike
/// showed 1–10 files parse serially within budget; 50 is a generous
/// ceiling that still bounds worst-case work.
pub const DEFAULT_MAX_FILES: usize = 50;

/// One file's proposed post-edit state. `content` is the FULL new file
/// content (not a diff hunk) — the engine re-parses it wholesale.
#[derive(Debug, Clone)]
pub struct ProposedEdit {
    /// Workspace-relative path of the file being edited.
    pub file: String,
    /// Full post-edit content of the file.
    pub content: String,
}

/// Severity of a single [`Finding`]. Drives the rolled-up [`Verdict`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    /// Ships a break: a real caller will no longer compile/resolve.
    Critical,
    /// Worth a look but not provably a break (e.g. a dangling ref that a
    /// later edit in the same change might resolve).
    Warning,
    /// Informational only (e.g. a newly-introduced symbol).
    Info,
}

impl Severity {
    /// Wire string for the `findings[].severity` field.
    pub fn as_wire_str(self) -> &'static str {
        match self {
            Severity::Critical => "critical",
            Severity::Warning => "warning",
            Severity::Info => "info",
        }
    }
}

/// The rolled-up gate result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// No findings worse than `Info`, and every file was analyzed.
    Pass,
    /// At least one `Warning` (or a skipped file) but no `Critical`.
    Warn,
    /// At least one `Critical` finding.
    Fail,
}

impl Verdict {
    /// Wire string for the `verdict` field.
    pub fn as_wire_str(self) -> &'static str {
        match self {
            Verdict::Pass => "pass",
            Verdict::Warn => "warn",
            Verdict::Fail => "fail",
        }
    }
}

/// The category of a [`Finding`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FindingKind {
    /// A live caller of a removed def.
    BrokenCaller,
    /// A removed def that still has live callers (the def's references
    /// are about to dangle).
    DanglingRef,
    /// A live caller of a def whose arity the edit changes.
    SignatureBreak,
    /// An added def whose name is not yet in the index.
    NewSymbol,
}

impl FindingKind {
    /// Wire string for the `findings[].kind` field.
    pub fn as_wire_str(self) -> &'static str {
        match self {
            FindingKind::BrokenCaller => "broken_caller",
            FindingKind::DanglingRef => "dangling_ref",
            FindingKind::SignatureBreak => "signature_break",
            FindingKind::NewSymbol => "new_symbol",
        }
    }
}

/// A concrete location associated with a [`Finding`] — the call site (for
/// caller-side findings) resolved to its enclosing definition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Site {
    /// Workspace-relative file of the site.
    pub file: String,
    /// 1-based line of the site.
    pub line: u32,
    /// Qualified name of the def enclosing the site (`""` when unknown).
    pub enclosing: String,
}

/// One structured finding from the edit verification.
#[derive(Debug, Clone)]
pub struct Finding {
    /// How serious this finding is.
    pub severity: Severity,
    /// What category of finding this is.
    pub kind: FindingKind,
    /// The symbol the finding is about (the edited def's name).
    pub symbol: String,
    /// The associated location, when the finding is tied to a call site.
    pub site: Option<Site>,
    /// Human-readable detail (e.g. `"callee arity 1 -> 2"`).
    pub detail: String,
}

/// The full structured result of an edit verification.
#[derive(Debug, Clone)]
pub struct EditVerdict {
    /// Rolled-up pass/warn/fail.
    pub verdict: Verdict,
    /// Every finding, in discovery order.
    pub findings: Vec<Finding>,
    /// How many files were actually parsed + diffed.
    pub files_analyzed: usize,
    /// Files that contributed nothing (unsupported language, or dropped by
    /// the `max_files` cap). A non-empty list bumps the verdict to at
    /// least `Warn`.
    pub files_skipped: Vec<String>,
}

/// A def identity for the delta diff: `(parent, name)`.
type DefKey = (Option<String>, String);

/// One parsed def with the data the diff needs.
struct DefInfo {
    /// The F4 signature shape, when decidable for the def's language.
    /// `None` for an undecidable/unsupported shape — an arity check then
    /// degrades to "no signature_break fired" (a removed def is still
    /// caught by name).
    shape: Option<SignatureShape>,
}

/// Evaluate a set of proposed edits against the live index.
///
/// `root` is the workspace root (for reading OLD content). `edits` are the
/// proposed post-edit file states. `max_files` caps how many edits are
/// analyzed; the rest land in `files_skipped`. Read-only throughout.
pub fn evaluate(
    store: &Arc<Store>,
    root: &Path,
    edits: &[ProposedEdit],
    max_files: usize,
) -> EditVerdict {
    let max_files = max_files.max(1);

    // Apply the file cap up front: analyze the first `max_files`, the rest
    // are skipped (and bump the verdict away from a bare `Pass`).
    let (analyzed_edits, capped) = if edits.len() > max_files {
        (&edits[..max_files], &edits[max_files..])
    } else {
        (edits, &[][..])
    };

    // The set of files being edited. Callers inside this set are excluded
    // from every cross-file check — those files are themselves changing, so
    // the stale index's view of them is not authoritative.
    let patched_files: std::collections::HashSet<&str> =
        analyzed_edits.iter().map(|e| e.file.as_str()).collect();

    let mut findings: Vec<Finding> = Vec::new();
    let mut files_skipped: Vec<String> = capped.iter().map(|e| e.file.clone()).collect();
    let mut files_analyzed = 0usize;

    for edit in analyzed_edits {
        let info = match crate::language::info_for_path(&edit.file) {
            Some(i) => i,
            None => {
                // No language mapping → can't parse → skip (no fabricated
                // findings). It contributes nothing but is recorded.
                files_skipped.push(edit.file.clone());
                continue;
            }
        };
        let lang = info.language;
        // We diff defs and need their signature shapes; both require a
        // parseable language. `supports_references` gates the same Rust /
        // TS / Python set `signature_shape` and the def diff rely on; for
        // anything else there's no honest delta to compute, so skip.
        if !supports_references(lang) {
            files_skipped.push(edit.file.clone());
            continue;
        }

        files_analyzed += 1;
        analyze_one(store, root, edit, lang, &patched_files, &mut findings);
    }

    // Verdict roll-up. Any Critical → Fail; else any Warning → Warn; else
    // Pass. A non-empty `files_skipped` forces at least `Warn` so a partial
    // analysis never reads as a clean pass.
    let has_critical = findings.iter().any(|f| f.severity == Severity::Critical);
    let has_warning = findings.iter().any(|f| f.severity == Severity::Warning);
    let verdict = if has_critical {
        Verdict::Fail
    } else if has_warning || !files_skipped.is_empty() {
        Verdict::Warn
    } else {
        Verdict::Pass
    };

    EditVerdict {
        verdict,
        findings,
        files_analyzed,
        files_skipped,
    }
}

/// Analyze a single edit, appending any findings.
fn analyze_one(
    store: &Arc<Store>,
    root: &Path,
    edit: &ProposedEdit,
    lang: Language,
    patched_files: &std::collections::HashSet<&str>,
    findings: &mut Vec<Finding>,
) {
    // OLD content from disk (missing → new file, no old defs).
    let old_content: String = match crate::path::resolve_workspace_path(root, &edit.file) {
        Ok((abs, _)) => std::fs::read_to_string(&abs).unwrap_or_default(),
        Err(_) => String::new(),
    };
    let new_content = &edit.content;

    // Parse defs for OLD and NEW. A parse error yields no symbols, which is
    // handled gracefully (an unparseable NEW simply produces no added/
    // sig-changed findings rather than a fabricated one).
    let old_defs = collect_defs(&old_content, lang);
    let new_defs = collect_defs(new_content, lang);

    // F3 references on NEW. Parsed for contract stability / future use; the
    // cross-file caller checks below query the live index, not these.
    let _new_refs = extract_references(new_content.as_bytes(), lang);

    // Diff by (parent, name).
    for (key, new_info) in &new_defs {
        if !old_defs.contains_key(key) {
            // ADDED def → new_symbol Info when absent from the live index.
            let name = &key.1;
            let in_index = store.sid_for_name(name).ok().flatten().is_some();
            if !in_index {
                findings.push(Finding {
                    severity: Severity::Info,
                    kind: FindingKind::NewSymbol,
                    symbol: render_name(key),
                    site: None,
                    detail: "new symbol not yet in index".to_string(),
                });
            }
            continue;
        }
        // In both → check for a signature (arity) change.
        let old_info = &old_defs[key];
        if let (Some(old_shape), Some(new_shape)) = (&old_info.shape, &new_info.shape) {
            if old_shape.arity != new_shape.arity {
                // Arity changed → every live caller OUTSIDE the patch is a
                // signature break (Critical).
                let detail = format!("callee arity {} -> {}", old_shape.arity, new_shape.arity);
                for site in live_caller_sites(store, &key.1, patched_files) {
                    findings.push(Finding {
                        severity: Severity::Critical,
                        kind: FindingKind::SignatureBreak,
                        symbol: render_name(key),
                        site: Some(site),
                        detail: detail.clone(),
                    });
                }
            }
        }
    }

    for key in old_defs.keys() {
        if new_defs.contains_key(key) {
            continue;
        }
        // REMOVED def. Gather its live callers outside the patch once.
        let sites = live_caller_sites(store, &key.1, patched_files);
        if sites.is_empty() {
            continue;
        }
        // Every live caller outside the patch is a BrokenCaller (Critical).
        for site in &sites {
            findings.push(Finding {
                severity: Severity::Critical,
                kind: FindingKind::BrokenCaller,
                symbol: render_name(key),
                site: Some(site.clone()),
                detail: "caller references removed symbol".to_string(),
            });
        }
        // And the removed def itself dangles (Warning) — surfaced once,
        // pointing at the def's name (no specific site).
        findings.push(Finding {
            severity: Severity::Warning,
            kind: FindingKind::DanglingRef,
            symbol: render_name(key),
            site: None,
            detail: format!(
                "{} live caller(s) reference the removed symbol",
                sites.len()
            ),
        });
    }
}

/// Parse `content` for `lang` and collect its defs keyed by `(parent,
/// name)`, each carrying the line-anchored F4 signature shape.
fn collect_defs(content: &str, lang: Language) -> HashMap<DefKey, DefInfo> {
    let mut out: HashMap<DefKey, DefInfo> = HashMap::new();
    let outcome = match parse_content(content, lang) {
        Ok(o) => o,
        Err(_) => return out,
    };
    if outcome.symbols.is_empty() {
        return out;
    }

    // Parse once for the whole file so we can anchor `signature_shape` on
    // each def node. Reuse the daemon's `find_def_node` walk.
    let src = content.as_bytes();
    let parser = match Parser::new(lang) {
        Ok(p) => p,
        Err(_) => {
            // No tree → record defs without shapes (arity checks degrade to
            // "undecidable", i.e. no signature_break fired; a removed def is
            // still caught by name).
            for sym in &outcome.symbols {
                out.entry((sym.parent.clone(), sym.name.clone()))
                    .or_insert(DefInfo { shape: None });
            }
            return out;
        }
    };
    let tree = match parser.parse(content, None) {
        Ok(t) => t,
        Err(_) => {
            for sym in &outcome.symbols {
                out.entry((sym.parent.clone(), sym.name.clone()))
                    .or_insert(DefInfo { shape: None });
            }
            return out;
        }
    };
    let root_node = tree.root_node().inner();

    for sym in &outcome.symbols {
        let key: DefKey = (sym.parent.clone(), sym.name.clone());
        // Anchor on the byte offset at the start of the def's line. The
        // symbol's column isn't always the def keyword, so anchoring on the
        // line start and letting `find_def_node` pick the innermost def
        // covering that offset is robust enough for the diff.
        let shape = byte_offset_of_line(src, sym.start_line)
            .and_then(|off| find_def_node(root_node, off))
            .and_then(|node| signature_shape(node, src, lang));
        // First def with a given key wins; an overload collision is rare in
        // the same file and the diff only needs presence + one shape.
        out.entry(key).or_insert(DefInfo { shape });
    }
    out
}

/// Byte offset of the first character of 1-based `line` in `src`. Returns
/// `None` when the line is past EOF.
fn byte_offset_of_line(src: &[u8], line: usize) -> Option<usize> {
    if line == 0 {
        return None;
    }
    if line == 1 {
        return Some(0);
    }
    let mut current = 1usize;
    for (i, b) in src.iter().enumerate() {
        if *b == b'\n' {
            current += 1;
            if current == line {
                return Some(i + 1);
            }
        }
    }
    None
}

/// Depth-first search for the innermost recognised function/method
/// definition node whose byte range covers `offset`. Mirrors the daemon's
/// `methods::index::find_def_node` (kept local to keep the engine pure).
fn find_def_node(
    node: rust_tree_sitter::tree_sitter::Node<'_>,
    offset: usize,
) -> Option<rust_tree_sitter::tree_sitter::Node<'_>> {
    const DEF_KINDS: &[&str] = &[
        "function_item",
        "function_signature_item",
        "function_declaration",
        "function_signature",
        "method_definition",
        "method_signature",
        "generator_function_declaration",
        "function_definition",
    ];

    if offset < node.start_byte() || offset >= node.end_byte() {
        return None;
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if let Some(found) = find_def_node(child, offset) {
            return Some(found);
        }
    }
    if DEF_KINDS.contains(&node.kind()) {
        return Some(node);
    }
    None
}

/// Resolve the LIVE callers of the bare symbol `name` into [`Site`]s,
/// EXCLUDING any caller whose file is in the patched fileset. Returns an
/// empty vec when the symbol is unknown or has no callers. Read-only.
fn live_caller_sites(
    store: &Arc<Store>,
    name: &str,
    patched_files: &std::collections::HashSet<&str>,
) -> Vec<Site> {
    let sid = match store.sid_for_name(name).ok().flatten() {
        Some(s) => s,
        None => return Vec::new(),
    };
    let refs = match store.refs_to_symbol(sid) {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };
    let mut out: Vec<Site> = Vec::new();
    // Cache fid → path so a hot callee in one file isn't resolved twice.
    let mut path_cache: HashMap<u32, Option<String>> = HashMap::new();
    for rs in refs {
        let path = path_cache
            .entry(rs.fid)
            .or_insert_with(|| store.path_for_fid(rs.fid).ok().flatten())
            .clone();
        let Some(path) = path else { continue };
        // EXCLUDE callers inside the patched fileset — those files are being
        // edited; flagging them against the stale index is a false positive.
        if patched_files.contains(path.as_str()) {
            continue;
        }
        // Resolve the enclosing def name when the ref carries a caller_sid.
        let enclosing = rs
            .caller_sid
            .and_then(|cs| store.caller_def_info(cs, rs.fid).ok().flatten())
            .map(|info| info.name)
            .unwrap_or_default();
        out.push(Site {
            file: path,
            line: rs.start_line,
            enclosing,
        });
    }
    out
}

/// Render a `(parent, name)` key as a qualified name (`parent::name`).
fn render_name(key: &DefKey) -> String {
    match &key.0 {
        Some(p) if !p.is_empty() => format!("{p}::{}", key.1),
        _ => key.1.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rust_tree_sitter::languages::Language;

    // ---- pure unit tests that don't need a Store ----

    #[test]
    fn collect_defs_diffs_added_and_removed() {
        let old = "pub fn a() {}\npub fn b() {}\n";
        let new = "pub fn a() {}\npub fn c() {}\n";
        let old_defs = collect_defs(old, Language::Rust);
        let new_defs = collect_defs(new, Language::Rust);
        assert!(old_defs.contains_key(&(None, "a".to_string())));
        assert!(old_defs.contains_key(&(None, "b".to_string())));
        assert!(new_defs.contains_key(&(None, "c".to_string())));
        // removed = old ∖ new = {b}
        assert!(!new_defs.contains_key(&(None, "b".to_string())));
        // added = new ∖ old = {c}
        assert!(!old_defs.contains_key(&(None, "c".to_string())));
    }

    #[test]
    fn collect_defs_detects_arity_change() {
        let old = "pub fn target(x: u32) -> u32 { x }\n";
        let new = "pub fn target(x: u32, y: u32) -> u32 { x + y }\n";
        let old_defs = collect_defs(old, Language::Rust);
        let new_defs = collect_defs(new, Language::Rust);
        let k = (None, "target".to_string());
        let os = old_defs[&k].shape.as_ref().expect("old shape");
        let ns = new_defs[&k].shape.as_ref().expect("new shape");
        assert_eq!(os.arity, 1);
        assert_eq!(ns.arity, 2);
    }

    #[test]
    fn collect_defs_arity_preserving_edit_same_shape() {
        let old = "pub fn target(x: u32) -> u32 { x + 1 }\n";
        let new = "pub fn target(x: u32) -> u32 { x + 2 }\n";
        let old_defs = collect_defs(old, Language::Rust);
        let new_defs = collect_defs(new, Language::Rust);
        let k = (None, "target".to_string());
        assert_eq!(
            old_defs[&k].shape.as_ref().map(|s| s.arity),
            new_defs[&k].shape.as_ref().map(|s| s.arity),
        );
    }

    #[test]
    fn byte_offset_of_line_basic() {
        let src = b"line1\nline2\nline3\n";
        assert_eq!(byte_offset_of_line(src, 1), Some(0));
        assert_eq!(byte_offset_of_line(src, 2), Some(6));
        assert_eq!(byte_offset_of_line(src, 3), Some(12));
        assert_eq!(byte_offset_of_line(src, 99), None);
        assert_eq!(byte_offset_of_line(src, 0), None);
    }

    #[test]
    fn render_name_qualifies() {
        assert_eq!(render_name(&(None, "foo".to_string())), "foo");
        assert_eq!(
            render_name(&(Some("Hub".to_string()), "ping".to_string())),
            "Hub::ping"
        );
    }

    #[test]
    fn wire_strings_are_stable() {
        assert_eq!(Verdict::Pass.as_wire_str(), "pass");
        assert_eq!(Verdict::Warn.as_wire_str(), "warn");
        assert_eq!(Verdict::Fail.as_wire_str(), "fail");
        assert_eq!(Severity::Critical.as_wire_str(), "critical");
        assert_eq!(Severity::Warning.as_wire_str(), "warning");
        assert_eq!(Severity::Info.as_wire_str(), "info");
        assert_eq!(FindingKind::BrokenCaller.as_wire_str(), "broken_caller");
        assert_eq!(FindingKind::DanglingRef.as_wire_str(), "dangling_ref");
        assert_eq!(FindingKind::SignatureBreak.as_wire_str(), "signature_break");
        assert_eq!(FindingKind::NewSymbol.as_wire_str(), "new_symbol");
    }
}
