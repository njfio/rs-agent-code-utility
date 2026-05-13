//! AST-precise reference extraction for outline + closure walker.
//!
//! ### What this replaces
//!
//! Prior to alpha.27, `outline` and `closure` used a regex tokenizer
//! (`outline::extract_identifiers`) to pull every `[A-Za-z_][A-Za-z0-9_]*`
//! run out of a file's text and filter against the workspace-wide
//! def-name set. That's cheap but noisy:
//!
//! - Locals that shadow defined fn names get counted as references
//! - Identifiers in comments and string literals get counted
//! - Trait names in generic bounds get counted as if they were calls
//!
//! For the closure walker the noise translates directly to junk
//! entries in the agent-visible `dependencies` list. For outline it
//! biases PageRank toward files that *mention* a symbol over files
//! that *call* it.
//!
//! ### What this ships
//!
//! `extract_references(language, content)` parses `content` with
//! tree-sitter and runs a per-language tags.scm-derived query that
//! captures `@name` nodes inside `@reference.*` patterns. The result
//! is the set of names that are actually *referenced* at call sites,
//! not just text-occurring.
//!
//! ### Scope (v0)
//!
//! Tags.scm precision is wired for **Rust, Python, Go, Ruby** — the
//! four languages whose upstream `tree-sitter-*/queries/tags.scm`
//! ships clean `@reference.call` (and `@reference.implementation`
//! for Rust) captures with `@name` sub-captures.
//!
//! For the other seven languages (C, C++, Java, JavaScript, TypeScript,
//! PHP, Swift), the upstream tags.scm either omits `@reference.*`
//! captures or uses different conventions. Those fall through to the
//! existing regex tokenizer — **no regression** vs alpha.26. A v1.1
//! slice adds locally-authored query overrides for the remaining
//! languages once they have a concrete user asking.

use rust_tree_sitter::{Language, Parser, query::Query};

/// Extract the set of *referenced* symbol names from `content` parsed
/// as `language`, using the supplied pre-compiled `Query`. The query
/// is built once per language (cached via `OnceLock` in
/// [`crate::language::cached_refs_query`]) and reused for every call —
/// `Query::new` is expensive (recompiles the query DSL on each call)
/// and the outline path runs this per file.
///
/// Errors during parse return `None`; this is a best-effort precision
/// improvement and the regex fallback is always available.
pub(crate) fn extract_references(
    language: Language,
    query: &Query,
    content: &str,
) -> Option<Vec<String>> {
    let parser = Parser::new(language).ok()?;
    let tree = parser.parse(content, None).ok()?;
    let captures = query.captures(&tree).ok()?;
    let mut out: Vec<String> = Vec::with_capacity(captures.len());
    for c in captures {
        // Only `@name` captures are the referenced symbol; the wrapping
        // `@reference.call` etc. captures are spans, not names.
        if c.name() == Some("name") {
            if let Ok(text) = c.node().text() {
                out.push(text.to_string());
            }
        }
    }
    Some(out)
}

/// Dispatcher used by `outline` + `closure` for each file they walk.
/// Tries AST-precise extraction first; falls back to the regex
/// tokenizer for languages without a query.
///
/// The fallback path is a stable owned-`Vec<String>` shape so callers
/// don't have to branch on `Option`. We allocate either way; the
/// AST-precise path is the win, not the allocation profile.
///
/// Both the `Language` enum variant and the pre-compiled tags.scm
/// query come from [`crate::language`] — the single source of truth
/// for per-language facts. `cached_refs_query` returns a process-wide
/// `&'static Query` so we don't recompile per call.
pub(crate) fn references_for_path(rel_path: &str, content: &str) -> Vec<String> {
    if let Some(info) = crate::language::info_for_path(rel_path) {
        if let Some(query) = crate::language::cached_refs_query(&info) {
            if let Some(refs) = extract_references(info.language, query, content) {
                return refs;
            }
        }
    }
    crate::outline::extract_identifiers(content)
        .map(|s| s.to_string())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: look up the per-language cached query in the central
    /// registry. Tests don't have to know which file holds the query
    /// strings or whether the cache has been populated yet.
    fn refs_query_for(rel_path: &str) -> Option<(Language, &'static Query)> {
        let info = crate::language::info_for_path(rel_path)?;
        let q = crate::language::cached_refs_query(&info)?;
        Some((info.language, q))
    }

    #[test]
    fn rust_references_capture_call_sites_only() {
        // `target_fn` is referenced inside the body (a call). `local_var`
        // is a local — the regex tokenizer would include it; tags.scm
        // does not.
        let src = "\
fn caller() {
    let local_var = 0;
    target_fn(local_var);
}";
        let (lang, q) = refs_query_for("a.rs").unwrap();
        let refs = extract_references(lang, q, src).expect("rust has a query");
        assert!(
            refs.contains(&"target_fn".to_string()),
            "expected target_fn (call site); got {refs:?}"
        );
        assert!(
            !refs.contains(&"local_var".to_string()),
            "local_var is not a call site; got {refs:?}"
        );
        assert!(
            !refs.contains(&"caller".to_string()),
            "caller is a def, not a ref; got {refs:?}"
        );
    }

    #[test]
    fn rust_references_pick_up_macros_and_method_calls() {
        let src = "\
fn caller() {
    let s = String::new();
    println!(\"{}\", s);
    s.push_str(\"x\");
}";
        let (lang, q) = refs_query_for("a.rs").unwrap();
        let refs = extract_references(lang, q, src).expect("rust has a query");
        assert!(
            refs.iter().any(|n| n == "println"),
            "println! should be captured; got {refs:?}"
        );
        assert!(
            refs.iter().any(|n| n == "push_str"),
            "push_str method should be captured; got {refs:?}"
        );
    }

    #[test]
    fn python_references_capture_calls_only() {
        let src = "\
def caller():
    local = 0
    target_fn(local)
    obj.method_name()
";
        let (lang, q) = refs_query_for("a.py").unwrap();
        let refs = extract_references(lang, q, src).expect("python has a query");
        assert!(refs.contains(&"target_fn".to_string()));
        assert!(refs.contains(&"method_name".to_string()));
        assert!(
            !refs.contains(&"local".to_string()),
            "local var should not be a ref; got {refs:?}"
        );
    }

    #[test]
    fn references_for_path_falls_back_to_regex_on_unknown_lang() {
        // .lua is not in our supported set; the fallback regex
        // tokenizer should return identifier-shaped tokens.
        let src = "function caller() local x = target_fn(1) end";
        let refs = references_for_path("script.lua", src);
        // Regex tokenizer returns ALL identifier-shaped tokens, so
        // both `caller` and `target_fn` (plus keywords like `function`)
        // appear. We just assert the fallback didn't crash and
        // included something.
        assert!(!refs.is_empty());
        assert!(refs.iter().any(|s| s == "target_fn"));
    }

    #[test]
    fn references_for_path_uses_tags_for_rust() {
        // Same content as the unit test above, routed through the
        // path-driven dispatcher.
        let src = "fn caller() { let local_var = 0; target_fn(local_var); }";
        let refs = references_for_path("src/lib.rs", src);
        assert!(refs.iter().any(|n| n == "target_fn"));
        assert!(
            !refs.iter().any(|n| n == "local_var"),
            "rust path should use tags.scm; got {refs:?}"
        );
    }

    #[test]
    fn unsupported_language_returns_none_from_extract() {
        // Java isn't wired in this slice; should return None and let
        // the dispatcher fall through.
        // (We can't pass an unsupported Language variant — the enum is
        // exhaustive — but we can confirm the path-driven dispatcher
        // routes via the regex.)
        let src = "public class C { void f() { other(); } }";
        let refs = references_for_path("X.java", src);
        // Regex fallback picks up everything, including class/void/etc.
        // The point is: it returns something non-empty.
        assert!(!refs.is_empty());
    }
}
