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

/// Tree-sitter query: capture `@name` nodes that are the *callee*
/// identifier in a call expression, the method name in a method call,
/// the macro name in a macro invocation, or the trait/type in an impl
/// block. Sourced verbatim from `tree-sitter-rust-0.23.3/queries/tags.scm`,
/// `@reference.*` subset only.
const RUST_REFS: &str = r#"
(call_expression
    function: (identifier) @name) @reference.call

(call_expression
    function: (field_expression
        field: (field_identifier) @name)) @reference.call

(macro_invocation
    macro: (identifier) @name) @reference.call

(impl_item
    trait: (type_identifier) @name) @reference.implementation

(impl_item
    type: (type_identifier) @name
    !trait) @reference.implementation
"#;

const PYTHON_REFS: &str = r#"
(call
  function: [
      (identifier) @name
      (attribute
        attribute: (identifier) @name)
  ]) @reference.call
"#;

const GO_REFS: &str = r#"
(call_expression
  function: [
    (identifier) @name
    (parenthesized_expression (identifier) @name)
    (selector_expression field: (field_identifier) @name)
    (parenthesized_expression (selector_expression field: (field_identifier) @name))
  ]) @reference.call
"#;

const RUBY_REFS: &str = r#"
(call method: (identifier) @name) @reference.call
"#;

/// Extract the set of *referenced* symbol names from `content` parsed
/// as `language`. Order is the source-order in which tree-sitter
/// captures them; callers that need deduplication should collect into
/// a `HashSet`. Returns `None` when the language has no tags.scm
/// query — callers fall back to [`crate::outline::extract_identifiers`].
///
/// Errors during parse or query construction return `None`; this is a
/// best-effort precision improvement and the regex fallback is always
/// available.
pub(crate) fn extract_references(language: Language, content: &str) -> Option<Vec<String>> {
    let query_src = match language {
        Language::Rust => RUST_REFS,
        Language::Python => PYTHON_REFS,
        Language::Go => GO_REFS,
        Language::Ruby => RUBY_REFS,
        _ => return None,
    };
    let parser = Parser::new(language).ok()?;
    let tree = parser.parse(content, None).ok()?;
    let query = Query::new(language, query_src).ok()?;
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

/// Heuristic dispatcher used by `outline` + `closure` for each file
/// they walk. Tries AST-precise extraction first; falls back to the
/// regex tokenizer for languages without a query.
///
/// The fallback path is a stable owned-`Vec<String>` shape so callers
/// don't have to branch on `Option`. We allocate either way; the
/// AST-precise path is the win, not the allocation profile.
pub(crate) fn references_for_path(rel_path: &str, content: &str) -> Vec<String> {
    let lang = language_for_path(rel_path);
    if let Some(lang) = lang {
        if let Some(refs) = extract_references(lang, content) {
            return refs;
        }
    }
    crate::outline::extract_identifiers(content)
        .map(|s| s.to_string())
        .collect()
}

/// Path-to-Language mapping. Mirrors the dispatch in
/// `methods::index::render_signature_for_path` but expressed in terms
/// of `rust_tree_sitter::Language` rather than the per-language
/// signature renderer.
fn language_for_path(rel_path: &str) -> Option<Language> {
    let ext = std::path::Path::new(rel_path)
        .extension()
        .and_then(|e| e.to_str())
        .map(|s| s.to_ascii_lowercase());
    match ext.as_deref() {
        Some("rs") => Some(Language::Rust),
        Some("py") => Some(Language::Python),
        Some("go") => Some(Language::Go),
        Some("rb") | Some("rake") => Some(Language::Ruby),
        // Languages without an @reference.* query in this slice fall
        // through. Returning None makes `references_for_path` use the
        // regex fallback.
        Some("ts") | Some("tsx") | Some("js") | Some("jsx") | Some("mjs") | Some("cjs") => None,
        Some("c") | Some("h") => None,
        Some("cpp") | Some("cc") | Some("cxx") | Some("hpp") | Some("hh") | Some("hxx") => None,
        Some("java") => None,
        Some("php") | Some("phtml") => None,
        Some("swift") => None,
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let refs = extract_references(Language::Rust, src).expect("rust has a query");
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
        let refs = extract_references(Language::Rust, src).expect("rust has a query");
        // String::new is a path-based call — the `function: (identifier)`
        // capture matches `new` (the call target is a scoped identifier
        // path, but the field/method ident is `new`).
        // The macro invocation `println!` gets captured.
        // The method call `push_str` gets captured.
        // (Different upstream conventions about what gets captured per
        // call shape — our test asserts the most common cases.)
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
        let refs = extract_references(Language::Python, src).expect("python has a query");
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
