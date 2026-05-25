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
//! Tags.scm precision is wired for **Rust, Python, Go, Ruby,
//! JavaScript, TypeScript, Java, PHP, Swift, C#** — 10 of the 12
//! indexed languages. C and C++ stay on the regex tokenizer for now
//! (function-pointer calls look identical to identifier references,
//! so the precision win is smaller).

use rust_tree_sitter::{Language, Parser, query::Query};

use crate::store::RefHit;

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

/// Like [`extract_references`] but emits one [`RefHit`] per call site
/// (carrying the byte range and 1-based inclusive line range of the
/// `@name` capture). Used by the writer to populate the v0.3
/// `REFS`/`FID_REFS`/`SID_REFS_OUT` tables; the at-query-time outline
/// loop and the closure walker both switch to reading those indexed
/// edges instead of re-extracting per call.
///
/// Returns `None` on parser failure — callers should fall back to a
/// language-agnostic shape (e.g. an empty Vec when the daemon
/// supports the language but parsing failed).
pub(crate) fn extract_references_with_ranges(
    language: Language,
    query: &Query,
    content: &str,
) -> Option<Vec<RefHit>> {
    let parser = Parser::new(language).ok()?;
    let tree = parser.parse(content, None).ok()?;
    let captures = query.captures(&tree).ok()?;
    let mut out: Vec<RefHit> = Vec::with_capacity(captures.len());
    for c in captures {
        if c.name() == Some("name") {
            let node = c.node();
            if let Ok(text) = node.text() {
                let start_byte = node.start_byte() as u32;
                let end_byte = node.end_byte() as u32;
                // tree-sitter rows are 0-based; protocol-v0 line
                // ranges are 1-based inclusive (matching DefSite).
                let start_row = node.start_position().row as u32 + 1;
                let end_row = node.end_position().row as u32 + 1;
                out.push(RefHit {
                    name: text.to_string(),
                    start: start_byte,
                    end: end_byte,
                    start_line: start_row,
                    end_line: end_row,
                });
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

/// Range-carrying variant of [`references_for_path`]. Used by the
/// writer (v0.3 U1) to populate the persistent ref graph.
///
/// For languages with a tags.scm reference query (Rust, Python, Go,
/// Ruby, JavaScript, TypeScript, Java, PHP, Swift, C#), each hit
/// carries a precise byte range from the `@name` capture. For the
/// remaining regex-fallback languages (C, C++) we synthesize the
/// byte range as `start = end = 0` and 1-based
/// `start_line = end_line = 1` — enough to populate the index for
/// "who calls X?" queries but not precise enough for "show me the
/// call site."
pub(crate) fn references_with_ranges(rel_path: &str, content: &str) -> Vec<RefHit> {
    if let Some(info) = crate::language::info_for_path(rel_path) {
        if let Some(query) = crate::language::cached_refs_query(&info) {
            if let Some(refs) = extract_references_with_ranges(info.language, query, content) {
                return refs;
            }
        }
    }
    // Regex fallback: identifier-shaped tokens with no precise range.
    // The store can still answer "who calls X" but the RefSite range
    // will be 0..0 / line 1..1.
    crate::outline::extract_identifiers(content)
        .map(|s| RefHit {
            name: s.to_string(),
            start: 0,
            end: 0,
            start_line: 1,
            end_line: 1,
        })
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
    fn javascript_references_capture_calls_and_new() {
        let src = "
function caller(input) {
    let local = input + 1;
    targetFn(local);
    obj.methodName();
    const x = new Widget(local);
    return x;
}
";
        let (lang, q) = refs_query_for("a.js").unwrap();
        let refs = extract_references(lang, q, src).expect("js has a query");
        assert!(refs.contains(&"targetFn".to_string()), "got {refs:?}");
        assert!(refs.contains(&"methodName".to_string()), "got {refs:?}");
        assert!(refs.contains(&"Widget".to_string()), "got {refs:?}");
        assert!(
            !refs.contains(&"local".to_string()),
            "local var should not be a ref; got {refs:?}"
        );
        assert!(
            !refs.contains(&"caller".to_string()),
            "caller is a def, not a ref; got {refs:?}"
        );
    }

    #[test]
    fn typescript_references_capture_calls_and_new() {
        let src = "
function caller(input: number): number {
    const local = input + 1;
    targetFn(local);
    obj.methodName();
    const x = new Widget(local);
    return x.value;
}
";
        let (lang, q) = refs_query_for("a.ts").unwrap();
        let refs = extract_references(lang, q, src).expect("ts has a query");
        assert!(refs.contains(&"targetFn".to_string()), "got {refs:?}");
        assert!(refs.contains(&"methodName".to_string()), "got {refs:?}");
        assert!(refs.contains(&"Widget".to_string()), "got {refs:?}");
        assert!(
            !refs.contains(&"local".to_string()),
            "local var should not be a ref; got {refs:?}"
        );
        assert!(
            !refs.contains(&"caller".to_string()),
            "caller is a def, not a ref; got {refs:?}"
        );
    }

    #[test]
    fn typescript_tsx_alias_uses_same_query() {
        // .tsx routes to TypeScript; same call_expression shape; same
        // refs. (TypeScript grammar accepts JSX syntax natively.)
        let src = "
function caller(): JSX.Element {
    targetFn();
    return <Widget />;
}
";
        let (lang, q) = refs_query_for("a.tsx").unwrap();
        let refs = extract_references(lang, q, src).expect("tsx has a query");
        // JSX `<Widget />` isn't a call_expression; only `targetFn()` is.
        // This pins the boundary: agents using TSX get function call
        // refs but not JSX element refs (which would be a v1.1 surface
        // anyway — closure-walking a React component's JSX is a
        // bigger question).
        assert!(refs.contains(&"targetFn".to_string()));
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
    fn java_references_capture_calls_and_object_creation() {
        // `other()` is a call site; `new Widget()` is object creation.
        // `local` is a local variable — regex tokenizer would include
        // it; tags.scm-style query does not.
        let src = "\
public class C {
    void caller() {
        int local = 0;
        other(local);
        Widget w = new Widget(local);
    }
}";
        let refs = references_for_path("C.java", src);
        assert!(
            refs.iter().any(|n| n == "other"),
            "method call should be captured; got {refs:?}"
        );
        assert!(
            refs.iter().any(|n| n == "Widget"),
            "object creation should be captured; got {refs:?}"
        );
        assert!(
            !refs.iter().any(|n| n == "local"),
            "local var should not be a ref; got {refs:?}"
        );
        assert!(
            !refs.iter().any(|n| n == "caller"),
            "caller is a def, not a ref; got {refs:?}"
        );
    }

    #[test]
    fn php_references_capture_calls_member_and_static() {
        // Mixes function call, member call, scoped (static) call,
        // namespace-qualified call, and `new`. All should resolve;
        // `$x` local variable should not.
        let src = "<?php
function caller() {
    $x = 0;
    bare_call($x);
    $obj->member_call();
    Klass::static_call();
    \\Foo\\namespaced_call();
    $w = new Widget();
}
";
        let refs = references_for_path("a.php", src);
        for expected in [
            "bare_call",
            "member_call",
            "static_call",
            "namespaced_call",
            "Widget",
        ] {
            assert!(
                refs.iter().any(|n| n == expected),
                "expected {expected:?} in php refs; got {refs:?}"
            );
        }
        assert!(
            !refs.iter().any(|n| n == "x"),
            "variable name should not be a ref; got {refs:?}"
        );
        assert!(
            !refs.iter().any(|n| n == "caller"),
            "caller is a def, not a ref; got {refs:?}"
        );
    }

    #[test]
    fn swift_references_capture_bare_and_method_calls() {
        // Bare call, method call via navigation, and a trailing-closure
        // call should all resolve.
        let src = "\
func caller() {
    let local = 0
    bareCall(local)
    obj.methodName()
    runWithClosure { _ in }
}
";
        let refs = references_for_path("App.swift", src);
        assert!(
            refs.iter().any(|n| n == "bareCall"),
            "bare call should be captured; got {refs:?}"
        );
        assert!(
            refs.iter().any(|n| n == "methodName"),
            "method call should be captured; got {refs:?}"
        );
        assert!(
            refs.iter().any(|n| n == "runWithClosure"),
            "trailing-closure call should be captured; got {refs:?}"
        );
        assert!(
            !refs.iter().any(|n| n == "local"),
            "local var should not be a ref; got {refs:?}"
        );
        assert!(
            !refs.iter().any(|n| n == "caller"),
            "caller is a def, not a ref; got {refs:?}"
        );
    }

    #[test]
    fn csharp_references_capture_calls_generics_and_new() {
        // Bare, member, generic, generic-member, and `new` — all
        // shapes should resolve. `local` should not.
        let src = "\
class C {
    void Caller() {
        int local = 0;
        Bare(local);
        obj.MemberCall(local);
        Generic<int>(local);
        obj.GenericMember<int>(local);
        var w = new Widget(local);
        var lst = new List<int>();
    }
}
";
        let refs = references_for_path("Program.cs", src);
        for expected in [
            "Bare",
            "MemberCall",
            "Generic",
            "GenericMember",
            "Widget",
            "List",
        ] {
            assert!(
                refs.iter().any(|n| n == expected),
                "expected {expected:?} in c# refs; got {refs:?}"
            );
        }
        assert!(
            !refs.iter().any(|n| n == "local"),
            "local var should not be a ref; got {refs:?}"
        );
        assert!(
            !refs.iter().any(|n| n == "Caller"),
            "Caller is a def, not a ref; got {refs:?}"
        );
    }
}
