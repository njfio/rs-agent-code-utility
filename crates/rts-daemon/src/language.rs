//! Per-language dispatch — the single source of truth for "what does
//! this file extension imply about the toolchain?".
//!
//! Prior to alpha.28, three modules each had their own
//! extension-to-something tables:
//!
//! - `methods::index::render_signature_for_path` (ext → renderer fn)
//! - `refs::language_for_path`                  (ext → `Language` enum)
//! - `writer::detect_language_from_path`        (ext → `Language` enum)
//!
//! That worked but had three problems the alpha.27 architecture review
//! surfaced:
//!
//! 1. Adding a new language meant updating three tables; nobody can
//!    enforce they agree.
//! 2. `closure.rs` had to reach into `methods::index` for the renderer,
//!    forcing `mod index` to be `pub(crate)` (a real coupling smell —
//!    `closure` is a domain module, `methods::index` is wire dispatch).
//! 3. The three tables had already drifted: `.tsx` routes to the
//!    TypeScript renderer (`methods/index.rs:998`) but `refs.rs:160`
//!    returns `None`. That's defensible for v0 (no JS/TS refs query
//!    yet), but the asymmetry was buried.
//!
//! The single registry below replaces all three. `info_for_path(rel_path)`
//! returns a `LanguageInfo` with the language, optional signature
//! renderer, and optional tags.scm references query. Consumers pick
//! the field they need.
//!
//! ### Adding a language
//!
//! 1. Add an arm to the `match` in [`info_for_path`].
//! 2. Reference the signature renderer from
//!    `rust_tree_sitter::signature` (or `None` if not yet implemented).
//! 3. Reference a tags.scm-derived `@reference.*` query (or `None` —
//!    the regex fallback in `crate::refs` will handle it).
//!
//! No other module changes. The whole dispatch is one file.

use std::sync::OnceLock;

use rust_tree_sitter::{Language, query::Query};

/// Function pointer for a signature renderer. All renderers in
/// `rust_tree_sitter::signature` share this shape:
/// `(body_bytes) -> Option<rendered_signature_string>`.
pub type SignatureRenderer = fn(&[u8]) -> Option<String>;

/// What the daemon needs to know about a file's language. Returned by
/// [`info_for_path`]; carries everything a consumer might want without
/// asking the caller to re-dispatch on extension.
#[derive(Debug, Clone, Copy)]
pub struct LanguageInfo {
    /// The tree-sitter `Language` enum variant. Used by the writer to
    /// parse the file + extract symbols, and by [`crate::refs`] to run
    /// the tags.scm query.
    pub language: Language,
    /// Per-language signature renderer. `None` when the language is
    /// indexable for symbol extraction but no signature renderer ships
    /// yet. Callers fall back to the full body in that case.
    pub signature_renderer: Option<SignatureRenderer>,
    /// Tree-sitter query (tags.scm `@reference.*` subset) for
    /// AST-precise reference extraction. `None` when no query is
    /// available; [`crate::refs`] falls back to the regex tokenizer.
    pub refs_query: Option<&'static str>,
}

// ---- tags.scm `@reference.*` query subsets ----
// Sourced verbatim from `tree-sitter-<lang>/queries/tags.scm`.

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

/// Path → [`LanguageInfo`]. The canonical extension table.
///
/// `.tsx` is intentionally routed to the same TypeScript renderer as
/// `.ts` — the tree-sitter-typescript grammar accepts both and the
/// agent-facing signature shape is identical. Same for `.h` → C
/// renderer (C++ headers `.hpp/.hh/.hxx` get the C++ renderer; they're
/// distinct grammars).
///
/// Returns `None` for any extension the daemon doesn't index.
pub fn info_for_path(rel_path: &str) -> Option<LanguageInfo> {
    let ext = std::path::Path::new(rel_path)
        .extension()
        .and_then(|e| e.to_str())
        .map(|s| s.to_ascii_lowercase());
    match ext.as_deref()? {
        "rs" => Some(LanguageInfo {
            language: Language::Rust,
            signature_renderer: Some(rust_tree_sitter::signature::render_rust),
            refs_query: Some(RUST_REFS),
        }),
        "py" => Some(LanguageInfo {
            language: Language::Python,
            signature_renderer: Some(rust_tree_sitter::signature::render_python),
            refs_query: Some(PYTHON_REFS),
        }),
        "ts" | "tsx" => Some(LanguageInfo {
            language: Language::TypeScript,
            signature_renderer: Some(rust_tree_sitter::signature::render_typescript),
            // Upstream tree-sitter-typescript tags.scm doesn't ship
            // `@reference.*` captures; locally-authored override is
            // v1.1 work.
            refs_query: None,
        }),
        "js" | "jsx" | "mjs" | "cjs" => Some(LanguageInfo {
            language: Language::JavaScript,
            signature_renderer: Some(rust_tree_sitter::signature::render_javascript),
            // Same v1.1 deferral as TypeScript.
            refs_query: None,
        }),
        "go" => Some(LanguageInfo {
            language: Language::Go,
            signature_renderer: Some(rust_tree_sitter::signature::render_go),
            refs_query: Some(GO_REFS),
        }),
        "java" => Some(LanguageInfo {
            language: Language::Java,
            signature_renderer: Some(rust_tree_sitter::signature::render_java),
            refs_query: None,
        }),
        "c" | "h" => Some(LanguageInfo {
            language: Language::C,
            signature_renderer: Some(rust_tree_sitter::signature::render_c),
            refs_query: None,
        }),
        "cpp" | "cc" | "cxx" | "hpp" | "hh" | "hxx" => Some(LanguageInfo {
            language: Language::Cpp,
            signature_renderer: Some(rust_tree_sitter::signature::render_cpp),
            refs_query: None,
        }),
        "php" | "phtml" => Some(LanguageInfo {
            language: Language::Php,
            signature_renderer: Some(rust_tree_sitter::signature::render_php),
            refs_query: None,
        }),
        "rb" | "rake" => Some(LanguageInfo {
            language: Language::Ruby,
            signature_renderer: Some(rust_tree_sitter::signature::render_ruby),
            refs_query: Some(RUBY_REFS),
        }),
        "swift" => Some(LanguageInfo {
            language: Language::Swift,
            signature_renderer: Some(rust_tree_sitter::signature::render_swift),
            refs_query: None,
        }),
        _ => None,
    }
}

// ---- Cached `Query` objects per language ----
//
// `Query::new` is expensive (tree-sitter recompiles the query DSL,
// interns capture names, etc.). The alpha.27 outline path calls
// `references_for_path` once per file in the workspace; a 1000-file
// Rust workspace would rebuild the same query 1000 times per cold
// `Index.Outline` call.
//
// One `OnceLock<Option<Query>>` per language with a `@reference.*`
// query. `Option` lets us absorb construction errors (e.g. tree-sitter
// rejects the query string) and fall through to the regex tokenizer.
// `OnceLock` is thread-safe, lock-free after first init, and lets the
// Query live for the lifetime of the process (intentional — we never
// invalidate).

static RUST_QUERY: OnceLock<Option<Query>> = OnceLock::new();
static PYTHON_QUERY: OnceLock<Option<Query>> = OnceLock::new();
static GO_QUERY: OnceLock<Option<Query>> = OnceLock::new();
static RUBY_QUERY: OnceLock<Option<Query>> = OnceLock::new();

/// Cached `Query` for `language`. Returns `Some` if the language has a
/// tags.scm-derived `@reference.*` query *and* construction succeeded;
/// `None` otherwise (caller falls back to the regex tokenizer).
///
/// First call per language pays the `Query::new` cost; subsequent calls
/// are an atomic load + pointer deref.
pub fn cached_refs_query(info: &LanguageInfo) -> Option<&'static Query> {
    let cell = match info.language {
        Language::Rust => &RUST_QUERY,
        Language::Python => &PYTHON_QUERY,
        Language::Go => &GO_QUERY,
        Language::Ruby => &RUBY_QUERY,
        _ => return None,
    };
    let query_src = info.refs_query?;
    cell.get_or_init(|| Query::new(info.language, query_src).ok())
        .as_ref()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rust_dispatch_carries_renderer_and_query() {
        let info = info_for_path("src/lib.rs").expect("rust supported");
        assert_eq!(info.language, Language::Rust);
        assert!(info.signature_renderer.is_some());
        assert!(info.refs_query.is_some());
    }

    #[test]
    fn typescript_has_renderer_but_no_refs_query_in_v0() {
        // .tsx and .ts both route to TypeScript; both have a renderer.
        // Neither has a refs query in v0 (deferred to v1.1).
        for ext in ["src/a.ts", "src/a.tsx"] {
            let info = info_for_path(ext).expect("ts/tsx supported");
            assert_eq!(info.language, Language::TypeScript);
            assert!(
                info.signature_renderer.is_some(),
                "{ext} should have renderer"
            );
            assert!(info.refs_query.is_none(), "{ext} v0 refs query is None");
        }
    }

    #[test]
    fn javascript_aliases_all_map() {
        for ext in ["a.js", "a.jsx", "a.mjs", "a.cjs"] {
            let info = info_for_path(ext).expect("{ext} should be supported");
            assert_eq!(info.language, Language::JavaScript);
        }
    }

    #[test]
    fn cpp_header_aliases_route_to_cpp_not_c() {
        // .h goes to C; .hpp/.hh/.hxx go to C++. .cpp/.cc/.cxx go to
        // C++. Test the lot.
        assert_eq!(info_for_path("a.c").unwrap().language, Language::C);
        assert_eq!(info_for_path("a.h").unwrap().language, Language::C);
        for ext in ["a.cpp", "a.cc", "a.cxx", "a.hpp", "a.hh", "a.hxx"] {
            assert_eq!(
                info_for_path(ext).unwrap().language,
                Language::Cpp,
                "{ext} should route to C++"
            );
        }
    }

    #[test]
    fn ruby_rake_alias() {
        for ext in ["a.rb", "Rakefile.rake"] {
            assert_eq!(info_for_path(ext).unwrap().language, Language::Ruby);
        }
    }

    #[test]
    fn unsupported_extension_returns_none() {
        assert!(info_for_path("a.lua").is_none());
        assert!(info_for_path("a.zig").is_none());
        assert!(info_for_path("README").is_none());
    }

    #[test]
    fn case_insensitive_extension() {
        // Match on lowercase — `.RS` and `.PY` should still resolve.
        // We don't promise this, but it falls out for free from the
        // `.to_ascii_lowercase()` in `info_for_path`.
        assert!(info_for_path("Demo.RS").is_some());
        assert!(info_for_path("DEMO.PY").is_some());
    }

    #[test]
    fn signature_renderer_invokable_for_rust() {
        let info = info_for_path("a.rs").unwrap();
        let render = info.signature_renderer.unwrap();
        let body = b"pub fn foo(x: u32) -> u32 { x + 1 }";
        let sig = render(body).expect("renderer should produce a signature");
        assert!(sig.contains("pub fn foo"), "got {sig:?}");
    }
}
