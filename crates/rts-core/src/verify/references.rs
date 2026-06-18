//! Use-site reference extraction for the verification layer (Phase F, F3).
//!
//! [`extract_references`] is the inverse of definition extraction: it
//! walks the parse tree of an arbitrary snippet and emits the symbols and
//! imports it *uses* — calls, type references, imports, and qualified
//! paths — rather than the symbols it *defines*.
//!
//! Coverage in Phase F is **Rust, TypeScript, and Python**. The other ten
//! languages return `[]`; call [`supports_references`] to learn coverage
//! before relying on an empty result.
//!
//! Identifiers inside comments and string literals are never reported:
//! tree-sitter gives those their own node kinds, and the walks below only
//! descend into real call / type / import nodes.

use crate::languages::Language;
use serde::Serialize;
use tree_sitter::Node;

/// The category of a use-site [`Reference`].
#[derive(Debug, Clone, PartialEq, Serialize)]
pub enum RefKind {
    /// A call expression (`foo(x)`, `obj.method(x)`).
    Call,
    /// A type reference (`Vec<Entry>`, `: CommitOptions`).
    Type,
    /// An import / use declaration (`use a::b::C`, `from m import f`).
    Import,
    /// A qualified path reference that isn't itself a call or import
    /// (`store::Store`).
    Path,
}

/// A single referenced symbol or import discovered in a snippet.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Reference {
    /// The referenced name — the final segment for qualified references
    /// and imports.
    pub name: String,
    /// The full qualified path when known (e.g. the import path), else
    /// `None`.
    pub qualified: Option<String>,
    /// What kind of use-site this is.
    pub kind: RefKind,
    /// 1-based line of the reference (matches [`crate::Symbol`]).
    pub line: usize,
    /// 0-based column of the reference (matches [`crate::Symbol`]).
    pub column: usize,
    /// For [`RefKind::Call`], the number of arguments; `None` otherwise.
    pub call_arity: Option<u32>,
}

/// Whether [`extract_references`] has a real walk for `lang`. Languages
/// outside this set always yield `[]`.
pub fn supports_references(lang: Language) -> bool {
    matches!(lang, Language::Rust | Language::TypeScript | Language::Python)
}

/// Walk the parse tree of `content` for `language` and return the
/// referenced symbols / imports (NOT definitions). Returns `[]` for
/// unsupported languages or unparseable input.
pub fn extract_references(content: &[u8], language: Language) -> Vec<Reference> {
    if !supports_references(language) {
        return Vec::new();
    }
    let Ok(ts_language) = language.tree_sitter_language() else {
        return Vec::new();
    };
    let mut parser = tree_sitter::Parser::new();
    if parser.set_language(&ts_language).is_err() {
        return Vec::new();
    }
    let Some(tree) = parser.parse(content, None) else {
        return Vec::new();
    };
    let root = tree.root_node();

    let mut refs = Vec::new();
    match language {
        Language::Rust => walk_rust(root, content, &mut refs),
        Language::TypeScript => walk_typescript(root, content, &mut refs),
        Language::Python => walk_python(root, content, &mut refs),
        _ => {}
    }
    refs
}

/// 1-based line, 0-based column for a node's start, matching `Symbol`.
fn pos(node: &Node<'_>) -> (usize, usize) {
    let p = node.start_position();
    (p.row + 1, p.column)
}

fn text<'a>(node: &Node<'_>, src: &'a [u8]) -> Option<&'a str> {
    node.utf8_text(src).ok()
}

/// The final `::`/`.`-delimited segment of a path string.
fn final_segment(path: &str) -> &str {
    path.rsplit(['.', ':']).next().unwrap_or(path)
}

fn for_each_child<'tree>(node: Node<'tree>, mut f: impl FnMut(Node<'tree>)) {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        f(child);
    }
}

fn count_call_arguments(args: &Node<'_>) -> u32 {
    // `arguments` / `argument_list` wraps the args in punctuation
    // (`(`, `,`, `)`); count only the named (real) children.
    let mut cursor = args.walk();
    args.named_children(&mut cursor).count() as u32
}

// ---------- Rust ----------

fn walk_rust(node: Node<'_>, src: &[u8], out: &mut Vec<Reference>) {
    match node.kind() {
        "call_expression" => {
            if let Some(func) = node.child_by_field_name("function") {
                if let Some(name) = callable_name_rust(&func, src) {
                    let arity = node
                        .child_by_field_name("arguments")
                        .map(|a| count_call_arguments(&a));
                    let (line, column) = pos(&func);
                    out.push(Reference {
                        name: final_segment(&name).to_string(),
                        qualified: qualified_if_path(&name),
                        kind: RefKind::Call,
                        line,
                        column,
                        call_arity: arity,
                    });
                }
            }
        }
        "use_declaration" => {
            collect_rust_use(&node, src, out);
            // Don't descend into the use tree as generic paths.
            return;
        }
        "type_identifier" => {
            // A type reference; skip the names that are part of a
            // definition's own name (those live under `name` fields and
            // are handled by definition extraction, not here). We accept
            // all type_identifiers in use-position; definitions of types
            // are rare in arbitrary verification snippets and harmless.
            if let Some(name) = text(&node, src) {
                let (line, column) = pos(&node);
                out.push(Reference {
                    name: name.to_string(),
                    qualified: None,
                    kind: RefKind::Type,
                    line,
                    column,
                    call_arity: None,
                });
            }
        }
        _ => {}
    }

    for_each_child(node, |child| walk_rust(child, src, out));
}

/// Extract a callable's textual name from a `call_expression`'s function
/// child. Handles plain identifiers, `a::b::c` scoped identifiers, and
/// `obj.method` field expressions (returns the method name).
fn callable_name_rust(func: &Node<'_>, src: &[u8]) -> Option<String> {
    match func.kind() {
        "identifier" => text(func, src).map(|s| s.to_string()),
        "scoped_identifier" => text(func, src).map(|s| s.to_string()),
        "field_expression" => func
            .child_by_field_name("field")
            .and_then(|f| text(&f, src))
            .map(|s| s.to_string()),
        // Generic function calls (`foo::<T>()`) wrap the path in a
        // `generic_function` node with a `function` field.
        "generic_function" => func
            .child_by_field_name("function")
            .and_then(|inner| callable_name_rust(&inner, src)),
        _ => None,
    }
}

fn qualified_if_path(name: &str) -> Option<String> {
    if name.contains("::") {
        Some(name.to_string())
    } else {
        None
    }
}

fn collect_rust_use(node: &Node<'_>, src: &[u8], out: &mut Vec<Reference>) {
    // `use_declaration` has an `argument` field holding the use tree.
    let Some(arg) = node.child_by_field_name("argument") else {
        return;
    };
    let (line, column) = pos(node);
    collect_rust_use_tree(&arg, src, "", line, column, out);
}

/// Recursively expand a Rust use tree into one `Import` per leaf.
fn collect_rust_use_tree(
    node: &Node<'_>,
    src: &[u8],
    prefix: &str,
    line: usize,
    column: usize,
    out: &mut Vec<Reference>,
) {
    match node.kind() {
        "scoped_identifier" | "identifier" => {
            if let Some(full) = text(node, src) {
                let qualified = join_path(prefix, full);
                out.push(Reference {
                    name: final_segment(&qualified).to_string(),
                    qualified: Some(qualified),
                    kind: RefKind::Import,
                    line,
                    column,
                    call_arity: None,
                });
            }
        }
        "use_as_clause" => {
            // `use a::b as c` — index the path, not the alias.
            if let Some(path) = node.child_by_field_name("path") {
                collect_rust_use_tree(&path, src, prefix, line, column, out);
            }
        }
        "scoped_use_list" | "use_list" => {
            // `a::{b, c}` — the path before `{` is the new prefix.
            let new_prefix = node
                .child_by_field_name("path")
                .and_then(|p| text(&p, src))
                .map(|p| join_path(prefix, p))
                .unwrap_or_else(|| prefix.to_string());
            for_each_child(*node, |child| {
                if matches!(
                    child.kind(),
                    "scoped_identifier"
                        | "identifier"
                        | "scoped_use_list"
                        | "use_list"
                        | "use_as_clause"
                ) {
                    collect_rust_use_tree(&child, src, &new_prefix, line, column, out);
                }
            });
        }
        "use_wildcard" => {
            // `a::*` — index the prefix path as a glob import.
            if let Some(path) = node.child_by_field_name("path").or_else(|| {
                let mut c = node.walk();
                node.children(&mut c).find(|n| {
                    matches!(n.kind(), "scoped_identifier" | "identifier")
                })
            }) {
                if let Some(p) = text(&path, src) {
                    let qualified = join_path(prefix, p);
                    out.push(Reference {
                        name: final_segment(&qualified).to_string(),
                        qualified: Some(format!("{qualified}::*")),
                        kind: RefKind::Import,
                        line,
                        column,
                        call_arity: None,
                    });
                }
            }
        }
        _ => {}
    }
}

fn join_path(prefix: &str, segment: &str) -> String {
    if prefix.is_empty() {
        segment.to_string()
    } else {
        format!("{prefix}::{segment}")
    }
}

// ---------- TypeScript ----------

fn walk_typescript(node: Node<'_>, src: &[u8], out: &mut Vec<Reference>) {
    match node.kind() {
        "call_expression" => {
            if let Some(func) = node.child_by_field_name("function") {
                if let Some(name) = callable_name_ts(&func, src) {
                    let arity = node
                        .child_by_field_name("arguments")
                        .map(|a| count_call_arguments(&a));
                    let (line, column) = pos(&func);
                    out.push(Reference {
                        name,
                        qualified: None,
                        kind: RefKind::Call,
                        line,
                        column,
                        call_arity: arity,
                    });
                }
            }
        }
        "import_statement" => {
            collect_ts_import(&node, src, out);
            return;
        }
        "type_identifier" => {
            if let Some(name) = text(&node, src) {
                let (line, column) = pos(&node);
                out.push(Reference {
                    name: name.to_string(),
                    qualified: None,
                    kind: RefKind::Type,
                    line,
                    column,
                    call_arity: None,
                });
            }
        }
        _ => {}
    }

    for_each_child(node, |child| walk_typescript(child, src, out));
}

fn callable_name_ts(func: &Node<'_>, src: &[u8]) -> Option<String> {
    match func.kind() {
        "identifier" => text(func, src).map(|s| s.to_string()),
        "member_expression" => func
            .child_by_field_name("property")
            .and_then(|p| text(&p, src))
            .map(|s| s.to_string()),
        _ => None,
    }
}

fn collect_ts_import(node: &Node<'_>, src: &[u8], out: &mut Vec<Reference>) {
    // `import { a, b } from "mod"` / `import Foo from "mod"`. The module
    // source is the `source` field (a string); the imported names live in
    // an `import_clause`.
    let source = node
        .child_by_field_name("source")
        .and_then(|s| text(&s, src))
        .map(|s| s.trim_matches(|c| c == '"' || c == '\'' || c == '`').to_string());
    let (line, column) = pos(node);

    let mut found_clause = false;
    for_each_child(*node, |child| {
        if child.kind() == "import_clause" {
            found_clause = true;
            collect_ts_import_clause(&child, src, source.as_deref(), line, column, out);
        }
    });

    // Bare `import "mod"` side-effect imports: index the module itself.
    if !found_clause {
        if let Some(src_path) = &source {
            out.push(Reference {
                name: final_segment(src_path).to_string(),
                qualified: Some(src_path.clone()),
                kind: RefKind::Import,
                line,
                column,
                call_arity: None,
            });
        }
    }
}

fn collect_ts_import_clause(
    clause: &Node<'_>,
    src: &[u8],
    module: Option<&str>,
    line: usize,
    column: usize,
    out: &mut Vec<Reference>,
) {
    fn push(
        name: &str,
        module: Option<&str>,
        line: usize,
        column: usize,
        out: &mut Vec<Reference>,
    ) {
        let qualified = module.map(|m| format!("{m}::{name}"));
        out.push(Reference {
            name: name.to_string(),
            qualified,
            kind: RefKind::Import,
            line,
            column,
            call_arity: None,
        });
    }

    let mut cursor = clause.walk();
    for child in clause.children(&mut cursor) {
        match child.kind() {
            // `import Foo from "m"` — default import.
            "identifier" => {
                if let Some(n) = text(&child, src) {
                    push(n, module, line, column, out);
                }
            }
            // `import { a, b } from "m"` — named imports.
            "named_imports" => {
                let mut c2 = child.walk();
                for spec in child.children(&mut c2) {
                    if spec.kind() == "import_specifier" {
                        // Use the imported name (`name` field), not any
                        // `as` alias.
                        if let Some(name_node) = spec.child_by_field_name("name") {
                            if let Some(n) = text(&name_node, src) {
                                push(n, module, line, column, out);
                            }
                        }
                    }
                }
            }
            // `import * as ns from "m"` — namespace import.
            "namespace_import" => {
                let mut c2 = child.walk();
                for n in child.children(&mut c2) {
                    if n.kind() == "identifier" {
                        if let Some(name) = text(&n, src) {
                            push(name, module, line, column, out);
                        }
                    }
                }
            }
            _ => {}
        }
    }
}

// ---------- Python ----------

fn walk_python(node: Node<'_>, src: &[u8], out: &mut Vec<Reference>) {
    match node.kind() {
        "call" => {
            if let Some(func) = node.child_by_field_name("function") {
                if let Some(name) = callable_name_py(&func, src) {
                    let arity = node
                        .child_by_field_name("arguments")
                        .map(|a| count_call_arguments(&a));
                    let (line, column) = pos(&func);
                    out.push(Reference {
                        name,
                        qualified: None,
                        kind: RefKind::Call,
                        line,
                        column,
                        call_arity: arity,
                    });
                }
            }
        }
        "import_statement" => {
            collect_py_import(&node, src, out);
            return;
        }
        "import_from_statement" => {
            collect_py_import_from(&node, src, out);
            return;
        }
        _ => {}
    }

    for_each_child(node, |child| walk_python(child, src, out));
}

fn callable_name_py(func: &Node<'_>, src: &[u8]) -> Option<String> {
    match func.kind() {
        "identifier" => text(func, src).map(|s| s.to_string()),
        // `obj.method(...)` — attribute access; report the method name.
        "attribute" => func
            .child_by_field_name("attribute")
            .and_then(|a| text(&a, src))
            .map(|s| s.to_string()),
        _ => None,
    }
}

fn collect_py_import(node: &Node<'_>, src: &[u8], out: &mut Vec<Reference>) {
    // `import a.b.c` / `import a.b as c` — each `name` child is a
    // dotted_name or aliased_import.
    let (line, column) = pos(node);
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        match child.kind() {
            "dotted_name" => {
                if let Some(full) = text(&child, src) {
                    out.push(Reference {
                        name: final_segment(full).to_string(),
                        qualified: Some(full.to_string()),
                        kind: RefKind::Import,
                        line,
                        column,
                        call_arity: None,
                    });
                }
            }
            "aliased_import" => {
                if let Some(path) = child.child_by_field_name("name") {
                    if let Some(full) = text(&path, src) {
                        out.push(Reference {
                            name: final_segment(full).to_string(),
                            qualified: Some(full.to_string()),
                            kind: RefKind::Import,
                            line,
                            column,
                            call_arity: None,
                        });
                    }
                }
            }
            _ => {}
        }
    }
}

fn collect_py_import_from(node: &Node<'_>, src: &[u8], out: &mut Vec<Reference>) {
    // `from m import a, b` — `module_name` field is the package; the
    // remaining `dotted_name` / `aliased_import` children are the names.
    let (line, column) = pos(node);
    let module = node
        .child_by_field_name("module_name")
        .and_then(|m| text(&m, src))
        .map(|s| s.to_string());

    let module_node_id = node.child_by_field_name("module_name").map(|m| m.id());
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if Some(child.id()) == module_node_id {
            continue; // skip the `from <module>` part itself
        }
        match child.kind() {
            "dotted_name" => {
                if let Some(name) = text(&child, src) {
                    let qualified = module
                        .as_ref()
                        .map(|m| format!("{m}.{name}"))
                        .or_else(|| Some(name.to_string()));
                    out.push(Reference {
                        name: final_segment(name).to_string(),
                        qualified,
                        kind: RefKind::Import,
                        line,
                        column,
                        call_arity: None,
                    });
                }
            }
            "aliased_import" => {
                if let Some(path) = child.child_by_field_name("name") {
                    if let Some(name) = text(&path, src) {
                        let qualified = module
                            .as_ref()
                            .map(|m| format!("{m}.{name}"))
                            .or_else(|| Some(name.to_string()));
                        out.push(Reference {
                            name: final_segment(name).to_string(),
                            qualified,
                            kind: RefKind::Import,
                            line,
                            column,
                            call_arity: None,
                        });
                    }
                }
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rust_call_and_import() {
        let snippet = b"fn f(){ commit_batch(x); }\nuse crate::store::CommitOptions;";
        let refs = extract_references(snippet, Language::Rust);

        let call = refs
            .iter()
            .find(|r| r.kind == RefKind::Call && r.name == "commit_batch")
            .expect("commit_batch call");
        assert_eq!(call.call_arity, Some(1));

        let import = refs
            .iter()
            .find(|r| r.kind == RefKind::Import && r.name == "CommitOptions")
            .expect("CommitOptions import");
        assert_eq!(
            import.qualified.as_deref(),
            Some("crate::store::CommitOptions")
        );
    }

    #[test]
    fn rust_ignores_comments_and_strings() {
        let snippet = b"fn f(){\n // commit_batch should be ignored\n let s = \"commit_batch\"; \n}";
        let refs = extract_references(snippet, Language::Rust);
        assert!(
            !refs.iter().any(|r| r.name == "commit_batch"),
            "comment/string mention must not be a reference: {refs:?}"
        );
    }

    #[test]
    fn python_call_and_import() {
        let snippet = b"commit_batch(x)\nfrom store import CommitOptions\n";
        let refs = extract_references(snippet, Language::Python);

        let call = refs
            .iter()
            .find(|r| r.kind == RefKind::Call && r.name == "commit_batch")
            .expect("commit_batch call");
        assert_eq!(call.call_arity, Some(1));

        let import = refs
            .iter()
            .find(|r| r.kind == RefKind::Import && r.name == "CommitOptions")
            .expect("CommitOptions import");
        assert_eq!(import.qualified.as_deref(), Some("store.CommitOptions"));
    }

    #[test]
    fn python_ignores_comments_and_strings() {
        let snippet = b"# commit_batch in a comment\ns = \"commit_batch\"\n";
        let refs = extract_references(snippet, Language::Python);
        assert!(!refs.iter().any(|r| r.name == "commit_batch"), "{refs:?}");
    }

    #[test]
    fn typescript_call_and_import() {
        let snippet =
            b"commitBatch(x);\nimport { CommitOptions } from \"./store\";\n";
        let refs = extract_references(snippet, Language::TypeScript);

        let call = refs
            .iter()
            .find(|r| r.kind == RefKind::Call && r.name == "commitBatch")
            .expect("commitBatch call");
        assert_eq!(call.call_arity, Some(1));

        let import = refs
            .iter()
            .find(|r| r.kind == RefKind::Import && r.name == "CommitOptions")
            .expect("CommitOptions import");
        assert_eq!(
            import.qualified.as_deref(),
            Some("./store::CommitOptions")
        );
    }

    #[test]
    fn typescript_ignores_comments_and_strings() {
        let snippet = b"// commitBatch in a comment\nconst s = \"commitBatch\";\n";
        let refs = extract_references(snippet, Language::TypeScript);
        assert!(!refs.iter().any(|r| r.name == "commitBatch"), "{refs:?}");
    }

    #[test]
    fn unsupported_language_returns_empty() {
        assert!(!supports_references(Language::Go));
        let refs = extract_references(b"func main() { foo() }", Language::Go);
        assert!(refs.is_empty());
    }

    #[test]
    fn supports_only_three_languages() {
        assert!(supports_references(Language::Rust));
        assert!(supports_references(Language::TypeScript));
        assert!(supports_references(Language::Python));
        for lang in [
            Language::JavaScript,
            Language::C,
            Language::Cpp,
            Language::Go,
            Language::Java,
            Language::Php,
            Language::Ruby,
            Language::Swift,
            Language::CSharp,
            Language::Markdown,
        ] {
            assert!(!supports_references(lang), "{lang:?} should be unsupported");
        }
    }
}
