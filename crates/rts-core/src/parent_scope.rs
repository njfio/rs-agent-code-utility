//! Assign each symbol its nearest enclosing container's name (single
//! level). Container kinds + how to read a container's name are
//! per-language; matching is by node-range containment over the tree.

use crate::languages::Language;
use crate::symbol::Symbol;
use crate::tree::{Node, SyntaxTree};

/// Fill `Symbol.parent`: the name of the innermost container node
/// strictly enclosing the symbol's start, excluding the symbol's own node.
pub(crate) fn assign_parents(
    tree: &SyntaxTree,
    content: &str,
    language: Language,
    symbols: &mut [Symbol],
) {
    let kinds = container_kinds(language);
    if kinds.is_empty() {
        return;
    }
    // (start, end, name) in byte offsets.
    let mut containers: Vec<(usize, usize, String)> = Vec::new();
    for kind in kinds {
        for node in tree.find_nodes_by_kind(kind) {
            if let Some(name) = container_name(&node, kind) {
                containers.push((node.start_byte(), node.end_byte(), name));
            }
        }
    }
    if containers.is_empty() {
        return;
    }
    // Precompute the byte offset of the start of each line so we can map a
    // symbol's (line, column) location to a byte offset comparable with the
    // container byte ranges.
    let line_starts = line_start_offsets(content);
    for sym in symbols.iter_mut() {
        let pos = sym_start(sym, &line_starts);
        let mut best: Option<(usize, String)> = None; // (span, name)
        for (s, e, name) in &containers {
            // Strictly enclosing the symbol's start. A container is the
            // symbol's own node when it starts at the same offset AND
            // carries the symbol's name; exclude that so a symbol is never
            // its own parent. Among the rest, the smallest span wins (the
            // innermost container).
            if *s <= pos && pos < *e {
                let is_self = *s == pos && name == &sym.name;
                if is_self {
                    continue;
                }
                let span = e - s;
                if best.as_ref().map_or(true, |(b, _)| span < *b) {
                    best = Some((span, name.clone()));
                }
            }
        }
        sym.parent = best.map(|(_, n)| n);
    }
}

/// Byte offset of the start of each line (0-indexed by line). `line_starts[i]`
/// is the byte offset of the first character of line `i + 1` (1-indexed lines).
fn line_start_offsets(content: &str) -> Vec<usize> {
    let mut starts = Vec::with_capacity(64);
    starts.push(0);
    for (i, b) in content.bytes().enumerate() {
        if b == b'\n' {
            starts.push(i + 1);
        }
    }
    starts
}

/// Byte offset of a symbol's start position. `Symbol` records its location as
/// a 1-indexed `start_line` and 0-indexed `start_column`; containment compares
/// against container byte ranges, so we reconstruct a byte offset.
fn sym_start(sym: &Symbol, line_starts: &[usize]) -> usize {
    let line_idx = sym.start_line.saturating_sub(1);
    let base = line_starts.get(line_idx).copied().unwrap_or(0);
    base + sym.start_column
}

fn container_kinds(language: Language) -> &'static [&'static str] {
    match language {
        Language::Rust => &["impl_item", "trait_item", "mod_item"],
        Language::Python => &["class_definition"],
        Language::JavaScript | Language::TypeScript => &["class_declaration"],
        Language::Java => &[
            "class_declaration",
            "interface_declaration",
            "enum_declaration",
            "record_declaration",
        ],
        Language::CSharp => &[
            "class_declaration",
            "interface_declaration",
            "struct_declaration",
            "record_declaration",
        ],
        Language::C => &["struct_specifier"],
        Language::Cpp => &["class_specifier", "struct_specifier", "namespace_definition"],
        Language::Php => &["class_declaration", "interface_declaration", "trait_declaration"],
        Language::Ruby => &["class", "module"],
        Language::Swift => &["class_declaration", "protocol_declaration"],
        _ => &[], // other languages added by later tasks
    }
}

/// Read a container node's name. Rust `impl_item` exposes the implemented
/// TYPE via the `type` field (ignore the `trait` field of `impl Trait for Type`).
fn container_name(node: &Node, kind: &str) -> Option<String> {
    match kind {
        "impl_item" => node
            .child_by_field_name("type")
            .and_then(|n| n.text().ok())
            .map(type_head),
        _ => node
            .child_by_field_name("name")
            .and_then(|n| n.text().ok())
            .map(|s| s.to_string()),
    }
}

/// `Vec<T>` -> `Vec`, `module::Foo` -> `Foo`, `&Foo` -> `Foo`.
fn type_head(t: &str) -> String {
    let t = t.trim_start_matches(['&', '*', ' ']);
    let head = t.split(['<', ' ']).next().unwrap_or(t);
    head.rsplit("::").next().unwrap_or(head).to_string()
}

#[cfg(test)]
mod tests {
    use crate::Language;
    use crate::parse_content;

    fn parent_of(src: &str, lang: Language, sym: &str) -> Option<String> {
        let outcome = parse_content(src, lang).unwrap();
        outcome
            .symbols
            .into_iter()
            .find(|s| s.name == sym)
            .unwrap()
            .parent
    }

    #[test]
    fn rust_method_parent_is_impl_type() {
        let src = "struct QueryBuilder; impl QueryBuilder { fn new() -> Self { Self } }\nfn free() {}";
        assert_eq!(
            parent_of(src, Language::Rust, "new").as_deref(),
            Some("QueryBuilder")
        );
        assert_eq!(parent_of(src, Language::Rust, "free"), None);
    }

    #[test]
    fn rust_trait_impl_parent_is_type_not_trait() {
        let src = "struct Foo; trait T { fn go(&self); } impl T for Foo { fn go(&self) {} }";
        assert_eq!(parent_of(src, Language::Rust, "go").as_deref(), Some("Foo"));
    }

    #[test]
    fn python_method_parent_is_class() {
        let src = "class Parser:\n    def parse(self):\n        pass\n\ndef free():\n    pass\n";
        assert_eq!(parent_of(src, Language::Python, "parse").as_deref(), Some("Parser"));
        assert_eq!(parent_of(src, Language::Python, "free"), None);
    }

    #[test]
    fn js_method_parent_is_class() {
        let src = "class Parser { parse() {} }\nfunction free() {}";
        assert_eq!(parent_of(src, Language::JavaScript, "parse").as_deref(), Some("Parser"));
        assert_eq!(parent_of(src, Language::JavaScript, "free"), None);
    }

    #[test]
    fn ts_method_parent_is_class() {
        let src = "class Parser { parse(): void {} }";
        assert_eq!(parent_of(src, Language::TypeScript, "parse").as_deref(), Some("Parser"));
    }

    #[test]
    fn java_method_parent_is_class() {
        let src = "class Parser { void parse() {} }";
        assert_eq!(parent_of(src, Language::Java, "parse").as_deref(), Some("Parser"));
    }

    #[test]
    fn csharp_method_parent_is_class() {
        let src = "class Parser { void Parse() {} }";
        assert_eq!(parent_of(src, Language::CSharp, "Parse").as_deref(), Some("Parser"));
    }

    #[test]
    fn cpp_method_parent_is_class() {
        // Use a defined (bodied) method: the C++ extractor only emits a symbol
        // for a method definition, not a bare declaration (`void parse();`).
        let src = "class Parser { void parse() {} };";
        assert_eq!(parent_of(src, Language::Cpp, "parse").as_deref(), Some("Parser"));
    }

    #[test]
    fn php_method_parent_is_class() {
        let src = "<?php class Parser { function parse() {} }";
        assert_eq!(parent_of(src, Language::Php, "parse").as_deref(), Some("Parser"));
    }

    #[test]
    fn ruby_method_parent_is_class() {
        let src = "class Parser\n  def parse\n  end\nend\n";
        assert_eq!(parent_of(src, Language::Ruby, "parse").as_deref(), Some("Parser"));
    }

    #[test]
    fn swift_method_parent_is_class() {
        let src = "class Parser { func parse() {} }";
        assert_eq!(parent_of(src, Language::Swift, "parse").as_deref(), Some("Parser"));
    }
}
