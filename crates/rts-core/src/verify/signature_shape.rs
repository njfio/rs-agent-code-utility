//! Definition signature-shape extraction for the verification layer
//! (Phase F, F4).
//!
//! [`signature_shape`] reads a function/method definition node and reports
//! its arity, parameter names, and return type. It returns `None` whenever
//! the parameter set can't be decided confidently — variadics, `*args` /
//! `**kwargs`, `...rest` — so a caller never sees a confidently-wrong
//! arity (the caller treats `None` as
//! [`crate::verify::Resolution::Indeterminate`]).
//!
//! Coverage in Phase F is **Rust, TypeScript, and Python**. Other
//! languages return `None`. A leading `self` / receiver is excluded from
//! both `arity` and `params`.

use crate::languages::Language;
use serde::Serialize;
use tree_sitter::Node;

/// The decided shape of a definition's signature.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SignatureShape {
    /// Number of parameters, excluding any leading `self`/receiver.
    pub arity: u32,
    /// Parameter names in order (excluding `self`/receiver).
    pub params: Vec<String>,
    /// Rendered return type, if the definition declares one.
    pub returns: Option<String>,
}

/// Extract the signature shape from a definition node. Returns `None` when
/// `lang` is unsupported, `def_node` isn't a recognised function/method
/// definition, or the parameter set is undecidable (variadics / `*args` /
/// `**kwargs` / `...rest`).
pub fn signature_shape(def_node: Node<'_>, src: &[u8], lang: Language) -> Option<SignatureShape> {
    match lang {
        Language::Rust => rust_shape(def_node, src),
        Language::TypeScript => typescript_shape(def_node, src),
        Language::Python => python_shape(def_node, src),
        _ => None,
    }
}

fn node_text<'a>(node: &Node<'_>, src: &'a [u8]) -> Option<&'a str> {
    node.utf8_text(src).ok()
}

// ---------- Rust ----------

fn rust_shape(def: Node<'_>, src: &[u8]) -> Option<SignatureShape> {
    if def.kind() != "function_item" && def.kind() != "function_signature_item" {
        return None;
    }
    let params_node = def.child_by_field_name("parameters")?;
    let mut params = Vec::new();
    let mut cursor = params_node.walk();
    for child in params_node.named_children(&mut cursor) {
        match child.kind() {
            // `&self`, `self`, `&mut self` — the receiver; excluded.
            "self_parameter" => continue,
            "parameter" => {
                let pat = child.child_by_field_name("pattern")?;
                // A variadic in the pattern position is not expected in
                // Rust fns; the C-variadic `...` shows up as a distinct
                // child kind handled below.
                let name = node_text(&pat, src)?.trim().to_string();
                params.push(name);
            }
            // `extern "C" fn f(x: u32, ...)` — C variadics: undecidable.
            "variadic_parameter" => return None,
            _ => {}
        }
    }

    let returns = def
        .child_by_field_name("return_type")
        .and_then(|r| node_text(&r, src))
        .map(|s| s.trim().to_string());

    Some(SignatureShape {
        arity: params.len() as u32,
        params,
        returns,
    })
}

// ---------- TypeScript ----------

fn typescript_shape(def: Node<'_>, src: &[u8]) -> Option<SignatureShape> {
    if !matches!(
        def.kind(),
        "function_declaration"
            | "function_signature"
            | "method_definition"
            | "method_signature"
            | "generator_function_declaration"
    ) {
        return None;
    }
    let params_node = def.child_by_field_name("parameters")?;
    let mut params = Vec::new();
    let mut cursor = params_node.walk();
    for child in params_node.named_children(&mut cursor) {
        match child.kind() {
            // `(a: number)`, `(a?: number)` — required / optional params.
            "required_parameter" | "optional_parameter" => {
                let pat = child.child_by_field_name("pattern")?;
                if pat.kind() == "rest_pattern" {
                    // `...rest` — undecidable arity.
                    return None;
                }
                let name = node_text(&pat, src)?.trim().to_string();
                params.push(name);
            }
            // A bare rest element, defensive.
            "rest_pattern" => return None,
            _ => {}
        }
    }

    let returns = def
        .child_by_field_name("return_type")
        .and_then(|r| node_text(&r, src))
        // Drop the leading `: ` of a TS type annotation for a clean type.
        .map(|s| s.trim().trim_start_matches(':').trim().to_string());

    Some(SignatureShape {
        arity: params.len() as u32,
        params,
        returns,
    })
}

// ---------- Python ----------

fn python_shape(def: Node<'_>, src: &[u8]) -> Option<SignatureShape> {
    if def.kind() != "function_definition" {
        return None;
    }
    let params_node = def.child_by_field_name("parameters")?;
    let mut params = Vec::new();
    let mut cursor = params_node.walk();
    for child in params_node.named_children(&mut cursor) {
        match child.kind() {
            // `self` / `cls` receiver — excluded from arity.
            "identifier" => {
                let name = node_text(&child, src)?;
                if name == "self" || name == "cls" {
                    continue;
                }
                params.push(name.to_string());
            }
            // `a: int` typed param.
            "typed_parameter" => {
                // The bound name is the first child that's an identifier.
                let mut c2 = child.walk();
                let name = child
                    .children(&mut c2)
                    .find(|n| n.kind() == "identifier")
                    .and_then(|n| node_text(&n, src))?;
                if name == "self" || name == "cls" {
                    continue;
                }
                params.push(name.to_string());
            }
            // `a=2` and `a: int = 2` default params.
            "default_parameter" | "typed_default_parameter" => {
                let name_node = child.child_by_field_name("name")?;
                let name = node_text(&name_node, src)?;
                if name == "self" || name == "cls" {
                    continue;
                }
                params.push(name.to_string());
            }
            // `*args`, `**kwargs`, bare `*` / typed splats — undecidable.
            "list_splat_pattern"
            | "dictionary_splat_pattern"
            | "list_splat"
            | "dictionary_splat"
            | "typed_splat_parameter"
            | "variadic_parameter" => {
                return None;
            }
            _ => {}
        }
    }

    let returns = def
        .child_by_field_name("return_type")
        .and_then(|r| node_text(&r, src))
        .map(|s| s.trim().to_string());

    Some(SignatureShape {
        arity: params.len() as u32,
        params,
        returns,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Parse `code` and return the first node of `kind` (depth-first).
    fn first_node_of_kind<'t>(
        tree: &'t tree_sitter::Tree,
        kind: &str,
    ) -> Option<Node<'t>> {
        fn walk<'t>(node: Node<'t>, kind: &str) -> Option<Node<'t>> {
            if node.kind() == kind {
                return Some(node);
            }
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if let Some(found) = walk(child, kind) {
                    return Some(found);
                }
            }
            None
        }
        walk(tree.root_node(), kind)
    }

    fn parse(code: &str, lang: Language) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&lang.tree_sitter_language().unwrap())
            .unwrap();
        parser.parse(code, None).unwrap()
    }

    fn shape_of(code: &str, lang: Language, def_kind: &str) -> Option<SignatureShape> {
        let tree = parse(code, lang);
        let node = first_node_of_kind(&tree, def_kind).expect("def node");
        signature_shape(node, code.as_bytes(), lang)
    }

    #[test]
    fn rust_method_excludes_self() {
        let shape = shape_of(
            "fn commit_batch(&mut self, entries: Vec<Entry>) -> Result<()> { todo!() }",
            Language::Rust,
            "function_item",
        )
        .expect("shape");
        assert_eq!(shape.arity, 1);
        assert_eq!(shape.params, vec!["entries".to_string()]);
        assert_eq!(shape.returns.as_deref(), Some("Result<()>"));
    }

    #[test]
    fn rust_free_fn_no_return() {
        let shape = shape_of("fn f(a: u32, b: u32) {}", Language::Rust, "function_item")
            .expect("shape");
        assert_eq!(shape.arity, 2);
        assert_eq!(shape.params, vec!["a".to_string(), "b".to_string()]);
        assert_eq!(shape.returns, None);
    }

    #[test]
    fn python_default_param_counts() {
        let shape = shape_of("def f(a, b=2):\n    pass\n", Language::Python, "function_definition")
            .expect("shape");
        assert_eq!(shape.arity, 2);
        assert_eq!(shape.params, vec!["a".to_string(), "b".to_string()]);
    }

    #[test]
    fn python_varargs_is_none() {
        let shape = shape_of("def g(*rest):\n    pass\n", Language::Python, "function_definition");
        assert_eq!(shape, None);
    }

    #[test]
    fn python_kwargs_is_none() {
        let shape = shape_of(
            "def g(**opts):\n    pass\n",
            Language::Python,
            "function_definition",
        );
        assert_eq!(shape, None);
    }

    #[test]
    fn python_method_excludes_self() {
        let shape = shape_of(
            "def m(self, x):\n    pass\n",
            Language::Python,
            "function_definition",
        )
        .expect("shape");
        assert_eq!(shape.arity, 1);
        assert_eq!(shape.params, vec!["x".to_string()]);
    }

    #[test]
    fn typescript_optional_param_counts() {
        let shape = shape_of(
            "function f(a: number, b?: number): void {}",
            Language::TypeScript,
            "function_declaration",
        )
        .expect("shape");
        assert_eq!(shape.arity, 2);
        assert_eq!(shape.params, vec!["a".to_string(), "b".to_string()]);
        assert_eq!(shape.returns.as_deref(), Some("void"));
    }

    #[test]
    fn typescript_rest_param_is_none() {
        let shape = shape_of(
            "function f(...rest: number[]): void {}",
            Language::TypeScript,
            "function_declaration",
        );
        assert_eq!(shape, None);
    }

    #[test]
    fn unsupported_language_is_none() {
        // Parse a Go function and confirm Go returns None regardless of
        // the node passed in.
        let tree = parse("func F(a int) {}", Language::Go);
        let node = first_node_of_kind(&tree, "function_declaration").expect("fn");
        assert_eq!(signature_shape(node, b"func F(a int) {}", Language::Go), None);
    }

    #[test]
    fn malformed_input_never_panics() {
        // Truncated/garbage function definitions are arbitrary agent output —
        // shape extraction must return without panicking (None or partial).
        for lang in [Language::Rust, Language::TypeScript, Language::Python] {
            for code in ["fn f(", "def f(", "function (", "@#$%", ""] {
                let tree = parse(code, lang);
                // Pass the root node; the walkers must not panic on a partial tree.
                let _ = signature_shape(tree.root_node(), code.as_bytes(), lang);
            }
        }
    }
}
