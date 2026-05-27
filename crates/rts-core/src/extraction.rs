//! Symbol extraction from tree-sitter parse trees.
//!
//! `extract_symbols(tree, content, language)` is the single entry
//! point. It dispatches to per-language extractors that walk the
//! syntax tree and emit `Symbol` records (functions, classes,
//! structs, etc.) used by the daemon's `Index.FindSymbol` /
//! `Index.Outline` / `Index.ReadSymbol` surfaces.
//!
//! Hoisted from `impl CodebaseAnalyzer` in PR-B (B0) so the
//! `parse_content` facade and any future direct consumer can call
//! into it without instantiating a stateful analyzer.

use crate::error::Result;
use crate::languages::Language;
use crate::symbol::Symbol;
use crate::tree::SyntaxTree;

pub(crate) fn extract_symbols(
    tree: &SyntaxTree,
    content: &str,
    language: Language,
) -> Result<Vec<Symbol>> {
    let mut symbols = Vec::new();

    match language {
        Language::Rust => {
            extract_rust_symbols(tree, content, &mut symbols)?;
        }
        Language::JavaScript | Language::TypeScript => {
            extract_javascript_symbols(tree, content, &mut symbols)?;
        }
        Language::Python => {
            extract_python_symbols(tree, content, &mut symbols)?;
        }
        Language::C | Language::Cpp => {
            extract_c_symbols(tree, content, &mut symbols)?;
        }
        Language::Go => {
            extract_go_symbols(tree, content, &mut symbols)?;
        }
        Language::Java => {
            extract_java_symbols(tree, content, &mut symbols)?;
        }
        Language::Php => {
            extract_php_symbols(tree, content, &mut symbols)?;
        }
        Language::Ruby => {
            extract_ruby_symbols(tree, content, &mut symbols)?;
        }
        Language::Swift => {
            extract_swift_symbols(tree, content, &mut symbols)?;
        }
        Language::CSharp => {
            extract_csharp_symbols(tree, content, &mut symbols)?;
        }
        Language::Markdown => {
            extract_markdown_symbols(tree, content, &mut symbols)?;
        }
    }

    Ok(symbols)
}

/// Extract Rust symbols
pub(crate) fn extract_rust_symbols(
    tree: &SyntaxTree,
    content: &str,
    symbols: &mut Vec<Symbol>,
) -> Result<()> {
    // Extract functions
    let functions = tree.find_nodes_by_kind("function_item");
    for func in functions {
        if let Some(name_node) = func.child_by_field_name("name") {
            if let Ok(name) = name_node.text() {
                let visibility = if func
                    .children()
                    .iter()
                    .any(|child| child.kind() == "visibility_modifier")
                {
                    "public"
                } else {
                    "private"
                };

                let docs = extract_rust_doc_comments(content, func.start_position().row);

                symbols.push(Symbol {
                    name: name.to_string(),
                    kind: "function".to_string(),
                    start_line: func.start_position().row + 1,
                    end_line: func.end_position().row + 1,
                    start_column: func.start_position().column,
                    end_column: func.end_position().column,
                    visibility: visibility.to_string(),
                    documentation: docs,
                });
            }
        }
    }

    // Extract structs
    let structs = tree.find_nodes_by_kind("struct_item");
    for struct_node in structs {
        if let Some(name_node) = struct_node.child_by_field_name("name") {
            if let Ok(name) = name_node.text() {
                let visibility = if struct_node
                    .children()
                    .iter()
                    .any(|child| child.kind() == "visibility_modifier")
                {
                    "public"
                } else {
                    "private"
                };

                symbols.push(Symbol {
                    name: name.to_string(),
                    kind: "struct".to_string(),
                    start_line: struct_node.start_position().row + 1,
                    end_line: struct_node.end_position().row + 1,
                    start_column: struct_node.start_position().column,
                    end_column: struct_node.end_position().column,
                    visibility: visibility.to_string(),
                    documentation: None,
                });
            }
        }
    }

    // Extract enums
    let enums = tree.find_nodes_by_kind("enum_item");
    for enum_node in enums {
        if let Some(name_node) = enum_node.child_by_field_name("name") {
            if let Ok(name) = name_node.text() {
                let visibility = if enum_node
                    .children()
                    .iter()
                    .any(|child| child.kind() == "visibility_modifier")
                {
                    "public"
                } else {
                    "private"
                };

                symbols.push(Symbol {
                    name: name.to_string(),
                    kind: "enum".to_string(),
                    start_line: enum_node.start_position().row + 1,
                    end_line: enum_node.end_position().row + 1,
                    start_column: enum_node.start_position().column,
                    end_column: enum_node.end_position().column,
                    visibility: visibility.to_string(),
                    documentation: None,
                });
            }
        }
    }

    // Extract impl blocks
    let impl_blocks = tree.find_nodes_by_kind("impl_item");
    for impl_node in impl_blocks {
        // Extract the type being implemented
        if let Some(type_node) = impl_node.child_by_field_name("type") {
            if let Ok(type_text) = type_node.text() {
                // Extract just the base type name (e.g., "Array" from "Array<T, N>")
                let base_type = if let Some(angle_pos) = type_text.find('<') {
                    type_text[..angle_pos].trim()
                } else {
                    type_text.trim()
                };

                symbols.push(Symbol {
                    name: base_type.to_string(),
                    kind: "impl".to_string(),
                    start_line: impl_node.start_position().row + 1,
                    end_line: impl_node.end_position().row + 1,
                    start_column: impl_node.start_position().column,
                    end_column: impl_node.end_position().column,
                    visibility: "public".to_string(),
                    documentation: None,
                });
            }
        }
    }

    // Extract let declarations as variable symbols (best-effort).
    //
    // **Subtle bug to avoid**: a naïve "first identifier descendant"
    // search picks up the FUNCTION NAME of any call expression in
    // the let's value, e.g. `let _ = hub_compute(1);` would otherwise
    // register `hub_compute` as a variable. Restrict the search to
    // the `pattern` field — that's where the binding name lives.
    let lets = tree.find_nodes_by_kind("let_declaration");
    for let_node in lets {
        let pattern = match let_node.child_by_field_name("pattern") {
            Some(p) => p,
            None => continue,
        };
        // Skip wildcard / placeholder patterns (`let _ = …`).
        if pattern.kind() == "_" || pattern.text().map(|t| t.trim() == "_").unwrap_or(false) {
            continue;
        }
        let ids = pattern.find_descendants(|n| n.kind() == "identifier");
        let name = match ids.first().and_then(|n| n.text().ok()) {
            Some(s) => s.to_string(),
            // No identifier in pattern (probably a tuple destructure
            // without simple names); skip rather than synthesise a
            // placeholder name that pollutes the index.
            None => continue,
        };

        symbols.push(Symbol {
            name,
            kind: "variable".to_string(),
            start_line: let_node.start_position().row + 1,
            end_line: let_node.end_position().row + 1,
            start_column: let_node.start_position().column,
            end_column: let_node.end_position().column,
            visibility: "private".to_string(),
            documentation: None,
        });
    }

    // Extract `const` and `static` declarations.
    //
    // Surfaces module-level constants (e.g. `pub const DEFAULT_LIMIT:
    // usize = 256;`) and statics (e.g. `static FOO: AtomicU32 = …`)
    // via `find_symbol`. Without this, agents searching by constant
    // name fall back to grep — a real dogfooding gap surfaced in
    // PR #76's report.
    //
    // tree-sitter rust grammar: `const_item` and `static_item`. Both
    // expose a `name` child field. Doc comments use the same
    // `///`-line scan as fns / structs / enums.
    for kind_name in ["const_item", "static_item"] {
        let items = tree.find_nodes_by_kind(kind_name);
        for item in items {
            if let Some(name_node) = item.child_by_field_name("name") {
                if let Ok(name) = name_node.text() {
                    let visibility = if item
                        .children()
                        .iter()
                        .any(|child| child.kind() == "visibility_modifier")
                    {
                        "public"
                    } else {
                        "private"
                    };
                    let docs = extract_rust_doc_comments(content, item.start_position().row);
                    let kind_label = if kind_name == "const_item" {
                        "const"
                    } else {
                        "static"
                    };
                    symbols.push(Symbol {
                        name: name.to_string(),
                        kind: kind_label.to_string(),
                        start_line: item.start_position().row + 1,
                        end_line: item.end_position().row + 1,
                        start_column: item.start_position().column,
                        end_column: item.end_position().column,
                        visibility: visibility.to_string(),
                        documentation: docs,
                    });
                }
            }
        }
    }

    // Extract traits, type aliases, unions, and declarative macros.
    // Surfaced as a real gap during external-corpus authoring (v0.5.4):
    // `find_symbol --name Log` on `rust-lang/log` returned empty
    // because `pub trait Log` was never extracted. Traits are
    // first-class Rust API surface — for any library that
    // exposes a trait, find_symbol failed without this.
    //
    // tree-sitter rust grammar node kinds:
    //   - `trait_item`           → kind="trait"
    //   - `type_item`            → kind="type"   (e.g. `type Result<T> = ...`)
    //   - `union_item`           → kind="union"
    //   - `macro_definition`     → kind="macro"  (declarative macros)
    //
    // All four expose a `name` child field with the same shape
    // as const/static. Visibility / doc-comment extraction
    // mirrors the existing paths.
    for (kind_name, kind_label) in [
        ("trait_item", "trait"),
        ("type_item", "type"),
        ("union_item", "union"),
        ("macro_definition", "macro"),
    ] {
        let items = tree.find_nodes_by_kind(kind_name);
        for item in items {
            if let Some(name_node) = item.child_by_field_name("name") {
                if let Ok(name) = name_node.text() {
                    let visibility = if item
                        .children()
                        .iter()
                        .any(|child| child.kind() == "visibility_modifier")
                    {
                        "public"
                    } else {
                        "private"
                    };
                    let docs = extract_rust_doc_comments(content, item.start_position().row);
                    symbols.push(Symbol {
                        name: name.to_string(),
                        kind: kind_label.to_string(),
                        start_line: item.start_position().row + 1,
                        end_line: item.end_position().row + 1,
                        start_column: item.start_position().column,
                        end_column: item.end_position().column,
                        visibility: visibility.to_string(),
                        documentation: docs,
                    });
                }
            }
        }
    }

    Ok(())
}

/// Extract JavaScript symbols
pub(crate) fn extract_javascript_symbols(
    tree: &SyntaxTree,
    content: &str,
    symbols: &mut Vec<Symbol>,
) -> Result<()> {
    // Extract function declarations
    let functions = tree.find_nodes_by_kind("function_declaration");
    for func in functions {
        if let Some(name_node) = func.child_by_field_name("name") {
            if let Ok(name) = name_node.text() {
                let docs = extract_c_doc_comments(content, func.start_position().row);
                symbols.push(Symbol {
                    name: name.to_string(),
                    kind: "function".to_string(),
                    start_line: func.start_position().row + 1,
                    end_line: func.end_position().row + 1,
                    start_column: func.start_position().column,
                    end_column: func.end_position().column,
                    visibility: "public".to_string(),
                    documentation: docs,
                });
            }
        }
    }

    // Extract arrow functions assigned to variables
    let variable_declarations = tree.find_nodes_by_kind("variable_declaration");
    for var_decl in variable_declarations {
        for child in var_decl.children() {
            if child.kind() == "variable_declarator" {
                if let Some(name_node) = child.child_by_field_name("name") {
                    if let Some(value_node) = child.child_by_field_name("value") {
                        if value_node.kind() == "arrow_function" {
                            if let Ok(name) = name_node.text() {
                                let docs =
                                    extract_c_doc_comments(content, var_decl.start_position().row);
                                symbols.push(Symbol {
                                    name: name.to_string(),
                                    kind: "function".to_string(),
                                    start_line: var_decl.start_position().row + 1,
                                    end_line: var_decl.end_position().row + 1,
                                    start_column: var_decl.start_position().column,
                                    end_column: var_decl.end_position().column,
                                    visibility: "public".to_string(),
                                    documentation: docs,
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    // Extract class declarations
    let classes = tree.find_nodes_by_kind("class_declaration");
    for class in classes {
        if let Some(name_node) = class.child_by_field_name("name") {
            if let Ok(name) = name_node.text() {
                let docs = extract_c_doc_comments(content, class.start_position().row);
                symbols.push(Symbol {
                    name: name.to_string(),
                    kind: "class".to_string(),
                    start_line: class.start_position().row + 1,
                    end_line: class.end_position().row + 1,
                    start_column: class.start_position().column,
                    end_column: class.end_position().column,
                    visibility: "public".to_string(),
                    documentation: docs,
                });
            }
        }
    }

    // Extract method definitions within classes
    let method_definitions = tree.find_nodes_by_kind("method_definition");
    for method in method_definitions {
        if let Some(name_node) = method.child_by_field_name("name") {
            if let Ok(name) = name_node.text() {
                let docs = extract_c_doc_comments(content, method.start_position().row);
                symbols.push(Symbol {
                    name: name.to_string(),
                    kind: "method".to_string(),
                    start_line: method.start_position().row + 1,
                    end_line: method.end_position().row + 1,
                    start_column: method.start_position().column,
                    end_column: method.end_position().column,
                    visibility: "public".to_string(),
                    documentation: docs,
                });
            }
        }
    }

    Ok(())
}

/// Extract Python symbols
pub(crate) fn extract_python_symbols(
    tree: &SyntaxTree,
    content: &str,
    symbols: &mut Vec<Symbol>,
) -> Result<()> {
    // Extract function definitions
    let functions = tree.find_nodes_by_kind("function_definition");
    for func in functions {
        if let Some(name_node) = func.child_by_field_name("name") {
            if let Ok(name) = name_node.text() {
                let visibility = if name.starts_with('_') {
                    "private"
                } else {
                    "public"
                };
                let docs = extract_python_docstring(content, &func);

                symbols.push(Symbol {
                    name: name.to_string(),
                    kind: "function".to_string(),
                    start_line: func.start_position().row + 1,
                    end_line: func.end_position().row + 1,
                    start_column: func.start_position().column,
                    end_column: func.end_position().column,
                    visibility: visibility.to_string(),
                    documentation: docs,
                });
            }
        }
    }

    // Extract class definitions
    let classes = tree.find_nodes_by_kind("class_definition");
    for class in classes {
        if let Some(name_node) = class.child_by_field_name("name") {
            if let Ok(name) = name_node.text() {
                let visibility = if name.starts_with('_') {
                    "private"
                } else {
                    "public"
                };
                let docs = extract_python_docstring(content, &class);

                symbols.push(Symbol {
                    name: name.to_string(),
                    kind: "class".to_string(),
                    start_line: class.start_position().row + 1,
                    end_line: class.end_position().row + 1,
                    start_column: class.start_position().column,
                    end_column: class.end_position().column,
                    visibility: visibility.to_string(),
                    documentation: docs,
                });
            }
        }
    }

    // Extract global variable assignments
    let assignments = tree.find_nodes_by_kind("assignment");
    for assignment in assignments {
        if let Some(left) = assignment.child_by_field_name("left") {
            if left.kind() == "identifier" {
                if let Ok(name) = left.text() {
                    // Only include if it looks like a constant (ALL_CAPS)
                    if name
                        .chars()
                        .all(|c| c.is_uppercase() || c == '_' || c.is_numeric())
                    {
                        let visibility = if name.starts_with('_') {
                            "private"
                        } else {
                            "public"
                        };
                        symbols.push(Symbol {
                            name: name.to_string(),
                            kind: "constant".to_string(),
                            start_line: assignment.start_position().row + 1,
                            end_line: assignment.end_position().row + 1,
                            start_column: assignment.start_position().column,
                            end_column: assignment.end_position().column,
                            visibility: visibility.to_string(),
                            documentation: None,
                        });
                    }
                }
            }
        }
    }

    Ok(())
}

/// Extract C/C++ symbols
pub(crate) fn extract_c_symbols(
    tree: &SyntaxTree,
    content: &str,
    symbols: &mut Vec<Symbol>,
) -> Result<()> {
    // Extract function definitions
    let functions = tree.find_nodes_by_kind("function_definition");
    for func in functions {
        // The grammar tree for a C function looks like:
        //   function_definition
        //     type:      primitive_type / type_identifier
        //     declarator: function_declarator       ← usually here
        //                   declarator: identifier  ← the name
        //                   parameters: ...
        //     body:      compound_statement
        //
        // …but pointer-returning functions wrap the function_declarator
        // in a pointer_declarator, so we search for the
        // `function_declarator` whether it's the direct child or one
        // level deeper.
        let Some(declarator) = func.child_by_field_name("declarator") else {
            continue;
        };
        let func_declarator = if declarator.kind() == "function_declarator" {
            declarator
        } else {
            match declarator
                .children()
                .into_iter()
                .find(|child| child.kind() == "function_declarator")
            {
                Some(d) => d,
                None => continue,
            }
        };
        let Some(name_node) = func_declarator.child_by_field_name("declarator") else {
            continue;
        };
        if let Ok(name) = name_node.text() {
            let docs = extract_c_doc_comments(content, func.start_position().row);
            symbols.push(Symbol {
                name: name.to_string(),
                kind: "function".to_string(),
                start_line: func.start_position().row + 1,
                end_line: func.end_position().row + 1,
                start_column: func.start_position().column,
                end_column: func.end_position().column,
                visibility: "public".to_string(),
                documentation: docs,
            });
        }
    }

    // Extract struct declarations
    let structs = tree.find_nodes_by_kind("struct_specifier");
    for struct_node in structs {
        if let Some(name_node) = struct_node.child_by_field_name("name") {
            if let Ok(name) = name_node.text() {
                let docs = extract_c_doc_comments(content, struct_node.start_position().row);
                symbols.push(Symbol {
                    name: name.to_string(),
                    kind: "struct".to_string(),
                    start_line: struct_node.start_position().row + 1,
                    end_line: struct_node.end_position().row + 1,
                    start_column: struct_node.start_position().column,
                    end_column: struct_node.end_position().column,
                    visibility: "public".to_string(),
                    documentation: docs,
                });
            }
        }
    }

    // Extract enum declarations
    let enums = tree.find_nodes_by_kind("enum_specifier");
    for enum_node in enums {
        if let Some(name_node) = enum_node.child_by_field_name("name") {
            if let Ok(name) = name_node.text() {
                let docs = extract_c_doc_comments(content, enum_node.start_position().row);
                symbols.push(Symbol {
                    name: name.to_string(),
                    kind: "enum".to_string(),
                    start_line: enum_node.start_position().row + 1,
                    end_line: enum_node.end_position().row + 1,
                    start_column: enum_node.start_position().column,
                    end_column: enum_node.end_position().column,
                    visibility: "public".to_string(),
                    documentation: docs,
                });
            }
        }
    }

    // Extract typedef declarations
    let typedefs = tree.find_nodes_by_kind("type_definition");
    for typedef_node in typedefs {
        if let Some(declarator) = typedef_node.child_by_field_name("declarator") {
            if let Ok(name) = declarator.text() {
                let docs = extract_c_doc_comments(content, typedef_node.start_position().row);
                symbols.push(Symbol {
                    name: name.to_string(),
                    kind: "typedef".to_string(),
                    start_line: typedef_node.start_position().row + 1,
                    end_line: typedef_node.end_position().row + 1,
                    start_column: typedef_node.start_position().column,
                    end_column: typedef_node.end_position().column,
                    visibility: "public".to_string(),
                    documentation: docs,
                });
            }
        }
    }

    Ok(())
}

/// Extract Go symbols
pub(crate) fn extract_go_symbols(
    tree: &SyntaxTree,
    content: &str,
    symbols: &mut Vec<Symbol>,
) -> Result<()> {
    // Extract function declarations
    let functions = tree.find_nodes_by_kind("function_declaration");
    for func in functions {
        if let Some(name_node) = func.child_by_field_name("name") {
            if let Ok(name) = name_node.text() {
                let visibility = if name.chars().next().unwrap_or('a').is_uppercase() {
                    "public"
                } else {
                    "private"
                };
                let docs = extract_go_doc_comments(content, func.start_position().row);
                symbols.push(Symbol {
                    name: name.to_string(),
                    kind: "function".to_string(),
                    start_line: func.start_position().row + 1,
                    start_column: func.start_position().column,
                    end_line: func.end_position().row + 1,
                    end_column: func.end_position().column,
                    visibility: visibility.to_string(),
                    documentation: docs,
                });
            }
        }
    }

    // Extract method declarations
    let methods = tree.find_nodes_by_kind("method_declaration");
    for method in methods {
        if let Some(name_node) = method.child_by_field_name("name") {
            if let Ok(name) = name_node.text() {
                let visibility = if name.chars().next().unwrap_or('a').is_uppercase() {
                    "public"
                } else {
                    "private"
                };
                let docs = extract_go_doc_comments(content, method.start_position().row);
                symbols.push(Symbol {
                    name: name.to_string(),
                    kind: "method".to_string(),
                    start_line: method.start_position().row + 1,
                    start_column: method.start_position().column,
                    end_line: method.end_position().row + 1,
                    end_column: method.end_position().column,
                    visibility: visibility.to_string(),
                    documentation: docs,
                });
            }
        }
    }

    // Extract type declarations (structs, interfaces)
    let types = tree.find_nodes_by_kind("type_declaration");
    for type_decl in types {
        // Look for type_spec children
        for child in type_decl.children() {
            if child.kind() == "type_spec" {
                if let Some(name_node) = child.child_by_field_name("name") {
                    if let Ok(name) = name_node.text() {
                        let kind = if let Some(type_node) = child.child_by_field_name("type") {
                            match type_node.kind() {
                                "struct_type" => "struct",
                                "interface_type" => "interface",
                                _ => "type",
                            }
                        } else {
                            "type"
                        };
                        let visibility = if name.chars().next().unwrap_or('a').is_uppercase() {
                            "public"
                        } else {
                            "private"
                        };
                        let docs = extract_go_doc_comments(content, type_decl.start_position().row);
                        symbols.push(Symbol {
                            name: name.to_string(),
                            kind: kind.to_string(),
                            start_line: type_decl.start_position().row + 1,
                            start_column: type_decl.start_position().column,
                            end_line: type_decl.end_position().row + 1,
                            end_column: type_decl.end_position().column,
                            visibility: visibility.to_string(),
                            documentation: docs,
                        });
                    }
                }
            }
        }
    }

    Ok(())
}

/// Extract Java symbols
pub(crate) fn extract_java_symbols(
    tree: &SyntaxTree,
    content: &str,
    symbols: &mut Vec<Symbol>,
) -> Result<()> {
    // Javadoc is `/** ... */` — reuse extract_c_doc_comments.
    let classes = tree.find_nodes_by_kind("class_declaration");
    for class in classes {
        if let Some(name_node) = class.child_by_field_name("name") {
            if let Ok(name) = name_node.text() {
                let docs = extract_c_doc_comments(content, class.start_position().row);
                symbols.push(Symbol {
                    name: name.to_string(),
                    kind: "class".to_string(),
                    start_line: class.start_position().row + 1,
                    start_column: class.start_position().column,
                    end_line: class.end_position().row + 1,
                    end_column: class.end_position().column,
                    visibility: "public".to_string(),
                    documentation: docs,
                });
            }
        }
    }

    let methods = tree.find_nodes_by_kind("method_declaration");
    for method in methods {
        if let Some(name_node) = method.child_by_field_name("name") {
            if let Ok(name) = name_node.text() {
                let docs = extract_c_doc_comments(content, method.start_position().row);
                symbols.push(Symbol {
                    name: name.to_string(),
                    kind: "method".to_string(),
                    start_line: method.start_position().row + 1,
                    start_column: method.start_position().column,
                    end_line: method.end_position().row + 1,
                    end_column: method.end_position().column,
                    visibility: "public".to_string(),
                    documentation: docs,
                });
            }
        }
    }

    Ok(())
}

/// Extract Ruby symbols
pub(crate) fn extract_ruby_symbols(
    tree: &SyntaxTree,
    content: &str,
    symbols: &mut Vec<Symbol>,
) -> Result<()> {
    let classes = tree.find_nodes_by_kind("class");
    for class in classes {
        if let Some(name_node) = class.child_by_field_name("name") {
            if let Ok(name) = name_node.text() {
                let docs = extract_ruby_doc_comments(content, class.start_position().row);
                symbols.push(Symbol {
                    name: name.to_string(),
                    kind: "class".to_string(),
                    start_line: class.start_position().row + 1,
                    start_column: class.start_position().column,
                    end_line: class.end_position().row + 1,
                    end_column: class.end_position().column,
                    visibility: "public".to_string(),
                    documentation: docs,
                });
            }
        }
    }

    let methods = tree.find_nodes_by_kind("method");
    for method in methods {
        if let Some(name_node) = method.child_by_field_name("name") {
            if let Ok(name) = name_node.text() {
                let docs = extract_ruby_doc_comments(content, method.start_position().row);
                symbols.push(Symbol {
                    name: name.to_string(),
                    kind: "method".to_string(),
                    start_line: method.start_position().row + 1,
                    start_column: method.start_position().column,
                    end_line: method.end_position().row + 1,
                    end_column: method.end_position().column,
                    visibility: "public".to_string(),
                    documentation: docs,
                });
            }
        }
    }

    Ok(())
}

/// Extract Swift symbols
pub(crate) fn extract_swift_symbols(
    tree: &SyntaxTree,
    content: &str,
    symbols: &mut Vec<Symbol>,
) -> Result<()> {
    // TODO: Implement full Swift symbol extraction
    // For now, extract basic class, struct and function symbols
    let classes = tree.find_nodes_by_kind("class_declaration");
    for class in classes {
        if let Some(name_node) = class.child_by_field_name("name") {
            if let Ok(name) = name_node.text() {
                let docs = extract_swift_doc_comments(content, class.start_position().row);
                symbols.push(Symbol {
                    name: name.to_string(),
                    kind: "class".to_string(),
                    start_line: class.start_position().row + 1,
                    start_column: class.start_position().column,
                    end_line: class.end_position().row + 1,
                    end_column: class.end_position().column,
                    visibility: "internal".to_string(), // Default for Swift
                    documentation: docs,
                });
            }
        }
    }

    let structs = tree.find_nodes_by_kind("struct_declaration");
    for struct_node in structs {
        if let Some(name_node) = struct_node.child_by_field_name("name") {
            if let Ok(name) = name_node.text() {
                let docs = extract_swift_doc_comments(content, struct_node.start_position().row);
                symbols.push(Symbol {
                    name: name.to_string(),
                    kind: "struct".to_string(),
                    start_line: struct_node.start_position().row + 1,
                    start_column: struct_node.start_position().column,
                    end_line: struct_node.end_position().row + 1,
                    end_column: struct_node.end_position().column,
                    visibility: "internal".to_string(), // Default for Swift
                    documentation: docs,
                });
            }
        }
    }

    let functions = tree.find_nodes_by_kind("function_declaration");
    for func in functions {
        if let Some(name_node) = func.child_by_field_name("name") {
            if let Ok(name) = name_node.text() {
                let docs = extract_swift_doc_comments(content, func.start_position().row);
                symbols.push(Symbol {
                    name: name.to_string(),
                    kind: "function".to_string(),
                    start_line: func.start_position().row + 1,
                    start_column: func.start_position().column,
                    end_line: func.end_position().row + 1,
                    end_column: func.end_position().column,
                    visibility: "internal".to_string(), // Default for Swift
                    documentation: docs,
                });
            }
        }
    }

    Ok(())
}

/// Extract Ruby-style doc comments preceding an item start line.
///
/// Ruby convention: contiguous `#` line comments immediately
/// above the declaration, similar to Go's `//` shape but with
/// the `#` lead character. Honors shebang lines (`#!`) by
/// stopping early — those are not documentation.
pub(crate) fn extract_ruby_doc_comments(content: &str, start_row: usize) -> Option<String> {
    let lines: Vec<&str> = content.lines().collect();
    if start_row == 0 {
        return None;
    }
    let mut docs = Vec::new();
    let mut line_idx = start_row as isize - 1;
    while line_idx >= 0 {
        let line = lines[line_idx as usize].trim();
        if let Some(rest) = line.strip_prefix('#') {
            if rest.starts_with('!') {
                break;
            }
            docs.push(rest.trim());
            line_idx -= 1;
        } else {
            break;
        }
    }
    if docs.is_empty() {
        None
    } else {
        docs.reverse();
        Some(docs.join("\n"))
    }
}

/// Extract Go-style doc comments preceding an item start line.
///
/// Go convention: documentation is a contiguous block of `//`
/// line comments immediately above the declaration, with no
/// blank-line gap. The first sentence typically starts with the
/// symbol name (`// Foo does …`). We collect all contiguous
/// `//` lines walking backward and stop at the first non-comment,
/// non-blank line — but unlike Rust we DO stop at blank lines,
/// because the Go style explicitly uses a blank line to detach
/// preceding comments.
pub(crate) fn extract_go_doc_comments(content: &str, start_row: usize) -> Option<String> {
    let lines: Vec<&str> = content.lines().collect();
    if start_row == 0 {
        return None;
    }
    let mut docs = Vec::new();
    let mut line_idx = start_row as isize - 1;
    while line_idx >= 0 {
        let line = lines[line_idx as usize].trim();
        if let Some(rest) = line.strip_prefix("//") {
            docs.push(rest.trim());
            line_idx -= 1;
        } else {
            break;
        }
    }
    if docs.is_empty() {
        None
    } else {
        docs.reverse();
        Some(docs.join("\n"))
    }
}

/// Extract Swift-style doc comments preceding an item start line.
///
/// Swift convention: contiguous `///` lines (single-line doc
/// comments) above the declaration. Block `/** */` is also valid
/// Swift doc syntax but isn't handled here for v0; the `///`
/// form dominates in practice. Same line-scan shape as Rust:
/// allows blank-line gaps but stops at any non-doc, non-blank
/// content.
pub(crate) fn extract_swift_doc_comments(content: &str, start_row: usize) -> Option<String> {
    // Same logic as Rust; Swift `///` is identical syntax.
    extract_rust_doc_comments(content, start_row)
}

/// Extract C# XML doc comments preceding an item start line.
///
/// C# convention: contiguous `///`-prefixed lines carrying XML
/// elements (`<summary>`, `<param>`, `<returns>`, etc.). Same
/// line-scan shape as Rust/Swift `///`. We retain the raw XML
/// payload — agents searching `doc_contains` get matches against
/// `<summary>...evicts the cache...</summary>` as written.
/// Block-form `/** */` is also legal C# doc syntax but is
/// vanishingly rare in practice; not handled in v0.5.3.
pub(crate) fn extract_csharp_doc_comments(content: &str, start_row: usize) -> Option<String> {
    // Same logic as Rust; C# `///` is identical syntax (only the
    // contents differ — XML instead of Markdown).
    extract_rust_doc_comments(content, start_row)
}

/// Extract C# symbols (classes, interfaces, structs, records, enums, methods).
///
/// Closes the v0.5.0 "out of scope" follow-up for C# doc-comment
/// indexing. Brings in-tree language coverage from 11 → 12 and
/// doc-comment extraction from 10 → 11 languages.
pub(crate) fn extract_csharp_symbols(
    tree: &SyntaxTree,
    content: &str,
    symbols: &mut Vec<Symbol>,
) -> Result<()> {
    // Type declarations: class, interface, struct, record, enum.
    // All share the same shape — `child_by_field_name("name")`
    // returns the type identifier.
    for kind_name in [
        "class_declaration",
        "interface_declaration",
        "struct_declaration",
        "record_declaration",
        "enum_declaration",
    ] {
        let nodes = tree.find_nodes_by_kind(kind_name);
        for node in nodes {
            if let Some(name_node) = node.child_by_field_name("name") {
                if let Ok(name) = name_node.text() {
                    let docs = extract_csharp_doc_comments(content, node.start_position().row);
                    symbols.push(Symbol {
                        name: name.to_string(),
                        // Wire-side kind strings: keep `class` for
                        // class_declaration / record_declaration
                        // (records are nominal-typed classes that
                        // generate `Equals`/`GetHashCode`), `interface`
                        // for interfaces, `struct` for value types,
                        // `enum` for enumerations.
                        kind: match kind_name {
                            "class_declaration" | "record_declaration" => "class".to_string(),
                            "interface_declaration" => "interface".to_string(),
                            "struct_declaration" => "struct".to_string(),
                            "enum_declaration" => "enum".to_string(),
                            _ => "class".to_string(),
                        },
                        start_line: node.start_position().row + 1,
                        start_column: node.start_position().column,
                        end_line: node.end_position().row + 1,
                        end_column: node.end_position().column,
                        // C# default access for top-level types is
                        // `internal`; for nested types it's `private`.
                        // Determining this precisely requires walking
                        // the modifier list — defer for v0.5.3 and
                        // default to `public` to match the precedent
                        // set by Java/PHP/Swift extractors.
                        visibility: "public".to_string(),
                        documentation: docs,
                    });
                }
            }
        }
    }

    // Method declarations.
    let methods = tree.find_nodes_by_kind("method_declaration");
    for method in methods {
        if let Some(name_node) = method.child_by_field_name("name") {
            if let Ok(name) = name_node.text() {
                let docs = extract_csharp_doc_comments(content, method.start_position().row);
                symbols.push(Symbol {
                    name: name.to_string(),
                    kind: "method".to_string(),
                    start_line: method.start_position().row + 1,
                    start_column: method.start_position().column,
                    end_line: method.end_position().row + 1,
                    end_column: method.end_position().column,
                    visibility: "public".to_string(),
                    documentation: docs,
                });
            }
        }
    }

    Ok(())
}

/// Extract Markdown headings as `Symbol` records.
///
/// v1 captures only `atx_heading` and `setext_heading` nodes — paragraphs,
/// list items, and code blocks are not symbols (industry consensus from
/// ctags / Marksman / VSCode / JetBrains). Headings inside fenced code
/// blocks are skipped (the tree-sitter-md block grammar emits them as
/// `fenced_code_block.code_fence_content` children, opaque to ATX/Setext
/// queries — so they're naturally excluded).
///
/// - `kind="heading"` for all H1–H6 (flat encoding; depth carried by
///   `signature` and `name`/qualified path).
/// - `name` = hierarchical qualified path joined by `" > "`
///   (`"README.md > Title > Installation"`). The leading file-stem is
///   added by the caller in the daemon writer where the path is known;
///   here we emit `"Title > Installation"`.
/// - `signature` is not stored on `Symbol`; it's rendered on demand by
///   `signature::render_markdown` from the heading line in the source.
/// - `documentation` captures the first paragraph immediately following
///   the heading (single-line collapsed, ~512 char cap), enabling
///   `find_symbol --doc-contains` over prose.
pub(crate) fn extract_markdown_symbols(
    tree: &SyntaxTree,
    content: &str,
    symbols: &mut Vec<Symbol>,
) -> Result<()> {
    markdown::extract(tree, content, symbols)
}

/// Extract doc comments preceding a Rust item start line
pub(crate) fn extract_rust_doc_comments(content: &str, start_row: usize) -> Option<String> {
    let lines: Vec<&str> = content.lines().collect();
    if start_row == 0 {
        return None;
    }

    let mut docs = Vec::new();
    let mut line_idx = start_row as isize - 1;
    while line_idx >= 0 {
        let line = lines[line_idx as usize].trim();
        if line.starts_with("///") {
            docs.push(line.trim_start_matches("///").trim());
        } else if line.is_empty() {
            line_idx -= 1;
            continue;
        } else {
            break;
        }
        line_idx -= 1;
    }

    if docs.is_empty() {
        None
    } else {
        docs.reverse();
        Some(docs.join("\n"))
    }
}

/// Extract PHP symbols
pub(crate) fn extract_php_symbols(
    tree: &SyntaxTree,
    content: &str,
    symbols: &mut Vec<Symbol>,
) -> Result<()> {
    // PHPDoc is `/** ... */` — reuse extract_c_doc_comments.
    let classes = tree.find_nodes_by_kind("class_declaration");
    for class in classes {
        if let Some(name_node) = class.child_by_field_name("name") {
            if let Ok(name) = name_node.text() {
                let docs = extract_c_doc_comments(content, class.start_position().row);
                symbols.push(Symbol {
                    name: name.to_string(),
                    kind: "class".to_string(),
                    start_line: class.start_position().row + 1,
                    start_column: class.start_position().column,
                    end_line: class.end_position().row + 1,
                    end_column: class.end_position().column,
                    visibility: "public".to_string(),
                    documentation: docs,
                });
            }
        }
    }

    let functions = tree.find_nodes_by_kind("function_definition");
    for func in functions {
        if let Some(name_node) = func.child_by_field_name("name") {
            if let Ok(name) = name_node.text() {
                let docs = extract_c_doc_comments(content, func.start_position().row);
                symbols.push(Symbol {
                    name: name.to_string(),
                    kind: "function".to_string(),
                    start_line: func.start_position().row + 1,
                    start_column: func.start_position().column,
                    end_line: func.end_position().row + 1,
                    end_column: func.end_position().column,
                    visibility: "public".to_string(),
                    documentation: docs,
                });
            }
        }
    }

    // Method bodies inside class_declaration / interface_declaration /
    // trait_declaration. The bare method name is the indexed key so
    // `Index.FindCallers("methodName")` resolves member-call and
    // scoped-call edges (the PHP_REFS query in rts-daemon captures
    // those references with the bare name, matching the Java/Ruby
    // extractor convention).
    let methods = tree.find_nodes_by_kind("method_declaration");
    for method in methods {
        let Some(name_node) = method.child_by_field_name("name") else {
            continue;
        };
        let Ok(name) = name_node.text() else { continue };
        let docs = extract_c_doc_comments(content, method.start_position().row);
        // PHP visibility defaults to public when no modifier is
        // present (matches the language spec).
        let mut visibility = "public".to_string();
        for child in method.children() {
            if child.kind() == "visibility_modifier" {
                if let Ok(v) = child.text() {
                    visibility = v.trim().to_lowercase();
                }
                break;
            }
        }
        symbols.push(Symbol {
            name: name.to_string(),
            kind: "method".to_string(),
            start_line: method.start_position().row + 1,
            start_column: method.start_position().column,
            end_line: method.end_position().row + 1,
            end_column: method.end_position().column,
            visibility,
            documentation: docs,
        });
    }

    Ok(())
}

/// Extract Python docstring from function or class definition
pub(crate) fn extract_python_docstring(_content: &str, node: &crate::Node) -> Option<String> {
    // Look for the first string literal in the body
    if let Some(body) = node.child_by_field_name("body") {
        for child in body.children() {
            if child.kind() == "expression_statement" {
                for expr_child in child.children() {
                    if expr_child.kind() == "string" {
                        if let Ok(docstring) = expr_child.text() {
                            // Clean up the docstring
                            let cleaned = docstring
                                .trim_start_matches("\"\"\"")
                                .trim_end_matches("\"\"\"")
                                .trim_start_matches("'''")
                                .trim_end_matches("'''")
                                .trim_start_matches('"')
                                .trim_end_matches('"')
                                .trim_start_matches('\'')
                                .trim_end_matches('\'')
                                .trim();

                            if !cleaned.is_empty() {
                                return Some(cleaned.to_string());
                            }
                        }
                    }
                }
            }
        }
    }
    None
}

/// Extract C/C++ doc comments (/* */ or //) preceding an item start line
pub(crate) fn extract_c_doc_comments(content: &str, start_row: usize) -> Option<String> {
    let lines: Vec<&str> = content.lines().collect();
    if start_row == 0 {
        return None;
    }

    let mut docs = Vec::new();
    let mut line_idx = start_row as isize - 1;
    let mut in_block_comment = false;

    while line_idx >= 0 {
        let line = lines[line_idx as usize].trim();

        if line.ends_with("*/") && line.contains("/*") {
            // Single line block comment. Strip both the `/*`
            // opening and an immediately-following `*` (the
            // JSDoc / `/**` convention) so the doc text doesn't
            // carry a stray leading asterisk.
            let doc_content = line
                .trim_start_matches("/*")
                .trim_start_matches('*')
                .trim_end_matches("*/")
                .trim();
            if !doc_content.is_empty() {
                docs.push(doc_content);
            }
            break;
        } else if line.ends_with("*/") {
            in_block_comment = true;
            let doc_content = line.trim_end_matches("*/").trim();
            if !doc_content.is_empty() && !doc_content.starts_with('*') {
                docs.push(doc_content);
            } else if doc_content.starts_with('*') {
                docs.push(doc_content.trim_start_matches('*').trim());
            }
        } else if in_block_comment {
            if line.starts_with("/*") {
                // Same JSDoc-aware strip as the single-line case.
                let doc_content = line.trim_start_matches("/*").trim_start_matches('*').trim();
                if !doc_content.is_empty() {
                    docs.push(doc_content);
                }
                break;
            } else if line.starts_with('*') {
                let doc_content = line.trim_start_matches('*').trim();
                if !doc_content.is_empty() {
                    docs.push(doc_content);
                }
            } else if !line.is_empty() {
                docs.push(line);
            }
        } else if line.starts_with("//") {
            // Single line comment
            docs.push(line.trim_start_matches("//").trim());
        } else if line.is_empty() {
            line_idx -= 1;
            continue;
        } else {
            break;
        }
        line_idx -= 1;
    }

    if docs.is_empty() {
        None
    } else {
        docs.reverse();
        Some(docs.join("\n"))
    }
}

/// Markdown extraction helpers — heading-as-symbol walker, hierarchical
/// qualified-name builder, and first-paragraph body capture for the
/// `documentation` field.
///
/// Kept in this module rather than a `languages/markdown.rs` sub-module
/// to mirror C/C++/C# (which have no language sub-module either — there
/// are no markdown-specific helpers to expose).
mod markdown {
    use super::*;

    /// First-paragraph cap for the `documentation` field — long enough
    /// for `find_symbol --doc-contains` to find shape-shaped phrases,
    /// short enough that it doesn't blow up the docs multimap.
    const DOC_CHAR_CAP: usize = 512;

    /// Walk the tree-sitter-md section tree and emit one `Symbol` per
    /// heading. Section nesting in the grammar already encodes heading
    /// hierarchy — H2 under H1 produces `section[H1] > section[H2]`,
    /// no manual depth stack needed.
    pub(super) fn extract(
        tree: &SyntaxTree,
        content: &str,
        symbols: &mut Vec<Symbol>,
    ) -> Result<()> {
        let bytes = content.as_bytes();
        let root = tree.root_node();
        // Stack of (level, name) pairs from outermost to current. Both
        // section-nested ATX headings and flat setext-heading siblings
        // funnel through the same stack — we pop entries whose level is
        // ≥ the new heading's level before pushing.
        let mut stack: Vec<(u8, String)> = Vec::new();
        walk_node(&root, bytes, &mut stack, symbols);
        Ok(())
    }

    fn walk_node(
        node: &crate::Node<'_>,
        bytes: &[u8],
        stack: &mut Vec<(u8, String)>,
        symbols: &mut Vec<Symbol>,
    ) {
        let kind = node.kind();
        match kind {
            "atx_heading" | "setext_heading" => {
                let info = if kind == "atx_heading" {
                    atx_heading_info(node, bytes)
                } else {
                    setext_heading_info(node, bytes)
                };
                if let Some((level, text)) = info {
                    // Pop any entries at this level or deeper — a new
                    // heading of level N closes every open heading of
                    // level ≥ N.
                    while stack.last().is_some_and(|(l, _)| *l >= level) {
                        stack.pop();
                    }
                    stack.push((level, text.clone()));
                    // Hierarchical heading path captured in
                    // `documentation` as a prefix so it survives the
                    // wire path (the `Symbol.name` field stores ONLY
                    // the leaf so `find_symbol --name "Installation"`
                    // matches). When body text exists we join with a
                    // single `\n\n` separator; when absent we still
                    // emit the path so `find_symbol --doc-contains`
                    // over the ancestor names works.
                    let path: Vec<String> = stack.iter().map(|(_, n)| n.clone()).collect();
                    let body = match kind {
                        // ATX headings: body is the first paragraph
                        // child of the enclosing `section`.
                        "atx_heading" => node
                            .parent()
                            .and_then(|p| first_paragraph_in_section(&p, bytes)),
                        // Setext headings: surrounding section
                        // contains the body paragraph as a sibling.
                        "setext_heading" => node
                            .parent()
                            .and_then(|p| first_paragraph_after_setext(&p, node, bytes)),
                        _ => None,
                    };
                    let documentation = match body {
                        Some(b) if path.len() > 1 => Some(format!("{}\n\n{b}", path.join(" > "))),
                        Some(b) => Some(b),
                        None if path.len() > 1 => Some(path.join(" > ")),
                        None => None,
                    };
                    symbols.push(Symbol {
                        // Leaf only — searchable by exact name match.
                        name: text,
                        kind: "heading".to_string(),
                        start_line: node.start_position().row + 1,
                        end_line: node.end_position().row + 1,
                        start_column: node.start_position().column,
                        end_column: node.end_position().column,
                        visibility: "public".to_string(),
                        documentation,
                    });
                }
                return;
            }
            // Fenced code blocks are opaque — never recurse in. Belt &
            // suspenders; the block grammar already keeps headings inside
            // a fence from existing in the named-children walk, but
            // future grammar tweaks shouldn't silently change behavior.
            "fenced_code_block" | "indented_code_block" => return,
            _ => {}
        }

        for child in node.named_children() {
            walk_node(&child, bytes, stack, symbols);
        }
    }

    /// Extract `(level, text)` from an `atx_heading` node.
    /// Markers are `atx_h1_marker` .. `atx_h6_marker`.
    fn atx_heading_info(node: &crate::Node<'_>, bytes: &[u8]) -> Option<(u8, String)> {
        let mut level: Option<u8> = None;
        let mut text: Option<String> = None;
        for child in node.children() {
            match child.kind() {
                "atx_h1_marker" => level = Some(1),
                "atx_h2_marker" => level = Some(2),
                "atx_h3_marker" => level = Some(3),
                "atx_h4_marker" => level = Some(4),
                "atx_h5_marker" => level = Some(5),
                "atx_h6_marker" => level = Some(6),
                _ => {}
            }
        }
        if let Some(content_node) = node.child_by_field_name("heading_content") {
            text = Some(clean_heading_text(content_node.utf8_text(bytes).ok()?));
        }
        Some((level?, text.unwrap_or_default()))
    }

    /// Extract `(level, text)` from a `setext_heading` node.
    /// Underline `setext_h1_underline` = level 1, `setext_h2_underline` = 2.
    fn setext_heading_info(node: &crate::Node<'_>, bytes: &[u8]) -> Option<(u8, String)> {
        let mut level: Option<u8> = None;
        let mut text: Option<String> = None;
        for child in node.children() {
            match child.kind() {
                "setext_h1_underline" => level = Some(1),
                "setext_h2_underline" => level = Some(2),
                _ => {}
            }
        }
        if let Some(content_node) = node.child_by_field_name("heading_content") {
            text = Some(clean_heading_text(content_node.utf8_text(bytes).ok()?));
        }
        Some((level?, text.unwrap_or_default()))
    }

    /// Trim leading/trailing whitespace and CommonMark closing `#`s.
    /// (`## Foo ##` → `Foo`.)
    fn clean_heading_text(s: &str) -> String {
        let trimmed = s.trim();
        // Strip a trailing run of `#` chars (CommonMark closing-hash).
        let stripped = trimmed.trim_end_matches('#').trim_end();
        stripped.to_string()
    }

    /// Find the first `paragraph` body block in this section (not nested
    /// in a sub-section); flatten to a single line and clip to
    /// `DOC_CHAR_CAP` chars.
    fn first_paragraph_in_section(section: &crate::Node<'_>, bytes: &[u8]) -> Option<String> {
        // For ATX-style hierarchies the section contains the heading as
        // the first named child, then the body paragraph(s) and nested
        // sections. Iterate past the leading heading; stop at the first
        // nested section / heading sibling.
        let mut past_heading = false;
        for child in section.named_children() {
            match child.kind() {
                "atx_heading" | "setext_heading" => {
                    if !past_heading {
                        past_heading = true;
                        continue;
                    }
                    // Hit a sibling heading without finding a paragraph —
                    // no docs.
                    return None;
                }
                "paragraph" => {
                    let raw = child.utf8_text(bytes).ok()?;
                    return Some(collapse_paragraph(raw));
                }
                "section" => return None,
                _ => continue,
            }
        }
        None
    }

    /// Find the first paragraph appearing *after* `heading` inside the
    /// enclosing section. tree-sitter-md emits setext headings as flat
    /// siblings inside one section (unlike ATX, which builds nested
    /// sections), so the body paragraph is a later named child of the
    /// same section.
    fn first_paragraph_after_setext(
        section: &crate::Node<'_>,
        heading: &crate::Node<'_>,
        bytes: &[u8],
    ) -> Option<String> {
        let heading_start = heading.start_byte();
        for child in section.named_children() {
            // Only consider children that start strictly after the
            // heading we're looking at.
            if child.start_byte() <= heading_start {
                continue;
            }
            match child.kind() {
                "paragraph" => {
                    let raw = child.utf8_text(bytes).ok()?;
                    return Some(collapse_paragraph(raw));
                }
                // Another heading interrupts — no doc paragraph for the
                // current heading.
                "atx_heading" | "setext_heading" => return None,
                _ => continue,
            }
        }
        None
    }

    /// Collapse a paragraph's whitespace to single spaces and clip.
    fn collapse_paragraph(raw: &str) -> String {
        let mut buf = String::new();
        let mut prev_ws = false;
        for ch in raw.chars() {
            if ch.is_whitespace() {
                if !prev_ws && !buf.is_empty() {
                    buf.push(' ');
                }
                prev_ws = true;
            } else {
                buf.push(ch);
                prev_ws = false;
            }
            if buf.chars().count() >= DOC_CHAR_CAP {
                break;
            }
        }
        // Take exactly DOC_CHAR_CAP chars (character-aligned, not byte).
        let s: String = buf.trim_end().chars().take(DOC_CHAR_CAP).collect();
        s
    }
}

#[cfg(test)]
mod tests {
    use crate::Language;
    use crate::parse_content;

    /// Go-style doc comments (// lines immediately above) flow through
    /// to `Symbol::documentation`. A blank line severs the comment from
    /// the declaration (Go convention).
    #[test]
    fn go_doc_comments_extracted() {
        let src = "package main\n\n// Greet returns a friendly hello message.\n// Used as the default response when no name is provided.\nfunc Greet() string {\n    return \"hello\"\n}\n\n// Counter holds a running total.\ntype Counter struct {\n    n int\n}\n";
        let outcome = parse_content(src, Language::Go).unwrap();

        let greet = outcome
            .symbols
            .iter()
            .find(|s| s.name == "Greet")
            .expect("Greet symbol should be extracted");
        let docs = greet
            .documentation
            .as_ref()
            .expect("Greet should have docs");
        assert!(docs.contains("friendly hello"), "got docs={docs:?}");
        assert!(docs.contains("default response"), "got docs={docs:?}");

        let counter = outcome
            .symbols
            .iter()
            .find(|s| s.name == "Counter")
            .expect("Counter type should be extracted");
        assert_eq!(
            counter.documentation.as_deref(),
            Some("Counter holds a running total."),
            "Counter docs should be the single comment line"
        );
    }

    /// Go convention: a blank line between the comment and the
    /// declaration means the comment is NOT documentation.
    #[test]
    fn go_doc_comments_blank_line_severs() {
        let src = "package main\n\n// This is not documentation, just a stray comment.\n\nfunc Orphan() {}\n";
        let outcome = parse_content(src, Language::Go).unwrap();
        let orphan = outcome.symbols.iter().find(|s| s.name == "Orphan").unwrap();
        assert!(
            orphan.documentation.is_none(),
            "Orphan should have no docs (blank line severs): got {:?}",
            orphan.documentation
        );
    }

    /// JSDoc /** ... */ blocks should flow through to
    /// `Symbol::documentation`. The cosmetic `*` on continuation lines
    /// is stripped.
    #[test]
    fn jsdoc_extraction_for_javascript() {
        let src = "/**\n * Greet returns a friendly hello message.\n * Used when no name is provided.\n */\nfunction greet() { return \"hi\"; }\n\n/** Single-line JSDoc. */\nclass Counter { }\n";
        let outcome = parse_content(src, Language::JavaScript).unwrap();

        let greet = outcome
            .symbols
            .iter()
            .find(|s| s.name == "greet")
            .expect("greet symbol should be extracted");
        let docs = greet
            .documentation
            .as_ref()
            .expect("greet should have docs");
        assert!(
            !docs.starts_with('*'),
            "JSDoc opening `*` should be stripped, got: {docs:?}"
        );
        assert!(docs.contains("friendly hello"), "got docs={docs:?}");

        let counter = outcome
            .symbols
            .iter()
            .find(|s| s.name == "Counter")
            .expect("Counter class should be extracted");
        let counter_docs = counter
            .documentation
            .as_ref()
            .expect("Counter should have docs");
        assert_eq!(
            counter_docs, "Single-line JSDoc.",
            "single-line JSDoc should strip leading `*`"
        );
    }

    /// Module-level `const` and `static` declarations surface as
    /// symbols so agents can look them up by name.
    #[test]
    fn rust_const_and_static_extraction() {
        let src = "/// The default request limit.\npub const DEFAULT_LIMIT: usize = 256;\n\n/// Maximum supported.\npub const MAX_LIMIT: usize = 4096;\n\nstatic INTERNAL_FLAG: bool = false;\n";
        let outcome = parse_content(src, Language::Rust).unwrap();

        let default_limit = outcome
            .symbols
            .iter()
            .find(|s| s.name == "DEFAULT_LIMIT")
            .expect("DEFAULT_LIMIT should be extracted as a symbol");
        assert_eq!(default_limit.kind, "const");
        assert_eq!(default_limit.visibility, "public");
        assert_eq!(
            default_limit.documentation.as_deref(),
            Some("The default request limit."),
            "const doc should flow through"
        );

        let max_limit = outcome
            .symbols
            .iter()
            .find(|s| s.name == "MAX_LIMIT")
            .expect("MAX_LIMIT should be extracted");
        assert_eq!(max_limit.kind, "const");

        let internal_flag = outcome
            .symbols
            .iter()
            .find(|s| s.name == "INTERNAL_FLAG")
            .expect("static INTERNAL_FLAG should be extracted as a symbol");
        assert_eq!(internal_flag.kind, "static");
        assert_eq!(internal_flag.visibility, "private");
    }

    /// Ruby doc comments (#-prefixed lines, no shebang).
    #[test]
    fn ruby_doc_extraction() {
        let src = "# Greeter returns hello strings.\n# Use the static `hello` method for the default.\nclass Greeter\n  # The default greeting.\n  def hello\n    return \"hi\"\n  end\nend\n";
        let outcome = parse_content(src, Language::Ruby).unwrap();

        if let Some(greeter) = outcome.symbols.iter().find(|s| s.name == "Greeter") {
            let docs = greeter
                .documentation
                .as_ref()
                .expect("Greeter should have docs");
            assert!(docs.contains("returns hello"), "got docs={docs:?}");
        }
        if let Some(hello) = outcome.symbols.iter().find(|s| s.name == "hello") {
            assert_eq!(
                hello.documentation.as_deref(),
                Some("The default greeting.")
            );
        }
    }

    /// Javadoc /** ... */ flows through with cosmetic `*` strip.
    #[test]
    fn java_doc_extraction() {
        let src = "/**\n * Greeter returns hello strings.\n * Use the static `hello()` for the default.\n */\npublic class Greeter {\n    /** The default greeting. */\n    public String hello() { return \"hi\"; }\n}\n";
        let outcome = parse_content(src, Language::Java).unwrap();

        if let Some(greeter) = outcome.symbols.iter().find(|s| s.name == "Greeter") {
            let docs = greeter
                .documentation
                .as_ref()
                .expect("Greeter should have Javadoc");
            assert!(docs.contains("returns hello"), "got docs={docs:?}");
            assert!(!docs.starts_with('*'), "Javadoc `*` should be stripped");
        }
    }

    /// Swift uses `///` like Rust. The extractor reuses the Rust path.
    #[test]
    fn swift_doc_extraction() {
        let src = "/// Greeter returns hello strings.\n/// Use the static `hello()` for the default.\nclass Greeter {\n    /// The default greeting.\n    func hello() -> String { return \"hi\" }\n}\n";
        let outcome = parse_content(src, Language::Swift).unwrap();

        if let Some(greeter) = outcome.symbols.iter().find(|s| s.name == "Greeter") {
            let docs = greeter
                .documentation
                .as_ref()
                .expect("Greeter should have docs");
            assert!(docs.contains("returns hello"), "got docs={docs:?}");
        }
        if let Some(hello) = outcome.symbols.iter().find(|s| s.name == "hello") {
            assert_eq!(
                hello.documentation.as_deref(),
                Some("The default greeting.")
            );
        }
    }

    /// C# uses `///` XML doc comments and surfaces class/method/
    /// interface/record symbols.
    #[test]
    fn csharp_extraction() {
        let src = "namespace Demo;\n\n\
             /// <summary>\n\
             /// Greeter returns hello strings.\n\
             /// </summary>\n\
             public class Greeter\n\
             {\n\
             /// <summary>The default greeting.</summary>\n\
             public string Hello() { return \"hi\"; }\n\
             }\n\n\
             /// <summary>A record for caching.</summary>\n\
             public record CacheKey(string Name);\n\n\
             /// <summary>Eviction policy contract.</summary>\n\
             public interface IEvictionPolicy { void Evict(); }\n";
        let outcome = parse_content(src, Language::CSharp).unwrap();

        let greeter = outcome
            .symbols
            .iter()
            .find(|s| s.name == "Greeter")
            .expect("Greeter class should be extracted");
        let docs = greeter.documentation.as_ref().expect("Greeter has docs");
        assert!(
            docs.contains("Greeter returns hello"),
            "Greeter doc should preserve XML payload, got: {docs:?}"
        );

        let hello = outcome
            .symbols
            .iter()
            .find(|s| s.name == "Hello")
            .expect("Hello method should be extracted");
        assert_eq!(hello.kind, "method");
        let hello_docs = hello.documentation.as_ref().expect("Hello has docs");
        assert!(
            hello_docs.contains("default greeting"),
            "got: {hello_docs:?}"
        );

        let cache_key = outcome
            .symbols
            .iter()
            .find(|s| s.name == "CacheKey")
            .expect("CacheKey record should be extracted");
        assert_eq!(
            cache_key.kind, "class",
            "records surface as class kind for wire stability"
        );

        let policy = outcome
            .symbols
            .iter()
            .find(|s| s.name == "IEvictionPolicy")
            .expect("IEvictionPolicy interface should be extracted");
        assert_eq!(policy.kind, "interface");
        let policy_docs = policy
            .documentation
            .as_ref()
            .expect("IEvictionPolicy has docs");
        assert!(policy_docs.contains("Eviction"), "got: {policy_docs:?}");
    }

    /// PHP class with a single public method: the method must be
    /// indexed as a top-level Symbol with `kind == "method"` and the
    /// bare method name (the form PHP_REFS captures).
    #[test]
    fn php_class_method_indexed_with_bare_name() {
        let src = "<?php\n\
             class Greeter {\n\
                 public function greet() { return \"hi\"; }\n\
             }\n";
        let outcome = parse_content(src, Language::Php).unwrap();

        let greet = outcome
            .symbols
            .iter()
            .find(|s| s.name == "greet")
            .expect("greet method should be extracted with bare name");
        assert_eq!(greet.kind, "method");
        assert_eq!(greet.visibility, "public");
    }

    /// Visibility modifiers (public/private/protected) propagate to
    /// `Symbol.visibility`. A method with no modifier defaults to
    /// public (PHP language rule). `static` does not change visibility.
    #[test]
    fn php_method_visibility_modifiers_extracted() {
        let src = "<?php\n\
             class Klass {\n\
                 public function pub_method() {}\n\
                 private function priv_method() {}\n\
                 protected function prot_method() {}\n\
                 public static function static_method() {}\n\
                 function default_method() {}\n\
             }\n";
        let outcome = parse_content(src, Language::Php).unwrap();
        let visibility_of = |name: &str| -> String {
            outcome
                .symbols
                .iter()
                .find(|s| s.name == name && s.kind == "method")
                .unwrap_or_else(|| panic!("method {name} not extracted"))
                .visibility
                .clone()
        };

        assert_eq!(visibility_of("pub_method"), "public");
        assert_eq!(visibility_of("priv_method"), "private");
        assert_eq!(visibility_of("prot_method"), "protected");
        assert_eq!(visibility_of("static_method"), "public");
        assert_eq!(visibility_of("default_method"), "public");
    }

    /// Interface method signatures are indexed so callers of
    /// `$svc->doThing()` resolve through the interface signature.
    #[test]
    fn php_interface_methods_indexed() {
        let src = "<?php\n\
             interface Service {\n\
                 public function doThing();\n\
                 public function reset();\n\
             }\n";
        let outcome = parse_content(src, Language::Php).unwrap();

        for name in ["doThing", "reset"] {
            assert!(
                outcome
                    .symbols
                    .iter()
                    .any(|s| s.name == name && s.kind == "method"),
                "interface method {name} should be extracted; got {:?}",
                outcome
                    .symbols
                    .iter()
                    .map(|s| (&s.name, &s.kind))
                    .collect::<Vec<_>>()
            );
        }
    }

    /// Trait methods are call targets just like class methods.
    #[test]
    fn php_trait_methods_indexed() {
        let src = "<?php\n\
             trait Loggable {\n\
                 public function log_event(string $msg) {}\n\
                 protected function flush() {}\n\
             }\n";
        let outcome = parse_content(src, Language::Php).unwrap();

        let log_event = outcome
            .symbols
            .iter()
            .find(|s| s.name == "log_event")
            .expect("trait method log_event should be extracted");
        assert_eq!(log_event.kind, "method");
        assert_eq!(log_event.visibility, "public");

        let flush = outcome
            .symbols
            .iter()
            .find(|s| s.name == "flush")
            .expect("trait method flush should be extracted");
        assert_eq!(flush.visibility, "protected");
    }

    /// A class inside a `namespace \Foo\Bar { ... }` block still has
    /// methods indexed by bare name (PHP_REFS captures unqualified).
    #[test]
    fn php_namespaced_class_methods_indexed_by_bare_name() {
        let src = "<?php\n\
             namespace Foo\\Bar;\n\
             class Klass {\n\
                 public function nested_method() {}\n\
             }\n";
        let outcome = parse_content(src, Language::Php).unwrap();

        let method = outcome
            .symbols
            .iter()
            .find(|s| s.name == "nested_method")
            .expect("nested_method should be extracted by bare name");
        assert_eq!(method.kind, "method");
    }

    /// Rust trait/type/union/macro all surface as symbols. Closes
    /// v0.5.4 dogfood gap: `find_symbol --name Log` on `rust-lang/log`
    /// returned empty pre-fix because `pub trait Log` wasn't extracted.
    #[test]
    fn rust_trait_type_union_macro_all_extracted() {
        let src = "\
/// A trait encapsulating logging.
pub trait Log: Send + Sync {
    fn enabled(&self) -> bool;
}

/// Result alias.
pub type LogResult<T> = std::result::Result<T, std::io::Error>;

pub union Word {
    int: u32,
    bytes: [u8; 4],
}

macro_rules! log_at {
    ($level:expr, $($arg:tt)+) => {};
}
";
        let outcome = parse_content(src, Language::Rust).unwrap();
        let by_name = |n: &str, k: &str| outcome.symbols.iter().any(|s| s.name == n && s.kind == k);
        assert!(
            by_name("Log", "trait"),
            "trait extraction missing: {:?}",
            outcome
                .symbols
                .iter()
                .map(|s| (&s.name, &s.kind))
                .collect::<Vec<_>>()
        );
        assert!(
            by_name("LogResult", "type"),
            "type-alias extraction missing"
        );
        assert!(by_name("Word", "union"), "union extraction missing");
        assert!(by_name("log_at", "macro"), "macro extraction missing");

        let log = outcome
            .symbols
            .iter()
            .find(|s| s.name == "Log" && s.kind == "trait")
            .unwrap();
        assert_eq!(
            log.documentation.as_deref(),
            Some("A trait encapsulating logging.")
        );
    }

    // ---- Markdown heading extraction (v0.7.0) ----
    //
    // The block-grammar tree-sitter-md indexer emits headings as
    // `kind="heading"` symbols. Depth is encoded in:
    //   - `name` — hierarchical path joined by " > " (no file stem
    //     prefix; that's the daemon writer's job at index time once
    //     the file path is known).
    //   - `signature` — rendered on demand by
    //     `signature::render_markdown` from the heading line in source
    //     (re-derives the leading-`#` count without storing it on
    //     `Symbol`, preserving the public API shape).

    fn markdown_symbols(src: &str) -> Vec<crate::Symbol> {
        parse_content(src, Language::Markdown).unwrap().symbols
    }

    #[test]
    fn extract_markdown_atx_h1_to_h6() {
        // Each level should produce one heading with kind="heading"
        // and the correct start_line.
        let src = "# One\n\n## Two\n\n### Three\n\n#### Four\n\n##### Five\n\n###### Six\n";
        let syms = markdown_symbols(src);
        assert_eq!(syms.len(), 6, "expected 6 headings, got {syms:?}");
        for sym in &syms {
            assert_eq!(
                sym.kind, "heading",
                "every heading symbol gets kind=heading"
            );
            assert_eq!(sym.visibility, "public", "headings are public by default");
        }
        // `Symbol.name` stores the LEAF only so `find_symbol(name="X")`
        // exact-match works. Hierarchy is exposed via the
        // `documentation` field prefix (so `--doc-contains` over the
        // ancestor names works) and via `signature::render_markdown`
        // (which displays the marker count).
        assert_eq!(syms[0].name, "One");
        assert_eq!(syms[1].name, "Two");
        assert_eq!(syms[2].name, "Three");
        assert_eq!(syms[5].name, "Six");
        // The hierarchy lives in the `documentation` prefix (no body
        // paragraph in this fixture → docs are just the path).
        assert_eq!(syms[1].documentation.as_deref(), Some("One > Two"));
        assert_eq!(
            syms[5].documentation.as_deref(),
            Some("One > Two > Three > Four > Five > Six")
        );
        // The H1 has nothing to nest under and no body, so docs stay
        // empty.
        assert!(syms[0].documentation.is_none());
    }

    #[test]
    fn extract_markdown_setext_h1_h2() {
        // Setext (underline-style) H1 and H2 should be captured the
        // same way ATX H1/H2 are.
        let src = "Top Title\n=========\n\nSubsection\n----------\n";
        let syms = markdown_symbols(src);
        assert_eq!(syms.len(), 2, "expected 2 setext headings, got {syms:?}");
        assert_eq!(syms[0].kind, "heading");
        assert_eq!(syms[0].name, "Top Title");
        assert_eq!(syms[1].name, "Subsection");
        // Setext H2 inherits the H1 as its parent.
        assert_eq!(
            syms[1].documentation.as_deref(),
            Some("Top Title > Subsection"),
        );
    }

    #[test]
    fn extract_markdown_strips_closing_hashes_and_trims() {
        // CommonMark allows `## Foo ##` — trailing hashes are decorative
        // and must be stripped from the symbol name.
        let src = "## Trimmed Title  ##\n\nBody.\n";
        let syms = markdown_symbols(src);
        assert_eq!(syms.len(), 1);
        assert_eq!(syms[0].name, "Trimmed Title");
    }

    #[test]
    fn extract_markdown_multiple_h1_siblings() {
        // Two H1s are siblings — neither nests under the other; their
        // names are independent leaf strings.
        let src = "# First Topic\n\nA paragraph.\n\n# Second Topic\n\nAnother paragraph.\n";
        let syms = markdown_symbols(src);
        let names: Vec<&str> = syms.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(names, vec!["First Topic", "Second Topic"]);
    }

    #[test]
    fn extract_markdown_hierarchy_resets_on_higher_heading() {
        // After going H1 → H2 → H3, a new H1 should reset the path —
        // subsequent H2 nests under the *new* H1, not the old one.
        // Verify via the `documentation` prefix.
        let src = "# Alpha\n\n## A1\n\n### A1a\n\n# Beta\n\n## B1\n";
        let syms = markdown_symbols(src);
        let names: Vec<&str> = syms.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(names, vec!["Alpha", "A1", "A1a", "Beta", "B1"]);
        // The B1 documentation should carry `Beta > B1`, NOT `Alpha > B1`.
        let b1 = syms.iter().find(|s| s.name == "B1").unwrap();
        assert_eq!(b1.documentation.as_deref(), Some("Beta > B1"));
        // A1a documentation has the full triple-deep path.
        let a1a = syms.iter().find(|s| s.name == "A1a").unwrap();
        assert_eq!(a1a.documentation.as_deref(), Some("Alpha > A1 > A1a"));
    }

    #[test]
    fn extract_markdown_documentation_from_first_paragraph() {
        // The first paragraph after a heading populates `documentation`
        // so `find_symbol --doc-contains` can match prose. The path
        // prefix is prepended when the heading has ancestors.
        let src = "# Project\n\n## Installation\n\nDownload the prebuilt binary from\nthe releases page,\nthen run `cargo install`.\n\n### Notes\n";
        let syms = markdown_symbols(src);
        let install = syms.iter().find(|s| s.name == "Installation").unwrap();
        let docs = install
            .documentation
            .as_ref()
            .expect("Installation heading should have docs");
        // Path prefix: H2 → "Project > Installation".
        assert!(
            docs.starts_with("Project > Installation"),
            "expected path prefix; got {docs:?}",
        );
        // Body: "releases page" comma form survives the collapse.
        assert!(docs.contains("releases page,"), "got docs={docs:?}");
        // The next heading's body should NOT bleed in.
        assert!(!docs.contains("Notes"), "got docs={docs:?}");
    }

    #[test]
    fn extract_markdown_no_documentation_when_immediate_subheading() {
        // A heading immediately followed by a subheading (no body)
        // gets the path prefix only — no body. An H1 with no body and
        // no parents stays None.
        let src = "## Outer\n### Inner\n\nInner body.\n";
        let syms = markdown_symbols(src);
        let outer = syms.iter().find(|s| s.name == "Outer").unwrap();
        assert!(
            outer.documentation.is_none(),
            "Outer (no parents, no body) should have None docs: got {:?}",
            outer.documentation
        );
        // Inner gets the full path + body.
        let inner = syms.iter().find(|s| s.name == "Inner").unwrap();
        let docs = inner.documentation.as_deref().unwrap();
        assert!(docs.starts_with("Outer > Inner"), "got {docs:?}");
        assert!(docs.contains("Inner body."), "got {docs:?}");
    }

    #[test]
    fn extract_markdown_skips_headings_inside_fenced_code_blocks() {
        // A `#` inside a fenced code block is code, not a heading. The
        // tree-sitter-md block grammar emits the fence as
        // `fenced_code_block.code_fence_content` — opaque to the
        // ATX/Setext queries, so headings nested in a fence never reach
        // our extractor.
        let src = "# Real Heading\n\n```\n# Not a heading\n## Also not\n```\n\nMore body.\n";
        let syms = markdown_symbols(src);
        // Only the real heading should be captured.
        assert_eq!(syms.len(), 1, "expected 1 heading, got {syms:?}");
        assert_eq!(syms[0].name, "Real Heading");
    }

    #[test]
    fn extract_markdown_start_line_is_one_based() {
        // start_line is 1-based (matches all other extractors). Verify
        // on a non-trivial offset — heading sits on line 4.
        let src = "Intro paragraph.\n\nMore intro.\n\n# Heading on line five\n";
        let syms = markdown_symbols(src);
        assert_eq!(syms.len(), 1);
        assert_eq!(syms[0].start_line, 5);
    }

    #[test]
    fn extract_markdown_empty_file() {
        let syms = markdown_symbols("");
        assert!(syms.is_empty());
    }
}
