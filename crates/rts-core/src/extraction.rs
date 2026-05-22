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

use crate::analyzer::Symbol;
use crate::error::Result;
use crate::languages::Language;
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
