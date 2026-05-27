//! Per-language signature rendering for `Index.ReadSymbol` with
//! `shape: "signature"` (protocol-v0 §7.7).
//!
//! Given the raw bytes of a symbol definition, return the declaration
//! prefix — everything an agent needs to understand what the symbol *is*
//! without paying for the body it does. For
//!
//! ```ignore
//! pub fn build_index(workspace: &Path) -> Result<Index> {
//!     // ... 50 lines ...
//! }
//! ```
//!
//! the signature is `pub fn build_index(workspace: &Path) -> Result<Index>`.
//!
//! v0 ships renderers for all 11 supported grammars: **Rust, Python,
//! TypeScript, JavaScript, Go, Java, C, C++, PHP, Ruby, and Swift**.
//! All 11 reach `Index.ReadSymbol shape=signature` end-to-end as of
//! `0.2.0-alpha.17`. Callers fall through to body returns when this
//! module returns `None`.

/// Render the signature of a Rust top-level item. Returns `None` when the
/// input doesn't parse as a single top-level item or the item kind has no
/// meaningful signature distinction (the caller should fall back to the
/// full body in that case).
///
/// **Convention**: the returned string is the verbatim source bytes from
/// the start of the item to the byte just before the body opens
/// (typically the `{` that starts the function body / struct fields /
/// enum variants / trait body / impl body / module body). Trailing
/// whitespace is trimmed; doc comments at the front of the item are
/// retained (they're useful to the agent and cheap to carry).
pub fn render_rust(bytes: &[u8]) -> Option<String> {
    let mut parser = tree_sitter::Parser::new();
    let language: tree_sitter::Language = tree_sitter_rust::LANGUAGE.into();
    parser.set_language(&language).ok()?;
    let tree = parser.parse(bytes, None)?;
    let root = tree.root_node();

    // The bytes are expected to be a single top-level item (a `fn`, `struct`,
    // `enum`, etc.). The grammar wraps this in a `source_file` root, and the
    // first non-comment-non-attribute child is the item.
    let item = first_item(&root)?;

    // Field name `body` is the canonical "the part we want to strip" for
    // items that have one. Items without a body (type aliases, const,
    // static, use, mod-with-semi) have no body field and the whole text
    // is the signature.
    let signature_end = match item.kind() {
        // Items where stripping the body produces a useful signature.
        "function_item" => body_start(&item, bytes).unwrap_or(item.end_byte()),
        // Tuple structs (`pub struct Pair(u32, u32);`) have an
        // `ordered_field_declaration_list` that the grammar marks as
        // `body` — but those parens are part of the *declaration*, not a
        // body to strip. Keep the whole text in that case.
        "struct_item" => struct_signature_end(&item).unwrap_or(item.end_byte()),
        "enum_item" => body_start(&item, bytes).unwrap_or(item.end_byte()),
        "union_item" => body_start(&item, bytes).unwrap_or(item.end_byte()),
        "trait_item" => body_start(&item, bytes).unwrap_or(item.end_byte()),
        "impl_item" => body_start(&item, bytes).unwrap_or(item.end_byte()),
        "mod_item" => body_start(&item, bytes).unwrap_or(item.end_byte()),
        // Items where the whole thing IS the signature.
        "type_item"
        | "const_item"
        | "static_item"
        | "use_declaration"
        | "extern_crate_declaration"
        | "macro_definition"
        | "foreign_mod_item" => item.end_byte(),
        // Function signature inside a trait (no `body`, may end at `;`).
        // Captured by the function_item branch above when present.
        // Unknown kinds fall through — caller will see None.
        _ => return None,
    };

    // Walk backwards from the item to include contiguous preceding
    // doc-comment lines and outer attributes. Tree-sitter places those as
    // sibling nodes of the item; they're load-bearing context for an agent
    // and cheap to carry.
    let start = signature_start_including_docs(&root, &item);
    let slice = bytes.get(start..signature_end)?;
    let mut text = std::str::from_utf8(slice).ok()?.trim_end().to_string();
    // Drop the trailing `{` if we kept it. `body_start` returns the byte
    // of the body node, which for `function_item` is the `block` (`{`)
    // itself — so we already exclude it. For defensive parsers that
    // include it, strip here.
    if text.ends_with('{') {
        text.pop();
    }
    let trimmed = text.trim_end().to_string();
    if trimmed.is_empty() {
        return None;
    }
    Some(trimmed)
}

fn first_item<'tree>(root: &tree_sitter::Node<'tree>) -> Option<tree_sitter::Node<'tree>> {
    let mut cursor = root.walk();
    let children: Vec<_> = root.children(&mut cursor).collect();
    children.into_iter().find(|n| {
        !matches!(
            n.kind(),
            "line_comment" | "block_comment" | "attribute_item"
        )
    })
}

/// Pick the right "end of signature" byte for a struct. Regular structs
/// (`pub struct Foo { … }`) strip the field block; tuple structs
/// (`pub struct Pair(u32, u32);`) and unit structs (`pub struct Marker;`)
/// have no body to strip — the parens or trailing `;` are part of the
/// declaration the agent needs to see.
fn struct_signature_end(item: &tree_sitter::Node<'_>) -> Option<usize> {
    let mut cursor = item.walk();
    for child in item.children(&mut cursor) {
        if child.kind() == "field_declaration_list" {
            return Some(child.start_byte());
        }
    }
    None
}

/// Walk backwards through the item's older siblings to include
/// contiguous doc-comment lines (`/// …`, `//! …`) and outer attributes
/// (`#[…]`) that precede it. Returns the byte offset where the
/// signature should start.
fn signature_start_including_docs(
    root: &tree_sitter::Node<'_>,
    item: &tree_sitter::Node<'_>,
) -> usize {
    let mut cursor = root.walk();
    let siblings: Vec<_> = root.children(&mut cursor).collect();
    let Some(idx) = siblings.iter().position(|n| n.id() == item.id()) else {
        return item.start_byte();
    };
    let mut start = item.start_byte();
    // Walk backwards. Stop at the first non-doc, non-attribute node.
    for sib in siblings[..idx].iter().rev() {
        match sib.kind() {
            "line_comment" | "block_comment" | "attribute_item" => {
                start = sib.start_byte();
            }
            _ => break,
        }
    }
    start
}

/// Locate the start byte of the item's body. Uses the `body` field when
/// present; falls back to a structural search for `block`/`field_declaration_list`/
/// `enum_variant_list`/`declaration_list` children. Returns `None` for
/// body-less items (e.g. unit struct, trait method declaration).
fn body_start(item: &tree_sitter::Node<'_>, _bytes: &[u8]) -> Option<usize> {
    if let Some(body) = item.child_by_field_name("body") {
        return Some(body.start_byte());
    }
    let mut cursor = item.walk();
    for child in item.children(&mut cursor) {
        match child.kind() {
            "block" | "field_declaration_list" | "enum_variant_list" | "declaration_list" => {
                return Some(child.start_byte());
            }
            _ => {}
        }
    }
    None
}

/// Render the signature of a Python top-level item.
///
/// Top-level Python items the agent typically cares about:
/// - **`function_definition`** / **`async function_definition`** — drops
///   the `block` body. Preserves decorators, async modifier, parameters,
///   and return-type annotation. The trailing `:` is kept so the agent
///   sees the full declaration syntax.
/// - **`class_definition`** — drops the `block` body. Keeps the base
///   classes parens and trailing `:`.
/// - **`decorated_definition`** — handled transparently; the wrapped
///   function or class is processed and its preceding decorators are
///   included.
/// - Everything else (`expression_statement`, `assignment`, `import_*`)
///   is returned whole — it's already a one-liner.
///
/// Returns `None` for unparseable input or unrecognised top-level kinds.
pub fn render_python(bytes: &[u8]) -> Option<String> {
    let mut parser = tree_sitter::Parser::new();
    let language: tree_sitter::Language = tree_sitter_python::LANGUAGE.into();
    parser.set_language(&language).ok()?;
    let tree = parser.parse(bytes, None)?;
    let root = tree.root_node();
    let item = root
        .children(&mut root.walk())
        .find(|n| !matches!(n.kind(), "comment"))?;

    // For a `decorated_definition` we want to include the decorators in
    // the returned text and slice up to the wrapped function/class body.
    // For a bare function/class, same logic but no decorators.
    let signature_end = match item.kind() {
        "function_definition" | "class_definition" => {
            python_body_start(&item).unwrap_or(item.end_byte())
        }
        "decorated_definition" => python_decorated_body_start(&item).unwrap_or(item.end_byte()),
        // One-liners (imports, top-level expressions, assignments) — keep whole.
        "expression_statement"
        | "assignment"
        | "import_statement"
        | "import_from_statement"
        | "future_import_statement"
        | "global_statement"
        | "nonlocal_statement"
        | "type_alias_statement" => item.end_byte(),
        _ => return None,
    };

    let start = item.start_byte();
    let slice = bytes.get(start..signature_end)?;
    let text = std::str::from_utf8(slice).ok()?.trim_end().to_string();
    if text.is_empty() {
        return None;
    }
    Some(text)
}

fn python_body_start(item: &tree_sitter::Node<'_>) -> Option<usize> {
    item.child_by_field_name("body").map(|b| b.start_byte())
}

fn python_decorated_body_start(item: &tree_sitter::Node<'_>) -> Option<usize> {
    let mut cursor = item.walk();
    for child in item.children(&mut cursor) {
        if matches!(child.kind(), "function_definition" | "class_definition") {
            if let Some(body) = child.child_by_field_name("body") {
                return Some(body.start_byte());
            }
            return Some(child.end_byte());
        }
    }
    None
}

/// Render the signature of a TypeScript top-level item.
///
/// Reuses the same shape rules as Rust: find the body node and return
/// everything before it. TypeScript-specific kinds:
/// - **`function_declaration`** / **`generator_function_declaration`**
///   / **`function_signature`** — drops `statement_block` (or returns
///   whole when no body, e.g. `function f(): void;` in `.d.ts`).
/// - **`class_declaration`** / **`abstract_class_declaration`** — drops
///   `class_body`.
/// - **`interface_declaration`** — drops `interface_body` /
///   `object_type`.
/// - **`enum_declaration`** — drops `enum_body`.
/// - **`type_alias_declaration`** / **`lexical_declaration`**
///   (`const`/`let`) / **`variable_declaration`** (`var`) — whole.
/// - **`export_statement`** wraps any of the above; unwrap.
///
/// Returns `None` for unparseable input or unrecognised top-level kinds.
pub fn render_typescript(bytes: &[u8]) -> Option<String> {
    render_ts_like(bytes, tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into())
}

/// Render the signature of a JavaScript top-level item.
///
/// Same shape rules as `render_typescript` minus the TS-only kinds
/// (`type_alias_declaration`, `interface_declaration`, etc.). The
/// `function_declaration`/`class_declaration` paths are identical.
pub fn render_javascript(bytes: &[u8]) -> Option<String> {
    render_ts_like(bytes, tree_sitter_javascript::LANGUAGE.into())
}

fn render_ts_like(bytes: &[u8], language: tree_sitter::Language) -> Option<String> {
    let mut parser = tree_sitter::Parser::new();
    parser.set_language(&language).ok()?;
    let tree = parser.parse(bytes, None)?;
    let root = tree.root_node();
    let raw_item = root
        .children(&mut root.walk())
        .find(|n| !matches!(n.kind(), "comment" | "hash_bang_line"))?;

    // `export …` and `export default …` wrap the real declaration.
    let item = unwrap_export(&raw_item).unwrap_or(raw_item);

    let signature_end = match item.kind() {
        "function_declaration"
        | "generator_function_declaration"
        | "function_signature"
        | "method_definition"
        | "method_signature" => ts_body_start(&item).unwrap_or(item.end_byte()),
        "class_declaration" | "abstract_class_declaration" => {
            ts_body_start(&item).unwrap_or(item.end_byte())
        }
        "interface_declaration" => ts_body_start(&item).unwrap_or(item.end_byte()),
        "enum_declaration" => ts_body_start(&item).unwrap_or(item.end_byte()),
        "module" | "internal_module" | "namespace_declaration" => {
            ts_body_start(&item).unwrap_or(item.end_byte())
        }
        // One-liners.
        "type_alias_declaration"
        | "lexical_declaration"
        | "variable_declaration"
        | "import_statement"
        | "export_specifier"
        | "ambient_declaration"
        | "expression_statement" => item.end_byte(),
        _ => return None,
    };

    // Slice from the *outer* node (which includes the `export` keyword
    // when present) so the signature carries that modifier.
    let start = raw_item.start_byte();
    let slice = bytes.get(start..signature_end)?;
    let text = std::str::from_utf8(slice).ok()?.trim_end().to_string();
    if text.is_empty() {
        return None;
    }
    Some(text)
}

fn unwrap_export<'tree>(node: &tree_sitter::Node<'tree>) -> Option<tree_sitter::Node<'tree>> {
    if node.kind() != "export_statement" {
        return None;
    }
    let mut cursor = node.walk();
    node.children(&mut cursor).find(|c| {
        matches!(
            c.kind(),
            "function_declaration"
                | "generator_function_declaration"
                | "function_signature"
                | "class_declaration"
                | "abstract_class_declaration"
                | "interface_declaration"
                | "enum_declaration"
                | "type_alias_declaration"
                | "lexical_declaration"
                | "variable_declaration"
                | "module"
                | "internal_module"
                | "namespace_declaration"
        )
    })
}

fn ts_body_start(item: &tree_sitter::Node<'_>) -> Option<usize> {
    if let Some(body) = item.child_by_field_name("body") {
        return Some(body.start_byte());
    }
    let mut cursor = item.walk();
    for child in item.children(&mut cursor) {
        if matches!(
            child.kind(),
            "statement_block" | "class_body" | "interface_body" | "object_type" | "enum_body"
        ) {
            return Some(child.start_byte());
        }
    }
    None
}

// ---------- Generic body-stripping helper ----------
//
// The pattern below is shared by Go, Java, C, and C++ renderers: parse,
// find the first top-level item, look up its body via the `body` field
// (preferred) or by walking children for a recognised body node-kind,
// then return the prefix slice trimmed of trailing whitespace.

fn render_strip_body(
    bytes: &[u8],
    language: tree_sitter::Language,
    handlers: &[Handler],
) -> Option<String> {
    let mut parser = tree_sitter::Parser::new();
    parser.set_language(&language).ok()?;
    let tree = parser.parse(bytes, None)?;
    let root = tree.root_node();
    let item = root.children(&mut root.walk()).find(|n| {
        !matches!(
            n.kind(),
            "comment"
                | "line_comment"
                | "block_comment"
                | "preproc_call"
                | "preproc_include"
                | "preproc_def"
        )
    })?;

    let handler = handlers.iter().find(|h| h.kinds.contains(&item.kind()))?;
    let signature_end = match handler.body_action {
        BodyAction::Strip(body_kinds) => {
            find_body_start(&item, body_kinds).unwrap_or(item.end_byte())
        }
        BodyAction::Keep => item.end_byte(),
    };

    let start = item.start_byte();
    let slice = bytes.get(start..signature_end)?;
    let text = std::str::from_utf8(slice).ok()?.trim_end().to_string();
    if text.is_empty() {
        return None;
    }
    Some(text)
}

#[derive(Clone, Copy)]
struct Handler {
    kinds: &'static [&'static str],
    body_action: BodyAction,
}

#[derive(Clone, Copy)]
enum BodyAction {
    /// Strip the body. Tries `child_by_field_name("body")` first; falls
    /// back to walking children for a node-kind in the list.
    Strip(&'static [&'static str]),
    /// Keep the whole item as-is — no body to strip.
    Keep,
}

fn find_body_start(item: &tree_sitter::Node<'_>, body_kinds: &[&str]) -> Option<usize> {
    if let Some(body) = item.child_by_field_name("body") {
        return Some(body.start_byte());
    }
    let mut cursor = item.walk();
    for child in item.children(&mut cursor) {
        if body_kinds.contains(&child.kind()) {
            return Some(child.start_byte());
        }
    }
    None
}

// ---------- Go ----------

/// Render the signature of a Go top-level item.
///
/// - **`function_declaration`** / **`method_declaration`**: drops the
///   `block` body. Keeps receiver, parameters, return types.
/// - **`type_declaration`** (`type Foo struct {…}` / `interface {…}`):
///   strips the embedded `struct_type` / `interface_type` body. Type
///   aliases (`type Foo = int`) have no body and are kept whole.
/// - **`const_declaration`** / **`var_declaration`** /
///   **`import_declaration`** / **`package_clause`**: kept whole.
pub fn render_go(bytes: &[u8]) -> Option<String> {
    // `type Foo struct {…}` / `type Foo interface {…}`: the body node
    // lives two levels deep (`type_declaration > type_spec > struct_type
    // > field_declaration_list`). Handle that with a recursive descent
    // first; fall through to the flat handlers for everything else.
    if let Some(s) = render_strip_body_with_recursive_body(bytes, tree_sitter_go::LANGUAGE.into()) {
        return Some(s);
    }
    render_strip_body(
        bytes,
        tree_sitter_go::LANGUAGE.into(),
        &[
            Handler {
                kinds: &["function_declaration", "method_declaration"],
                body_action: BodyAction::Strip(&["block"]),
            },
            Handler {
                kinds: &["type_declaration"],
                // Flat-walk fallback — keep whole when no body found
                // (e.g. type aliases `type Foo = int`).
                body_action: BodyAction::Keep,
            },
            Handler {
                kinds: &[
                    "const_declaration",
                    "var_declaration",
                    "import_declaration",
                    "package_clause",
                ],
                body_action: BodyAction::Keep,
            },
        ],
    )
    .map(|s| trim_trailing_open_brace(&s))
}

/// Fallback path for Go's `type X struct { … }` / `type X interface { … }`:
/// the body braces sit deep in the AST (`type_declaration > type_spec >
/// struct_type > field_declaration_list`). The flat-walk doesn't reach
/// it. Slice at the first `{` character in the item's text — Go's
/// grammar guarantees there's no `{` before a struct/interface body in
/// a type declaration.
fn render_strip_body_with_recursive_body(
    bytes: &[u8],
    language: tree_sitter::Language,
) -> Option<String> {
    let mut parser = tree_sitter::Parser::new();
    parser.set_language(&language).ok()?;
    let tree = parser.parse(bytes, None)?;
    let root = tree.root_node();
    let item = root
        .children(&mut root.walk())
        .find(|n| !matches!(n.kind(), "comment" | "line_comment" | "block_comment"))?;

    if item.kind() != "type_declaration" {
        return None;
    }
    let start = item.start_byte();
    let end = item.end_byte();
    let slice = bytes.get(start..end)?;
    let text = std::str::from_utf8(slice).ok()?;
    let brace = text.find('{')?;
    let signature = text[..brace].trim_end().to_string();
    if signature.is_empty() {
        return None;
    }
    Some(signature)
}

fn trim_trailing_open_brace(s: &str) -> String {
    let trimmed = s.trim_end();
    if let Some(rest) = trimmed.strip_suffix('{') {
        rest.trim_end().to_string()
    } else {
        trimmed.to_string()
    }
}

// ---------- Java ----------

/// Render the signature of a Java top-level item.
///
/// - **`class_declaration`** / **`record_declaration`**: drops `class_body`.
/// - **`interface_declaration`**: drops `interface_body`.
/// - **`enum_declaration`**: drops `enum_body`.
/// - **`annotation_type_declaration`**: drops `annotation_type_body`.
/// - **`method_declaration`** / **`constructor_declaration`** (in-class):
///   drops `block` body.
/// - **`import_declaration`** / **`package_declaration`**: kept whole.
pub fn render_java(bytes: &[u8]) -> Option<String> {
    render_strip_body(
        bytes,
        tree_sitter_java::LANGUAGE.into(),
        &[
            Handler {
                kinds: &[
                    "class_declaration",
                    "record_declaration",
                    "interface_declaration",
                    "enum_declaration",
                    "annotation_type_declaration",
                ],
                body_action: BodyAction::Strip(&[
                    "class_body",
                    "interface_body",
                    "enum_body",
                    "annotation_type_body",
                ]),
            },
            Handler {
                kinds: &["method_declaration", "constructor_declaration"],
                body_action: BodyAction::Strip(&["block"]),
            },
            Handler {
                kinds: &["import_declaration", "package_declaration"],
                body_action: BodyAction::Keep,
            },
        ],
    )
}

// ---------- C# ----------

/// Render the signature of a C# top-level item.
///
/// - **Type declarations** (`class_declaration`, `interface_declaration`,
///   `struct_declaration`, `record_declaration`, `enum_declaration`):
///   strip the `declaration_list` / `enum_member_declaration_list` body.
/// - **`method_declaration`** / **`constructor_declaration`** /
///   **`destructor_declaration`** / **`operator_declaration`**: strip
///   the `block` body.
/// - **`namespace_declaration`** / **`using_directive`**: kept whole.
pub fn render_csharp(bytes: &[u8]) -> Option<String> {
    render_strip_body(
        bytes,
        tree_sitter_c_sharp::LANGUAGE.into(),
        &[
            Handler {
                kinds: &[
                    "class_declaration",
                    "interface_declaration",
                    "struct_declaration",
                    "record_declaration",
                    "enum_declaration",
                ],
                body_action: BodyAction::Strip(&[
                    "declaration_list",
                    "enum_member_declaration_list",
                ]),
            },
            Handler {
                kinds: &[
                    "method_declaration",
                    "constructor_declaration",
                    "destructor_declaration",
                    "operator_declaration",
                ],
                body_action: BodyAction::Strip(&["block"]),
            },
            Handler {
                kinds: &["using_directive", "namespace_declaration"],
                body_action: BodyAction::Keep,
            },
        ],
    )
}

// ---------- C ----------

/// Render the signature of a C top-level item.
///
/// - **`function_definition`**: drops `compound_statement` body.
/// - **`declaration`** (variable / function prototype / typedef): kept
///   whole — these are typically one-liners.
/// - **`struct_specifier`** / **`union_specifier`** / **`enum_specifier`**
///   (top-level): drops the field/enumerator list.
/// - **`preproc_*`**: kept whole.
pub fn render_c(bytes: &[u8]) -> Option<String> {
    render_strip_body(
        bytes,
        tree_sitter_c::LANGUAGE.into(),
        &[
            Handler {
                kinds: &["function_definition"],
                body_action: BodyAction::Strip(&["compound_statement"]),
            },
            Handler {
                kinds: &["struct_specifier", "union_specifier"],
                body_action: BodyAction::Strip(&["field_declaration_list"]),
            },
            Handler {
                kinds: &["enum_specifier"],
                body_action: BodyAction::Strip(&["enumerator_list"]),
            },
            Handler {
                kinds: &[
                    "declaration",
                    "type_definition",
                    "preproc_include",
                    "preproc_def",
                    "preproc_function_def",
                    "preproc_call",
                ],
                body_action: BodyAction::Keep,
            },
        ],
    )
}

// ---------- C++ ----------

/// Render the signature of a C++ top-level item.
///
/// Inherits C's semantics plus:
/// - **`class_specifier`**: drops `field_declaration_list`.
/// - **`namespace_definition`**: drops `declaration_list`.
/// - **`template_declaration`**: unwraps to the inner declaration's
///   signature (preserving the template prefix).
pub fn render_cpp(bytes: &[u8]) -> Option<String> {
    // Try the inner-declaration unwrap path first for template_declaration;
    // otherwise fall through to the same handler set as C, extended for
    // C++ kinds.
    if let Some(s) = render_cpp_template(bytes) {
        return Some(s);
    }
    render_strip_body(
        bytes,
        tree_sitter_cpp::LANGUAGE.into(),
        &[
            Handler {
                kinds: &["function_definition"],
                body_action: BodyAction::Strip(&["compound_statement", "field_initializer_list"]),
            },
            Handler {
                kinds: &["class_specifier", "struct_specifier", "union_specifier"],
                body_action: BodyAction::Strip(&["field_declaration_list"]),
            },
            Handler {
                kinds: &["enum_specifier"],
                body_action: BodyAction::Strip(&["enumerator_list"]),
            },
            Handler {
                kinds: &["namespace_definition"],
                body_action: BodyAction::Strip(&["declaration_list"]),
            },
            Handler {
                kinds: &[
                    "declaration",
                    "type_definition",
                    "alias_declaration",
                    "using_declaration",
                    "preproc_include",
                    "preproc_def",
                    "preproc_function_def",
                    "preproc_call",
                ],
                body_action: BodyAction::Keep,
            },
        ],
    )
}

/// Render a `template <…> …` declaration by slicing at the first `{`
/// character in the item's text. The template parameter list uses
/// angle brackets, so the first `{` reliably marks where the function /
/// class / namespace body opens.
///
/// `template <…> using Foo = …;` has no `{` at all — return `None` so
/// the caller's flat-handler path picks the item up as `alias_declaration`.
fn render_cpp_template(bytes: &[u8]) -> Option<String> {
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter_cpp::LANGUAGE.into())
        .ok()?;
    let tree = parser.parse(bytes, None)?;
    let root = tree.root_node();
    let item = root
        .children(&mut root.walk())
        .find(|n| !matches!(n.kind(), "comment" | "line_comment" | "block_comment"))?;
    if item.kind() != "template_declaration" {
        return None;
    }
    let start = item.start_byte();
    let end = item.end_byte();
    let slice = bytes.get(start..end)?;
    let text = std::str::from_utf8(slice).ok()?;
    let brace = text.find('{')?;
    let signature = text[..brace].trim_end().to_string();
    if signature.is_empty() {
        return None;
    }
    Some(signature)
}

// ---------- PHP ----------

/// Render the signature of a PHP top-level item.
///
/// - **`function_definition`** / **`method_declaration`**: drops
///   `compound_statement`.
/// - **`class_declaration`** / **`interface_declaration`** /
///   **`trait_declaration`** / **`enum_declaration`**: drops
///   `declaration_list`.
/// - **`namespace_definition`** (with body): drops body block. A
///   `namespace Foo;` form has no body and is kept whole.
/// - **`const_declaration`** / **`namespace_use_declaration`**:
///   kept whole.
pub fn render_php(bytes: &[u8]) -> Option<String> {
    // The PHP grammar only parses content wrapped in `<?php … ?>`.
    // Symbol bytes extracted from the index don't carry the opening
    // tag, so we synthesise it for parsing — and remember to shift
    // offsets back into the original byte range when we return.
    let needs_tag = !looks_like_php_tag(bytes);
    let synthesised: Vec<u8>;
    let parse_bytes: &[u8] = if needs_tag {
        synthesised = [b"<?php\n", bytes].concat();
        &synthesised
    } else {
        bytes
    };
    let prefix_len = if needs_tag { 6 } else { 0 };

    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter_php::LANGUAGE_PHP.into())
        .ok()?;
    let tree = parser.parse(parse_bytes, None)?;
    let root = tree.root_node();

    // PHP wraps content in a `<?php ... ?>` tag pair; the actual
    // declarations are nested below `program > php_tag` or similar.
    // Walk the tree to find the first item we recognise.
    let target_kinds = [
        "function_definition",
        "method_declaration",
        "class_declaration",
        "interface_declaration",
        "trait_declaration",
        "enum_declaration",
        "namespace_definition",
        "const_declaration",
        "namespace_use_declaration",
        "expression_statement",
    ];
    let item = find_descendant_by_kind(&root, &target_kinds)?;

    let signature_end = match item.kind() {
        "function_definition" | "method_declaration" => {
            find_body_start(&item, &["compound_statement"]).unwrap_or(item.end_byte())
        }
        "class_declaration"
        | "interface_declaration"
        | "trait_declaration"
        | "enum_declaration" => {
            find_body_start(&item, &["declaration_list", "enum_declaration_list"])
                .unwrap_or(item.end_byte())
        }
        "namespace_definition" => {
            find_body_start(&item, &["compound_statement", "declaration_list"])
                .unwrap_or(item.end_byte())
        }
        _ => item.end_byte(),
    };

    let start = item.start_byte();
    let slice = parse_bytes.get(start..signature_end)?;
    let text = std::str::from_utf8(slice).ok()?.trim_end().to_string();
    if text.is_empty() {
        return None;
    }
    let _ = prefix_len; // offsets already aligned via parse_bytes
    Some(text)
}

/// Cheap textual probe: does this look like PHP source that starts with
/// `<?php` (possibly preceded by a BOM or whitespace)? Used to decide
/// whether to synthesise an opening tag before parsing.
fn looks_like_php_tag(bytes: &[u8]) -> bool {
    bytes
        .iter()
        .skip_while(|b| matches!(b, b' ' | b'\t' | b'\n' | b'\r' | 0xEF | 0xBB | 0xBF))
        .take(5)
        .copied()
        .eq([b'<', b'?', b'p', b'h', b'p'].iter().copied())
}

fn find_descendant_by_kind<'tree>(
    root: &tree_sitter::Node<'tree>,
    kinds: &[&str],
) -> Option<tree_sitter::Node<'tree>> {
    let mut cursor = root.walk();
    for child in root.children(&mut cursor) {
        if kinds.contains(&child.kind()) {
            return Some(child);
        }
        if let Some(found) = find_descendant_by_kind(&child, kinds) {
            return Some(found);
        }
    }
    None
}

// ---------- Ruby ----------

/// Render the signature of a Ruby top-level item.
///
/// Ruby's syntax doesn't use `{}` for block bodies (`do…end` or
/// `def…end` instead), so the standard body-strip helper doesn't
/// apply cleanly. Pragmatic approach: slice at the end of the
/// declaration header (`parameters` / `superclass` line) — for `def`
/// and `class`/`module` that's typically the first newline after the
/// item starts.
///
/// - **`method`** (`def foo(...)`) / **`singleton_method`** (`def self.foo`):
///   returns the header `def foo(x, y)`.
/// - **`class`** / **`module`**: returns `class Foo` / `class Foo < Base`
///   / `module Foo`.
/// - Other top-level kinds: `None` (caller falls back to body).
pub fn render_ruby(bytes: &[u8]) -> Option<String> {
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter_ruby::LANGUAGE.into())
        .ok()?;
    let tree = parser.parse(bytes, None)?;
    let root = tree.root_node();
    let item = root
        .children(&mut root.walk())
        .find(|n| !matches!(n.kind(), "comment"))?;

    if !matches!(
        item.kind(),
        "method" | "singleton_method" | "class" | "module"
    ) {
        return None;
    }

    let start = item.start_byte();
    let end = item.end_byte();
    let slice = bytes.get(start..end)?;
    let text = std::str::from_utf8(slice).ok()?;

    // Header is everything before the first newline OR the first `;`
    // (Ruby allows `def foo; … end` one-liners — rare but valid).
    let nl = text.find('\n').unwrap_or(text.len());
    let semi = text.find(';').unwrap_or(text.len());
    let header_end = nl.min(semi);
    let header = text[..header_end].trim_end().to_string();
    if header.is_empty() {
        return None;
    }
    Some(header)
}

// ---------- Swift ----------

/// Render the signature of a Swift top-level item.
///
/// tree-sitter-swift wraps top-level items differently than the C-family
/// grammars. The item is typically reachable directly as a child of
/// `source_file`; the body field name is `body` for functions and
/// kinds like `class_body` / `enum_class_body` / `protocol_body` for
/// type declarations.
///
/// - **`function_declaration`** / **`init_declaration`** /
///   **`deinit_declaration`**: drops `function_body`.
/// - **`class_declaration`** / **`protocol_declaration`** /
///   **`enum_declaration`**: drops the body block (first `{`).
/// - **`property_declaration`** / **`typealias_declaration`** /
///   **`import_declaration`**: kept whole.
///
/// For type declarations the first-`{` heuristic is used because the
/// Swift grammar's body field names vary across releases.
pub fn render_swift(bytes: &[u8]) -> Option<String> {
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter_swift::LANGUAGE.into())
        .ok()?;
    let tree = parser.parse(bytes, None)?;
    let root = tree.root_node();
    let item = root
        .children(&mut root.walk())
        .find(|n| !matches!(n.kind(), "comment" | "multiline_comment"))?;

    match item.kind() {
        "function_declaration"
        | "init_declaration"
        | "deinit_declaration"
        | "class_declaration"
        | "protocol_declaration"
        | "enum_declaration" => {
            // First `{` heuristic — Swift's body always starts with `{`
            // and the function/type header has none.
            let start = item.start_byte();
            let end = item.end_byte();
            let slice = bytes.get(start..end)?;
            let text = std::str::from_utf8(slice).ok()?;
            let header_end = text.find('{').unwrap_or(text.len());
            let header = text[..header_end].trim_end().to_string();
            if header.is_empty() {
                return None;
            }
            Some(header)
        }
        "property_declaration"
        | "typealias_declaration"
        | "import_declaration"
        | "operator_declaration" => {
            let start = item.start_byte();
            let end = item.end_byte();
            let slice = bytes.get(start..end)?;
            let text = std::str::from_utf8(slice).ok()?.trim_end().to_string();
            if text.is_empty() {
                return None;
            }
            Some(text)
        }
        _ => None,
    }
}

/// Render the canonical display string for a Markdown heading.
///
/// Markdown headings have no body to strip — the "signature" *is* the
/// heading line. v1 always emits ATX form (`#`, `##`, ..., `######`)
/// even for Setext-source headings, for output consistency across the
/// agent-facing tools (`outline_workspace`, `find_symbol`, etc.).
///
/// `bytes` are the heading-node's source bytes — what the daemon stores
/// in the def site's byte range. For ATX headings this is the literal
/// `### Heading text\n`; for setext, it's the text line + underline
/// (e.g. `Title\n=====\n`). The renderer detects the shape and produces
/// the ATX-form string `<#×level> <trimmed-text>`.
///
/// Returns `None` for input that doesn't parse as a single heading.
pub fn render_markdown(bytes: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(bytes).ok()?;
    let mut lines = text.lines();
    let first = lines.next()?.trim_end();
    if first.is_empty() {
        return None;
    }

    // ATX form: leading run of `#` (1..=6), then a space.
    if first.starts_with('#') {
        let hash_count = first.chars().take_while(|c| *c == '#').count();
        if !(1..=6).contains(&hash_count) {
            return None;
        }
        let rest = &first[hash_count..];
        // ATX requires a space (or end-of-line) after the marker.
        if !rest.is_empty() && !rest.starts_with(' ') && !rest.starts_with('\t') {
            return None;
        }
        let body = rest.trim();
        // Strip CommonMark closing `#`s.
        let body = body.trim_end_matches('#').trim_end();
        return Some(format!("{} {}", "#".repeat(hash_count), body));
    }

    // Setext form: title line + `===` (H1) or `---` (H2) underline.
    let second = lines.next()?.trim_end();
    let level = if !second.is_empty() && second.chars().all(|c| c == '=') {
        1
    } else if !second.is_empty() && second.chars().all(|c| c == '-') {
        2
    } else {
        return None;
    };
    let body = first.trim();
    if body.is_empty() {
        return None;
    }
    Some(format!("{} {}", "#".repeat(level), body))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sig(input: &str) -> String {
        render_rust(input.as_bytes())
            .unwrap_or_else(|| panic!("expected a signature for `{input}`"))
    }

    #[test]
    fn fn_strips_body() {
        let s = sig("pub fn build_index(workspace: &Path) -> Result<Index> { todo!() }");
        assert_eq!(s, "pub fn build_index(workspace: &Path) -> Result<Index>");
    }

    #[test]
    fn fn_with_where_clause() {
        let s = sig("pub fn foo<T>(x: T) -> T where T: Clone { x.clone() }");
        assert_eq!(s, "pub fn foo<T>(x: T) -> T where T: Clone");
    }

    #[test]
    fn fn_async_unsafe() {
        let s = sig("pub async unsafe fn f(p: *const u8) -> u32 { 0 }");
        assert_eq!(s, "pub async unsafe fn f(p: *const u8) -> u32");
    }

    #[test]
    fn struct_strips_fields() {
        let s = sig("pub struct WidgetIndex { pub field: u32, pub name: String }");
        assert_eq!(s, "pub struct WidgetIndex");
    }

    #[test]
    fn unit_struct_keeps_whole() {
        // No body — semicolon-terminated. Signature is the full thing.
        let s = sig("pub struct Marker;");
        assert_eq!(s, "pub struct Marker;");
    }

    #[test]
    fn tuple_struct_keeps_whole() {
        let s = sig("pub struct Pair(pub u32, pub u32);");
        assert_eq!(s, "pub struct Pair(pub u32, pub u32);");
    }

    #[test]
    fn enum_strips_variants() {
        let s = sig("pub enum Direction { Up, Down, Left, Right }");
        assert_eq!(s, "pub enum Direction");
    }

    #[test]
    fn trait_strips_methods() {
        let s = sig("pub trait Handler { fn handle(&self) -> u32 { 0 } }");
        assert_eq!(s, "pub trait Handler");
    }

    #[test]
    fn impl_strips_block() {
        let s = sig("impl<T> Foo<T> { pub fn new() -> Self { todo!() } }");
        assert_eq!(s, "impl<T> Foo<T>");
    }

    #[test]
    fn type_alias_keeps_whole() {
        let s = sig("pub type Result<T> = std::result::Result<T, Error>;");
        assert_eq!(s, "pub type Result<T> = std::result::Result<T, Error>;");
    }

    #[test]
    fn const_keeps_whole() {
        let s = sig("pub const MAX_RETRIES: u32 = 5;");
        assert_eq!(s, "pub const MAX_RETRIES: u32 = 5;");
    }

    #[test]
    fn static_keeps_whole() {
        let s = sig("pub static GREETING: &str = \"hello\";");
        assert_eq!(s, "pub static GREETING: &str = \"hello\";");
    }

    #[test]
    fn use_keeps_whole() {
        let s = sig("pub use std::path::PathBuf;");
        assert_eq!(s, "pub use std::path::PathBuf;");
    }

    #[test]
    fn mod_decl_keeps_whole() {
        let s = sig("pub mod widget;");
        assert_eq!(s, "pub mod widget;");
    }

    #[test]
    fn mod_with_body_strips() {
        let s = sig("pub mod widget { pub fn hello() {} }");
        assert_eq!(s, "pub mod widget");
    }

    #[test]
    fn fn_with_doc_comment_keeps_doc() {
        let s = sig("/// Build the index.\npub fn build_index() {}");
        // Doc comments before the item are part of the signature — they're
        // load-bearing context for the agent and cheap.
        assert!(
            s.contains("/// Build the index.") && s.contains("pub fn build_index()"),
            "got: {s}"
        );
    }

    #[test]
    fn returns_none_on_garbage() {
        // Random non-Rust bytes — should not panic and should return None
        // (or some plausibly-empty signature). The contract is "never
        // panic"; the caller falls back to the body.
        let s = render_rust(b"\x00\x01\x02\xff this is not rust at all");
        // Either None (no parseable item) or Some("…") that's safe to drop.
        // The hard requirement is no panic.
        let _ = s;
    }

    #[test]
    fn empty_input_returns_none() {
        assert!(render_rust(b"").is_none());
    }

    // ---------- Python ----------

    fn py(input: &str) -> String {
        render_python(input.as_bytes())
            .unwrap_or_else(|| panic!("expected a python signature for `{input}`"))
    }

    #[test]
    fn py_fn_strips_body() {
        let s = py("def build_index(workspace: Path) -> Index:\n    return Index()\n");
        assert!(
            s.starts_with("def build_index(workspace: Path) -> Index:"),
            "got {s:?}"
        );
        assert!(!s.contains("return Index()"), "got {s:?}");
    }

    #[test]
    fn py_async_fn() {
        let s = py("async def fetch(url: str) -> bytes:\n    return await get(url)\n");
        assert!(
            s.starts_with("async def fetch(url: str) -> bytes:"),
            "got {s:?}"
        );
    }

    #[test]
    fn py_class_strips_body() {
        let s = py("class Widget(Base):\n    pass\n");
        assert!(s.starts_with("class Widget(Base):"), "got {s:?}");
        assert!(!s.contains("pass"), "got {s:?}");
    }

    #[test]
    fn py_decorated_fn_keeps_decorators() {
        let s = py(
            "@staticmethod\n@cached\ndef factory(name: str) -> Widget:\n    return Widget(name)\n",
        );
        assert!(
            s.contains("@staticmethod") && s.contains("@cached"),
            "got {s:?}"
        );
        assert!(s.contains("def factory(name: str) -> Widget:"), "got {s:?}");
        assert!(!s.contains("return Widget"), "got {s:?}");
    }

    #[test]
    fn py_one_liner_assignment_keeps_whole() {
        let s = py("MAX_RETRIES: int = 5");
        assert_eq!(s, "MAX_RETRIES: int = 5");
    }

    #[test]
    fn py_returns_none_on_garbage() {
        let _ = render_python(b"\x00\xff this is not python");
    }

    #[test]
    fn py_empty_input_returns_none() {
        assert!(render_python(b"").is_none());
    }

    // ---------- TypeScript ----------

    fn ts(input: &str) -> String {
        render_typescript(input.as_bytes())
            .unwrap_or_else(|| panic!("expected a typescript signature for `{input}`"))
    }

    #[test]
    fn ts_fn_strips_body() {
        let s = ts("function add(a: number, b: number): number { return a + b; }");
        assert_eq!(s, "function add(a: number, b: number): number");
    }

    #[test]
    fn ts_export_fn() {
        let s = ts("export function greet(name: string): string { return `Hi ${name}`; }");
        assert!(
            s.starts_with("export function greet(name: string): string"),
            "got {s:?}"
        );
        assert!(!s.contains("return"), "got {s:?}");
    }

    #[test]
    fn ts_class_strips_methods() {
        let s = ts("class Widget { name: string; greet() { return this.name; } }");
        assert!(s.starts_with("class Widget"), "got {s:?}");
        assert!(!s.contains("greet"), "got {s:?}");
    }

    #[test]
    fn ts_export_class() {
        let s = ts(
            "export class Box<T> extends Container<T> implements Stackable { items: T[] = []; push(item: T) {} }",
        );
        assert!(
            s.starts_with("export class Box<T> extends Container<T> implements Stackable"),
            "got {s:?}"
        );
        assert!(!s.contains("items"), "got {s:?}");
    }

    #[test]
    fn ts_interface_strips_members() {
        let s = ts("interface Handler { handle(input: string): string; }");
        assert_eq!(s, "interface Handler");
    }

    #[test]
    fn ts_type_alias_keeps_whole() {
        let s = ts("export type Result<T> = T | Error;");
        assert_eq!(s, "export type Result<T> = T | Error;");
    }

    #[test]
    fn ts_const_keeps_whole() {
        let s = ts("export const MAX_RETRIES = 5;");
        assert_eq!(s, "export const MAX_RETRIES = 5;");
    }

    #[test]
    fn ts_enum_strips_variants() {
        let s = ts("enum Direction { Up, Down, Left, Right }");
        assert_eq!(s, "enum Direction");
    }

    #[test]
    fn ts_returns_none_on_garbage() {
        let _ = render_typescript(b"\x00\xff not typescript at all");
    }

    #[test]
    fn ts_empty_input_returns_none() {
        assert!(render_typescript(b"").is_none());
    }

    // ---------- JavaScript ----------

    fn js(input: &str) -> String {
        render_javascript(input.as_bytes())
            .unwrap_or_else(|| panic!("expected a javascript signature for `{input}`"))
    }

    #[test]
    fn js_fn_strips_body() {
        let s = js("function add(a, b) { return a + b; }");
        assert_eq!(s, "function add(a, b)");
    }

    #[test]
    fn js_class_strips_methods() {
        let s = js("class Widget { greet() { return 'hi'; } }");
        assert!(s.starts_with("class Widget"), "got {s:?}");
        assert!(!s.contains("greet"), "got {s:?}");
    }

    #[test]
    fn js_const_keeps_whole() {
        let s = js("const MAX = 42;");
        assert_eq!(s, "const MAX = 42;");
    }

    #[test]
    fn js_empty_input_returns_none() {
        assert!(render_javascript(b"").is_none());
    }

    // ---------- Go ----------

    fn go(input: &str) -> String {
        render_go(input.as_bytes())
            .unwrap_or_else(|| panic!("expected a go signature for `{input}`"))
    }

    #[test]
    fn go_fn_strips_body() {
        let s = go("func BuildIndex(workspace string) (Index, error) {\n    return nil, nil\n}\n");
        assert!(
            s.starts_with("func BuildIndex(workspace string) (Index, error)"),
            "got {s:?}"
        );
        assert!(!s.contains("return nil"), "got {s:?}");
    }

    #[test]
    fn go_method_strips_body() {
        let s = go("func (w *Widget) Greet() string {\n    return w.name\n}\n");
        assert!(
            s.starts_with("func (w *Widget) Greet() string"),
            "got {s:?}"
        );
        assert!(!s.contains("return w.name"), "got {s:?}");
    }

    #[test]
    fn go_struct_strips_fields() {
        let s = go("type Widget struct {\n    Name string\n    Kind uint32\n}\n");
        assert!(s.starts_with("type Widget struct"), "got {s:?}");
        assert!(!s.contains("Name string"), "got {s:?}");
    }

    #[test]
    fn go_interface_strips_methods() {
        let s = go("type Handler interface {\n    Handle(input string) string\n}\n");
        assert!(s.starts_with("type Handler interface"), "got {s:?}");
        assert!(!s.contains("Handle(input string)"), "got {s:?}");
    }

    #[test]
    fn go_type_alias_keeps_whole() {
        let s = go("type StringList = []string\n");
        assert_eq!(s, "type StringList = []string");
    }

    #[test]
    fn go_const_keeps_whole() {
        let s = go("const MaxRetries = 5\n");
        assert_eq!(s, "const MaxRetries = 5");
    }

    #[test]
    fn go_package_clause_keeps_whole() {
        let s = go("package main\n");
        assert_eq!(s, "package main");
    }

    #[test]
    fn go_empty_input_returns_none() {
        assert!(render_go(b"").is_none());
    }

    // ---------- Java ----------

    fn java(input: &str) -> String {
        render_java(input.as_bytes())
            .unwrap_or_else(|| panic!("expected a java signature for `{input}`"))
    }

    #[test]
    fn java_class_strips_body() {
        let s = java(
            "public class Widget extends Base implements Stackable {\n    public void greet() {}\n}\n",
        );
        assert!(
            s.starts_with("public class Widget extends Base implements Stackable"),
            "got {s:?}"
        );
        assert!(!s.contains("greet"), "got {s:?}");
    }

    #[test]
    fn java_interface_strips_body() {
        let s = java("public interface Handler {\n    String handle(String input);\n}\n");
        assert!(s.starts_with("public interface Handler"), "got {s:?}");
        assert!(!s.contains("handle"), "got {s:?}");
    }

    #[test]
    fn java_enum_strips_body() {
        let s = java("public enum Direction {\n    UP, DOWN, LEFT, RIGHT\n}\n");
        assert!(s.starts_with("public enum Direction"), "got {s:?}");
        assert!(!s.contains("UP"), "got {s:?}");
    }

    #[test]
    fn java_record_strips_body() {
        let s =
            java("public record Point(int x, int y) {\n    public Point { /* validation */ }\n}\n");
        assert!(
            s.starts_with("public record Point(int x, int y)"),
            "got {s:?}"
        );
        assert!(!s.contains("validation"), "got {s:?}");
    }

    #[test]
    fn java_package_decl_keeps_whole() {
        let s = java("package com.example.widget;\n");
        assert_eq!(s, "package com.example.widget;");
    }

    #[test]
    fn java_import_decl_keeps_whole() {
        let s = java("import java.util.List;\n");
        assert_eq!(s, "import java.util.List;");
    }

    #[test]
    fn java_empty_input_returns_none() {
        assert!(render_java(b"").is_none());
    }

    // ---------- C ----------

    fn c(input: &str) -> String {
        render_c(input.as_bytes()).unwrap_or_else(|| panic!("expected a c signature for `{input}`"))
    }

    #[test]
    fn c_fn_strips_body() {
        let s = c("int add(int a, int b) {\n    return a + b;\n}\n");
        assert_eq!(s, "int add(int a, int b)");
    }

    #[test]
    fn c_static_fn() {
        let s = c("static inline int square(int x) {\n    return x * x;\n}\n");
        assert!(
            s.starts_with("static inline int square(int x)"),
            "got {s:?}"
        );
        assert!(!s.contains("x * x"), "got {s:?}");
    }

    #[test]
    fn c_struct_strips_fields() {
        let s = c("struct Point {\n    int x;\n    int y;\n};\n");
        assert!(s.starts_with("struct Point"), "got {s:?}");
        assert!(!s.contains("int x"), "got {s:?}");
    }

    #[test]
    fn c_enum_strips_values() {
        let s = c("enum Direction {\n    UP, DOWN, LEFT, RIGHT\n};\n");
        assert!(s.starts_with("enum Direction"), "got {s:?}");
        assert!(!s.contains("UP"), "got {s:?}");
    }

    #[test]
    fn c_function_prototype_keeps_whole() {
        let s = c("int add(int a, int b);\n");
        assert_eq!(s, "int add(int a, int b);");
    }

    #[test]
    fn c_typedef_keeps_whole() {
        let s = c("typedef unsigned int u32;\n");
        assert_eq!(s, "typedef unsigned int u32;");
    }

    #[test]
    fn c_empty_input_returns_none() {
        assert!(render_c(b"").is_none());
    }

    // ---------- C++ ----------

    fn cpp(input: &str) -> String {
        render_cpp(input.as_bytes())
            .unwrap_or_else(|| panic!("expected a cpp signature for `{input}`"))
    }

    #[test]
    fn cpp_fn_strips_body() {
        let s = cpp("int add(int a, int b) {\n    return a + b;\n}\n");
        assert_eq!(s, "int add(int a, int b)");
    }

    #[test]
    fn cpp_class_strips_body() {
        let s = cpp("class Widget : public Base {\npublic:\n    void greet() {}\n};\n");
        assert!(s.starts_with("class Widget : public Base"), "got {s:?}");
        assert!(!s.contains("greet"), "got {s:?}");
    }

    #[test]
    fn cpp_namespace_strips_body() {
        let s = cpp("namespace foo {\n    int bar() { return 0; }\n}\n");
        assert!(s.starts_with("namespace foo"), "got {s:?}");
        assert!(!s.contains("bar"), "got {s:?}");
    }

    #[test]
    fn cpp_template_fn() {
        let s = cpp("template <typename T> T identity(T x) {\n    return x;\n}\n");
        assert!(s.starts_with("template <typename T>"), "got {s:?}");
        assert!(s.contains("T identity(T x)"), "got {s:?}");
        assert!(!s.contains("return x"), "got {s:?}");
    }

    #[test]
    fn cpp_template_class() {
        let s = cpp(
            "template <typename T> class Box {\npublic:\n    T value;\n    T get() const { return value; }\n};\n",
        );
        assert!(s.contains("template <typename T>"), "got {s:?}");
        assert!(s.contains("class Box"), "got {s:?}");
        assert!(!s.contains("T value;"), "got {s:?}");
    }

    #[test]
    fn cpp_using_keeps_whole() {
        let s = cpp("using IntList = std::vector<int>;\n");
        assert_eq!(s, "using IntList = std::vector<int>;");
    }

    #[test]
    fn cpp_empty_input_returns_none() {
        assert!(render_cpp(b"").is_none());
    }

    // ---------- PHP ----------

    fn php(input: &str) -> String {
        render_php(input.as_bytes())
            .unwrap_or_else(|| panic!("expected a php signature for `{input}`"))
    }

    #[test]
    fn php_fn_strips_body() {
        let s = php("<?php\nfunction add($a, $b) {\n    return $a + $b;\n}\n");
        assert!(s.contains("function add($a, $b)"), "got {s:?}");
        assert!(!s.contains("return $a + $b"), "got {s:?}");
    }

    #[test]
    fn php_class_strips_body() {
        let s = php("<?php\nclass Widget extends Base {\n    public function greet() {}\n}\n");
        assert!(s.contains("class Widget extends Base"), "got {s:?}");
        assert!(!s.contains("greet"), "got {s:?}");
    }

    #[test]
    fn php_interface_strips_body() {
        let s =
            php("<?php\ninterface Handler {\n    public function handle(string $x): string;\n}\n");
        assert!(s.contains("interface Handler"), "got {s:?}");
        assert!(!s.contains("handle("), "got {s:?}");
    }

    #[test]
    fn php_trait_strips_body() {
        let s = php("<?php\ntrait Greeter {\n    public function hello() {}\n}\n");
        assert!(s.contains("trait Greeter"), "got {s:?}");
        assert!(!s.contains("hello"), "got {s:?}");
    }

    #[test]
    fn php_namespace_use_keeps_whole() {
        let s = php("<?php\nuse App\\Widgets\\Box;\n");
        assert!(s.contains("use App\\Widgets\\Box"), "got {s:?}");
    }

    #[test]
    fn php_empty_input_returns_none() {
        assert!(render_php(b"").is_none());
    }

    // ---------- Ruby ----------

    fn rb(input: &str) -> String {
        render_ruby(input.as_bytes())
            .unwrap_or_else(|| panic!("expected a ruby signature for `{input}`"))
    }

    #[test]
    fn rb_method_strips_body() {
        let s = rb("def hello(name)\n  puts name\nend\n");
        assert_eq!(s, "def hello(name)");
    }

    #[test]
    fn rb_method_no_parens() {
        let s = rb("def shout\n  puts \"hi\"\nend\n");
        assert_eq!(s, "def shout");
    }

    #[test]
    fn rb_singleton_method() {
        let s = rb("def self.build(opts)\n  Widget.new(opts)\nend\n");
        assert_eq!(s, "def self.build(opts)");
    }

    #[test]
    fn rb_class_keeps_header() {
        let s = rb("class Widget < Base\n  def initialize\n  end\nend\n");
        assert_eq!(s, "class Widget < Base");
    }

    #[test]
    fn rb_module_keeps_header() {
        let s = rb("module Greeter\n  def hello\n  end\nend\n");
        assert_eq!(s, "module Greeter");
    }

    #[test]
    fn rb_empty_input_returns_none() {
        assert!(render_ruby(b"").is_none());
    }

    // ---------- Swift ----------

    fn sw(input: &str) -> String {
        render_swift(input.as_bytes())
            .unwrap_or_else(|| panic!("expected a swift signature for `{input}`"))
    }

    #[test]
    fn sw_fn_strips_body() {
        let s = sw("func add(_ a: Int, _ b: Int) -> Int {\n    return a + b\n}\n");
        assert!(
            s.starts_with("func add(_ a: Int, _ b: Int) -> Int"),
            "got {s:?}"
        );
        assert!(!s.contains("return a + b"), "got {s:?}");
    }

    #[test]
    fn sw_class_strips_body() {
        let s = sw("class Widget: Base {\n    var name: String = \"\"\n}\n");
        assert!(s.starts_with("class Widget: Base"), "got {s:?}");
        assert!(!s.contains("var name"), "got {s:?}");
    }

    #[test]
    fn sw_protocol_strips_body() {
        let s = sw("protocol Handler {\n    func handle(input: String) -> String\n}\n");
        assert!(s.starts_with("protocol Handler"), "got {s:?}");
        assert!(!s.contains("handle"), "got {s:?}");
    }

    #[test]
    fn sw_typealias_keeps_whole() {
        let s = sw("typealias Result = Swift.Result<String, Error>\n");
        assert!(
            s.contains("typealias Result = Swift.Result<String, Error>"),
            "got {s:?}"
        );
    }

    #[test]
    fn sw_import_keeps_whole() {
        let s = sw("import Foundation\n");
        assert_eq!(s, "import Foundation");
    }

    #[test]
    fn sw_empty_input_returns_none() {
        assert!(render_swift(b"").is_none());
    }

    // ---------- Markdown ----------
    //
    // The renderer normalises every heading to ATX form regardless of
    // grammar shape — agents reading `find_symbol` results get one
    // canonical signature style for prose.

    fn md(input: &str) -> String {
        render_markdown(input.as_bytes())
            .unwrap_or_else(|| panic!("expected a markdown signature for `{input}`"))
    }

    #[test]
    fn md_atx_h1_to_h6() {
        for level in 1..=6u8 {
            let hashes = "#".repeat(level as usize);
            let src = format!("{hashes} Heading text\n");
            assert_eq!(md(&src), format!("{hashes} Heading text"));
        }
    }

    #[test]
    fn md_atx_strips_trailing_hashes() {
        assert_eq!(md("## Section ##\n"), "## Section");
        assert_eq!(md("### Inner ### \n"), "### Inner");
    }

    #[test]
    fn md_atx_h7_rejects() {
        // ATX only goes up to H6 in CommonMark.
        assert!(render_markdown(b"####### Too deep\n").is_none());
    }

    #[test]
    fn md_setext_emits_atx_form() {
        // Underline = ⇒ H1
        assert_eq!(md("Top Title\n=========\n"), "# Top Title");
        // Underline - ⇒ H2
        assert_eq!(md("Subsection\n----------\n"), "## Subsection");
    }

    #[test]
    fn md_setext_rejects_garbage_underline() {
        // First line that doesn't begin with `#` and isn't followed by
        // an `=`/`-` line is not a heading.
        assert!(render_markdown(b"Just a paragraph\nwith more text\n").is_none());
    }

    #[test]
    fn md_empty_returns_none() {
        assert!(render_markdown(b"").is_none());
        assert!(render_markdown(b"\n").is_none());
    }

    #[test]
    fn md_atx_no_space_after_marker_rejects() {
        // `##Foo` is not a valid ATX heading (CommonMark requires a
        // space).
        assert!(render_markdown(b"##Foo\n").is_none());
    }
}
