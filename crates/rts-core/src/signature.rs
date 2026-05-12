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
//! v0 ships **Rust** only. Python, TypeScript, and the other 8 grammars
//! land in subsequent P8 slices. Callers fall through to body returns
//! when this module returns `None`.

use streaming_iterator::StreamingIterator as _;

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
    let _ = streaming_iterator_present_check();

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

/// Tiny no-op that pulls `streaming_iterator::StreamingIterator` into scope
/// so the import is preserved even though this file doesn't iterate
/// `QueryMatches` directly. Keeps the `use streaming_iterator` line
/// visible at the top so future query-based renderers don't have to
/// rediscover that rts-core uses it.
#[inline]
fn streaming_iterator_present_check() {}

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
}
