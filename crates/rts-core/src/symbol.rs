//! The [`Symbol`] payload produced by [`parse_content`] / the
//! internal `extraction::extract_symbols` dispatch.
//!
//! Pulled out of the deleted `analyzer.rs` in PR-B (B3) so the
//! struct lives next to its only consumer (`extraction`) rather
//! than inside a struct (`CodebaseAnalyzer`) that itself was
//! about to be deleted.
//!
//! [`parse_content`]: crate::parse_content

use serde::{Deserialize, Serialize};

/// A code symbol (function, class, struct, etc.) extracted from a
/// tree-sitter parse tree.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Symbol {
    /// Symbol name
    pub name: String,
    /// Symbol type (function, class, struct, etc.)
    pub kind: String,
    /// Start line (1-based)
    pub start_line: usize,
    /// End line (1-based)
    pub end_line: usize,
    /// Start column (0-based)
    pub start_column: usize,
    /// End column (0-based)
    pub end_column: usize,
    /// Symbol visibility (public, private, etc.)
    pub visibility: String,
    /// Symbol documentation if available
    pub documentation: Option<String>,
    /// Name of the nearest enclosing container definition (impl / class /
    /// struct / trait / enum / …), or `None` for a top-level symbol.
    /// Populated by `crate::parent_scope::assign_parents`. Used to render
    /// `qualified_name` as `parent::name` and to disambiguate overloaded
    /// names across types.
    #[serde(default)]
    pub parent: Option<String>,
}
