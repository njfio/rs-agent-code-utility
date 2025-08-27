//! Syntax tree navigation and manipulation utilities

use crate::error::{Error, Result};
use tree_sitter::{InputEdit, Point, Range};

/// A wrapper around tree-sitter's Tree with additional functionality
#[derive(Clone)]
pub struct SyntaxTree {
    inner: tree_sitter::Tree,
    source: String,
}

impl SyntaxTree {
    /// Create a new syntax tree
    pub(crate) fn new(tree: tree_sitter::Tree, source: String) -> Self {
        Self {
            inner: tree,
            source,
        }
    }

    /// Get the underlying tree-sitter tree
    pub(crate) fn inner(&self) -> &tree_sitter::Tree {
        &self.inner
    }

    /// Get the source code
    pub fn source(&self) -> &str {
        &self.source
    }

    /// Get the root node of the tree
    pub fn root_node(&self) -> Node<'_> {
        Node::new(self.inner.root_node(), &self.source)
    }

    /// Create a tree cursor for traversing the tree
    pub fn walk(&self) -> TreeCursor<'_> {
        TreeCursor::new(self.inner.walk(), &self.source)
    }

    /// Edit the tree with the given input edit
    pub fn edit(&mut self, edit: &InputEdit) {
        self.inner.edit(edit);
    }

    /// Get the language of this tree
    pub fn language(&self) -> tree_sitter::Language {
        self.inner.language().clone()
    }

    /// Check if the tree has any parse errors
    pub fn has_error(&self) -> bool {
        self.root_node().has_error()
    }

    /// Get all nodes with errors
    pub fn error_nodes(&self) -> Vec<Node<'_>> {
        let mut errors = Vec::new();
        self.collect_error_nodes(self.root_node(), &mut errors);
        errors
    }

    fn collect_error_nodes<'a>(&self, node: Node<'a>, errors: &mut Vec<Node<'a>>) {
        if node.is_error() || node.is_missing() {
            errors.push(node);
        }

        for child in node.children() {
            self.collect_error_nodes(child, errors);
        }
    }

    /// Find all nodes of a specific kind (optimized with pre-allocation)
    pub fn find_nodes_by_kind(&self, kind: &str) -> Vec<Node<'_>> {
        let mut nodes = Vec::with_capacity(32); // Pre-allocate for common case
        self.collect_nodes_by_kind(self.root_node(), kind, &mut nodes);
        nodes.shrink_to_fit(); // Reclaim unused memory
        nodes
    }

    fn collect_nodes_by_kind<'a>(&self, node: Node<'a>, kind: &str, nodes: &mut Vec<Node<'a>>) {
        if node.kind() == kind {
            nodes.push(node);
        }

        for child in node.children() {
            self.collect_nodes_by_kind(child, kind, nodes);
        }
    }

    /// Get the text content of a range
    pub fn text_for_range(&self, range: Range) -> Result<&str> {
        let start = range.start_byte;
        let end = range.end_byte;
        
        if end > self.source.len() {
            return Err(Error::tree_error("Range extends beyond source text"));
        }
        
        Ok(&self.source[start..end])
    }

    /// Get changed ranges between this tree and another tree
    pub fn changed_ranges(&self, old_tree: &SyntaxTree) -> Vec<Range> {
        self.inner.changed_ranges(&old_tree.inner).collect()
    }
}

/// A wrapper around tree-sitter's Node with additional functionality
#[derive(Debug, Clone, Copy)]
pub struct Node<'a> {
    inner: tree_sitter::Node<'a>,
    source: &'a str,
}

impl<'a> Node<'a> {
    /// Create a new node wrapper
    pub(crate) fn new(node: tree_sitter::Node<'a>, source: &'a str) -> Self {
        Self {
            inner: node,
            source,
        }
    }

    /// Get the underlying tree-sitter node
    pub fn inner(&self) -> tree_sitter::Node<'a> {
        self.inner
    }

    /// Get the kind of this node
    pub fn kind(&self) -> &str {
        self.inner.kind()
    }

    /// Get the text content of this node
    pub fn text(&self) -> Result<&'a str> {
        self.inner.utf8_text(self.source.as_bytes())
            .map_err(|e| Error::tree_error(&format!("Failed to get node text: {}", e)))
    }

    /// Get the byte range of this node
    pub fn byte_range(&self) -> Range {
        Range {
            start_byte: self.inner.start_byte(),
            end_byte: self.inner.end_byte(),
            start_point: self.inner.start_position(),
            end_point: self.inner.end_position(),
        }
    }

    /// Get the start position of this node
    pub fn start_position(&self) -> Point {
        self.inner.start_position()
    }

    /// Get the end position of this node
    pub fn end_position(&self) -> Point {
        self.inner.end_position()
    }

    /// Get the start byte offset of this node
    pub fn start_byte(&self) -> usize {
        self.inner.start_byte()
    }

    /// Get the end byte offset of this node
    pub fn end_byte(&self) -> usize {
        self.inner.end_byte()
    }

    /// Check if this node has an error
    pub fn has_error(&self) -> bool {
        self.inner.has_error()
    }

    /// Check if this node is an error node
    pub fn is_error(&self) -> bool {
        self.inner.is_error()
    }

    /// Check if this node is missing
    pub fn is_missing(&self) -> bool {
        self.inner.is_missing()
    }

    /// Check if this node is named
    pub fn is_named(&self) -> bool {
        self.inner.is_named()
    }

    /// Get the parent of this node
    pub fn parent(&self) -> Option<Node<'a>> {
        self.inner.parent().map(|p| Node::new(p, self.source))
    }

    /// Get the number of children
    pub fn child_count(&self) -> usize {
        self.inner.child_count()
    }

    /// Get a child by index
    pub fn child(&self, index: usize) -> Option<Node<'a>> {
        self.inner.child(index).map(|c| Node::new(c, self.source))
    }

    /// Get a child by field name
    pub fn child_by_field_name(&self, field_name: &str) -> Option<Node<'a>> {
        self.inner.child_by_field_name(field_name).map(|c| Node::new(c, self.source))
    }

    /// Get all children
    pub fn children(&self) -> Vec<Node<'a>> {
        (0..self.child_count())
            .filter_map(|i| self.child(i))
            .collect()
    }

    /// Get all named children
    pub fn named_children(&self) -> Vec<Node<'a>> {
        self.children().into_iter().filter(|c| c.is_named()).collect()
    }

    /// Get the next sibling
    pub fn next_sibling(&self) -> Option<Node<'a>> {
        self.inner.next_sibling().map(|s| Node::new(s, self.source))
    }

    /// Get the previous sibling
    pub fn prev_sibling(&self) -> Option<Node<'a>> {
        self.inner.prev_sibling().map(|s| Node::new(s, self.source))
    }

    /// Walk the tree starting from this node
    pub fn walk(&self) -> TreeCursor<'a> {
        TreeCursor::new(self.inner.walk(), self.source)
    }

    /// Get the S-expression representation of this node
    pub fn to_sexp(&self) -> String {
        self.inner.to_sexp()
    }

    /// Find the first descendant node that matches a predicate
    pub fn find_descendant<F>(&self, predicate: F) -> Option<Node<'a>>
    where
        F: Fn(&Node<'a>) -> bool,
    {
        self.find_descendant_impl(&predicate)
    }

    fn find_descendant_impl<F>(&self, predicate: &F) -> Option<Node<'a>>
    where
        F: Fn(&Node<'a>) -> bool,
    {
        if predicate(self) {
            return Some(*self);
        }

        for child in self.children() {
            if let Some(found) = child.find_descendant_impl(predicate) {
                return Some(found);
            }
        }

        None
    }

    /// Find all descendant nodes that match a predicate (optimized)
    pub fn find_descendants<F>(&self, predicate: F) -> Vec<Node<'a>>
    where
        F: Fn(&Node<'a>) -> bool,
    {
        let mut results = Vec::with_capacity(16); // Pre-allocate for common case
        self.collect_descendants(&predicate, &mut results);
        results.shrink_to_fit(); // Reclaim unused memory
        results
    }

    fn collect_descendants<F>(&self, predicate: &F, results: &mut Vec<Node<'a>>)
    where
        F: Fn(&Node<'a>) -> bool,
    {
        if predicate(self) {
            results.push(*self);
        }

        for child in self.children() {
            child.collect_descendants(predicate, results);
        }
    }
}

/// A wrapper around tree-sitter's TreeCursor with additional functionality
pub struct TreeCursor<'a> {
    inner: tree_sitter::TreeCursor<'a>,
    source: &'a str,
}

impl<'a> TreeCursor<'a> {
    /// Create a new tree cursor wrapper
    pub(crate) fn new(cursor: tree_sitter::TreeCursor<'a>, source: &'a str) -> Self {
        Self {
            inner: cursor,
            source,
        }
    }

    /// Get the current node
    pub fn node(&self) -> Node<'a> {
        Node::new(self.inner.node(), self.source)
    }

    /// Move to the first child
    pub fn goto_first_child(&mut self) -> bool {
        self.inner.goto_first_child()
    }

    /// Move to the next sibling
    pub fn goto_next_sibling(&mut self) -> bool {
        self.inner.goto_next_sibling()
    }

    /// Move to the parent
    pub fn goto_parent(&mut self) -> bool {
        self.inner.goto_parent()
    }

    /// Reset the cursor to a specific node
    pub fn reset(&mut self, node: Node<'a>) {
        self.inner.reset(node.inner);
    }

    /// Get the field name of the current node
    pub fn field_name(&self) -> Option<&str> {
        self.inner.field_name()
    }
}

/// Represents an edit operation on a syntax tree
pub type TreeEdit = InputEdit;

#[cfg(test)]
mod tests {
    use crate::{Parser, Language};

    #[test]
    fn test_syntax_tree_basic() {
        let parser = Parser::new(Language::Rust).unwrap();
        let source = "fn main() { println!(\"Hello, world!\"); }";
        let tree = parser.parse(source, None).unwrap();

        assert_eq!(tree.root_node().kind(), "source_file");
        assert!(!tree.has_error());
        assert_eq!(tree.source(), source);
    }

    #[test]
    fn test_node_navigation() {
        let parser = Parser::new(Language::Rust).unwrap();
        let source = "fn main() { let x = 42; }";
        let tree = parser.parse(source, None).unwrap();

        let root = tree.root_node();
        assert!(root.child_count() > 0);

        let function = root.child(0).unwrap();
        assert_eq!(function.kind(), "function_item");

        let name = function.child_by_field_name("name").unwrap();
        assert_eq!(name.text().unwrap(), "main");
    }

    #[test]
    fn test_find_nodes_by_kind() {
        let parser = Parser::new(Language::Rust).unwrap();
        let source = "fn foo() {} fn bar() {}";
        let tree = parser.parse(source, None).unwrap();

        let functions = tree.find_nodes_by_kind("function_item");
        assert_eq!(functions.len(), 2);
    }
}
