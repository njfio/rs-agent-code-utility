//! Query system for pattern matching in syntax trees

use crate::error::{Error, Result, QueryErrorType};
use crate::languages::Language;
use crate::tree::{Node, SyntaxTree};
use tree_sitter::{Point, Range};

/// A wrapper around tree-sitter's Query with additional functionality
pub struct Query {
    inner: tree_sitter::Query,
    language: Language,
}

impl Query {
    /// Create a new query for the specified language
    pub fn new(language: Language, pattern: &str) -> Result<Self> {
        let ts_language = language.tree_sitter_language()?;
        let query = tree_sitter::Query::new(&ts_language, pattern)?;
        
        Ok(Self {
            inner: query,
            language,
        })
    }

    /// Get the language this query is for
    pub fn language(&self) -> Language {
        self.language
    }

    /// Get the number of patterns in this query
    pub fn pattern_count(&self) -> usize {
        self.inner.pattern_count()
    }

    /// Get capture names
    pub fn capture_names(&self) -> Vec<&str> {
        self.inner.capture_names().iter().copied().collect()
    }

    /// Execute the query on a syntax tree
    pub fn matches<'a>(&'a self, tree: &'a SyntaxTree) -> Result<Vec<QueryMatch<'a>>> {
        let mut cursor = tree_sitter::QueryCursor::new();
        let root = tree.root_node();

        let mut matches = Vec::new();

        // Collect all matches first to avoid lifetime issues
        let ts_matches: Vec<_> = cursor
            .matches(&self.inner, root.inner(), tree.source().as_bytes())
            .collect();

        // Convert to our QueryMatch type
        for ts_match in ts_matches {
            let mut captures = Vec::new();
            for capture in ts_match.captures {
                let node = Node::new(capture.node, tree.source());
                let query_capture = QueryCapture {
                    node,
                    index: capture.index,
                    name: self.inner.capture_names().get(capture.index as usize).map(|s| s.to_string()),
                };
                captures.push(query_capture);
            }

            let query_match = QueryMatch {
                pattern_index: ts_match.pattern_index,
                captures,
            };
            matches.push(query_match);
        }

        Ok(matches)
    }

    /// Execute the query and get captures
    pub fn captures<'a>(&'a self, tree: &'a SyntaxTree) -> Result<Vec<QueryCapture<'a>>> {
        let mut cursor = tree_sitter::QueryCursor::new();
        let root = tree.root_node();
        let ts_captures = cursor.captures(&self.inner, root.inner(), tree.source().as_bytes());

        let mut captures = Vec::new();
        for (m, idx) in ts_captures {
            let capture = m.captures[idx];
            captures.push(QueryCapture {
                node: Node::new(capture.node, tree.source()),
                index: capture.index,
                name: self
                    .inner
                    .capture_names()
                    .get(capture.index as usize)
                    .map(|s| s.to_string()),
            });
        }

        Ok(captures)
    }

    /// Execute the query on a specific node
    pub fn matches_in_node<'a>(&'a self, node: Node<'a>, source: &'a str) -> Result<Vec<QueryMatch<'a>>> {
        let mut cursor = tree_sitter::QueryCursor::new();
        let ts_matches: Vec<_> = cursor
            .matches(&self.inner, node.inner(), source.as_bytes())
            .collect();

        let mut matches_vec = Vec::new();
        for ts_match in ts_matches {
            let mut captures = Vec::new();
            for capture in ts_match.captures {
                captures.push(QueryCapture {
                    node: Node::new(capture.node, source),
                    index: capture.index,
                    name: self
                        .inner
                        .capture_names()
                        .get(capture.index as usize)
                        .map(|s| s.to_string()),
                });
            }

            matches_vec.push(QueryMatch {
                pattern_index: ts_match.pattern_index,
                captures,
            });
        }

        Ok(matches_vec)
    }

    /// Create a query for syntax highlighting
    pub fn highlights(language: Language) -> Result<Self> {
        let highlights_query = language.highlights_query()
            .ok_or_else(|| Error::not_supported_error(&format!("Highlights query for {}", language.name()), "Language does not support syntax highlighting"))?;
        
        Self::new(language, highlights_query)
    }

    /// Create a query for finding function definitions
    pub fn functions(language: Language) -> Result<Self> {
        let pattern = match language {
            Language::Rust => "(function_item name: (identifier) @name) @function",
            Language::JavaScript => "(function_declaration name: (identifier) @name) @function",
            Language::TypeScript => "(function_declaration name: (identifier) @name) @function",
            Language::Python => "(function_definition name: (identifier) @name) @function",
            Language::C => "(function_definition declarator: (function_declarator declarator: (identifier) @name)) @function",
            Language::Cpp => "(function_definition declarator: (function_declarator declarator: (identifier) @name)) @function",
            Language::Go => "(function_declaration name: (identifier) @name) @function",
        };

        Self::new(language, pattern)
    }

    /// Create a query for finding class/struct definitions
    pub fn classes(language: Language) -> Result<Self> {
        let pattern = match language {
            Language::Rust => "(struct_item name: (type_identifier) @name) @struct",
            Language::JavaScript => "(class_declaration name: (identifier) @name) @class",
            Language::TypeScript => "(class_declaration name: (type_identifier) @name) @class",
            Language::Python => "(class_definition name: (identifier) @name) @class",
            Language::C => "(struct_specifier name: (type_identifier) @name) @struct",
            Language::Cpp => "[(class_specifier name: (type_identifier) @name) (struct_specifier name: (type_identifier) @name)] @class",
            Language::Go => "(type_declaration (type_spec name: (type_identifier) @name)) @struct",
        };

        Self::new(language, pattern)
    }
}

/// A query match result
pub struct QueryMatch<'a> {
    pattern_index: usize,
    captures: Vec<QueryCapture<'a>>,
}

impl<'a> QueryMatch<'a> {


    /// Get the pattern index
    pub fn pattern_index(&self) -> usize {
        self.pattern_index
    }

    /// Get all captures in this match
    pub fn captures(&self) -> Vec<QueryCapture<'a>> {
        self.captures.clone()
    }

    /// Get a capture by name
    pub fn capture_by_name(&self, query: &Query, name: &str) -> Option<QueryCapture<'a>> {
        let capture_names = query.capture_names();
        let capture_index = capture_names.iter().position(|&n| n == name)?;

        self.captures.iter()
            .find(|capture| capture.index as usize == capture_index)
            .cloned()
    }
}

/// A query capture result
#[derive(Clone)]
pub struct QueryCapture<'a> {
    node: Node<'a>,
    index: u32,
    name: Option<String>,
}

impl<'a> QueryCapture<'a> {


    /// Get the captured node
    pub fn node(&self) -> Node<'a> {
        self.node
    }

    /// Get the capture index
    pub fn index(&self) -> u32 {
        self.index
    }

    /// Get the capture name (if available)
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    /// Get the text of the captured node
    pub fn text(&self) -> Result<&'a str> {
        self.node.text()
    }

    /// Get the byte range of the captured node
    pub fn byte_range(&self) -> Range {
        self.node.byte_range()
    }

    /// Get the start position of the captured node
    pub fn start_position(&self) -> Point {
        self.node.start_position()
    }

    /// Get the end position of the captured node
    pub fn end_position(&self) -> Point {
        self.node.end_position()
    }
}

/// Query builder for common patterns
pub struct QueryBuilder {
    language: Language,
    patterns: Vec<String>,
}

impl QueryBuilder {
    /// Create a new query builder
    pub fn new(language: Language) -> Self {
        Self {
            language,
            patterns: Vec::new(),
        }
    }

    /// Add a pattern to find nodes by kind
    pub fn find_kind(mut self, kind: &str, capture_name: &str) -> Self {
        self.patterns.push(format!("({}) @{}", kind, capture_name));
        self
    }

    /// Add a pattern to find nodes with specific field
    pub fn find_with_field(mut self, kind: &str, field: &str, field_kind: &str, capture_name: &str) -> Self {
        self.patterns.push(format!("({} {}: ({})) @{}", kind, field, field_kind, capture_name));
        self
    }

    /// Add a custom pattern
    pub fn add_pattern(mut self, pattern: &str) -> Self {
        self.patterns.push(pattern.to_string());
        self
    }

    /// Build the query
    pub fn build(self) -> Result<Query> {
        if self.patterns.is_empty() {
            return Err(Error::query_error("empty", "query_builder", QueryErrorType::CompilationError));
        }
        
        let combined_pattern = self.patterns.join("\n");
        Query::new(self.language, &combined_pattern)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Parser, Language};

    #[test]
    fn test_query_creation() {
        let query = Query::new(Language::Rust, "(function_item) @function");
        assert!(query.is_ok());
        
        let query = query.unwrap();
        assert_eq!(query.language(), Language::Rust);
        assert_eq!(query.pattern_count(), 1);
    }

    #[test]
    fn test_query_execution() {
        let parser = Parser::new(Language::Rust).unwrap();
        let source = "fn main() {} fn test() {}";
        let tree = parser.parse(source, None).unwrap();

        let query = Query::new(Language::Rust, "(function_item) @function").unwrap();
        let matches = query.matches(&tree).unwrap();
        
        assert_eq!(matches.len(), 2);
    }

    #[test]
    fn test_query_builder() {
        let query = QueryBuilder::new(Language::Rust)
            .find_kind("function_item", "function")
            .find_kind("struct_item", "struct")
            .build();

        match query {
            Ok(_) => {},
            Err(e) => {
                println!("Query error: {:?}", e);
                panic!("Query failed: {}", e);
            }
        }
    }

    #[test]
    fn test_predefined_queries() {
        let functions_query = Query::functions(Language::Rust);
        assert!(functions_query.is_ok());
        
        let classes_query = Query::classes(Language::Rust);
        assert!(classes_query.is_ok());
    }
}
