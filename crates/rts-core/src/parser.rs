//! Parser functionality for tree-sitter

use crate::error::{Error, Result};
use crate::languages::Language;
use crate::tree::SyntaxTree;
use lru::LruCache;
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};
use tree_sitter::{InputEdit, Point};

/// Default capacity for the parsed-tree cache.
///
/// Previously hardcoded as the field `max_cache_size: 100`. Same default, but
/// expressed as a constant so the eviction policy and capacity decision live
/// together.
const DEFAULT_TREE_CACHE_SIZE: usize = 100;

/// Configuration options for parsing
#[derive(Debug, Clone, Copy)]
pub struct ParseOptions {
    /// Maximum number of bytes to parse (None for unlimited)
    pub max_bytes: Option<usize>,
    /// Timeout for parsing in milliseconds (None for no timeout)
    pub timeout_millis: Option<u64>,
    /// Whether to include extra information in the tree
    pub include_extras: bool,
}

impl Default for ParseOptions {
    fn default() -> Self {
        Self {
            max_bytes: None,
            timeout_millis: Some(5000), // 5 second default timeout
            include_extras: true,
        }
    }
}

/// A thread-safe wrapper around the tree-sitter parser with caching.
///
/// The cache is an LRU of `(source_hash → SyntaxTree)`. Prior versions used a
/// `HashMap` with "first-key from HashMap iteration" eviction, which is
/// effectively random under `HashMap`'s rehash seed — the
/// performance-oracle review of the agentic-retrieval pivot plan flagged this
/// as a real latency hazard (hot symbols dropped at random). LRU eviction
/// makes the cache behavior deterministic and recency-aware.
pub struct Parser {
    inner: Arc<Mutex<tree_sitter::Parser>>,
    language: Language,
    options: ParseOptions,
    /// Cache for parsed trees to avoid re-parsing identical content.
    cache: Arc<Mutex<LruCache<u64, SyntaxTree>>>,
}

impl Parser {
    /// Create a new parser for the specified language
    pub fn new(language: Language) -> Result<Self> {
        let mut parser = tree_sitter::Parser::new();
        let ts_language = language.tree_sitter_language()?;

        parser.set_language(&ts_language).map_err(|e| {
            Error::language_error_with_cause(
                language.name(),
                "parser initialization",
                format!("{:?}", e),
            )
        })?;

        let cache_capacity = NonZeroUsize::new(DEFAULT_TREE_CACHE_SIZE)
            .expect("DEFAULT_TREE_CACHE_SIZE is a positive constant");
        Ok(Self {
            inner: Arc::new(Mutex::new(parser)),
            language,
            options: ParseOptions::default(),
            cache: Arc::new(Mutex::new(LruCache::new(cache_capacity))),
        })
    }

    /// Create a new parser with custom options
    pub fn with_options(language: Language, options: ParseOptions) -> Result<Self> {
        let mut parser = Self::new(language)?;
        parser.options = options;
        Ok(parser)
    }

    /// Get the current language
    pub fn language(&self) -> Language {
        self.language
    }

    /// Get the current parse options
    pub fn options(&self) -> &ParseOptions {
        &self.options
    }

    /// Set new parse options
    pub fn set_options(&mut self, options: ParseOptions) {
        self.options = options;
    }

    /// Parse source code into a syntax tree
    pub fn parse(&self, source: &str, old_tree: Option<&SyntaxTree>) -> Result<SyntaxTree> {
        // Check cache first (only for new parses, not incremental)
        if old_tree.is_none() {
            let cache_key = self.calculate_cache_key(source);

            // Try to get from cache. `LruCache::get` is `&mut` (it bumps
            // recency), so we hold the mutex exclusively even for hits — the
            // critical section is short.
            {
                let mut cache = self.cache.lock().map_err(|e| {
                    Error::internal_error("parser", format!("Failed to acquire cache lock: {}", e))
                })?;
                if let Some(cached_tree) = cache.get(&cache_key) {
                    return Ok(cached_tree.clone());
                }
            }
        }

        let mut parser = self.inner.lock().map_err(|e| {
            Error::internal_error("parser", format!("Failed to acquire parser lock: {}", e))
        })?;

        // Note: `Parser::set_timeout_micros` was removed in tree-sitter 0.26.
        // The replacement is `ParseOptions::progress_callback(cb)` returning
        // `ControlFlow::Break` to cancel parsing. Cooperative-timeout support is
        // a follow-up task; the historical `options.timeout_millis` is currently
        // a no-op. Tracked in the P1 migration notes.
        let _ = self.options.timeout_millis;

        // Convert old tree if provided
        let old_ts_tree = old_tree.map(|t| t.inner());

        // Parse the source
        let tree = parser
            .parse(source, old_ts_tree)
            .ok_or_else(|| Error::parse_error("Failed to parse source code"))?;

        // Note: We allow trees with errors to be returned, as they can still be useful
        // The caller can check tree.has_error() if they need to know about parse errors

        let syntax_tree = SyntaxTree::new(tree, source.to_string());

        // Cache the result (only for new parses, not incremental)
        if old_tree.is_none() {
            let cache_key = self.calculate_cache_key(source);
            self.cache_tree(cache_key, syntax_tree.clone())?;
        }

        Ok(syntax_tree)
    }

    /// Calculate a hash key for caching
    fn calculate_cache_key(&self, source: &str) -> u64 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        source.hash(&mut hasher);
        self.language.hash(&mut hasher);
        hasher.finish()
    }

    /// Cache a parsed tree. LRU-evicts the least-recently-used entry if the
    /// cache is at capacity.
    fn cache_tree(&self, key: u64, tree: SyntaxTree) -> Result<()> {
        let mut cache = self.cache.lock().map_err(|e| {
            Error::internal_error("parser", format!("Failed to acquire cache lock: {}", e))
        })?;
        cache.put(key, tree);
        Ok(())
    }

    /// Parse source code from bytes
    pub fn parse_bytes(&self, source: &[u8], old_tree: Option<&SyntaxTree>) -> Result<SyntaxTree> {
        let source_str = std::str::from_utf8(source)?;
        self.parse(source_str, old_tree)
    }

    /// Parse a file
    pub fn parse_file(&self, path: &str) -> Result<SyntaxTree> {
        let source = std::fs::read_to_string(path)?;
        self.parse(&source, None)
    }

    /// Parse with incremental updates
    pub fn parse_incremental(
        &self,
        source: &str,
        old_tree: &mut SyntaxTree,
        edits: &[InputEdit],
    ) -> Result<SyntaxTree> {
        // Apply edits to the old tree
        for edit in edits {
            old_tree.edit(edit);
        }

        // Parse with the edited tree
        self.parse(source, Some(old_tree))
    }

    /// Reset the parser state
    pub fn reset(&self) -> Result<()> {
        let mut parser = self.inner.lock().map_err(|e| {
            Error::internal_error("parser", format!("Failed to acquire parser lock: {}", e))
        })?;

        parser.reset();
        Ok(())
    }

    /// Set a new language for this parser
    pub fn set_language(&mut self, language: Language) -> Result<()> {
        let ts_language = language.tree_sitter_language()?;

        let mut parser = self.inner.lock().map_err(|e| {
            Error::internal_error("parser", format!("Failed to acquire parser lock: {}", e))
        })?;

        parser.set_language(&ts_language).map_err(|e| {
            Error::language_error_with_cause(language.name(), "language change", format!("{:?}", e))
        })?;

        self.language = language;
        Ok(())
    }

    /// Clone this parser (creates a new parser with the same configuration)
    pub fn clone_parser(&self) -> Result<Self> {
        Self::with_options(self.language, self.options)
    }

    /// Clear the parser cache
    pub fn clear_cache(&self) -> Result<()> {
        let mut cache = self.cache.lock().map_err(|e| {
            Error::internal_error("parser", format!("Failed to acquire cache lock: {}", e))
        })?;
        cache.clear();
        Ok(())
    }

    /// Get cache statistics: `(current_len, capacity)`.
    pub fn cache_stats(&self) -> Result<(usize, usize)> {
        let cache = self.cache.lock().map_err(|e| {
            Error::internal_error("parser", format!("Failed to acquire cache lock: {}", e))
        })?;
        Ok((cache.len(), cache.cap().get()))
    }

    /// Create a parser with a custom tree-cache capacity.
    ///
    /// `cache_size == 0` is silently clamped to 1, because `LruCache` requires
    /// a non-zero capacity and a zero-capacity cache is degenerate.
    pub fn with_cache_size(language: Language, cache_size: usize) -> Result<Self> {
        let parser = Self::new(language)?;
        let cap = NonZeroUsize::new(cache_size.max(1)).expect("cache_size.max(1) is non-zero");
        if let Ok(mut cache) = parser.cache.lock() {
            cache.resize(cap);
        }
        Ok(parser)
    }
}

impl Clone for Parser {
    fn clone(&self) -> Self {
        // Note: This creates a new parser instance rather than sharing the inner
        // parser. Safer for concurrent use; tree-sitter's `Parser` is `!Send`
        // across concurrent parse calls. The fresh parser starts with an empty
        // cache at the default capacity — explicit `with_cache_size` would
        // override that if a non-default capacity is desired.
        Self::with_options(self.language, self.options)
            .expect("Parser clone: with_options should succeed with valid language and options")
    }
}

/// Helper function to create an InputEdit from simple parameters
pub fn create_edit(
    start_byte: usize,
    old_end_byte: usize,
    new_end_byte: usize,
    start_row: usize,
    start_column: usize,
    old_end_row: usize,
    old_end_column: usize,
    new_end_row: usize,
    new_end_column: usize,
) -> InputEdit {
    InputEdit {
        start_byte,
        old_end_byte,
        new_end_byte,
        start_position: Point::new(start_row, start_column),
        old_end_position: Point::new(old_end_row, old_end_column),
        new_end_position: Point::new(new_end_row, new_end_column),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parser_creation() {
        let parser = Parser::new(Language::Rust);
        assert!(parser.is_ok());

        let parser = parser.unwrap();
        assert_eq!(parser.language(), Language::Rust);
    }

    #[test]
    fn test_basic_parsing() {
        let parser = Parser::new(Language::Rust).unwrap();
        let source = "fn main() { println!(\"Hello, world!\"); }";

        let tree = parser.parse(source, None);
        assert!(tree.is_ok());

        let tree = tree.unwrap();
        assert_eq!(tree.root_node().kind(), "source_file");
    }

    #[test]
    fn test_parse_options() {
        let options = ParseOptions {
            max_bytes: Some(1000),
            timeout_millis: Some(1000),
            include_extras: false,
        };

        let parser = Parser::with_options(Language::Rust, options);
        assert!(parser.is_ok());

        let parser = parser.unwrap();
        assert_eq!(parser.options().max_bytes, Some(1000));
        assert_eq!(parser.options().timeout_millis, Some(1000));
        assert!(!parser.options().include_extras);
    }

    #[test]
    fn test_parser_clone() {
        let parser1 = Parser::new(Language::Rust).unwrap();
        let parser2 = parser1.clone();

        assert_eq!(parser1.language(), parser2.language());
    }
}
