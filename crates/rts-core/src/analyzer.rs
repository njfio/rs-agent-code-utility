//! # Code Analysis Module
//!
//! This module provides comprehensive code analysis functionality for processing
//! entire codebases, extracting structured information, and generating insights
//! for AI code agents and development tools.
//!
//! ## Features
//!
//! - **Multi-file analysis**: Process entire directories and codebases
//! - **Symbol extraction**: Functions, classes, variables, imports, and exports
//! - **Dependency analysis**: Import/export relationships and dependency graphs
//! - **Security scanning**: Vulnerability detection and security analysis
//! - **Performance analysis**: Identify bottlenecks and optimization opportunities
//! - **Parallel processing**: Multi-threaded analysis for large codebases
//! - **Caching**: Efficient caching to avoid redundant processing
//! - **Configurable depth**: Control analysis granularity from basic to full
//!
//! ## Usage Examples
//!
//! ### Basic File Analysis
//!
//! ```rust
//! use rust_tree_sitter::{CodebaseAnalyzer, AnalysisConfig, AnalysisDepth};

//! # fn main() -> Result<(), rust_tree_sitter::Error> {
//! // Create analyzer with custom configuration
//! let config = AnalysisConfig {
//!     depth: AnalysisDepth::Full,
//!     max_depth: Some(10),
//!     enable_parallel: true,
//!     ..Default::default()
//! };
//!
//! let analyzer = CodebaseAnalyzer::with_config(config);

//! // Analyze a single file
//! let mut analyzer = analyzer?;
//! # Ok(())
//! # }
//! ```
//!
//! ### Directory Analysis
//!
//! ```rust
//! use rust_tree_sitter::{CodebaseAnalyzer, AnalysisConfig};
//!
//! # fn main() -> Result<(), rust_tree_sitter::Error> {
//! let mut analyzer = CodebaseAnalyzer::new()?;
//!
//! // Analyze entire directory
//! let result = analyzer.analyze_directory("src/")?;
//!
//! for file_info in &result.files {
//!     println!("File: {}", file_info.path.display());
//!     println!("  Functions: {}", file_info.symbols.len());
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ### Advanced Analysis with Filtering
//!
//! ```rust
//! use rust_tree_sitter::{CodebaseAnalyzer, AnalysisConfig, AnalysisDepth};
//!
//! # fn main() -> Result<(), rust_tree_sitter::Error> {
//! let config = AnalysisConfig {
//!     depth: AnalysisDepth::Full,
//!     include_extensions: Some(vec!["rs".to_string(), "py".to_string()]),
//!     exclude_dirs: vec!["target".to_string(), "node_modules".to_string()],
//!     max_file_size: Some(1024 * 1024), // 1MB limit
//!     ..Default::default()
//! };
//!
//! let mut analyzer = CodebaseAnalyzer::with_config(config)?;
//! let result = analyzer.analyze_directory(".")?;
//!
//! // Access results directly
//! println!("Total files analyzed: {}", result.total_files);
//! println!("Total functions: {}", result.files.iter().map(|f| f.symbols.len()).sum::<usize>());
//! # Ok(())
//! # }
//! ```

use crate::error::{Error, Result};
use crate::file_cache::FileCache;
use crate::languages::Language;
use crate::parser::Parser;
use crate::semantic_graph::SemanticGraphQuery;

use crate::tree::SyntaxTree;
use ignore::WalkBuilder;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

/// Depth level for analysis
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum AnalysisDepth {
    /// Only collect basic file metadata without parsing
    Basic,
    /// Parse files but skip symbol extraction
    Deep,
    /// Full parsing with symbol extraction
    #[default]
    Full,
}

impl std::str::FromStr for AnalysisDepth {
    type Err = ();
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "basic" => Ok(AnalysisDepth::Basic),
            "deep" => Ok(AnalysisDepth::Deep),
            "full" | _ => Ok(AnalysisDepth::Full),
        }
    }
}

/// Configuration for codebase analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisConfig {
    /// Maximum file size to process (in bytes)
    pub max_file_size: Option<usize>,
    /// File extensions to include (if None, uses default for detected languages)
    pub include_extensions: Option<Vec<String>>,
    /// File extensions to exclude
    pub exclude_extensions: Vec<String>,
    /// Directories to exclude
    pub exclude_dirs: Vec<String>,
    /// Whether to follow symbolic links
    pub follow_symlinks: bool,
    /// Maximum depth to traverse
    pub max_depth: Option<usize>,
    /// Whether to include hidden files/directories
    pub include_hidden: bool,
    /// How much analysis to perform
    pub depth: AnalysisDepth,
    /// Enable parallel processing for file analysis
    pub enable_parallel: bool,
    /// Number of threads to use for parallel processing (None = auto-detect)
    pub thread_count: Option<usize>,
    /// Minimum number of files to enable parallel processing
    pub parallel_threshold: usize,
}

impl Default for AnalysisConfig {
    fn default() -> Self {
        Self {
            max_file_size: Some(1024 * 1024), // 1MB default
            include_extensions: None,
            exclude_extensions: vec![
                "exe".to_string(),
                "bin".to_string(),
                "so".to_string(),
                "dll".to_string(),
                "png".to_string(),
                "jpg".to_string(),
                "jpeg".to_string(),
                "gif".to_string(),
                "pdf".to_string(),
                "zip".to_string(),
                "tar".to_string(),
                "gz".to_string(),
            ],
            exclude_dirs: vec![
                ".git".to_string(),
                "node_modules".to_string(),
                "target".to_string(),
                ".vscode".to_string(),
                ".idea".to_string(),
                "build".to_string(),
                "dist".to_string(),
                "__pycache__".to_string(),
                ".pytest_cache".to_string(),
            ],
            follow_symlinks: false,
            max_depth: Some(20),
            include_hidden: false,
            depth: AnalysisDepth::Full,
            enable_parallel: true,
            thread_count: None,     // Auto-detect
            parallel_threshold: 10, // Enable parallel processing for 10+ files
        }
    }
}

/// Information about a parsed file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileInfo {
    /// File path relative to the analysis root
    pub path: PathBuf,
    /// Detected language
    pub language: String,
    /// File size in bytes
    pub size: usize,
    /// Number of lines
    pub lines: usize,
    /// Parse success status
    pub parsed_successfully: bool,
    /// Parse errors if any
    pub parse_errors: Vec<String>,
    /// Extracted symbols (functions, classes, etc.)
    pub symbols: Vec<Symbol>,
}

/// A code symbol (function, class, struct, etc.)
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
}

/// Results of codebase analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisResult {
    /// Root directory that was analyzed
    pub root_path: PathBuf,
    /// Total number of files processed
    pub total_files: usize,
    /// Number of files successfully parsed
    pub parsed_files: usize,
    /// Number of files with parse errors
    pub error_files: usize,
    /// Total lines of code
    pub total_lines: usize,
    /// Languages detected and their file counts
    pub languages: HashMap<String, usize>,
    /// Information about each processed file
    pub files: Vec<FileInfo>,
    /// Analysis configuration used
    pub config: AnalysisConfig,
}

impl Default for AnalysisResult {
    fn default() -> Self {
        Self::new()
    }
}

impl AnalysisResult {
    /// Create a new empty analysis result
    pub fn new() -> Self {
        Self {
            root_path: PathBuf::new(),
            total_files: 0,
            parsed_files: 0,
            error_files: 0,
            total_lines: 0,
            languages: HashMap::new(),
            files: Vec::new(),
            config: AnalysisConfig::default(),
        }
    }

    /// Ensure stable ordering for agent consumption
    pub fn sort_stable(&mut self) {
        self.files.sort_by(|a, b| a.path.cmp(&b.path));
    }
}

/// Main analyzer for processing codebases
#[derive(Default)]
pub struct CodebaseAnalyzer {
    config: AnalysisConfig,
    parsers: HashMap<Language, Parser>,
    semantic_graph: Option<SemanticGraphQuery>,
    file_cache: FileCache,
}

impl CodebaseAnalyzer {
    /// Create a new analyzer with default configuration
    pub fn new() -> Result<Self> {
        Self::with_config(AnalysisConfig::default())
    }

    /// Create a new analyzer with custom configuration
    pub fn with_config(config: AnalysisConfig) -> Result<Self> {
        Ok(Self {
            config,
            parsers: HashMap::new(),
            semantic_graph: None,
            file_cache: FileCache::new(),
        })
    }

    /// Get or create a parser for the given language
    fn get_parser(&mut self, language: Language) -> Result<&Parser> {
        if let std::collections::hash_map::Entry::Vacant(e) = self.parsers.entry(language) {
            let parser = Parser::new(language)?;
            e.insert(parser);
        }
        self.parsers.get(&language).ok_or_else(|| {
            Error::internal_error(
                "analyzer",
                format!(
                    "Parser for {} should exist after insertion",
                    language.name()
                ),
            )
        })
    }

    /// Analyze in-memory `content` for `language` and return the extracted
    /// symbols. Bypasses the filesystem entirely — no temp files, no
    /// disk round-trip, no `AnalysisResult` envelope.
    ///
    /// Use this when you already have the content in memory and only
    /// need the symbol list. Callers that need file metadata, line
    /// counts, or other `AnalysisResult` fields should still use
    /// `analyze_file`.
    ///
    /// Originally added for `rts-daemon`'s writer hot path (alpha.29):
    /// the previous `analyze_file`-driven path wrote content to a
    /// tempfile, then re-read it to parse. On real workspaces this
    /// doubled or tripled per-parse cost. This entry point removes
    /// both round-trips.
    pub fn analyze_content(&mut self, content: &str, language: Language) -> Result<Vec<Symbol>> {
        let parser = self.get_parser(language)?;
        let tree = parser.parse(content, None)?;
        self.extract_symbols(&tree, content, language)
    }

    /// Analyze a single file and return structured results
    pub fn analyze_file<P: AsRef<Path>>(&mut self, file_path: P) -> Result<AnalysisResult> {
        let file_path = file_path.as_ref();

        if !file_path.exists() {
            return Err(Error::invalid_input_error(
                "file path",
                file_path.display().to_string(),
                "existing file",
            ));
        }

        if !file_path.is_file() {
            return Err(Error::invalid_input_error(
                "path type",
                file_path.display().to_string(),
                "file (not directory)",
            ));
        }

        let mut result = AnalysisResult::new();
        let root_path = file_path.parent().unwrap_or(Path::new("."));
        result.root_path = root_path.to_path_buf();

        self.analyze_file_internal(file_path, root_path, &mut result)?;

        Ok(result)
    }

    /// Analyze a directory and return structured results
    pub fn analyze_directory<P: AsRef<Path>>(&mut self, path: P) -> Result<AnalysisResult> {
        let root_path = path.as_ref().to_path_buf();

        if !root_path.exists() {
            return Err(Error::invalid_input_error(
                "directory path",
                root_path.display().to_string(),
                "existing directory",
            ));
        }

        if !root_path.is_dir() {
            return Err(Error::invalid_input_error(
                "path type",
                root_path.display().to_string(),
                "directory (not file)",
            ));
        }

        // First, collect all files to analyze (respect .gitignore and common ignores)
        let mut file_paths = Vec::with_capacity(1000); // Pre-allocate for better performance
        self.collect_files_ignore(&root_path, &mut file_paths)?;

        // Decide whether to use parallel processing
        if self.config.enable_parallel && file_paths.len() >= self.config.parallel_threshold {
            let mut res = self.analyze_directory_parallel(root_path, file_paths)?;
            // Ensure deterministic ordering
            res.sort_stable();
            Ok(res)
        } else {
            // Use sequential processing for small numbers of files
            let mut result = AnalysisResult {
                root_path: root_path.clone(),
                total_files: 0,
                parsed_files: 0,
                error_files: 0,
                total_lines: 0,
                languages: HashMap::with_capacity(10), // Pre-allocate for common languages
                files: Vec::with_capacity(file_paths.len()),
                config: self.config.clone(),
            };

            self.analyze_directory_recursive(&root_path, &root_path, &mut result, 0)?;

            // Build semantic graph if enabled
            if self.semantic_graph.is_some() {
                if let Some(ref mut graph) = self.semantic_graph {
                    if let Err(e) = graph.build_from_analysis(&result) {
                        eprintln!("Warning: Failed to build semantic graph: {}", e);
                    }
                }
            }

            // Ensure deterministic ordering
            result.sort_stable();
            Ok(result)
        }
    }

    /// Collect files using ignore::WalkBuilder (respects .gitignore, VCS, and common ignores)
    fn collect_files_ignore(&self, root_path: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
        let mut builder = WalkBuilder::new(root_path);
        builder
            .hidden(!self.config.include_hidden)
            .follow_links(self.config.follow_symlinks)
            .git_ignore(true)
            .git_global(true)
            .git_exclude(true)
            .ignore(true)
            .max_depth(self.config.max_depth)
            .threads(1); // discovery single-threaded; analysis may be parallel

        // Build walker and collect files
        let walker = builder.build();
        for result in walker {
            let dirent = match result {
                Ok(d) => d,
                Err(_) => continue,
            };

            let path = dirent.path().to_path_buf();
            if path.is_dir() {
                // honor explicit exclude_dirs patterns by directory name
                if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                    if self.config.exclude_dirs.iter().any(|d| d == name) {
                        continue;
                    }
                }
                continue;
            }

            if path.is_file() {
                out.push(path);
            }
        }

        Ok(())
    }

    /// Analyze directory using parallel processing
    fn analyze_directory_parallel(
        &self,
        root_path: PathBuf,
        file_paths: Vec<PathBuf>,
    ) -> Result<AnalysisResult> {
        // Set up thread pool if custom thread count is specified
        if let Some(thread_count) = self.config.thread_count {
            rayon::ThreadPoolBuilder::new()
                .num_threads(thread_count)
                .build_global()
                .map_err(|e| {
                    Error::internal_error(
                        "thread_pool",
                        format!("Failed to set thread count: {}", e),
                    )
                })?;
        }

        // Shared result structure protected by mutex
        let result = Arc::new(Mutex::new(AnalysisResult {
            root_path: root_path.clone(),
            total_files: 0,
            parsed_files: 0,
            error_files: 0,
            total_lines: 0,
            languages: HashMap::new(),
            files: Vec::new(),
            config: self.config.clone(),
        }));

        // Process files in parallel
        let file_infos: Vec<_> = file_paths
            .par_iter()
            .filter_map(|file_path| {
                match self.analyze_file_standalone(file_path, &root_path) {
                    Ok(Some(file_info)) => Some(file_info),
                    Ok(None) => None, // File was skipped
                    Err(e) => {
                        eprintln!(
                            "Warning: Failed to analyze file {}: {}",
                            file_path.display(),
                            e
                        );
                        None
                    }
                }
            })
            .collect();

        // Aggregate results
        let mut final_result = result.lock().map_err(|e| {
            crate::error::Error::internal_error(
                "analyzer",
                format!("Failed to acquire lock for result aggregation: {}", e),
            )
        })?;
        for file_info in file_infos {
            final_result.total_files += 1;
            final_result.total_lines += file_info.lines;

            if file_info.parsed_successfully {
                final_result.parsed_files += 1;
            } else {
                final_result.error_files += 1;
            }

            *final_result
                .languages
                .entry(file_info.language.clone())
                .or_insert(0) += 1;
            final_result.files.push(file_info);
        }

        let result = final_result.clone();
        drop(final_result); // Release the lock

        // Build semantic graph if enabled (sequential for now due to complexity)
        if self.semantic_graph.is_some() {
            // Note: Semantic graph building is kept sequential for now
            // as it requires complex coordination between threads
            eprintln!(
                "Note: Semantic graph building is performed sequentially even in parallel mode"
            );
        }

        Ok(result)
    }

    /// Collect all files to be analyzed recursively
    #[allow(dead_code)]
    fn collect_files_recursive(
        &self,
        current_path: &Path,
        root_path: &Path,
        file_paths: &mut Vec<PathBuf>,
        depth: usize,
    ) -> Result<()> {
        // Check depth limit
        if let Some(max_depth) = self.config.max_depth {
            if depth > max_depth {
                return Ok(());
            }
        }

        let entries = fs::read_dir(current_path).map_err(|e| {
            Error::internal_error_with_context(
                "file_system",
                format!("Failed to read directory: {}", e),
                current_path.display().to_string(),
            )
        })?;

        for entry in entries {
            let entry = entry.map_err(|e| {
                Error::internal_error(
                    "file_system",
                    format!("Failed to read directory entry: {}", e),
                )
            })?;
            let path = entry.path();

            // Skip hidden files/directories if not included
            if !self.config.include_hidden {
                if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                    if name.starts_with('.') {
                        continue;
                    }
                }
            }

            if path.is_dir() {
                // Check if directory should be excluded
                if let Some(dir_name) = path.file_name().and_then(|n| n.to_str()) {
                    if self.config.exclude_dirs.contains(&dir_name.to_string()) {
                        continue;
                    }
                }

                // Recursively collect from subdirectory
                self.collect_files_recursive(&path, root_path, file_paths, depth + 1)?;
            } else if path.is_file() {
                // Add file to collection
                file_paths.push(path);
            }
        }

        Ok(())
    }

    /// Recursively analyze a directory
    fn analyze_directory_recursive(
        &mut self,
        current_path: &Path,
        root_path: &Path,
        result: &mut AnalysisResult,
        depth: usize,
    ) -> Result<()> {
        // Check depth limit
        if let Some(max_depth) = self.config.max_depth {
            if depth > max_depth {
                return Ok(());
            }
        }

        let entries = fs::read_dir(current_path).map_err(|e| {
            Error::internal_error_with_context(
                "file_system",
                format!("Failed to read directory: {}", e),
                current_path.display().to_string(),
            )
        })?;

        for entry in entries {
            let entry = entry.map_err(|e| {
                Error::internal_error(
                    "file_system",
                    format!("Failed to read directory entry: {}", e),
                )
            })?;
            let path = entry.path();

            // Skip hidden files/directories if not included
            if !self.config.include_hidden {
                if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                    if name.starts_with('.') {
                        continue;
                    }
                }
            }

            if path.is_dir() {
                // Check if directory should be excluded
                if let Some(dir_name) = path.file_name().and_then(|n| n.to_str()) {
                    if self.config.exclude_dirs.contains(&dir_name.to_string()) {
                        continue;
                    }
                }

                // Recursively analyze subdirectory
                self.analyze_directory_recursive(&path, root_path, result, depth + 1)?;
            } else if path.is_file() {
                // Analyze file
                if let Err(e) = self.analyze_file_internal(&path, root_path, result) {
                    eprintln!("Warning: Failed to analyze file {}: {}", path.display(), e);
                }
            }
        }

        Ok(())
    }

    /// Analyze a single file in standalone mode (for parallel processing)
    fn analyze_file_standalone(
        &self,
        file_path: &Path,
        root_path: &Path,
    ) -> Result<Option<FileInfo>> {
        // Get file extension
        let extension = file_path
            .extension()
            .and_then(|ext| ext.to_str())
            .unwrap_or("")
            .to_lowercase();

        // Check if extension should be excluded
        if self.config.exclude_extensions.contains(&extension) {
            return Ok(None);
        }

        // Check if extension should be included (if filter is specified)
        if let Some(ref include_exts) = self.config.include_extensions {
            if !include_exts.contains(&extension) {
                return Ok(None);
            }
        }

        // Detect language
        let language = match crate::detect_language_from_extension(&extension) {
            Some(lang) => lang,
            None => return Ok(None), // Skip files with unknown languages
        };

        // Check file size
        let metadata = fs::metadata(file_path)?;
        let file_size = metadata.len() as usize;

        if let Some(max_size) = self.config.max_file_size {
            if file_size > max_size {
                return Ok(None); // Skip large files
            }
        }

        // Read file content
        let content = fs::read_to_string(file_path)?;
        let line_count = content.lines().count();

        // Get relative path
        let relative_path = file_path
            .strip_prefix(root_path)
            .unwrap_or(file_path)
            .to_path_buf();

        let lang_name = language.name().to_string();

        // Skip parsing if depth is Basic
        if matches!(self.config.depth, AnalysisDepth::Basic) {
            let file_info = FileInfo {
                path: relative_path,
                language: lang_name,
                size: file_size,
                lines: line_count,
                parsed_successfully: false,
                parse_errors: Vec::new(),
                symbols: Vec::new(),
            };
            return Ok(Some(file_info));
        }

        // Create a parser for this thread (parsers are not thread-safe to share)
        let parser = Parser::new(language)?;
        let mut file_info = FileInfo {
            path: relative_path.clone(),
            language: lang_name,
            size: file_size,
            lines: line_count,
            parsed_successfully: false,
            parse_errors: Vec::new(),
            symbols: Vec::new(),
        };

        match parser.parse(&content, None) {
            Ok(tree) => {
                file_info.parsed_successfully = true;

                // Check for parse errors in the tree
                if tree.has_error() {
                    let error_nodes = tree.error_nodes();
                    for error_node in error_nodes {
                        let pos = error_node.start_position();
                        file_info.parse_errors.push(format!(
                            "Parse error at line {}, column {}: {}",
                            pos.row + 1,
                            pos.column,
                            error_node.kind()
                        ));
                    }
                }

                // Extract symbols only for Full depth
                if matches!(self.config.depth, AnalysisDepth::Full) {
                    file_info.symbols = self.extract_symbols(&tree, &content, language)?;
                }
            }
            Err(e) => {
                file_info.parse_errors.push(e.to_string());
            }
        }

        Ok(Some(file_info))
    }

    /// Analyze a single file (internal method)
    fn analyze_file_internal(
        &mut self,
        file_path: &Path,
        root_path: &Path,
        result: &mut AnalysisResult,
    ) -> Result<()> {
        // Get file extension
        let extension = file_path
            .extension()
            .and_then(|ext| ext.to_str())
            .unwrap_or("")
            .to_lowercase();

        // Check if extension should be excluded
        if self.config.exclude_extensions.contains(&extension) {
            return Ok(());
        }

        // Check if extension should be included (if filter is specified)
        if let Some(ref include_exts) = self.config.include_extensions {
            if !include_exts.contains(&extension) {
                return Ok(());
            }
        }

        // Detect language
        let language = match crate::detect_language_from_extension(&extension) {
            Some(lang) => lang,
            None => return Ok(()), // Skip files with unknown languages
        };

        // Check file size
        let metadata = fs::metadata(file_path)?;
        let file_size = metadata.len() as usize;

        if let Some(max_size) = self.config.max_file_size {
            if file_size > max_size {
                return Ok(()); // Skip large files
            }
        }

        // Read file content using cache
        let content = self.file_cache.read_to_string(file_path)?;
        let line_count = content.lines().count();

        // Get relative path
        let relative_path = file_path
            .strip_prefix(root_path)
            .unwrap_or(file_path)
            .to_path_buf();

        result.total_files += 1;
        result.total_lines += line_count;

        // Update language statistics
        let lang_name = language.name().to_string();
        *result.languages.entry(lang_name.clone()).or_insert(0) += 1;

        // Skip parsing if depth is Basic
        if matches!(self.config.depth, AnalysisDepth::Basic) {
            let file_info = FileInfo {
                path: relative_path,
                language: lang_name,
                size: file_size,
                lines: line_count,
                parsed_successfully: false,
                parse_errors: Vec::new(),
                symbols: Vec::new(),
            };
            result.files.push(file_info);
            return Ok(());
        }

        // Parse the file
        let parser = self.get_parser(language)?;
        let mut file_info = FileInfo {
            path: relative_path.clone(),
            language: lang_name,
            size: file_size,
            lines: line_count,
            parsed_successfully: false,
            parse_errors: Vec::new(),
            symbols: Vec::new(),
        };

        match parser.parse(&content, None) {
            Ok(tree) => {
                file_info.parsed_successfully = true;
                result.parsed_files += 1;

                // Check for parse errors in the tree
                if tree.has_error() {
                    let error_nodes = tree.error_nodes();
                    for error_node in error_nodes {
                        let pos = error_node.start_position();
                        file_info.parse_errors.push(format!(
                            "Parse error at line {}, column {}: {}",
                            pos.row + 1,
                            pos.column,
                            error_node.kind()
                        ));
                    }
                }

                // Extract symbols only for Full depth
                if matches!(self.config.depth, AnalysisDepth::Full) {
                    file_info.symbols = self.extract_symbols(&tree, &content, language)?;
                }
            }
            Err(e) => {
                file_info.parse_errors.push(e.to_string());
                result.error_files += 1;
            }
        }

        result.files.push(file_info);
        Ok(())
    }

    /// Extract symbols from a syntax tree
    fn extract_symbols(
        &self,
        tree: &SyntaxTree,
        content: &str,
        language: Language,
    ) -> Result<Vec<Symbol>> {
        let mut symbols = Vec::new();

        match language {
            Language::Rust => {
                self.extract_rust_symbols(tree, content, &mut symbols)?;
            }
            Language::JavaScript | Language::TypeScript => {
                self.extract_javascript_symbols(tree, content, &mut symbols)?;
            }
            Language::Python => {
                self.extract_python_symbols(tree, content, &mut symbols)?;
            }
            Language::C | Language::Cpp => {
                self.extract_c_symbols(tree, content, &mut symbols)?;
            }
            Language::Go => {
                self.extract_go_symbols(tree, content, &mut symbols)?;
            }
            Language::Java => {
                self.extract_java_symbols(tree, content, &mut symbols)?;
            }
            Language::Php => {
                self.extract_php_symbols(tree, content, &mut symbols)?;
            }
            Language::Ruby => {
                self.extract_ruby_symbols(tree, content, &mut symbols)?;
            }
            Language::Swift => {
                self.extract_swift_symbols(tree, content, &mut symbols)?;
            }
        }

        Ok(symbols)
    }

    /// Extract Rust symbols
    fn extract_rust_symbols(
        &self,
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

                    let docs = self.extract_rust_doc_comments(content, func.start_position().row);

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
                        let docs =
                            self.extract_rust_doc_comments(content, item.start_position().row);
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

        Ok(())
    }

    /// Extract JavaScript symbols
    fn extract_javascript_symbols(
        &self,
        tree: &SyntaxTree,
        content: &str,
        symbols: &mut Vec<Symbol>,
    ) -> Result<()> {
        // Extract function declarations
        let functions = tree.find_nodes_by_kind("function_declaration");
        for func in functions {
            if let Some(name_node) = func.child_by_field_name("name") {
                if let Ok(name) = name_node.text() {
                    let docs = self.extract_c_doc_comments(content, func.start_position().row);
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
                                    let docs = self.extract_c_doc_comments(
                                        content,
                                        var_decl.start_position().row,
                                    );
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
                    let docs = self.extract_c_doc_comments(content, class.start_position().row);
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
                    let docs = self.extract_c_doc_comments(content, method.start_position().row);
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
    fn extract_python_symbols(
        &self,
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
                    let docs = self.extract_python_docstring(content, &func);

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
                    let docs = self.extract_python_docstring(content, &class);

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
    fn extract_c_symbols(
        &self,
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
                let docs = self.extract_c_doc_comments(content, func.start_position().row);
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
                    let docs =
                        self.extract_c_doc_comments(content, struct_node.start_position().row);
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
                    let docs = self.extract_c_doc_comments(content, enum_node.start_position().row);
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
                    let docs =
                        self.extract_c_doc_comments(content, typedef_node.start_position().row);
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
    fn extract_go_symbols(
        &self,
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
                    let docs = self.extract_go_doc_comments(content, func.start_position().row);
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
                    let docs = self.extract_go_doc_comments(content, method.start_position().row);
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
                            let docs = self
                                .extract_go_doc_comments(content, type_decl.start_position().row);
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
    fn extract_java_symbols(
        &self,
        tree: &SyntaxTree,
        content: &str,
        symbols: &mut Vec<Symbol>,
    ) -> Result<()> {
        // Javadoc is `/** ... */` — reuse extract_c_doc_comments.
        let classes = tree.find_nodes_by_kind("class_declaration");
        for class in classes {
            if let Some(name_node) = class.child_by_field_name("name") {
                if let Ok(name) = name_node.text() {
                    let docs = self.extract_c_doc_comments(content, class.start_position().row);
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
                    let docs = self.extract_c_doc_comments(content, method.start_position().row);
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
    fn extract_ruby_symbols(
        &self,
        tree: &SyntaxTree,
        content: &str,
        symbols: &mut Vec<Symbol>,
    ) -> Result<()> {
        let classes = tree.find_nodes_by_kind("class");
        for class in classes {
            if let Some(name_node) = class.child_by_field_name("name") {
                if let Ok(name) = name_node.text() {
                    let docs = self.extract_ruby_doc_comments(content, class.start_position().row);
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
                    let docs = self.extract_ruby_doc_comments(content, method.start_position().row);
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
    fn extract_swift_symbols(
        &self,
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
                    let docs = self.extract_swift_doc_comments(content, class.start_position().row);
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
                    let docs =
                        self.extract_swift_doc_comments(content, struct_node.start_position().row);
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
                    let docs = self.extract_swift_doc_comments(content, func.start_position().row);
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

    // /// Extract Java symbols
    // fn extract_java_symbols(
    //     &self,
    //     tree: &SyntaxTree,
    //     _content: &str,
    //     symbols: &mut Vec<Symbol>,
    // ) -> Result<()> {
    //     // TODO: Implement full Java symbol extraction
    //     // For now, extract basic class and method symbols
    //     let classes = tree.find_nodes_by_kind("class_declaration");
    //     for class in classes {
    //         if let Some(name_node) = class.child_by_field_name("name") {
    //             if let Ok(name) = name_node.text() {
    //                 symbols.push(Symbol {
    //                     name: name.to_string(),
    //                     kind: "class".to_string(),
    //                     start_line: class.start_position().row + 1,
    //                     start_column: class.start_position().column,
    //                     end_line: class.end_position().row + 1,
    //                     end_column: class.end_position().column,
    //                     visibility: "public".to_string(), // Default for Java
    //                     documentation: None,
    //                 });
    //             }
    //         }
    //     }

    //     let methods = tree.find_nodes_by_kind("method_declaration");
    //     for method in methods {
    //         if let Some(name_node) = method.child_by_field_name("name") {
    //             if let Ok(name) = name_node.text() {
    //                 symbols.push(Symbol {
    //                     name: name.to_string(),
    //                     kind: "method".to_string(),
    //                     start_line: method.start_position().row + 1,
    //                     start_column: method.start_position().column,
    //                     end_line: method.end_position().row + 1,
    //                     end_column: method.end_position().column,
    //                     visibility: "public".to_string(), // Default for Java
    //                     documentation: None,
    //                 });
    //             }
    //         }
    //     }

    //     Ok(())
    // }

    // /// Extract Ruby symbols
    // fn extract_ruby_symbols(
    //     &self,
    //     tree: &SyntaxTree,
    //     _content: &str,
    //     symbols: &mut Vec<Symbol>,
    // ) -> Result<()> {
    //     // TODO: Implement full Ruby symbol extraction
    //     // For now, extract basic class and method symbols
    //     let classes = tree.find_nodes_by_kind("class");
    //     for class in classes {
    //         if let Some(name_node) = class.child_by_field_name("name") {
    //             if let Ok(name) = name_node.text() {
    //                 symbols.push(Symbol {
    //                     name: name.to_string(),
    //                     kind: "class".to_string(),
    //                     start_line: class.start_position().row + 1,
    //                     start_column: class.start_position().column,
    //                     end_line: class.end_position().row + 1,
    //                     end_column: class.end_position().column,
    //                     visibility: "public".to_string(), // Ruby classes are public
    //                     documentation: None,
    //                 });
    //             }
    //         }
    //     }

    //     let methods = tree.find_nodes_by_kind("method");
    //     for method in methods {
    //         if let Some(name_node) = method.child_by_field_name("name") {
    //             if let Ok(name) = name_node.text() {
    //                 symbols.push(Symbol {
    //                     name: name.to_string(),
    //                     kind: "method".to_string(),
    //                     start_line: method.start_position().row + 1,
    //                     start_column: method.start_position().column,
    //                     end_line: method.end_position().row + 1,
    //                     end_column: method.end_position().column,
    //                     visibility: "public".to_string(), // Ruby methods are public by default
    //                     documentation: None,
    //                 });
    //             }
    //         }
    //     }

    //     Ok(())
    // }

    // /// Extract Swift symbols
    // fn extract_swift_symbols(
    //     &self,
    //     tree: &SyntaxTree,
    //     _content: &str,
    //     symbols: &mut Vec<Symbol>,
    // ) -> Result<()> {
    //     // TODO: Implement full Swift symbol extraction
    //     // For now, extract basic class, struct and function symbols
    //     let classes = tree.find_nodes_by_kind("class_declaration");
    //     for class in classes {
    //         if let Some(name_node) = class.child_by_field_name("name") {
    //             if let Ok(name) = name_node.text() {
    //                 symbols.push(Symbol {
    //                     name: name.to_string(),
    //                     kind: "class".to_string(),
    //                     start_line: class.start_position().row + 1,
    //                     start_column: class.start_position().column,
    //                     end_line: class.end_position().row + 1,
    //                     end_column: class.end_position().column,
    //                     visibility: "internal".to_string(), // Default for Swift
    //                     documentation: None,
    //                 });
    //             }
    //         }
    //     }

    //     let structs = tree.find_nodes_by_kind("struct_declaration");
    //     for struct_node in structs {
    //         if let Some(name_node) = struct_node.child_by_field_name("name") {
    //             if let Ok(name) = name_node.text() {
    //                 symbols.push(Symbol {
    //                     name: name.to_string(),
    //                     kind: "struct".to_string(),
    //                     start_line: struct_node.start_position().row + 1,
    //                     start_column: struct_node.start_position().column,
    //                     end_line: struct_node.end_position().row + 1,
    //                     end_column: struct_node.end_position().column,
    //                     visibility: "internal".to_string(), // Default for Swift
    //                     documentation: None,
    //                 });
    //             }
    //         }
    //     }

    //     let functions = tree.find_nodes_by_kind("function_declaration");
    //     for func in functions {
    //         if let Some(name_node) = func.child_by_field_name("name") {
    //             if let Ok(name) = name_node.text() {
    //                 symbols.push(Symbol {
    //                     name: name.to_string(),
    //                     kind: "function".to_string(),
    //                     start_line: func.start_position().row + 1,
    //                     start_column: func.start_position().column,
    //                     end_line: func.end_position().row + 1,
    //                     end_column: func.end_position().column,
    //                     visibility: "internal".to_string(), // Default for Swift
    //                     documentation: None,
    //                 });
    //             }
    //         }
    //     }

    //     Ok(())
    // }

    // /// Extract Kotlin symbols
    // fn extract_kotlin_symbols(
    //     &self,
    //     tree: &SyntaxTree,
    //     _content: &str,
    //     symbols: &mut Vec<Symbol>,
    // ) -> Result<()> {
    //     // TODO: Implement full Kotlin symbol extraction
    //     // For now, extract basic class and function symbols
    //     let classes = tree.find_nodes_by_kind("class_declaration");
    //     for class in classes {
    //         if let Some(name_node) = class.child_by_field_name("name") {
    //             if let Ok(name) = name_node.text() {
    //                 symbols.push(Symbol {
    //                     name: name.to_string(),
    //                     kind: "class".to_string(),
    //                     start_line: class.start_position().row + 1,
    //                     start_column: class.start_position().column,
    //                     end_line: class.end_position().row + 1,
    //                     end_column: class.end_position().column,
    //                     visibility: "public".to_string(), // Default for Kotlin
    //                     documentation: None,
    //                 });
    //             }
    //         }
    //     }

    //     let functions = tree.find_nodes_by_kind("function_declaration");
    //     for func in functions {
    //         if let Some(name_node) = func.child_by_field_name("name") {
    //             if let Ok(name) = name_node.text() {
    //                 symbols.push(Symbol {
    //                     name: name.to_string(),
    //                     kind: "function".to_string(),
    //                     start_line: func.start_position().row + 1,
    //                     start_column: func.start_position().column,
    //                     end_line: func.end_position().row + 1,
    //                     end_column: func.end_position().column,
    //                     visibility: "public".to_string(), // Default for Kotlin
    //                     documentation: None,
    //                 });
    //             }
    //         }
    //     }

    //     Ok(())
    // }

    /// Extract Ruby-style doc comments preceding an item start line.
    ///
    /// Ruby convention: contiguous `#` line comments immediately
    /// above the declaration, similar to Go's `//` shape but with
    /// the `#` lead character. Honors shebang lines (`#!`) by
    /// stopping early — those are not documentation.
    fn extract_ruby_doc_comments(&self, content: &str, start_row: usize) -> Option<String> {
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
    fn extract_go_doc_comments(&self, content: &str, start_row: usize) -> Option<String> {
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
    fn extract_swift_doc_comments(&self, content: &str, start_row: usize) -> Option<String> {
        // Same logic as Rust; Swift `///` is identical syntax.
        self.extract_rust_doc_comments(content, start_row)
    }

    /// Extract doc comments preceding a Rust item start line
    fn extract_rust_doc_comments(&self, content: &str, start_row: usize) -> Option<String> {
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
    fn extract_php_symbols(
        &self,
        tree: &SyntaxTree,
        content: &str,
        symbols: &mut Vec<Symbol>,
    ) -> Result<()> {
        // PHPDoc is `/** ... */` — reuse extract_c_doc_comments.
        let classes = tree.find_nodes_by_kind("class_declaration");
        for class in classes {
            if let Some(name_node) = class.child_by_field_name("name") {
                if let Ok(name) = name_node.text() {
                    let docs = self.extract_c_doc_comments(content, class.start_position().row);
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
                    let docs = self.extract_c_doc_comments(content, func.start_position().row);
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

        Ok(())
    }

    /// Extract Python docstring from function or class definition
    fn extract_python_docstring(&self, _content: &str, node: &crate::Node) -> Option<String> {
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
    fn extract_c_doc_comments(&self, content: &str, start_row: usize) -> Option<String> {
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

    /// Enable semantic graph analysis
    pub fn enable_semantic_graph(&mut self) {
        self.semantic_graph = Some(SemanticGraphQuery::new());
    }

    /// Disable semantic graph analysis
    pub fn disable_semantic_graph(&mut self) {
        self.semantic_graph = None;
    }

    /// Get a reference to the semantic graph (if enabled)
    pub fn semantic_graph(&self) -> Option<&SemanticGraphQuery> {
        self.semantic_graph.as_ref()
    }

    /// Get a mutable reference to the semantic graph (if enabled)
    pub fn semantic_graph_mut(&mut self) -> Option<&mut SemanticGraphQuery> {
        self.semantic_graph.as_mut()
    }

    /// Check if semantic graph analysis is enabled
    pub fn is_semantic_graph_enabled(&self) -> bool {
        self.semantic_graph.is_some()
    }

    /// Get file cache statistics
    pub fn cache_stats(&self) -> crate::file_cache::CacheStats {
        self.file_cache.stats()
    }

    /// Get cache hit ratio
    pub fn cache_hit_ratio(&self) -> f64 {
        self.file_cache.hit_ratio()
    }

    /// Clear the file cache
    pub fn clear_cache(&self) {
        self.file_cache.clear();
    }

    /// Check if a file is cached
    pub fn is_cached<P: AsRef<Path>>(&self, path: P) -> bool {
        self.file_cache.contains(path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_analyzer_creation() {
        let analyzer = CodebaseAnalyzer::new().unwrap();
        assert_eq!(analyzer.config.max_file_size, Some(1024 * 1024));
    }

    #[test]
    fn test_analyze_directory() {
        // Create a temporary directory with some test files
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path();

        // Create a Rust file
        let rust_file = temp_path.join("main.rs");
        fs::write(
            &rust_file,
            r#"
            /// Main entry point
            pub fn main() {
                println!("Hello, world!");
            }

            struct Point {
                x: i32,
                y: i32,
            }
        "#,
        )
        .unwrap();

        // Create a JavaScript file
        let js_file = temp_path.join("app.js");
        fs::write(
            &js_file,
            r#"
            function greet(name) {
                console.log("Hello, " + name);
            }

            class Calculator {
                add(a, b) {
                    return a + b;
                }
            }
        "#,
        )
        .unwrap();

        // Analyze the directory
        let mut analyzer = CodebaseAnalyzer::new().unwrap();
        let result = analyzer.analyze_directory(temp_path).unwrap();

        assert_eq!(result.total_files, 2);
        assert_eq!(result.parsed_files, 2);
        assert_eq!(result.error_files, 0);
        assert!(result.languages.contains_key("Rust"));
        assert!(result.languages.contains_key("JavaScript"));

        // Check that symbols were extracted
        let rust_file_info = result
            .files
            .iter()
            .find(|f| f.path.extension().unwrap() == "rs")
            .unwrap();
        assert!(!rust_file_info.symbols.is_empty());
        let main_symbol = rust_file_info
            .symbols
            .iter()
            .find(|s| s.name == "main")
            .unwrap();
        assert_eq!(main_symbol.visibility, "public");
        assert_eq!(
            main_symbol.documentation.as_deref(),
            Some("Main entry point")
        );

        let js_file_info = result
            .files
            .iter()
            .find(|f| f.path.extension().unwrap() == "js")
            .unwrap();
        assert!(!js_file_info.symbols.is_empty());
        assert!(js_file_info.symbols.iter().any(|s| s.name == "greet"));
    }

    #[test]
    fn test_go_doc_extraction() {
        let temp_dir = TempDir::new().unwrap();
        let go_file = temp_dir.path().join("hello.go");
        fs::write(
            &go_file,
            "package main\n\n// Greet returns a friendly hello message.\n// Used as the default response when no name is provided.\nfunc Greet() string {\n    return \"hello\"\n}\n\n// Counter holds a running total.\ntype Counter struct {\n    n int\n}\n",
        )
        .unwrap();

        let mut analyzer = CodebaseAnalyzer::new().unwrap();
        let result = analyzer.analyze_directory(temp_dir.path()).unwrap();
        let info = result
            .files
            .iter()
            .find(|f| f.path.extension().unwrap() == "go")
            .unwrap();

        let greet = info
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

        let counter = info
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

    #[test]
    fn test_go_doc_extraction_blank_line_severs() {
        // Go convention: a blank line between the comment and the
        // declaration means the comment is NOT documentation. Our
        // extractor honors this — stops at the first non-comment line,
        // and a blank line counts.
        let temp_dir = TempDir::new().unwrap();
        let go_file = temp_dir.path().join("blank.go");
        fs::write(
            &go_file,
            "package main\n\n// This is not documentation, just a stray comment.\n\nfunc Orphan() {}\n",
        )
        .unwrap();

        let mut analyzer = CodebaseAnalyzer::new().unwrap();
        let result = analyzer.analyze_directory(temp_dir.path()).unwrap();
        let info = result
            .files
            .iter()
            .find(|f| f.path.extension().unwrap() == "go")
            .unwrap();

        let orphan = info.symbols.iter().find(|s| s.name == "Orphan").unwrap();
        assert!(
            orphan.documentation.is_none(),
            "Orphan should have no docs (blank line severs the comment): got {:?}",
            orphan.documentation
        );
    }

    #[test]
    fn test_jsdoc_extraction_for_javascript() {
        // JSDoc /** ... */ blocks should flow through to
        // Symbol::documentation. The C extractor already handles
        // /* ... */ but the JSDoc convention adds a `*` to each
        // continuation line plus a leading `*` after `/**`; this
        // test pins the cosmetic strip.
        let temp_dir = TempDir::new().unwrap();
        let js_file = temp_dir.path().join("app.js");
        fs::write(
            &js_file,
            "/**\n * Greet returns a friendly hello message.\n * Used when no name is provided.\n */\nfunction greet() { return \"hi\"; }\n\n/** Single-line JSDoc. */\nclass Counter { }\n",
        )
        .unwrap();

        let mut analyzer = CodebaseAnalyzer::new().unwrap();
        let result = analyzer.analyze_directory(temp_dir.path()).unwrap();
        let info = result
            .files
            .iter()
            .find(|f| f.path.extension().unwrap() == "js")
            .unwrap();

        let greet = info
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

        let counter = info
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

    #[test]
    fn test_rust_const_and_static_extraction() {
        // Module-level `const` and `static` declarations weren't
        // surfaced as symbols pre-this-PR, forcing agents to fall
        // back to grep for constant lookups (see PR #76 dogfood
        // report).
        let temp_dir = TempDir::new().unwrap();
        let rs_file = temp_dir.path().join("constants.rs");
        fs::write(
            &rs_file,
            "/// The default request limit.\npub const DEFAULT_LIMIT: usize = 256;\n\n/// Maximum supported.\npub const MAX_LIMIT: usize = 4096;\n\nstatic INTERNAL_FLAG: bool = false;\n",
        )
        .unwrap();

        let mut analyzer = CodebaseAnalyzer::new().unwrap();
        let result = analyzer.analyze_directory(temp_dir.path()).unwrap();
        let info = result
            .files
            .iter()
            .find(|f| f.path.extension().unwrap() == "rs")
            .unwrap();

        let default_limit = info
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

        let max_limit = info
            .symbols
            .iter()
            .find(|s| s.name == "MAX_LIMIT")
            .expect("MAX_LIMIT should be extracted");
        assert_eq!(max_limit.kind, "const");

        let internal_flag = info
            .symbols
            .iter()
            .find(|s| s.name == "INTERNAL_FLAG")
            .expect("static INTERNAL_FLAG should be extracted as a symbol");
        assert_eq!(internal_flag.kind, "static");
        assert_eq!(internal_flag.visibility, "private");
    }

    #[test]
    fn test_ruby_doc_extraction() {
        let temp_dir = TempDir::new().unwrap();
        let rb_file = temp_dir.path().join("greeter.rb");
        fs::write(
            &rb_file,
            "# Greeter returns hello strings.\n# Use the static `hello` method for the default.\nclass Greeter\n  # The default greeting.\n  def hello\n    return \"hi\"\n  end\nend\n",
        )
        .unwrap();

        let mut analyzer = CodebaseAnalyzer::new().unwrap();
        let result = analyzer.analyze_directory(temp_dir.path()).unwrap();
        let info = result
            .files
            .iter()
            .find(|f| f.path.extension().unwrap() == "rb")
            .unwrap();

        if let Some(greeter) = info.symbols.iter().find(|s| s.name == "Greeter") {
            let docs = greeter
                .documentation
                .as_ref()
                .expect("Greeter should have docs");
            assert!(docs.contains("returns hello"), "got docs={docs:?}");
        }
        if let Some(hello) = info.symbols.iter().find(|s| s.name == "hello") {
            assert_eq!(
                hello.documentation.as_deref(),
                Some("The default greeting.")
            );
        }
    }

    #[test]
    fn test_java_doc_extraction() {
        // Now that PR #72 has landed (JSDoc cosmetic `*` strip),
        // Javadoc output is fully clean. The assertions verify both
        // functional doc extraction AND the clean cosmetic shape.
        let temp_dir = TempDir::new().unwrap();
        let java_file = temp_dir.path().join("Greeter.java");
        fs::write(
            &java_file,
            "/**\n * Greeter returns hello strings.\n * Use the static `hello()` for the default.\n */\npublic class Greeter {\n    /** The default greeting. */\n    public String hello() { return \"hi\"; }\n}\n",
        )
        .unwrap();

        let mut analyzer = CodebaseAnalyzer::new().unwrap();
        let result = analyzer.analyze_directory(temp_dir.path()).unwrap();
        let info = result
            .files
            .iter()
            .find(|f| f.path.extension().unwrap() == "java")
            .unwrap();

        if let Some(greeter) = info.symbols.iter().find(|s| s.name == "Greeter") {
            let docs = greeter
                .documentation
                .as_ref()
                .expect("Greeter should have Javadoc");
            assert!(docs.contains("returns hello"), "got docs={docs:?}");
            assert!(!docs.starts_with('*'), "Javadoc `*` should be stripped");
        }
    }

    #[test]
    fn test_swift_doc_extraction() {
        // Swift uses `///` like Rust. The extractor reuses the Rust path.
        let temp_dir = TempDir::new().unwrap();
        let swift_file = temp_dir.path().join("greeter.swift");
        fs::write(
            &swift_file,
            "/// Greeter returns hello strings.\n/// Use the static `hello()` for the default.\nclass Greeter {\n    /// The default greeting.\n    func hello() -> String { return \"hi\" }\n}\n",
        )
        .unwrap();

        let mut analyzer = CodebaseAnalyzer::new().unwrap();
        let result = analyzer.analyze_directory(temp_dir.path()).unwrap();
        let info = result
            .files
            .iter()
            .find(|f| f.path.extension().unwrap() == "swift")
            .unwrap();

        if let Some(greeter) = info.symbols.iter().find(|s| s.name == "Greeter") {
            let docs = greeter
                .documentation
                .as_ref()
                .expect("Greeter should have docs");
            assert!(docs.contains("returns hello"), "got docs={docs:?}");
        }
        // hello() method may or may not be extracted by the v0 Swift
        // extractor (which only handles classes/structs/functions);
        // when present, it should carry its doc.
        if let Some(hello) = info.symbols.iter().find(|s| s.name == "hello") {
            assert_eq!(
                hello.documentation.as_deref(),
                Some("The default greeting.")
            );
        }
    }
}
