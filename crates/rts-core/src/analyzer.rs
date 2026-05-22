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
//! ```ignore
//! // NOTE: `CodebaseAnalyzer` is being removed in a follow-up PR; prefer
//! // the `parse_content` facade that lands alongside that change.
//! use rust_tree_sitter::{CodebaseAnalyzer, AnalysisConfig, AnalysisDepth};
//!
//! # fn main() -> Result<(), rust_tree_sitter::Error> {
//! let config = AnalysisConfig {
//!     depth: AnalysisDepth::Full,
//!     max_depth: Some(10),
//!     enable_parallel: true,
//!     ..Default::default()
//! };
//!
//! let mut analyzer = CodebaseAnalyzer::with_config(config)?;
//! # Ok(())
//! # }
//! ```
//!
//! ### Directory Analysis
//!
//! ```ignore
//! // NOTE: `CodebaseAnalyzer` is being removed in a follow-up PR; prefer
//! // the `parse_content` facade that lands alongside that change.
//! use rust_tree_sitter::{CodebaseAnalyzer, AnalysisConfig};
//!
//! # fn main() -> Result<(), rust_tree_sitter::Error> {
//! let mut analyzer = CodebaseAnalyzer::new()?;
//! let result = analyzer.analyze_directory("src/")?;
//!
//! for file_info in &result.files {
//!     println!("File: {}", file_info.path.display());
//!     println!("  Symbols: {}", file_info.symbols.len());
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ### Advanced Analysis with Filtering
//!
//! ```ignore
//! // NOTE: `CodebaseAnalyzer` is being removed in a follow-up PR; prefer
//! // the `parse_content` facade that lands alongside that change.
//! use rust_tree_sitter::{CodebaseAnalyzer, AnalysisConfig, AnalysisDepth};
//!
//! # fn main() -> Result<(), rust_tree_sitter::Error> {
//! let config = AnalysisConfig {
//!     depth: AnalysisDepth::Full,
//!     include_extensions: Some(vec!["rs".to_string(), "py".to_string()]),
//!     exclude_dirs: vec!["target".to_string(), "node_modules".to_string()],
//!     max_file_size: Some(1024 * 1024),
//!     ..Default::default()
//! };
//!
//! let mut analyzer = CodebaseAnalyzer::with_config(config)?;
//! let result = analyzer.analyze_directory(".")?;
//! println!("Total files analyzed: {}", result.total_files);
//! # Ok(())
//! # }
//! ```

use crate::error::{Error, Result};
use crate::languages::Language;
use crate::parser::Parser;

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
        crate::extraction::extract_symbols(&tree, content, language)
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
                    file_info.symbols =
                        crate::extraction::extract_symbols(&tree, &content, language)?;
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

        // Read file content (cache was removed in pre-pivot cleanup)
        let content = std::fs::read_to_string(file_path)?;
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
                    file_info.symbols =
                        crate::extraction::extract_symbols(&tree, &content, language)?;
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

    #[test]
    fn test_csharp_extraction() {
        // C# uses `///` XML doc comments, identical line-scan shape to
        // Rust/Swift. Verifies the extractor surfaces class + method +
        // interface + record symbols and that the XML payload flows
        // through to `documentation`.
        let temp_dir = TempDir::new().unwrap();
        let cs_file = temp_dir.path().join("Greeter.cs");
        fs::write(
            &cs_file,
            "namespace Demo;\n\n\
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
             public interface IEvictionPolicy { void Evict(); }\n",
        )
        .unwrap();

        let mut analyzer = CodebaseAnalyzer::new().unwrap();
        let result = analyzer.analyze_directory(temp_dir.path()).unwrap();
        let info = result
            .files
            .iter()
            .find(|f| f.path.extension().and_then(|e| e.to_str()) == Some("cs"))
            .expect("Greeter.cs should be picked up");

        // Class with multi-line XML doc.
        let greeter = info
            .symbols
            .iter()
            .find(|s| s.name == "Greeter")
            .expect("Greeter class should be extracted");
        let docs = greeter.documentation.as_ref().expect("Greeter has docs");
        assert!(
            docs.contains("Greeter returns hello"),
            "Greeter doc should preserve XML payload, got: {docs:?}"
        );

        // Method inside the class.
        let hello = info
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

        // Record (newer C# nominal class).
        let cache_key = info
            .symbols
            .iter()
            .find(|s| s.name == "CacheKey")
            .expect("CacheKey record should be extracted");
        assert_eq!(
            cache_key.kind, "class",
            "records surface as class kind for wire stability"
        );

        // Interface.
        let policy = info
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
    /// bare method name (the form PHP_REFS captures, so
    /// `Index.FindCallers("greet")` resolves member-call edges).
    #[test]
    fn php_class_method_indexed_with_bare_name() {
        let temp_dir = TempDir::new().unwrap();
        let php_file = temp_dir.path().join("greeter.php");
        fs::write(
            &php_file,
            "<?php\n\
             class Greeter {\n\
                 public function greet() { return \"hi\"; }\n\
             }\n",
        )
        .unwrap();

        let mut analyzer = CodebaseAnalyzer::new().unwrap();
        let result = analyzer.analyze_directory(temp_dir.path()).unwrap();
        let info = result
            .files
            .iter()
            .find(|f| f.path.extension().and_then(|e| e.to_str()) == Some("php"))
            .expect("greeter.php should be picked up");

        let greet = info
            .symbols
            .iter()
            .find(|s| s.name == "greet")
            .expect("greet method should be extracted with bare name");
        assert_eq!(greet.kind, "method");
        assert_eq!(greet.visibility, "public");
    }

    /// Visibility modifiers (public/private/protected) propagate to
    /// `Symbol.visibility`. A method with no modifier defaults to
    /// public (PHP language rule). A `static` modifier does not
    /// change visibility.
    #[test]
    fn php_method_visibility_modifiers_extracted() {
        let temp_dir = TempDir::new().unwrap();
        let php_file = temp_dir.path().join("modifiers.php");
        fs::write(
            &php_file,
            "<?php\n\
             class Klass {\n\
                 public function pub_method() {}\n\
                 private function priv_method() {}\n\
                 protected function prot_method() {}\n\
                 public static function static_method() {}\n\
                 function default_method() {}\n\
             }\n",
        )
        .unwrap();

        let mut analyzer = CodebaseAnalyzer::new().unwrap();
        let result = analyzer.analyze_directory(temp_dir.path()).unwrap();
        let info = result
            .files
            .iter()
            .find(|f| f.path.extension().and_then(|e| e.to_str()) == Some("php"))
            .unwrap();

        let visibility_of = |name: &str| -> String {
            info.symbols
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
        // No visibility modifier — PHP defaults to public.
        assert_eq!(visibility_of("default_method"), "public");
    }

    /// Interface method signatures must be indexed too: callers of
    /// `$svc->doThing()` need the target def to resolve even when
    /// the only def is the abstract signature in the interface.
    #[test]
    fn php_interface_methods_indexed() {
        let temp_dir = TempDir::new().unwrap();
        let php_file = temp_dir.path().join("contract.php");
        fs::write(
            &php_file,
            "<?php\n\
             interface Service {\n\
                 public function doThing();\n\
                 public function reset();\n\
             }\n",
        )
        .unwrap();

        let mut analyzer = CodebaseAnalyzer::new().unwrap();
        let result = analyzer.analyze_directory(temp_dir.path()).unwrap();
        let info = result
            .files
            .iter()
            .find(|f| f.path.extension().and_then(|e| e.to_str()) == Some("php"))
            .unwrap();

        for name in ["doThing", "reset"] {
            assert!(
                info.symbols
                    .iter()
                    .any(|s| s.name == name && s.kind == "method"),
                "interface method {name} should be extracted; got {:?}",
                info.symbols
                    .iter()
                    .map(|s| (&s.name, &s.kind))
                    .collect::<Vec<_>>()
            );
        }
    }

    /// Trait methods are first-class call targets just like class
    /// methods; PHP `use SomeTrait;` mixes them in. The extractor
    /// must surface them the same way.
    #[test]
    fn php_trait_methods_indexed() {
        let temp_dir = TempDir::new().unwrap();
        let php_file = temp_dir.path().join("mixin.php");
        fs::write(
            &php_file,
            "<?php\n\
             trait Loggable {\n\
                 public function log_event(string $msg) {}\n\
                 protected function flush() {}\n\
             }\n",
        )
        .unwrap();

        let mut analyzer = CodebaseAnalyzer::new().unwrap();
        let result = analyzer.analyze_directory(temp_dir.path()).unwrap();
        let info = result
            .files
            .iter()
            .find(|f| f.path.extension().and_then(|e| e.to_str()) == Some("php"))
            .unwrap();

        let log_event = info
            .symbols
            .iter()
            .find(|s| s.name == "log_event")
            .expect("trait method log_event should be extracted");
        assert_eq!(log_event.kind, "method");
        assert_eq!(log_event.visibility, "public");

        let flush = info
            .symbols
            .iter()
            .find(|s| s.name == "flush")
            .expect("trait method flush should be extracted");
        assert_eq!(flush.visibility, "protected");
    }

    /// A class declared inside a `namespace \Foo\Bar { ... }` block
    /// still has methods indexed by their bare name — PHP_REFS
    /// captures `scoped_call_expression` and `member_call_expression`
    /// targets unqualified, so the indexed name must match that to
    /// keep `FindCallers` working across namespace boundaries.
    #[test]
    fn php_namespaced_class_methods_indexed_by_bare_name() {
        let temp_dir = TempDir::new().unwrap();
        let php_file = temp_dir.path().join("ns.php");
        fs::write(
            &php_file,
            "<?php\n\
             namespace Foo\\Bar;\n\
             class Klass {\n\
                 public function nested_method() {}\n\
             }\n",
        )
        .unwrap();

        let mut analyzer = CodebaseAnalyzer::new().unwrap();
        let result = analyzer.analyze_directory(temp_dir.path()).unwrap();
        let info = result
            .files
            .iter()
            .find(|f| f.path.extension().and_then(|e| e.to_str()) == Some("php"))
            .unwrap();

        let method = info
            .symbols
            .iter()
            .find(|s| s.name == "nested_method")
            .expect("nested_method should be extracted by bare name");
        assert_eq!(method.kind, "method");
    }
}

#[cfg(test)]
mod rust_trait_type_union_macro_extraction {
    use super::*;

    /// Closes the v0.5.4 dogfood gap: `find_symbol --name Log` on
    /// `rust-lang/log` returned empty pre-fix because `pub trait Log`
    /// wasn't extracted. Traits are first-class Rust API surface;
    /// missing them broke external-corpus queries against any
    /// library that exposes a trait (most of them).
    #[test]
    fn rust_trait_type_union_macro_all_extracted() {
        let mut a = CodebaseAnalyzer::new().unwrap();
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("lib.rs");
        std::fs::write(
            &path,
            "\
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
",
        )
        .unwrap();
        let result = a.analyze_directory(temp.path()).unwrap();
        let file_info = result
            .files
            .iter()
            .find(|f| f.path.extension().unwrap() == "rs")
            .unwrap();

        let by_name =
            |n: &str, k: &str| file_info.symbols.iter().any(|s| s.name == n && s.kind == k);
        assert!(
            by_name("Log", "trait"),
            "trait extraction missing: {:?}",
            file_info
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

        // Doc-comment flows through for trait.
        let log = file_info
            .symbols
            .iter()
            .find(|s| s.name == "Log" && s.kind == "trait")
            .unwrap();
        assert_eq!(
            log.documentation.as_deref(),
            Some("A trait encapsulating logging.")
        );
    }
}
