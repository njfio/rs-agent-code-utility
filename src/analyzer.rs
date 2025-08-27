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
//!     println!("  Security issues: {}", file_info.security_vulnerabilities.len());
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
//! println!("Security issues found: {}", result.files.iter().map(|f| f.security_vulnerabilities.len()).sum::<usize>());
//! # Ok(())
//! # }
//! ```

use crate::error::{Error, Result};
use crate::languages::Language;
use crate::parser::Parser;
use crate::advanced_security::{AdvancedSecurityAnalyzer, SecurityVulnerability};
use crate::semantic_graph::SemanticGraphQuery;
use crate::file_cache::FileCache;

use crate::tree::SyntaxTree;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use rayon::prelude::*;
use ignore::WalkBuilder;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Depth level for analysis
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum AnalysisDepth {
    /// Only collect basic file metadata without parsing
    Basic,
    /// Parse files but skip symbol extraction
    Deep,
    /// Full parsing with symbol extraction
    Full,
}

impl Default for AnalysisDepth {
    fn default() -> Self {
        AnalysisDepth::Full
    }
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
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
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
    /// Enable security analysis (OWASP, taint) during file analysis
    pub enable_security: bool,
}

impl Default for AnalysisConfig {
    fn default() -> Self {
        Self {
            max_file_size: Some(1024 * 1024), // 1MB default
            include_extensions: None,
            exclude_extensions: vec![
                "exe".to_string(), "bin".to_string(), "so".to_string(), "dll".to_string(),
                "png".to_string(), "jpg".to_string(), "jpeg".to_string(), "gif".to_string(),
                "pdf".to_string(), "zip".to_string(), "tar".to_string(), "gz".to_string(),
            ],
            exclude_dirs: vec![
                ".git".to_string(), "node_modules".to_string(), "target".to_string(),
                ".vscode".to_string(), ".idea".to_string(), "build".to_string(),
                "dist".to_string(), "__pycache__".to_string(), ".pytest_cache".to_string(),
            ],
            follow_symlinks: false,
            max_depth: Some(20),
            include_hidden: false,
            depth: AnalysisDepth::Full,
            enable_parallel: true,
            thread_count: None, // Auto-detect
            parallel_threshold: 10, // Enable parallel processing for 10+ files
            enable_security: false,
        }
    }
}

/// Information about a parsed file
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
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
    /// Security vulnerabilities found in this file
    pub security_vulnerabilities: Vec<SecurityVulnerability>,
}

/// A code symbol (function, class, struct, etc.)
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
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
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
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
pub struct CodebaseAnalyzer {
    config: AnalysisConfig,
    parsers: HashMap<Language, Parser>,
    security_analyzer: AdvancedSecurityAnalyzer,
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
            security_analyzer: AdvancedSecurityAnalyzer::new()?,
            semantic_graph: None,
            file_cache: FileCache::new(),
        })
    }

    /// Get or create a parser for the given language
    fn get_parser(&mut self, language: Language) -> Result<&Parser> {
        if !self.parsers.contains_key(&language) {
            let parser = Parser::new(language)?;
            self.parsers.insert(language, parser);
        }
        self.parsers.get(&language)
            .ok_or_else(|| Error::internal_error("analyzer", format!("Parser for {} should exist after insertion", language.name())))
    }

    /// Analyze a single file and return structured results
    pub fn analyze_file<P: AsRef<Path>>(&mut self, file_path: P) -> Result<AnalysisResult> {
        let file_path = file_path.as_ref();

        if !file_path.exists() {
            return Err(Error::invalid_input_error("file path", &file_path.display().to_string(), "existing file"));
        }

        if !file_path.is_file() {
            return Err(Error::invalid_input_error("path type", &file_path.display().to_string(), "file (not directory)"));
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
            return Err(Error::invalid_input_error("directory path", &root_path.display().to_string(), "existing directory"));
        }

        if !root_path.is_dir() {
            return Err(Error::invalid_input_error("path type", &root_path.display().to_string(), "directory (not file)"));
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
    fn analyze_directory_parallel(&self, root_path: PathBuf, file_paths: Vec<PathBuf>) -> Result<AnalysisResult> {
        // Set up thread pool if custom thread count is specified
        if let Some(thread_count) = self.config.thread_count {
            rayon::ThreadPoolBuilder::new()
                .num_threads(thread_count)
                .build_global()
                .map_err(|e| Error::internal_error("thread_pool", format!("Failed to set thread count: {}", e)))?;
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
                        eprintln!("Warning: Failed to analyze file {}: {}", file_path.display(), e);
                        None
                    }
                }
            })
            .collect();

        // Aggregate results
        let mut final_result = result.lock()
            .map_err(|e| crate::error::Error::internal_error("analyzer", format!("Failed to acquire lock for result aggregation: {}", e)))?;
        for file_info in file_infos {
            final_result.total_files += 1;
            final_result.total_lines += file_info.lines;

            if file_info.parsed_successfully {
                final_result.parsed_files += 1;
            } else {
                final_result.error_files += 1;
            }

            *final_result.languages.entry(file_info.language.clone()).or_insert(0) += 1;
            final_result.files.push(file_info);
        }

        let result = final_result.clone();
        drop(final_result); // Release the lock

        // Build semantic graph if enabled (sequential for now due to complexity)
        if self.semantic_graph.is_some() {
            // Note: Semantic graph building is kept sequential for now
            // as it requires complex coordination between threads
            eprintln!("Note: Semantic graph building is performed sequentially even in parallel mode");
        }

        Ok(result)
    }

    /// Collect all files to be analyzed recursively
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

        let entries = fs::read_dir(current_path)
            .map_err(|e| Error::internal_error_with_context("file_system", format!("Failed to read directory: {}", e), current_path.display().to_string()))?;

        for entry in entries {
            let entry = entry.map_err(|e| Error::internal_error("file_system", format!("Failed to read directory entry: {}", e)))?;
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

        let entries = fs::read_dir(current_path)
            .map_err(|e| Error::internal_error_with_context("file_system", format!("Failed to read directory: {}", e), current_path.display().to_string()))?;

        for entry in entries {
            let entry = entry.map_err(|e| Error::internal_error("file_system", format!("Failed to read directory entry: {}", e)))?;
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
    fn analyze_file_standalone(&self, file_path: &Path, root_path: &Path) -> Result<Option<FileInfo>> {
        // Get file extension
        let extension = file_path.extension()
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
        let relative_path = file_path.strip_prefix(root_path)
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
                security_vulnerabilities: Vec::new(),
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
            security_vulnerabilities: Vec::new(),
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

                // Perform security analysis for Deep and Full depth if enabled
                if self.config.enable_security && matches!(self.config.depth, AnalysisDepth::Deep | AnalysisDepth::Full) {
                    // Create a temporary FileInfo for security analysis with full path
                    let temp_file_info = FileInfo {
                        path: file_path.to_path_buf(), // Use full path for security analysis
                        language: file_info.language.clone(),
                        size: file_info.size,
                        lines: file_info.lines,
                        parsed_successfully: file_info.parsed_successfully,
                        parse_errors: file_info.parse_errors.clone(),
                        symbols: file_info.symbols.clone(),
                        security_vulnerabilities: Vec::new(),
                    };

                    // Create a new security analyzer for this thread
                    let security_analyzer = AdvancedSecurityAnalyzer::new()
                        .map_err(|e| Error::internal_error("security_analyzer", format!("Failed to create security analyzer: {}", e)))?;

                    match security_analyzer.detect_owasp_vulnerabilities(&temp_file_info) {
                        Ok(vulnerabilities) => {
                            // Update the vulnerabilities to use relative paths for consistency
                            let mut updated_vulnerabilities = vulnerabilities;
                            for vuln in &mut updated_vulnerabilities {
                                vuln.location.file = relative_path.clone();
                            }
                            file_info.security_vulnerabilities = updated_vulnerabilities;
                        }
                        Err(e) => {
                            eprintln!("Warning: Security analysis failed for {}: {}", file_path.display(), e);
                        }
                    }
                }
            }
            Err(e) => {
                file_info.parse_errors.push(e.to_string());
            }
        }

        Ok(Some(file_info))
    }

    /// Analyze a single file (internal method)
    fn analyze_file_internal(&mut self, file_path: &Path, root_path: &Path, result: &mut AnalysisResult) -> Result<()> {
        // Get file extension
        let extension = file_path.extension()
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
        let relative_path = file_path.strip_prefix(root_path)
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
                security_vulnerabilities: Vec::new(),
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
            security_vulnerabilities: Vec::new(),
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

                // Perform security analysis for Deep and Full depth if enabled
                if self.config.enable_security && matches!(self.config.depth, AnalysisDepth::Deep | AnalysisDepth::Full) {
                    // Create a temporary FileInfo for security analysis with full path
                    let temp_file_info = FileInfo {
                        path: file_path.to_path_buf(), // Use full path for security analysis
                        language: file_info.language.clone(),
                        size: file_info.size,
                        lines: file_info.lines,
                        parsed_successfully: file_info.parsed_successfully,
                        parse_errors: file_info.parse_errors.clone(),
                        symbols: file_info.symbols.clone(),
                        security_vulnerabilities: Vec::new(),
                    };

                    match self.security_analyzer.detect_owasp_vulnerabilities(&temp_file_info) {
                        Ok(vulnerabilities) => {
                            // Update the vulnerabilities to use relative paths for consistency
                            let mut updated_vulnerabilities = vulnerabilities;
                            for vuln in &mut updated_vulnerabilities {
                                vuln.location.file = relative_path.clone();
                            }
                            file_info.security_vulnerabilities = updated_vulnerabilities;
                        }
                        Err(e) => {
                            eprintln!("Warning: Security analysis failed for {}: {}", file_path.display(), e);
                        }
                    }
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
    fn extract_symbols(&self, tree: &SyntaxTree, content: &str, language: Language) -> Result<Vec<Symbol>> {
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
        }

        Ok(symbols)
    }

    /// Extract Rust symbols
    fn extract_rust_symbols(&self, tree: &SyntaxTree, content: &str, symbols: &mut Vec<Symbol>) -> Result<()> {
        // Extract functions
        let functions = tree.find_nodes_by_kind("function_item");
        for func in functions {
            if let Some(name_node) = func.child_by_field_name("name") {
                if let Ok(name) = name_node.text() {
                    let visibility = if func.children().iter().any(|child| child.kind() == "visibility_modifier") {
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
                    let visibility = if struct_node.children().iter().any(|child| child.kind() == "visibility_modifier") {
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
                    let visibility = if enum_node.children().iter().any(|child| child.kind() == "visibility_modifier") {
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

        // Extract let declarations as variable symbols (best-effort)
        let lets = tree.find_nodes_by_kind("let_declaration");
        for let_node in lets {
            // Try to find an identifier within the pattern
            let ids = let_node.find_descendants(|n| n.kind() == "identifier");
            let name = ids
                .get(0)
                .and_then(|n| n.text().ok())
                .map(|s| s.to_string())
                .unwrap_or_else(|| format!("var@{}:{}", let_node.start_position().row + 1, let_node.start_position().column));

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

        Ok(())
    }

    /// Extract JavaScript symbols
    fn extract_javascript_symbols(&self, tree: &SyntaxTree, content: &str, symbols: &mut Vec<Symbol>) -> Result<()> {
        // Extract function declarations
        let functions = tree.find_nodes_by_kind("function_declaration");
        for func in functions {
            if let Some(name_node) = func.child_by_field_name("name") {
                if let Ok(name) = name_node.text() {
                    let docs = self.extract_js_doc_comments(content, func.start_position().row);
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
                                    let docs = self.extract_js_doc_comments(content, var_decl.start_position().row);
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
                    let docs = self.extract_js_doc_comments(content, class.start_position().row);
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
                    let docs = self.extract_js_doc_comments(content, method.start_position().row);
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
    fn extract_python_symbols(&self, tree: &SyntaxTree, content: &str, symbols: &mut Vec<Symbol>) -> Result<()> {
        // Extract function definitions
        let functions = tree.find_nodes_by_kind("function_definition");
        for func in functions {
            if let Some(name_node) = func.child_by_field_name("name") {
                if let Ok(name) = name_node.text() {
                    let visibility = if name.starts_with('_') { "private" } else { "public" };
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
                    let visibility = if name.starts_with('_') { "private" } else { "public" };
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
                        if name.chars().all(|c| c.is_uppercase() || c == '_' || c.is_numeric()) {
                            let visibility = if name.starts_with('_') { "private" } else { "public" };
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
    fn extract_c_symbols(&self, tree: &SyntaxTree, content: &str, symbols: &mut Vec<Symbol>) -> Result<()> {
        // Extract function definitions
        let functions = tree.find_nodes_by_kind("function_definition");
        for func in functions {
            if let Some(declarator) = func.child_by_field_name("declarator") {
                if let Some(func_declarator) = declarator.children().iter()
                    .find(|child| child.kind() == "function_declarator") {
                    if let Some(name_node) = func_declarator.child_by_field_name("declarator") {
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
            }
        }

        // Extract struct declarations
        let structs = tree.find_nodes_by_kind("struct_specifier");
        for struct_node in structs {
            if let Some(name_node) = struct_node.child_by_field_name("name") {
                if let Ok(name) = name_node.text() {
                    let docs = self.extract_c_doc_comments(content, struct_node.start_position().row);
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
                    let docs = self.extract_c_doc_comments(content, typedef_node.start_position().row);
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
    fn extract_go_symbols(&self, tree: &SyntaxTree, _content: &str, symbols: &mut Vec<Symbol>) -> Result<()> {
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
                    symbols.push(Symbol {
                        name: name.to_string(),
                        kind: "function".to_string(),
                        start_line: func.start_position().row + 1,
                        start_column: func.start_position().column,
                        end_line: func.end_position().row + 1,
                        end_column: func.end_position().column,
                        visibility: visibility.to_string(),
                        documentation: None,
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
                    symbols.push(Symbol {
                        name: name.to_string(),
                        kind: "method".to_string(),
                        start_line: method.start_position().row + 1,
                        start_column: method.start_position().column,
                        end_line: method.end_position().row + 1,
                        end_column: method.end_position().column,
                        visibility: visibility.to_string(),
                        documentation: None,
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
                            symbols.push(Symbol {
                                name: name.to_string(),
                                kind: kind.to_string(),
                                start_line: type_decl.start_position().row + 1,
                                start_column: type_decl.start_position().column,
                                end_line: type_decl.end_position().row + 1,
                                end_column: type_decl.end_position().column,
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

    /// Extract JSDoc comments preceding a JavaScript item start line
    fn extract_js_doc_comments(&self, content: &str, start_row: usize) -> Option<String> {
        let lines: Vec<&str> = content.lines().collect();
        if start_row == 0 {
            return None;
        }

        let mut docs = Vec::new();
        let mut line_idx = start_row as isize - 1;
        let mut in_block_comment = false;

        while line_idx >= 0 {
            let line = lines[line_idx as usize].trim();

            if line.ends_with("*/") && line.contains("/**") {
                // Single line JSDoc comment
                let doc_content = line.trim_start_matches("/**").trim_end_matches("*/").trim();
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
                if line.starts_with("/**") {
                    let doc_content = line.trim_start_matches("/**").trim();
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
                // Single line block comment
                let doc_content = line.trim_start_matches("/*").trim_end_matches("*/").trim();
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
                    let doc_content = line.trim_start_matches("/*").trim();
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

impl Default for CodebaseAnalyzer {
    fn default() -> Self {
        Self::new().unwrap_or_else(|_| {
            // Fallback implementation if security analyzer fails
            Self {
                config: AnalysisConfig::default(),
                parsers: HashMap::new(),
                security_analyzer: AdvancedSecurityAnalyzer::default(),
                semantic_graph: None,
                file_cache: FileCache::new(),
            }
        })
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
        fs::write(&rust_file, r#"
            /// Main entry point
            pub fn main() {
                println!("Hello, world!");
            }
            
            struct Point {
                x: i32,
                y: i32,
            }
        "#).unwrap();

        // Create a JavaScript file
        let js_file = temp_path.join("app.js");
        fs::write(&js_file, r#"
            function greet(name) {
                console.log("Hello, " + name);
            }
            
            class Calculator {
                add(a, b) {
                    return a + b;
                }
            }
        "#).unwrap();

        // Analyze the directory
        let mut analyzer = CodebaseAnalyzer::new().unwrap();
        let result = analyzer.analyze_directory(temp_path).unwrap();

        assert_eq!(result.total_files, 2);
        assert_eq!(result.parsed_files, 2);
        assert_eq!(result.error_files, 0);
        assert!(result.languages.contains_key("Rust"));
        assert!(result.languages.contains_key("JavaScript"));

        // Check that symbols were extracted
        let rust_file_info = result.files.iter().find(|f| f.path.extension().unwrap() == "rs").unwrap();
        assert!(rust_file_info.symbols.len() > 0);
        let main_symbol = rust_file_info.symbols.iter().find(|s| s.name == "main").unwrap();
        assert_eq!(main_symbol.visibility, "public");
        assert_eq!(main_symbol.documentation.as_deref(), Some("Main entry point"));

        let js_file_info = result.files.iter().find(|f| f.path.extension().unwrap() == "js").unwrap();
        assert!(js_file_info.symbols.len() > 0);
        assert!(js_file_info.symbols.iter().any(|s| s.name == "greet"));
    }
}
