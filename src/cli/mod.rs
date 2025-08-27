//! CLI module for the rust-tree-sitter library
//! 
//! This module provides a clean separation of CLI concerns with modular command handling.

pub mod commands;
pub mod error;
pub mod output;
pub mod utils;
pub mod schemas;
pub mod sarif;
pub mod sbom;
// pub mod watch; // TODO: Implement watch module

use clap::{Parser, Subcommand};
use std::path::PathBuf;

/// Smart CLI interface for the rust-tree-sitter library
#[derive(Parser)]
#[command(name = "tree-sitter-cli")]
#[command(about = "Smart codebase analysis with tree-sitter")]
#[command(version = "1.0.0")]
#[command(author = "Rust Tree-sitter Team")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

/// Available CLI commands
#[derive(Subcommand)]
pub enum Commands {
    /// Analyze a codebase and extract insights
    Analyze {
        /// Directory to analyze
        #[arg(value_name = "PATH")]
        path: PathBuf,
        
        /// Output format (table, json, summary)
        #[arg(short, long, default_value = "table")]
        format: String,
        
        /// Maximum file size to process (in KB)
        #[arg(long, default_value = "1024")]
        max_size: usize,
        
        /// Maximum depth to traverse
        #[arg(long, default_value = "20")]
        max_depth: usize,

        /// Analysis depth: basic, deep, full
        #[arg(long, default_value = "full")]
        depth: String,
        
        /// Include hidden files and directories
        #[arg(long)]
        include_hidden: bool,
        
        /// Exclude directories (comma-separated)
        #[arg(long)]
        exclude_dirs: Option<String>,
        
        /// Include only specific file extensions (comma-separated)
        #[arg(long)]
        include_exts: Option<String>,
        
        /// Save results to file
        #[arg(short, long)]
        output: Option<PathBuf>,
        
        /// Show detailed symbol information
        #[arg(long)]
        detailed: bool,

        /// Number of threads to use (analysis)
        #[arg(long)]
        threads: Option<usize>,

        /// Enable heavy security scanning during analysis
        #[arg(long, default_value_t = false)]
        enable_security: bool,

        /// Print JSON schema and exit
        #[arg(long, default_value_t = false)]
        print_schema: bool,

        /// Schema version to print
        #[arg(long, default_value = "1")]
        schema_version: String,
    },
    
    /// Query code patterns across the codebase
    Query {
        /// Directory to search
        #[arg(value_name = "PATH")]
        path: PathBuf,
        
        /// Tree-sitter query pattern
        #[arg(short, long)]
        pattern: String,
        
        /// Language to query (rust, javascript, python, c, cpp)
        #[arg(short, long)]
        language: String,

        /// Prefilter files by substring before parsing
        #[arg(long)]
        prefilter: Option<String>,
        
        /// Show context lines around matches
        #[arg(short, long, default_value = "3")]
        context: usize,
        
        /// Output format (table, json)
        #[arg(short, long, default_value = "table")]
        format: String,
    },
    
    /// Show statistics about a codebase
    Stats {
        /// Directory to analyze
        #[arg(value_name = "PATH")]
        path: PathBuf,
        
        /// Show top N files by various metrics
        #[arg(long, default_value = "10")]
        top: usize,
    },
    
    /// Find specific symbols (functions, classes, etc.)
    Find {
        /// Directory to search
        #[arg(value_name = "PATH")]
        path: PathBuf,
        
        /// Symbol name to find (supports wildcards)
        #[arg(short, long)]
        name: Option<String>,
        
        /// Symbol type (function, class, struct, enum)
        #[arg(short, long)]
        symbol_type: Option<String>,
        
        /// Language to search in
        #[arg(short, long)]
        language: Option<String>,
        
        /// Show only public symbols
        #[arg(long)]
        public_only: bool,
    },

    /// List all symbols grouped by file
    Symbols {
        /// Directory to analyze
        #[arg(value_name = "PATH")]
        path: PathBuf,

        /// Output format (table or json)
        #[arg(short, long, default_value = "table")]
        format: String,

        /// Print JSON schema and exit
        #[arg(long, default_value_t = false)]
        print_schema: bool,

        /// Schema version to print
        #[arg(long, default_value = "1")]
        schema_version: String,
    },
    
    /// Show supported languages and their capabilities
    Languages,
    
    /// Interactive mode for exploring codebases
    Interactive {
        /// Directory to explore
        #[arg(value_name = "PATH")]
        path: PathBuf,
    },

    /// Generate AI-friendly insights and recommendations
    Insights {
        /// Directory to analyze
        #[arg(value_name = "PATH")]
        path: PathBuf,

        /// Focus area (architecture, quality, complexity, dependencies)
        #[arg(long, default_value = "all")]
        focus: String,

        /// Output format (markdown, json, text)
        #[arg(short, long, default_value = "markdown")]
        format: String,
    },

    /// Generate a visual code map of the project structure
    Map {
        /// Directory to map
        #[arg(value_name = "PATH")]
        path: PathBuf,

        /// Map type (tree, symbols, dependencies, call, modules, overview)
        #[arg(short, long, default_value = "overview")]
        map_type: String,

        /// Output format (ascii, unicode, json, mermaid, dot)
        #[arg(short, long, default_value = "unicode")]
        format: String,

        /// Maximum depth to show
        #[arg(long, default_value = "5")]
        max_depth: usize,

        /// Show file sizes
        #[arg(long)]
        show_sizes: bool,

        /// Show symbol counts
        #[arg(long)]
        show_symbols: bool,

        /// Include only specific languages
        #[arg(long)]
        languages: Option<String>,

        /// Collapse empty directories
        #[arg(long)]
        collapse_empty: bool,

        /// Analysis depth: basic, deep, full
        #[arg(long, default_value = "full")]
        depth: String,
    },

    /// AI-powered code explanations and insights
    Explain {
        /// Directory to analyze
        #[arg(value_name = "PATH")]
        path: PathBuf,

        /// Focus on specific file
        #[arg(short, long)]
        file: Option<PathBuf>,

        /// Focus on specific symbol
        #[arg(short, long)]
        symbol: Option<String>,

        /// Output format (markdown, json, text)
        #[arg(long, default_value = "markdown")]
        format: String,

        /// Include detailed explanations
        #[arg(long)]
        detailed: bool,

        /// Include learning recommendations
        #[arg(long)]
        learning: bool,
    },

    /// Security vulnerability scanning
    Security {
        /// Directory to scan
        #[arg(value_name = "PATH")]
        path: PathBuf,

        /// Output format (table, json, markdown)
        #[arg(short, long, default_value = "table")]
        format: String,

        /// Minimum severity level (critical, high, medium, low, info)
        #[arg(long, default_value = "low")]
        min_severity: String,

        /// Save detailed report to file
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Show only summary
        #[arg(long)]
        summary_only: bool,

        /// Include compliance information
        #[arg(long)]
        compliance: bool,

        /// Analysis depth: basic, deep, full
        #[arg(long, default_value = "full")]
        depth: String,

        /// Print JSON schema and exit
        #[arg(long, default_value_t = false)]
        print_schema: bool,

        /// Schema version to print
        #[arg(long, default_value = "1")]
        schema_version: String,
        
        /// Enable heavy security scanning during initial analysis (rarely needed)
        #[arg(long, default_value_t = false)]
        enable_security: bool,
    },

    /// Smart refactoring suggestions
    Refactor {
        /// Directory to analyze
        #[arg(value_name = "PATH")]
        path: PathBuf,

        /// Focus on specific category (complexity, duplication, naming, performance, architecture)
        #[arg(short, long)]
        category: Option<String>,

        /// Output format (table, json, markdown)
        #[arg(short, long, default_value = "table")]
        format: String,

        /// Show only quick wins (easy improvements)
        #[arg(long)]
        quick_wins: bool,

        /// Show only major improvements
        #[arg(long)]
        major_only: bool,

        /// Minimum priority level (critical, high, medium, low)
        #[arg(long, default_value = "low")]
        min_priority: String,

        /// Save detailed report to file
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Enhanced dependency analysis and security scanning
    Dependencies {
        /// Directory to analyze
        #[arg(value_name = "PATH")]
        path: PathBuf,

        /// Output format (table, json, markdown)
        #[arg(short, long, default_value = "table")]
        format: String,

        /// Include development dependencies
        #[arg(long)]
        include_dev: bool,

        /// Enable vulnerability scanning
        #[arg(long)]
        vulnerabilities: bool,

        /// Enable license compliance checking
        #[arg(long)]
        licenses: bool,

        /// Show outdated dependencies
        #[arg(long)]
        outdated: bool,

        /// Show dependency graph analysis
        #[arg(long)]
        graph: bool,

        /// Save detailed report to file
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Watch mode: re-run analysis at intervals (scaffold)
    Watch {
        /// Directory to analyze repeatedly
        #[arg(value_name = "PATH")]
        path: PathBuf,

        /// Interval in seconds between runs
        #[arg(long, default_value_t = 2u64)]
        interval: u64,

        /// Maximum iterations before exit (0 = run once)
        #[arg(long, default_value_t = 0usize)]
        max_iterations: usize,

        /// Analysis depth: basic, deep, full
        #[arg(long, default_value = "basic")]
        depth: String,
    },

    /// Wiki website generator
    Wiki {
        /// Directory to generate wiki for
        #[arg(value_name = "PATH")]
        path: PathBuf,

        /// Output directory for the site
        #[arg(short, long, value_name = "DIR")]
        output: Option<PathBuf>,

        /// Include API docs
        #[arg(long, default_value_t = true)]
        include_api: bool,

        /// Include examples
        #[arg(long, default_value_t = false)]
        include_examples: bool,

        /// Analysis depth (basic, deep, full)
        #[arg(long, default_value = "full")]
        depth: String,

        /// Enable AI-generated docs on the wiki
        #[arg(long, default_value_t = false)]
        ai: bool,

        /// Use mock AI providers (offline deterministic)
        #[arg(long, default_value_t = false)]
        ai_mock: bool,

        /// Path to AI configuration file
        #[arg(long, value_name = "FILE")]
        ai_config: Option<PathBuf>,
    },
}

/// Execute trait for command handling
pub trait Execute {
    type Error;
    
    fn execute(&self) -> Result<(), Self::Error>;
}
