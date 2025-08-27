# CLI Documentation

## Installation

```bash
# Clone the repository
git clone https://github.com/njfio/rust-treesitter-agent-code-utility.git
cd rust-treesitter-agent-code-utility

# Build the CLI tool
cargo build --release --bin tree-sitter-cli

# Install globally (optional)
cargo install --path . --bin tree-sitter-cli
```

## Global Options

All commands support these global options:

- `--help, -h` - Show help information
- `--version, -V` - Show version information
- `--verbose, -v` - Enable verbose output
- `--quiet, -q` - Suppress non-essential output

## Commands

### analyze - Comprehensive Codebase Analysis

Analyze directory structure, extract symbols, and generate comprehensive statistics.

```bash
tree-sitter-cli analyze <PATH> [OPTIONS]
```

**Options:**
- `-f, --format <FORMAT>` - Output format: table, json, summary [default: table]
- `-d, --detailed` - Show detailed analysis including symbol information
- `--max-depth <DEPTH>` - Maximum directory depth to analyze
- `--include <PATTERN>` - Include files matching pattern (can be used multiple times)
- `--exclude <PATTERN>` - Exclude files matching pattern (can be used multiple times)
- `--max-file-size <SIZE>` - Maximum file size to analyze (e.g., 1MB, 500KB)

**Examples:**
```bash
# Basic analysis
tree-sitter-cli analyze ./src

# Detailed JSON output
tree-sitter-cli analyze ./src --format json --detailed

# Analyze with filters
tree-sitter-cli analyze ./src --include "*.rs" --exclude "*/target/*" --max-depth 3
```

### security - Advanced Security Vulnerability Scanning

Comprehensive security analysis with multi-layered vulnerability detection.

```bash
tree-sitter-cli security <PATH> [OPTIONS]
```

**Options:**
- `-f, --format <FORMAT>` - Output format: table, json, markdown [default: table]
- `--min-severity <SEVERITY>` - Minimum severity: critical, high, medium, low, info [default: medium]
- `--save-report <FILE>` - Save detailed report to file
- `--enable-secrets` - Enable secrets detection
- `--enable-dependencies` - Enable dependency vulnerability scanning
- `--confidence <THRESHOLD>` - Minimum confidence threshold (0.0-1.0) [default: 0.7]
- `--max-findings <COUNT>` - Maximum findings per category [default: 50]

**Examples:**
```bash
# Basic security scan
tree-sitter-cli security ./src

# High-severity vulnerabilities with secrets detection
tree-sitter-cli security ./src --min-severity high --enable-secrets

# Comprehensive scan with report
tree-sitter-cli security ./src --enable-secrets --enable-dependencies --save-report security-report.json
```

### symbols - Symbol Extraction and Analysis

Extract and display code symbols with detailed information.

```bash
tree-sitter-cli symbols <PATH> [OPTIONS]
```

**Options:**
- `-f, --format <FORMAT>` - Output format: table, json [default: table]
- `--type <TYPE>` - Filter by symbol type: function, class, struct, interface, etc.
- `--visibility <VIS>` - Filter by visibility: public, private, protected
- `--language <LANG>` - Filter by language

**Examples:**
```bash
# All symbols
tree-sitter-cli symbols ./src

# Only public functions
tree-sitter-cli symbols ./src --type function --visibility public

# Rust symbols only
tree-sitter-cli symbols ./src --language rust --format json
```

### refactor - Smart Refactoring Engine

AI-powered code improvement suggestions and automated refactoring.

```bash
tree-sitter-cli refactor <PATH> [OPTIONS]
```

**Options:**
- `-f, --format <FORMAT>` - Output format: table, json, markdown [default: table]
- `--auto-apply` - Automatically apply safe refactoring suggestions
- `--complexity-threshold <THRESHOLD>` - Maximum complexity threshold for suggestions
- `--focus <AREA>` - Focus area: performance, maintainability, security

**Examples:**
```bash
# Basic refactoring suggestions
tree-sitter-cli refactor ./src

# Focus on performance improvements
tree-sitter-cli refactor ./src --focus performance --complexity-threshold 10

# Auto-apply safe refactorings
tree-sitter-cli refactor ./src --auto-apply --format json
```

### dependencies - Enhanced Dependency Analysis

Comprehensive dependency analysis with vulnerability scanning.

```bash
tree-sitter-cli dependencies <PATH> [OPTIONS]
```

**Options:**
- `-f, --format <FORMAT>` - Output format: table, json, markdown [default: table]
- `--check-vulnerabilities` - Check for known vulnerabilities in dependencies
- `--license-compliance` - Analyze license compatibility
- `--outdated` - Show outdated dependencies
- `--tree` - Show dependency tree

**Examples:**
```bash
# Basic dependency analysis
tree-sitter-cli dependencies ./

# Check for vulnerabilities
tree-sitter-cli dependencies ./ --check-vulnerabilities --format json

# Full analysis with license compliance
tree-sitter-cli dependencies ./ --check-vulnerabilities --license-compliance --outdated
```

### query - Advanced Code Querying

Powerful code search and analysis using semantic queries.

```bash
tree-sitter-cli query <PATH> <QUERY> [OPTIONS]
```

**Options:**
- `-f, --format <FORMAT>` - Output format: table, json [default: table]
- `--language <LANG>` - Target specific language
- `--context <LINES>` - Show context lines around matches [default: 3]
- `--case-sensitive` - Case-sensitive search
- `--regex` - Use regular expressions

**Examples:**
```bash
# Find authentication functions
tree-sitter-cli query ./src "function.*auth" --language rust

# Case-sensitive regex search
tree-sitter-cli query ./src "Auth.*" --case-sensitive --regex --context 5
```

### find - Semantic Code Search

Find code patterns, symbols, and relationships across the codebase.

```bash
tree-sitter-cli find <PATH> <PATTERN> [OPTIONS]
```

**Options:**
- `-t, --type <TYPE>` - Search type: symbol, pattern, reference, definition
- `--case-sensitive` - Case-sensitive search
- `--whole-word` - Match whole words only
- `--language <LANG>` - Target specific language

**Examples:**
```bash
# Find symbol references
tree-sitter-cli find ./src "authenticate" --type reference

# Find function definitions
tree-sitter-cli find ./src "login" --type definition --language rust
```

### map - Intent-to-Implementation Mapping

Map business requirements and user stories to code implementations.

```bash
tree-sitter-cli map <PATH> [OPTIONS]
```

**Options:**
- `-f, --format <FORMAT>` - Output format: table, json, markdown [default: table]
- `--requirements <FILE>` - Requirements specification file (JSON/YAML)
- `--confidence <THRESHOLD>` - Minimum mapping confidence threshold [default: 0.7]
- `--coverage-report` - Generate coverage report
- `--gaps-only` - Show only gaps and missing implementations

**Examples:**
```bash
# Basic mapping analysis
tree-sitter-cli map ./src

# Map with requirements file
tree-sitter-cli map ./src --requirements requirements.json --format json

# Show only gaps
tree-sitter-cli map ./src --gaps-only --confidence 0.8
```

### explain - AI Code Explanation

Generate comprehensive explanations of code functionality and architecture.

```bash
tree-sitter-cli explain <PATH> [OPTIONS]
```

**Options:**
- `-f, --format <FORMAT>` - Output format: markdown, json [default: markdown]
- `--detail-level <LEVEL>` - Explanation detail: basic, detailed, comprehensive [default: detailed]
- `--include-examples` - Include usage examples
- `--focus <ASPECT>` - Focus on specific aspect: functionality, architecture, security

**Examples:**
```bash
# Explain code functionality
tree-sitter-cli explain ./src/auth.rs

# Comprehensive explanation with examples
tree-sitter-cli explain ./src --detail-level comprehensive --include-examples

# Focus on security aspects
tree-sitter-cli explain ./src --focus security --format json
```

### insights - Codebase Insights

Generate high-level insights and recommendations for the codebase.

```bash
tree-sitter-cli insights <PATH> [OPTIONS]
```

**Options:**
- `-f, --format <FORMAT>` - Output format: table, json, markdown [default: table]
- `--focus <AREA>` - Focus area: security, performance, quality, architecture, all [default: all]
- `--threshold <SCORE>` - Minimum score threshold for recommendations
- `--detailed` - Include detailed analysis

**Examples:**
```bash
# General insights
tree-sitter-cli insights ./src

# Security-focused insights
tree-sitter-cli insights ./src --focus security --detailed

# Performance insights with threshold
tree-sitter-cli insights ./src --focus performance --threshold 80
```

### stats - Codebase Statistics

Generate detailed statistics about the codebase.

```bash
tree-sitter-cli stats <PATH> [OPTIONS]
```

**Options:**
- `-f, --format <FORMAT>` - Output format: table, json [default: table]
- `--by-language` - Group statistics by language
- `--include-tests` - Include test files in statistics
- `--detailed` - Show detailed per-file statistics

**Examples:**
```bash
# Basic statistics
tree-sitter-cli stats ./src

# Language breakdown
tree-sitter-cli stats ./src --by-language --format json

# Detailed statistics including tests
tree-sitter-cli stats ./src --detailed --include-tests
```

### interactive - Interactive Analysis Mode

Enter interactive mode for real-time code exploration and analysis.

```bash
tree-sitter-cli interactive <PATH>
```

**Interactive Commands:**
- `analyze [path]` - Analyze path
- `security [options]` - Run security scan
- `symbols [filters]` - Show symbols
- `query <pattern>` - Search code
- `explain <path>` - Explain code
- `help` - Show available commands
- `exit` - Exit interactive mode

**Examples:**
```bash
# Start interactive mode
tree-sitter-cli interactive ./src

# Interactive session
> analyze ./auth.rs
> security --min-severity high
> query "function.*login"
> explain ./auth.rs
> exit
```

## Output Formats

### Table Format
Human-readable tabular output with colors and formatting.

### JSON Format
Machine-readable JSON output for integration with other tools.

### Markdown Format
Documentation-friendly markdown output for reports.

### Summary Format
Condensed summary output for quick overview.

## Configuration File

Create a `.tree-sitter-cli.toml` file in your project root:

```toml
[analysis]
max_file_size = "1MB"
max_depth = 10
follow_symlinks = false
include_patterns = ["*.rs", "*.js", "*.py"]
exclude_patterns = ["*/target/*", "*/node_modules/*"]

[security]
min_confidence = 0.7
enable_secrets = true
enable_dependencies = true
max_findings_per_category = 100

[performance]
complexity_threshold = 10
enable_hotspot_detection = true

[output]
default_format = "table"
use_colors = true
verbose = false
```

## Exit Codes

- `0` - Success
- `1` - General error
- `2` - Invalid arguments
- `3` - File not found
- `4` - Permission denied
- `5` - Analysis failed
- `10` - Security vulnerabilities found (when using `--fail-on-findings`)
