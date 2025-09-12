# Tree-sitter CLI - Codebase Analysis Tool

A command-line interface for basic codebase analysis using tree-sitter. Provides fundamental parsing and analysis capabilities with some experimental features.

**⚠️ FEATURE STATUS DISCLAIMER:**
Many features listed below are experimental or have limited functionality. This CLI is suitable for basic analysis but not production-grade code intelligence.

## Features (With Honest Status)

- **🔍 Multi-language Analysis**: Support for 7 languages (basic parsing level)
- **📊 Basic Statistics**: File counts, symbol extraction, language detection
- **🎯 Pattern Matching**: Limited query system (syntax issues in complex patterns)
- **📈 Statistics & Metrics**: Basic codebase statistics only
- **🔎 Symbol Search**: Basic symbol finding (limited accuracy)
- **🎮 Interactive Mode**: Experimental feature with basic commands
- **🗺️ Visual Code Maps**: Basic tree structure output (limited formatting)
- **📋 Multiple Output Formats**: JSON, table, summary formats working
- **⚠️ Security Scanning**: Pattern-based detection with high false positive rate
- **⚠️ AI Analysis**: Basic implementations, not production-ready

## 🚀 Quick Start

### Installation

```bash
# Build from source
git clone https://github.com/yourusername/rust_tree_sitter.git
cd rust_tree_sitter
cargo build --release --bin tree-sitter-cli

# The binary will be at ./target/release/tree-sitter-cli
```

### Basic Usage

```bash
# Analyze a codebase
tree-sitter-cli analyze ./src

# Get smart insights
tree-sitter-cli insights ./src

# Show statistics
tree-sitter-cli stats ./src

# Find symbols
tree-sitter-cli find ./src --name "main*" --public-only

# Generate visual code maps
tree-sitter-cli map ./src --map-type overview --show-sizes --show-symbols

# Interactive exploration
tree-sitter-cli interactive ./src
```

### Analysis Depth Levels

Use `--depth` with commands like `analyze`, `map`, and `security` to control how much scanning is performed.

- `basic` – gather file metadata only
- `deep` – parse files but skip symbol extraction
- `full` – full parsing with symbols (default)

## 📚 Commands

### `analyze` - Comprehensive Codebase Analysis

Analyze a codebase and extract detailed information about files, symbols, and structure.

```bash
tree-sitter-cli analyze <PATH> [OPTIONS]

Options:
  -f, --format <FORMAT>        Output format: table, json, summary [default: table]
  --max-size <SIZE>           Maximum file size in KB [default: 1024]
  --max-depth <DEPTH>         Maximum directory depth [default: 20]
  --depth <LEVEL>             Analysis depth: basic, deep, full [default: full]
  --include-hidden            Include hidden files and directories
  --exclude-dirs <DIRS>       Exclude directories (comma-separated)
  --include-exts <EXTS>       Include only specific extensions (comma-separated)
  -o, --output <FILE>         Save results to file
  --detailed                  Show detailed symbol information
```

**Examples:**
```bash
# Basic analysis with summary
tree-sitter-cli analyze ./src --format summary

# Detailed analysis with JSON output
tree-sitter-cli analyze ./src --detailed --format json -o analysis.json

# Analyze only Rust files
tree-sitter-cli analyze ./src --include-exts rs

# Limit directory depth
tree-sitter-cli analyze ./src --max-depth 2 --format summary
```

### `insights` - Basic Code Analysis Report

**⚠️ EXPERIMENTAL FEATURE** - Generate basic insights about code structure. Limited analysis depth.

```bash
tree-sitter-cli insights <PATH> [OPTIONS]

Options:
  --focus <AREA>              Focus area: all, architecture, quality, complexity [default: all]
  -f, --format <FORMAT>       Output format: markdown, json, text [default: markdown]
```

**Examples:**
```bash
# Generate basic insights (limited analysis)
tree-sitter-cli insights ./src

# Focus on architecture analysis (basic pattern detection only)
tree-sitter-cli insights ./src --focus architecture

# JSON output for processing
tree-sitter-cli insights ./src --format json
```

**Limitations:**
- Analysis is basic pattern matching, not deep semantic understanding
- Architecture detection is limited to simple patterns
- Quality assessment is rudimentary

### `query` - Advanced Pattern Matching

Search for specific code patterns using tree-sitter queries.

```bash
tree-sitter-cli query <PATH> [OPTIONS]

Options:
  -p, --pattern <PATTERN>     Tree-sitter query pattern
  -l, --language <LANG>       Language: rust, javascript, python, c, cpp
  -c, --context <LINES>       Context lines around matches [default: 3]
  -f, --format <FORMAT>       Output format: table, json [default: table]
```

**Examples:**
```bash
# Find all public functions in Rust
tree-sitter-cli query ./src -p "(function_item (visibility_modifier) name: (identifier) @name)" -l rust

# Find all class definitions in JavaScript
tree-sitter-cli query ./src -p "(class_declaration name: (identifier) @name)" -l javascript
```

### `stats` - Codebase Statistics

Show comprehensive statistics about your codebase.

```bash
tree-sitter-cli stats <PATH> [OPTIONS]

Options:
  --top <N>                   Show top N files by various metrics [default: 10]
```

**Examples:**
```bash
# Show top 5 largest files
tree-sitter-cli stats ./src --top 5

# Full statistics
tree-sitter-cli stats ./src
```

### `find` - Symbol Search

Find specific symbols (functions, classes, structs, etc.) with advanced filtering.

```bash
tree-sitter-cli find <PATH> [OPTIONS]

Options:
  -n, --name <PATTERN>        Symbol name pattern (supports wildcards)
  -t, --symbol-type <TYPE>    Symbol type: function, class, struct, enum
  -l, --language <LANG>       Language filter
  --public-only               Show only public symbols
```

**Examples:**
```bash
# Find all functions starting with "test"
tree-sitter-cli find ./src --name "test*" --symbol-type function

# Find all public structs
tree-sitter-cli find ./src --symbol-type struct --public-only

# Find symbols in Rust files only
tree-sitter-cli find ./src --language rust
```

### `interactive` - Interactive Exploration

Explore codebases interactively with a command-line interface.

```bash
tree-sitter-cli interactive <PATH>

Available commands in interactive mode:
  help, h                     Show help
  stats                       Show codebase statistics
  languages, langs            Show language breakdown
  find <pattern>              Find symbols by name
  files <language>            Show files for language
  quit, exit, q               Exit interactive mode
```

### `map` - Visual Code Maps

Generate beautiful visual representations of your project structure.

```bash
tree-sitter-cli map <PATH> [OPTIONS]

Options:
  -m, --map-type <TYPE>       Map type: tree, symbols, dependencies, overview [default: overview]
  -f, --format <FORMAT>       Output format: ascii, unicode, json, mermaid [default: unicode]
  --max-depth <DEPTH>         Maximum depth to show [default: 5]
  --show-sizes                Show file sizes
  --show-symbols              Show symbol counts
  --languages <LANGUAGES>     Include only specific languages
  --collapse-empty            Collapse empty directories
  --depth <LEVEL>             Analysis depth: basic, deep, full [default: full]
```

**Examples:**
```bash
# Overview map with sizes and symbols
tree-sitter-cli map ./src --map-type overview --show-sizes --show-symbols

# Example output
src
├─ lib.rs (1.2 KB)
├─ parser.rs (3.4 KB)
└─ languages/
   └─ mod.rs (0.8 KB)

# Clean tree structure
tree-sitter-cli map ./src --map-type tree --max-depth 3

# Symbol distribution map
tree-sitter-cli map ./src --map-type symbols

# Mermaid diagram for documentation
tree-sitter-cli map ./src --format mermaid > project-structure.md

# JSON output for processing
tree-sitter-cli map ./src --format json > structure.json

# ASCII format for simple terminals
tree-sitter-cli map ./src --format ascii --collapse-empty

# Filter by language
tree-sitter-cli map ./src --languages rust,javascript
```

#### Map Types

- **`overview`**: Complete project overview with summary and tree structure
- **`tree`**: Clean directory tree with file information
- **`symbols`**: Detailed symbol breakdown by type and file
- **`dependencies`**: Module and file relationships

#### Output Formats

- **`unicode`**: Beautiful Unicode tree with icons (default)
- **`ascii`**: Simple ASCII tree for compatibility
- **`json`**: Structured data for programmatic use
- **`mermaid`**: Mermaid diagrams for documentation

### `security` - Security Scan (with Baselines, SARIF)

```bash
tree-sitter-cli security <PATH> [OPTIONS]

Options:
  -f, --format <FORMAT>           Output: table, json, markdown, sarif [default: table]
  --min-severity <LEVEL>          Min severity: critical|high|medium|low|info [default: low]
  --min-confidence <LEVEL>        Min confidence: low|medium|high [default: low]
  --fail-on <LEVEL>               Exit non-zero if >= level findings
  --summary-only                  Show summary only
  --compliance                    Include OWASP/CWE compliance info
  -o, --output <FILE>             Save report to file
  --no-ai-filter                  Disable AI/ML false-positive filtering
  --filter-mode <MODE>            strict|balanced|permissive [default: balanced]
  --baseline <FILE>               Suppress unchanged findings using baseline JSON
  --update-baseline               Rewrite baseline with current findings
  --include-tests                 Include tests (tests/, *_test.rs, test_*.rs)
  --include-examples              Include examples/demo files
  --include-non-code              Include docs/ and markdown
  --max-file-kb <N>               Skip files larger than N KB [default: 1024]
```

Examples:
```bash
# Human-readable table
tree-sitter-cli security ./src --min-severity medium

# JSON for automation
tree-sitter-cli security ./src --format json > security.json

# SARIF for code scanning integrations
tree-sitter-cli security ./src --format sarif -o security.sarif

# CI gating with baselines
tree-sitter-cli security ./src --baseline .ci/security-baseline.json --fail-on high

# Update baseline after triage
tree-sitter-cli security ./src --update-baseline --baseline .ci/security-baseline.json
```

Notes:
- Findings are filtered deterministically first (FilterMode), then by severity/confidence.
- Baseline fingerprints use `file:start_line:title:severity`; SARIF `baselineState` is set to new/unchanged.
- `--no-color` disables color globally; outputs avoid leaking debug `ColoredString`.

See also: `docs/SECURITY_SCANNER_GUIDE.md` for full baseline and SARIF workflows.

## Logging & Tracing

- Use `--log-level trace|debug|info|warn|error` to enable structured logs (defaults to off).
- `RUST_LOG` is also supported; `--log-level` takes precedence when provided.
- Example: `tree-sitter-cli security . --log-level debug --summary-only`.

### `ast-security` - AST-Based Security Analysis

Low false-positive, AST-driven security scanning with SARIF support.

```bash
tree-sitter-cli ast-security <PATH> [OPTIONS]

Options:
  -f, --format <FORMAT>           Output: table, json, markdown, sarif [default: table]
  --min-severity <LEVEL>          Min severity: critical|high|medium|low|info [default: low]
  --min-confidence <NUM>          Min confidence [0.0–1.0]
  --fail-on <LEVEL>               Exit non-zero if >= level findings
  --summary-only                  Show summary only
  --language <LANG>               Restrict by language (rust, js, ts, py, c, cpp, go)
  --baseline <FILE>               Suppress unchanged findings
  --update-baseline               Rewrite baseline with current findings
  --include-tests                 Include tests/spec files
  --include-examples              Include example/demo files
  -o, --output <FILE>             Save report to file
  --max-file-kb <N>               Skip files larger than N KB [default: 1024]
```

### `languages` - Supported Languages

Show all supported languages and their capabilities.

```bash
tree-sitter-cli languages
```

## 📊 Output Formats

### Table Format (Default)
Clean, readable tables perfect for terminal viewing.

### JSON Format
Structured data perfect for programmatic processing and AI agents.

### Markdown Format
Documentation-ready format with rich formatting.

### Summary Format
Concise overview with key metrics highlighted.

## 🎯 Use Cases

### For Developers
- **Code Review**: Quickly understand codebase structure and complexity
- **Refactoring**: Identify complexity hotspots and large files
- **Documentation**: Generate architecture overviews
- **Quality Assessment**: Check naming conventions and organization

### For AI Agents
- **Codebase Understanding**: Get structured information about code organization
- **Context Building**: Extract relevant symbols and their relationships
- **Quality Analysis**: Assess code quality and get improvement suggestions
- **Pattern Recognition**: Find specific code patterns across the codebase

### For Teams
- **Onboarding**: Help new team members understand codebase structure
- **Architecture Reviews**: Analyze separation of concerns and module organization
- **Technical Debt**: Identify areas needing refactoring
- **Standards Compliance**: Check naming conventions and code organization

## 🔧 Advanced Usage

### Combining Commands
```bash
# Generate insights and save detailed analysis
tree-sitter-cli insights ./src --format json > insights.json
tree-sitter-cli analyze ./src --detailed --format json > analysis.json

# Find complexity hotspots
tree-sitter-cli stats ./src --top 3
tree-sitter-cli find ./src --symbol-type function | head -20
```

### Integration with Other Tools
```bash
# Use with jq for JSON processing
tree-sitter-cli analyze ./src --format json | jq '.files[] | select(.symbols | length > 10)'

# Generate reports
tree-sitter-cli insights ./src --format markdown > ARCHITECTURE.md
```

### CI/CD Integration
```bash
# Check code quality in CI
tree-sitter-cli insights ./src --format json | jq '.quality.parse_success_rate < 95' && exit 1

# Generate documentation
tree-sitter-cli insights ./src --format markdown > docs/CODEBASE_ANALYSIS.md
```

## 🎨 Customization

### Configuration Files
The CLI respects standard configuration patterns and can be extended with custom analysis rules.

### Custom Queries
Write your own tree-sitter queries for specific pattern matching needs.

### Output Formatting
All output formats support customization and can be easily parsed by other tools.

## 🤝 Contributing

We welcome contributions! The CLI is built on top of the robust rust-tree-sitter library and can be extended with new analysis capabilities.

## 📄 License

This project is licensed under either of Apache License, Version 2.0 or MIT license at your option.

---

**Built with ❤️ using tree-sitter and Rust**
### `wiki` - Static Code Wiki Generator

Generate a static, navigable documentation website from a codebase.

```bash
tree-sitter-cli wiki <PATH> [OPTIONS]
```

Options (legacy and explicit):
- `--output <DIR>`: Output directory (default: `./wiki_site`)
- `--include-api`: Include per-file API docs and symbols
- `--include-examples`: Include examples (legacy)
- `--depth <LEVEL>`: Analysis depth: basic, deep, full [default: full]
- `--ai`, `--ai-json`: Legacy AI toggles (kept for compatibility)
- `--ai-mock`: Use mock AI providers
- `--ai-config <FILE>`: AI configuration
- `--ai-provider <PROVIDER>`: AI provider (groq, openai, anthropic, google, azureopenai, local, ollama)

Explicit wiki flags (preferred):
- `--wiki-ai`: Enable AI-generated content
- `--wiki-ai-json`: Request structured JSON responses
- `--wiki-security`: Generate security pages/blocks
- `--wiki-diagrams`: Enable diagram annotations
- `--wiki-examples`: Include examples
- `--wiki-max-results <N>`: Limit search results shown in UI (default 200)
- `--wiki-max-index-symbols <N>`: Cap symbols per file in search index
- `--wiki-templates <DIR>`: External templates directory (reserved)

Examples:
```bash
# Basic wiki
tree-sitter-cli wiki ./src --output wiki_site --include-api --depth full

# Enable AI (explicit)
tree-sitter-cli wiki ./src --output wiki_site --wiki-ai --wiki-ai-json

# Security-focused site
tree-sitter-cli wiki ./src --output wiki_site --wiki-security --wiki-diagrams

# Tune search UX
tree-sitter-cli wiki ./src --output wiki_site --include-api --wiki-max-results 150 --wiki-max-index-symbols 50
```
