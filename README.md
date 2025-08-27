# Rust Tree-sitter Agent Code Utility

A comprehensive Rust library for parsing and analyzing source code using tree-sitter, enhanced with AI-powered code analysis capabilities. Provides abstractions for parsing, navigating, and querying syntax trees across multiple programming languages with advanced AI-driven insights for security, performance, and code quality.

Built for developers and AI systems that need sophisticated code analysis tools with real AI integration for intelligent code understanding and recommendations.

## Table of Contents

- [Features](#features)
- [AI Integration](#ai-integration)
- [CLI Commands](#cli-commands)
- [Quick Start](#quick-start)
- [Library Usage](#library-usage)
- [AI Service Usage](#ai-service-usage)
- [Supported Languages](#supported-languages)
- [Configuration](#configuration)
- [Test Coverage](#test-coverage)
- [Contributing](#contributing)
- [License](#license)

## Features

### Core Language Support

- **7 Programming Languages**: Rust, JavaScript, TypeScript, Python, C, C++, Go
- **Language Detection**: Automatic detection from file extensions and content analysis
- **Symbol Extraction**: Functions, classes, structs, methods, types, interfaces, implementations
- **Language Features**: Language-specific construct detection and analysis

### Analysis Capabilities

- **Codebase Analysis**: Directory analysis with file metrics, symbol extraction, and statistics
- **Security Scanning**: Advanced security vulnerability detection with OWASP categorization
- **Complexity Analysis**: Comprehensive code complexity metrics including McCabe, cognitive, NPATH, and Halstead metrics
- **Performance Analysis**: Optimization recommendations and performance hotspot detection
- **Dependency Analysis**: Package manager file parsing (package.json, requirements.txt, Cargo.toml, go.mod)
- **Code Quality Analysis**: Code smell detection and refactoring suggestions

### AI-Powered Features

- **AI Code Explanation**: Detailed code analysis and explanation generation using LLMs
- **AI Security Analysis**: Intelligent vulnerability detection with contextual understanding
- **AI Refactoring Suggestions**: Smart code improvement recommendations
- **AI Architectural Insights**: Design pattern analysis and architectural guidance
- **AI Pattern Detection**: Identification of design patterns and anti-patterns
- **AI Quality Assessment**: Code quality evaluation with improvement suggestions
- **AI Documentation Generation**: Automated documentation creation
- **AI Test Generation**: Unit test generation and testing strategies

## AI Integration

The library includes a comprehensive AI service layer that integrates with multiple LLM providers for intelligent code analysis:

### Supported AI Providers

- **OpenAI**: GPT-4, GPT-3.5-turbo with full API integration
- **Anthropic**: Claude models with streaming support
- **Google**: Gemini models (configuration ready)
- **Azure OpenAI**: Enterprise-grade OpenAI integration
- **Local Models**: Ollama and custom local model support
- **Mock Provider**: Development and testing support

### AI Service Features

- **Configuration-Driven**: JSON/YAML configuration with environment variable support
- **Provider Abstraction**: Easy switching between AI providers
- **Intelligent Caching**: LRU cache with TTL for performance optimization
- **Rate Limiting**: Built-in rate limiting and retry logic
- **Error Handling**: Comprehensive error handling with graceful fallbacks
- **Cost Tracking**: Token usage monitoring and cost estimation

### CLI Interface

- **Available Commands**: analyze, security, refactor, dependencies, symbols, query, find
- **Output Formats**: JSON, table, markdown, summary
- **Progress Tracking**: Real-time progress indicators
- **Filtering**: Severity levels, file types, symbol types
- **Interactive Mode**: Real-time code exploration

## CLI Commands

### `analyze` - Codebase Analysis
Analyze directory structure, extract symbols, and generate statistics.

```bash
tree-sitter-cli analyze <PATH> [OPTIONS]

Options:
  -f, --format <FORMAT>    Output format: table, json, summary [default: table]
  -d, --detailed          Show detailed analysis
  --max-depth <DEPTH>     Maximum directory depth to analyze
```

**Example:**
```bash
tree-sitter-cli analyze ./src --format json
```

### `security` - Security Vulnerability Scanning

Pattern-based security analysis with vulnerability detection and compliance assessment.

```bash
tree-sitter-cli security <PATH> [OPTIONS]

Options:
  -f, --format <FORMAT>         Output format: table, json, markdown [default: table]
  --min-severity <SEVERITY>     Minimum severity: critical, high, medium, low, info [default: medium]
  --output <FILE>               Save detailed report to file
  --summary-only                Show summary only
  --compliance                  Include compliance assessment
  --depth <LEVEL>               Analysis depth: basic, deep, full [default: full]
```

**Example:**

```bash
tree-sitter-cli security ./src --min-severity high --format json
```

**Detection Capabilities:**

- **OWASP Patterns**: SQL injection, XSS, insecure deserialization, broken authentication
- **Code Injection**: Command injection, code execution vulnerabilities
- **Input Validation**: Missing validation patterns and sanitization
- **Authorization**: Missing access controls and privilege escalation
- **Cryptographic Issues**: Weak algorithms and insecure practices
- **Compliance Assessment**: OWASP and CWE compliance scoring

### `complexity` - Code Complexity Analysis

Comprehensive code complexity analysis with multiple metrics.

```bash
tree-sitter-cli complexity <PATH> [OPTIONS]

Options:
  -f, --format <FORMAT>    Output format: table, json, markdown [default: table]
  --metric <METRIC>        Specific metric: mccabe, cognitive, npath, halstead, all [default: all]
  --threshold <VALUE>      Complexity threshold for warnings
  --detailed               Show detailed per-function analysis
```

**Example:**
```bash
tree-sitter-cli complexity ./src --metric all --format json
```

**Metrics Calculated:**
- **McCabe Complexity**: Cyclomatic complexity based on control flow paths
- **Cognitive Complexity**: Human-perceived complexity with nesting penalties
- **NPATH Complexity**: Number of execution paths through functions
- **Halstead Metrics**: Volume, difficulty, and effort based on operators/operands
- **Lines of Code**: Physical and logical line counts
- **Nesting Depth**: Maximum nesting level in functions

### `symbols` - Symbol Extraction

Extract and display code symbols (functions, classes, structs, etc.).

```bash
tree-sitter-cli symbols <PATH> [OPTIONS]

Options:
  -f, --format <FORMAT>    Output format: table, json [default: table]
```

**Example:**
```bash
tree-sitter-cli symbols ./src --format json
```

**Extracts:**
- Functions and methods
- Classes and structs
- Interfaces and traits
- Implementations
- Types and enums
- Visibility information
- Line numbers and locations

### `refactor` - Smart Refactoring Engine

Code improvement suggestions with refactoring capabilities.

```bash
tree-sitter-cli refactor <PATH> [OPTIONS]

Options:
  -f, --format <FORMAT>    Output format: table, json, markdown [default: table]
  --category <CATEGORY>    Focus category: all, code_smells, patterns, performance
  --quick-wins             Show only quick wins
  --major-only             Show only major improvements
  --min-priority <LEVEL>   Minimum priority: low, medium, high, critical
  --output <FILE>          Save detailed report to file
```

**Capabilities:**

- **Code Smell Detection**: Identify anti-patterns and code quality issues
- **Design Pattern Recommendations**: Suggest appropriate design patterns
- **Modernization Suggestions**: Update code to use modern language features
- **Performance Optimization**: Identify and suggest performance improvements
- **Complexity Reduction**: Simplify overly complex code structures

### `dependencies` - Dependency Analysis

Dependency analysis with package manager integration.

```bash
tree-sitter-cli dependencies <PATH> [OPTIONS]

Options:
  -f, --format <FORMAT>    Output format: table, json, markdown [default: table]
  --include-dev            Include development dependencies
  --vulnerabilities        Enable vulnerability scanning
  --licenses               Enable license compliance checking
  --outdated               Show outdated dependencies
  --graph                  Show dependency graph analysis
  --output <FILE>          Save detailed report to file
```

**Features:**

- **Multi-Language Support**: package.json (Node.js), requirements.txt (Python), Cargo.toml (Rust), go.mod (Go)
- **Dependency Tree**: Visualize dependency relationships
- **License Analysis**: Identify license information
- **Update Information**: Show outdated dependencies

### `query` - Code Querying

Code search and analysis using tree-sitter queries.

```bash
tree-sitter-cli query <PATH> [OPTIONS]

Options:
  -p, --pattern <PATTERN>  Tree-sitter query pattern
  -l, --language <LANG>    Target specific language
  -c, --context <LINES>    Show context lines around matches [default: 2]
  -f, --format <FORMAT>    Output format: table, json [default: table]
```

### `find` - Symbol Search

Find symbols and patterns across the codebase.

```bash
tree-sitter-cli find <PATH> [OPTIONS]

Options:
  --name <PATTERN>         Symbol name pattern
  --symbol-type <TYPE>     Symbol type filter
  --language <LANG>        Target specific language
  --public-only            Show only public symbols
```

### `map` - Code Structure Mapping

Generate visual maps of code structure and relationships.

```bash
tree-sitter-cli map <PATH> [OPTIONS]

Options:
  --map-type <TYPE>        Map type: overview, tree, symbols, dependencies
  -f, --format <FORMAT>    Output format: unicode, ascii, json, mermaid
  --max-depth <DEPTH>      Maximum depth to show
  --show-sizes             Show file sizes
  --show-symbols           Show symbol counts
  --languages <LANGS>      Filter by languages
  --collapse-empty         Collapse empty directories
```

### `explain` - Code Explanation

Generate explanations of code functionality and architecture.

```bash
tree-sitter-cli explain <PATH> [OPTIONS]

Options:
  --file <FILE>            Specific file to explain
  --symbol <SYMBOL>        Specific symbol to explain
  -f, --format <FORMAT>    Output format: markdown, json [default: markdown]
  --detailed               Include detailed analysis
  --learning               Include learning recommendations
```

### `insights` - Codebase Insights

Generate insights and recommendations for the codebase.

```bash
tree-sitter-cli insights <PATH> [OPTIONS]

Options:
  --focus <AREA>           Focus area: all, architecture, quality, complexity
  -f, --format <FORMAT>    Output format: markdown, json, text [default: markdown]
```

### `interactive` - Interactive Mode

Enter interactive mode for real-time code exploration.

```bash
tree-sitter-cli interactive <PATH>
```

### `stats` - Codebase Statistics

Show comprehensive statistics about the codebase.

```bash
tree-sitter-cli stats <PATH> [OPTIONS]

Options:
  --top <N>                Show top N files by various metrics [default: 10]
```

## Quick Start

### CLI Installation

```bash
# Clone the repository
git clone https://github.com/njfio/rust-treesitter-agent-code-utility.git
cd rust-treesitter-agent-code-utility

# Build the CLI tool
cargo build --release --bin tree-sitter-cli

# Run analysis on your code
./target/release/tree-sitter-cli analyze ./src
```

### Library Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
rust_tree_sitter = { git = "https://github.com/njfio/rust-treesitter-agent-code-utility.git" }
```

### Basic Parsing

```rust
use rust_tree_sitter::{Parser, Language};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create a parser for Rust
    let mut parser = Parser::new(Language::Rust)?;

    // Parse some code
    let source = "fn main() { println!(\"Hello, world!\"); }";
    let tree = parser.parse(source, None)?;

    // Navigate the syntax tree
    let root = tree.root_node();
    println!("Root node: {}", root.kind());

    Ok(())
}
```

### Language Detection

```rust
use rust_tree_sitter::detect_language_from_extension;

// Detect language from extension
if let Some(lang) = detect_language_from_extension("py") {
    println!("Detected language: {}", lang.name());
}
```

### Codebase Analysis

```rust
use rust_tree_sitter::CodebaseAnalyzer;
use std::path::PathBuf;

// Create analyzer with error handling
let mut analyzer = CodebaseAnalyzer::new()?;

// Analyze directory
let result = analyzer.analyze_directory(&PathBuf::from("./src"))?;

// Access results
println!("Found {} files", result.files.len());
for file_info in &result.files {
    println!("📁 {} ({} symbols)", file_info.path.display(), file_info.symbols.len());
}
```

### Security Analysis

```rust
use rust_tree_sitter::{CodebaseAnalyzer, AdvancedSecurityAnalyzer};
use std::path::PathBuf;

// Analyze codebase
let mut analyzer = CodebaseAnalyzer::new()?;
let analysis = analyzer.analyze_directory(&PathBuf::from("./src"))?;

// Run security scan
let security_analyzer = AdvancedSecurityAnalyzer::new();
let security_result = security_analyzer.scan_analysis_result(&analysis)?;

println!("Security Score: {}/100", security_result.security_score);
println!("Found {} vulnerabilities", security_result.vulnerabilities.len());

// Display vulnerabilities
for vuln in &security_result.vulnerabilities {
    println!("🔒 {}: {} (line {})",
             vuln.severity, vuln.title, vuln.location.line);
}
```

## AI Service Usage

### Basic AI Service Setup

```rust
use rust_tree_sitter::ai::{
    AIService, AIServiceBuilder, AIConfig, AIProvider, AIFeature, AIRequest,
    ProviderConfig, ModelConfig
};
use rust_tree_sitter::ai::config::{RateLimitConfig, RetryConfig};
use std::collections::HashMap;
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create AI service configuration
    let mut config = AIConfig::default();
    config.default_provider = AIProvider::OpenAI;

    // Configure OpenAI provider
    let openai_config = ProviderConfig {
        enabled: true,
        api_key: Some("your-openai-api-key".to_string()),
        base_url: Some("https://api.openai.com/v1".to_string()),
        organization: None,
        models: vec![
            ModelConfig {
                name: "gpt-4".to_string(),
                context_length: 8192,
                max_tokens: 4096,
                supports_streaming: true,
                cost_per_token: Some(0.00003),
                supported_features: vec![
                    AIFeature::CodeExplanation,
                    AIFeature::SecurityAnalysis,
                    AIFeature::RefactoringSuggestions,
                ],
            }
        ],
        default_model: "gpt-4".to_string(),
        timeout: Duration::from_secs(30),
        rate_limit: RateLimitConfig::default(),
        retry: RetryConfig::default(),
    };

    config.providers.insert(AIProvider::OpenAI, openai_config);

    // Build AI service
    let service = AIServiceBuilder::new()
        .with_config(config)
        .build()
        .await?;

    // Create AI request for code explanation
    let request = AIRequest::new(
        AIFeature::CodeExplanation,
        r#"
        fn fibonacci(n: u32) -> u32 {
            match n {
                0 => 0,
                1 => 1,
                _ => fibonacci(n - 1) + fibonacci(n - 2),
            }
        }
        "#.to_string(),
    );

    // Process request
    let response = service.process_request(request).await?;
    println!("AI Explanation: {}", response.content);

    Ok(())
}
```

### Configuration File Usage

Create `ai_config.yaml`:

```yaml
default_provider: OpenAI
cache:
  enabled: true
  max_entries: 1000
  ttl_seconds: 3600

providers:
  OpenAI:
    enabled: true
    api_key: "${OPENAI_API_KEY}"
    base_url: "https://api.openai.com/v1"
    models:
      - name: "gpt-4"
        context_length: 8192
        max_tokens: 4096
        supports_streaming: true
        cost_per_token: 0.00003
        supported_features:
          - CodeExplanation
          - SecurityAnalysis
          - RefactoringSuggestions
    default_model: "gpt-4"
    timeout_seconds: 30
```

Then load the configuration:

```rust
use rust_tree_sitter::ai::{AIServiceBuilder, AIConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load configuration from file
    let service = AIServiceBuilder::new()
        .with_config_file("ai_config.yaml")?
        .build()
        .await?;

    // Use the service...
    Ok(())
}
```

### Complexity Analysis

```rust
use rust_tree_sitter::{Parser, Language, ComplexityAnalyzer};

// Create parser and analyzer
let mut parser = Parser::new(Language::Rust)?;
let analyzer = ComplexityAnalyzer::new("rust");

// Parse code
let source = r#"
    fn complex_function(x: i32, y: i32) -> i32 {
        if x > 0 {
            for i in 0..x {
                if i % 2 == 0 {
                    return i * y;
                }
            }
        }
        match y {
            0..=10 => y * 2,
            11..=100 => y + 50,
            _ => y - 25,
        }
    }
"#;

let tree = parser.parse(source, None)?;

// Analyze complexity
let metrics = analyzer.analyze_complexity(&tree)?;

println!("McCabe Complexity: {}", metrics.cyclomatic_complexity);
println!("Cognitive Complexity: {}", metrics.cognitive_complexity);
println!("NPATH Complexity: {}", metrics.npath_complexity);
println!("Halstead Volume: {:.2}", metrics.halstead_volume);
println!("Halstead Difficulty: {:.2}", metrics.halstead_difficulty);
println!("Halstead Effort: {:.2}", metrics.halstead_effort);
println!("Max Nesting Depth: {}", metrics.max_nesting_depth);
println!("Lines of Code: {}", metrics.lines_of_code);
```

### Performance Analysis

```rust
use rust_tree_sitter::{CodebaseAnalyzer, PerformanceAnalyzer};
use std::path::PathBuf;

// Analyze codebase
let mut analyzer = CodebaseAnalyzer::new()?;
let analysis = analyzer.analyze_directory(&PathBuf::from("./src"))?;

// Run performance analysis
let perf_analyzer = PerformanceAnalyzer::new();
let perf_result = perf_analyzer.analyze(&analysis)?;

println!("Performance Score: {}/100", perf_result.performance_score);
println!("Found {} hotspots", perf_result.hotspots.len());

for hotspot in &perf_result.hotspots {
    println!("⚡ {}: {} (severity: {:?})",
             hotspot.category, hotspot.location.file.display(), hotspot.severity);
}
```

### Semantic Context Analysis

```rust
use rust_tree_sitter::{SemanticContextAnalyzer, Language};
use std::path::PathBuf;

// Create semantic context analyzer
let mut semantic_analyzer = SemanticContextAnalyzer::new(Language::Rust)?;

// Parse and analyze code
let source = std::fs::read_to_string("src/main.rs")?;
let mut parser = Parser::new(Language::Rust)?;
let tree = parser.parse(&source, None)?;

// Perform comprehensive semantic analysis
let semantic_context = semantic_analyzer.analyze(&tree, &source)?;

// Access symbol table with scope information
println!("Found {} scopes", semantic_context.symbol_table.scopes.len());
println!("Found {} symbols", semantic_context.symbol_table.symbols.len());

// Access data flow analysis
println!("Reaching definitions: {}", semantic_context.data_flow.reaching_definitions.len());
println!("Use-def chains: {}", semantic_context.data_flow.use_def_chains.len());
println!("Taint flows: {}", semantic_context.data_flow.taint_flows.len());

// Access security context
let security_ctx = &semantic_context.security_context;
println!("Validation points: {}", security_ctx.validation_points.len());
println!("Sanitization points: {}", security_ctx.sanitization_points.len());
println!("Trust levels tracked: {}", security_ctx.trust_levels.len());

// Access call graph analysis
println!("Function calls: {}", semantic_context.call_graph.calls.len());
println!("Function definitions: {}", semantic_context.call_graph.functions.len());

// Access pattern detection
println!("Code patterns: {}", semantic_context.pattern_context.patterns.len());
println!("Anti-patterns: {}", semantic_context.pattern_context.anti_patterns.len());
```

## Supported Languages

| Language   | Extensions           | Symbol Extraction | Security Analysis | Status |
|------------|---------------------|-------------------|-------------------|---------|
| Rust       | `.rs`               | ✅ Functions, structs, impls, traits | ✅ Pattern-based | 🟢 Working |
| JavaScript | `.js`, `.mjs`, `.jsx` | ✅ Functions, classes, methods | ✅ Pattern-based | 🟢 Working |
| TypeScript | `.ts`, `.tsx`       | ✅ Functions, classes, interfaces, types | ✅ Pattern-based | 🟢 Working |
| Go         | `.go`               | ✅ Functions, structs, methods, interfaces | ✅ Pattern-based | 🟢 Working |
| Python     | `.py`, `.pyi`       | ✅ Functions, classes, methods | ✅ Pattern-based | 🟢 Working |
| C          | `.c`, `.h`          | ✅ Functions, structs, typedefs, macros | ✅ Pattern-based | 🟢 Working |
| C++        | `.cpp`, `.hpp`, etc | ✅ Functions, classes, namespaces, templates | ✅ Pattern-based | 🟢 Working |

### Symbol Types Extracted

- **Functions**: Regular functions, methods, constructors
- **Classes/Structs**: Class definitions, struct definitions, implementations
- **Types**: Interfaces, type aliases, enums, traits
- **Visibility**: Public, private, protected (language-dependent)
- **Location**: Line numbers, column positions
- **Documentation**: Extracted where available

### Security Vulnerability Detection

Pattern-based detection for:

- **SQL Injection**: Unsafe query construction
- **Command Injection**: Unsafe command execution
- **XSS**: Cross-site scripting patterns
- **Hardcoded Secrets**: API keys, passwords, tokens
- **Cryptographic Issues**: Weak algorithms, insecure practices
- **Input Validation**: Missing validation patterns
- **Authorization**: Missing access controls

## Configuration

### AI Service Configuration

The AI service supports both JSON and YAML configuration formats with environment variable substitution:

#### Environment Variables

```bash
export OPENAI_API_KEY="your-openai-key"
export ANTHROPIC_API_KEY="your-anthropic-key"
export AZURE_OPENAI_API_KEY="your-azure-key"
```

#### Configuration Options

- **Providers**: OpenAI, Anthropic, Google, Azure, Local, Ollama
- **Models**: Configure multiple models per provider
- **Rate Limiting**: Requests per minute/hour limits
- **Caching**: LRU cache with TTL support
- **Retry Logic**: Exponential backoff with jitter
- **Timeouts**: Configurable request timeouts
- **Cost Tracking**: Token usage and cost estimation

See `ai_config.json` and `ai_config.yaml` for complete configuration examples.

## Test Coverage

### Current Test Status

- **435+ Total Tests Passing**: Comprehensive test suite covering all functionality
- **AI Service Tests**: 6/6 tests passing with full provider integration testing
- **Core Parsing**: All parsing functionality working across 7 languages
- **Symbol Extraction**: Working for all supported languages with symbol detection
- **Security Analysis**: Advanced security scanning with OWASP categorization
- **Complexity Analysis**: Comprehensive complexity metrics (McCabe, cognitive, NPATH, Halstead)
- **AI Service Integration**: Complete AI service layer with provider abstraction
- **Performance Analysis**: Optimization recommendations and hotspot detection
- **CLI Commands**: Core commands working with comprehensive option support
- **Output Formats**: JSON, table, markdown, summary formats
- **Error Handling**: Robust Result<T,E> patterns throughout
- **Configuration**: AI service configuration with multiple provider support

### Test Categories

- **Unit Tests**: 400+ tests covering individual components and functions
- **AI Service Tests**: 6 comprehensive tests covering all AI functionality
- **Integration Tests**: End-to-end testing of CLI commands and workflows
- **Performance Tests**: 8 tests validating performance characteristics
- **Error Handling Tests**: Comprehensive error condition and edge case testing
- **Configuration Tests**: Validation of AI service and core configuration options

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.