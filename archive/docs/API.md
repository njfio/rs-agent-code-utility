# API Documentation

## Core Components

### CodebaseAnalyzer

The main entry point for analyzing codebases.

```rust
use rust_tree_sitter::CodebaseAnalyzer;

// Create analyzer with error handling
let mut analyzer = CodebaseAnalyzer::new()?;

// Analyze a single file
let file_result = analyzer.analyze_file(&path)?;

// Analyze entire directory
let directory_result = analyzer.analyze_directory(&path)?;
```

#### Methods

- `new() -> Result<Self>` - Create a new analyzer with default configuration
- `with_config(config: AnalysisConfig) -> Result<Self>` - Create analyzer with custom configuration
- `analyze_file(&mut self, path: &Path) -> Result<FileInfo>` - Analyze a single file
- `analyze_directory(&mut self, path: &Path) -> Result<AnalysisResult>` - Analyze directory recursively

### EnhancedSecurityScanner

Advanced security vulnerability detection with multi-layered analysis.

```rust
use rust_tree_sitter::EnhancedSecurityScanner;

// Create scanner with default configuration
let scanner = EnhancedSecurityScanner::new();

// Create scanner with custom configuration
let config = EnhancedSecurityConfig {
    enable_vulnerability_db: true,
    enable_secrets_detection: true,
    enable_owasp_scanning: true,
    enable_dependency_scanning: true,
    min_confidence: 0.8,
    max_findings_per_category: 100,
};
let scanner = EnhancedSecurityScanner::with_config(config);

// Scan analysis result
let security_result = scanner.scan_analysis_result(&analysis_result)?;
```

#### Security Features

- **Vulnerability Database**: Check against known vulnerability patterns
- **Secrets Detection**: Find hardcoded secrets with entropy analysis
- **OWASP Scanning**: Detect OWASP Top 10 vulnerabilities
- **Dependency Scanning**: Check dependencies for known CVEs
- **Compliance Assessment**: Generate compliance reports

### IntentMappingSystem

Map business requirements to code implementations with AI assistance.

```rust
use rust_tree_sitter::{IntentMappingSystem, Requirement, RequirementType, Priority};

// Create mapping system
let mut system = IntentMappingSystem::new();

// Add requirements
let requirement = Requirement {
    id: "REQ-001".to_string(),
    requirement_type: RequirementType::UserStory,
    description: "User authentication functionality".to_string(),
    priority: Priority::High,
    acceptance_criteria: vec!["Secure login".to_string()],
    stakeholders: vec!["Product Owner".to_string()],
    tags: vec!["auth".to_string(), "security".to_string()],
    status: RequirementStatus::Approved,
};

system.add_requirement(requirement);

// Generate mappings
let mappings = system.generate_mappings(&analysis_result)?;

// Build traceability matrix
let traceability = system.build_traceability_matrix()?;
```

#### Mapping Features

- **Requirement Tracing**: Track requirements to implementation
- **Coverage Analysis**: Identify gaps and missing implementations
- **Quality Assessment**: Evaluate implementation quality
- **Automated Validation**: AI-assisted validation of mappings

### PerformanceAnalyzer

Analyze code performance characteristics and identify optimization opportunities.

```rust
use rust_tree_sitter::PerformanceAnalyzer;

// Create analyzer
let analyzer = PerformanceAnalyzer::new();

// Analyze performance
let result = analyzer.analyze_performance(&analysis_result)?;

// Access results
println!("Performance Score: {}", result.overall_score);
for hotspot in &result.hotspots {
    println!("Hotspot: {} (impact: {})", hotspot.location.file.display(), hotspot.impact_score);
}
```

#### Performance Features

- **Hotspot Detection**: Identify performance bottlenecks
- **Complexity Analysis**: Calculate cyclomatic complexity
- **Optimization Suggestions**: Recommend performance improvements
- **Scoring System**: Overall performance scoring

## Data Structures

### AnalysisResult

Contains the complete analysis of a codebase.

```rust
pub struct AnalysisResult {
    pub root_path: PathBuf,
    pub total_files: usize,
    pub parsed_files: usize,
    pub error_files: usize,
    pub total_lines: usize,
    pub languages: HashMap<String, usize>,
    pub files: Vec<FileInfo>,
    pub config: AnalysisConfig,
}
```

### FileInfo

Information about a single analyzed file.

```rust
pub struct FileInfo {
    pub path: PathBuf,
    pub language: String,
    pub size: u64,
    pub lines: usize,
    pub parsed_successfully: bool,
    pub parse_errors: Vec<String>,
    pub symbols: Vec<Symbol>,
    pub security_vulnerabilities: Vec<SecurityVulnerability>,
}
```

### Symbol

Represents a code symbol (function, class, etc.).

```rust
pub struct Symbol {
    pub name: String,
    pub symbol_type: SymbolType,
    pub line: usize,
    pub column: usize,
    pub end_line: Option<usize>,
    pub end_column: Option<usize>,
    pub visibility: String,
    pub documentation: Option<String>,
    pub parameters: Vec<String>,
    pub return_type: Option<String>,
}
```

### SecurityVulnerability

Represents a detected security vulnerability.

```rust
pub struct SecurityVulnerability {
    pub id: String,
    pub title: String,
    pub description: String,
    pub severity: SecuritySeverity,
    pub confidence: f64,
    pub location: SecurityLocation,
    pub cwe_id: Option<String>,
    pub owasp_category: Option<String>,
    pub remediation: Option<String>,
}
```

## Configuration

### AnalysisConfig

Configure analysis behavior.

```rust
pub struct AnalysisConfig {
    pub max_file_size: Option<u64>,
    pub include_patterns: Vec<String>,
    pub exclude_patterns: Vec<String>,
    pub max_depth: Option<usize>,
    pub follow_symlinks: bool,
    pub parse_comments: bool,
    pub extract_documentation: bool,
}
```

### EnhancedSecurityConfig

Configure security analysis.

```rust
pub struct EnhancedSecurityConfig {
    pub enable_vulnerability_db: bool,
    pub enable_secrets_detection: bool,
    pub enable_owasp_scanning: bool,
    pub enable_dependency_scanning: bool,
    pub min_confidence: f64,
    pub max_findings_per_category: usize,
}
```

## Error Handling

All functions return `Result<T, E>` types for proper error handling:

```rust
use rust_tree_sitter::{CodebaseAnalyzer, AnalysisError};

match CodebaseAnalyzer::new() {
    Ok(mut analyzer) => {
        match analyzer.analyze_directory(&path) {
            Ok(result) => println!("Analysis complete: {} files", result.total_files),
            Err(e) => eprintln!("Analysis failed: {}", e),
        }
    }
    Err(e) => eprintln!("Failed to create analyzer: {}", e),
}
```

## Constants

All configuration constants are centralized in the `constants` module:

```rust
use rust_tree_sitter::constants::{
    security::DEFAULT_MIN_CONFIDENCE,
    performance::FUNCTION_LENGTH_HIGH_THRESHOLD,
    intent_mapping::DEFAULT_CONFIDENCE_THRESHOLD,
};
```

## Examples

See the `examples/` directory for complete usage examples:

- `basic_analysis.rs` - Basic codebase analysis
- `security_scan.rs` - Security vulnerability scanning
- `intent_mapping.rs` - Requirements mapping
- `performance_analysis.rs` - Performance analysis
- `cli_integration.rs` - CLI integration examples
