use crate::{SyntaxTree, Result, TaintAnalyzer, TaintFlow, VulnerabilityType};
use std::collections::{HashMap, HashSet};
use tree_sitter::Node;

/// SQL injection vulnerability detected by AST analysis
#[derive(Debug, Clone)]
pub struct SqlInjectionVulnerability {
    /// Unique identifier for this vulnerability
    pub id: String,
    /// Taint flow that leads to the vulnerability
    pub taint_flow: TaintFlow,
    /// SQL query pattern that's vulnerable
    pub query_pattern: SqlQueryPattern,
    /// Confidence level (0.0 to 1.0)
    pub confidence: f64,
    /// Severity level
    pub severity: SqlInjectionSeverity,
    /// Specific SQL injection type
    pub injection_type: SqlInjectionType,
    /// Remediation suggestions
    pub remediation: SqlInjectionRemediation,
}

/// Types of SQL injection vulnerabilities
#[derive(Debug, Clone, PartialEq)]
pub enum SqlInjectionType {
    /// Classic SQL injection via string concatenation
    StringConcatenation,
    /// SQL injection via format strings
    FormatString,
    /// SQL injection via template literals
    TemplateLiteral,
    /// SQL injection via dynamic query building
    DynamicQuery,
    /// Second-order SQL injection
    SecondOrder,
    /// Blind SQL injection
    Blind,
}

/// Severity levels for SQL injection
#[derive(Debug, Clone, PartialEq)]
pub enum SqlInjectionSeverity {
    Critical,
    High,
    Medium,
    Low,
}

/// SQL query patterns that can be vulnerable
#[derive(Debug, Clone)]
pub struct SqlQueryPattern {
    /// The SQL operation type
    pub operation: SqlOperation,
    /// Whether the query uses parameterization
    pub is_parameterized: bool,
    /// Whether user input is directly concatenated
    pub has_direct_concatenation: bool,
    /// Whether the query uses dynamic table/column names
    pub has_dynamic_identifiers: bool,
    /// SQL keywords found in the query
    pub sql_keywords: Vec<String>,
}

/// Types of SQL operations
#[derive(Debug, Clone, PartialEq)]
pub enum SqlOperation {
    Select,
    Insert,
    Update,
    Delete,
    Create,
    Drop,
    Alter,
    Union,
    Unknown,
}

/// Remediation guidance for SQL injection
#[derive(Debug, Clone)]
pub struct SqlInjectionRemediation {
    /// Primary remediation strategy
    pub primary_fix: String,
    /// Step-by-step remediation instructions
    pub steps: Vec<String>,
    /// Code examples showing secure alternatives
    pub secure_examples: Vec<SecureCodeExample>,
    /// Estimated effort to fix
    pub effort_level: RemediationEffort,
}

/// Secure code examples for remediation
#[derive(Debug, Clone)]
pub struct SecureCodeExample {
    /// Description of the secure approach
    pub description: String,
    /// Vulnerable code pattern
    pub vulnerable_code: String,
    /// Secure replacement code
    pub secure_code: String,
    /// Programming language
    pub language: String,
}

/// Effort level for remediation
#[derive(Debug, Clone, PartialEq)]
pub enum RemediationEffort {
    Trivial,
    Low,
    Medium,
    High,
    Critical,
}

/// SQL injection detector using AST-based taint analysis
pub struct SqlInjectionDetector {
    language: String,
    taint_analyzer: TaintAnalyzer,
    /// SQL keywords for different languages/frameworks
    sql_keywords: HashSet<String>,
    /// Known SQL functions and methods
    sql_functions: HashMap<String, SqlOperation>,
    /// Known parameterized query patterns
    safe_patterns: HashSet<String>,
}

impl SqlInjectionDetector {
    /// Create a new SQL injection detector for the specified language
    pub fn new(language: &str) -> Self {
        let mut detector = Self {
            language: language.to_string(),
            taint_analyzer: TaintAnalyzer::new(language),
            sql_keywords: HashSet::new(),
            sql_functions: HashMap::new(),
            safe_patterns: HashSet::new(),
        };
        
        detector.initialize_sql_patterns();
        detector
    }
    
    /// Initialize SQL patterns and keywords for the language
    fn initialize_sql_patterns(&mut self) {
        // Common SQL keywords
        let keywords = [
            "SELECT", "INSERT", "UPDATE", "DELETE", "CREATE", "DROP", "ALTER",
            "UNION", "WHERE", "FROM", "JOIN", "ORDER", "GROUP", "HAVING",
            "LIMIT", "OFFSET", "INTO", "VALUES", "SET"
        ];
        
        for keyword in &keywords {
            self.sql_keywords.insert(keyword.to_string());
            self.sql_keywords.insert(keyword.to_lowercase());
        }
        
        match self.language.as_str() {
            "rust" => self.initialize_rust_sql_patterns(),
            "javascript" | "typescript" => self.initialize_javascript_sql_patterns(),
            "python" => self.initialize_python_sql_patterns(),
            "c" | "cpp" | "c++" => self.initialize_c_sql_patterns(),
            "go" => self.initialize_go_sql_patterns(),
            _ => self.initialize_generic_sql_patterns(),
        }
    }
    
    /// Initialize Rust-specific SQL patterns
    fn initialize_rust_sql_patterns(&mut self) {
        // SQL functions
        self.sql_functions.insert("sqlx::query".to_string(), SqlOperation::Select);
        self.sql_functions.insert("sqlx::query_as".to_string(), SqlOperation::Select);
        self.sql_functions.insert("diesel::sql_query".to_string(), SqlOperation::Select);
        self.sql_functions.insert("rusqlite::prepare".to_string(), SqlOperation::Select);
        
        // Safe patterns (parameterized queries)
        self.safe_patterns.insert("sqlx::query!".to_string());
        self.safe_patterns.insert("sqlx::query_as!".to_string());
        self.safe_patterns.insert("diesel::insert_into".to_string());
    }
    
    /// Initialize JavaScript/TypeScript-specific SQL patterns
    fn initialize_javascript_sql_patterns(&mut self) {
        // SQL functions
        self.sql_functions.insert("mysql.query".to_string(), SqlOperation::Select);
        self.sql_functions.insert("pg.query".to_string(), SqlOperation::Select);
        self.sql_functions.insert("sqlite3.run".to_string(), SqlOperation::Select);
        self.sql_functions.insert("sequelize.query".to_string(), SqlOperation::Select);
        
        // Safe patterns
        self.safe_patterns.insert("mysql.execute".to_string());
        self.safe_patterns.insert("pg.query".to_string()); // When used with parameters
        self.safe_patterns.insert("sequelize.literal".to_string());
    }
    
    /// Initialize Python-specific SQL patterns
    fn initialize_python_sql_patterns(&mut self) {
        // SQL functions
        self.sql_functions.insert("cursor.execute".to_string(), SqlOperation::Select);
        self.sql_functions.insert("cursor.executemany".to_string(), SqlOperation::Select);
        self.sql_functions.insert("session.execute".to_string(), SqlOperation::Select);
        
        // Safe patterns
        self.safe_patterns.insert("cursor.execute".to_string()); // When used with parameters
        self.safe_patterns.insert("text".to_string()); // SQLAlchemy text() with parameters
    }
    
    /// Initialize C/C++-specific SQL patterns
    fn initialize_c_sql_patterns(&mut self) {
        // SQL functions
        self.sql_functions.insert("mysql_query".to_string(), SqlOperation::Select);
        self.sql_functions.insert("sqlite3_exec".to_string(), SqlOperation::Select);
        self.sql_functions.insert("PQexec".to_string(), SqlOperation::Select);
        
        // Safe patterns
        self.safe_patterns.insert("mysql_stmt_prepare".to_string());
        self.safe_patterns.insert("sqlite3_prepare_v2".to_string());
        self.safe_patterns.insert("PQprepare".to_string());
    }
    
    /// Initialize Go-specific SQL patterns
    fn initialize_go_sql_patterns(&mut self) {
        // SQL functions
        self.sql_functions.insert("db.Query".to_string(), SqlOperation::Select);
        self.sql_functions.insert("db.Exec".to_string(), SqlOperation::Select);
        self.sql_functions.insert("tx.Query".to_string(), SqlOperation::Select);
        
        // Safe patterns
        self.safe_patterns.insert("db.Query".to_string()); // When used with parameters
        self.safe_patterns.insert("db.Prepare".to_string());
    }
    
    /// Initialize generic SQL patterns
    fn initialize_generic_sql_patterns(&mut self) {
        self.sql_functions.insert("query".to_string(), SqlOperation::Select);
        self.sql_functions.insert("execute".to_string(), SqlOperation::Select);
        self.sql_functions.insert("exec".to_string(), SqlOperation::Select);
    }
    
    /// Detect SQL injection vulnerabilities in a syntax tree
    pub fn detect(&mut self, tree: &SyntaxTree) -> Result<Vec<SqlInjectionVulnerability>> {
        let mut vulnerabilities = Vec::new();

        // Perform enhanced taint analysis to find data flows
        let taint_flows = self.taint_analyzer.analyze(tree)?;
        
        // Filter flows that lead to SQL injection vulnerabilities
        for flow in taint_flows {
            if flow.sink.vulnerability_type == VulnerabilityType::SqlInjection {
                if let Some(vulnerability) = self.analyze_sql_injection_flow(tree, &flow)? {
                    vulnerabilities.push(vulnerability);
                }
            }
        }
        
        // Also perform direct AST analysis for SQL patterns
        let direct_vulnerabilities = self.detect_direct_sql_patterns(tree)?;
        vulnerabilities.extend(direct_vulnerabilities);
        
        // Deduplicate and rank by confidence
        vulnerabilities.sort_by(|a, b| b.confidence.partial_cmp(&a.confidence).unwrap_or(std::cmp::Ordering::Equal));
        vulnerabilities.dedup_by(|a, b| a.id == b.id);
        
        Ok(vulnerabilities)
    }
    
    /// Analyze a taint flow to determine if it represents a SQL injection vulnerability
    fn analyze_sql_injection_flow(&self, tree: &SyntaxTree, flow: &TaintFlow) -> Result<Option<SqlInjectionVulnerability>> {
        // Analyze the SQL query pattern at the sink
        let query_pattern = self.analyze_sql_query_pattern(tree, &flow.sink.location)?;
        
        // Determine injection type based on the flow and pattern
        let injection_type = self.determine_injection_type(&query_pattern, flow);
        
        // Calculate confidence based on various factors
        let confidence = self.calculate_confidence(&query_pattern, flow);
        
        // Skip if confidence is too low
        if confidence < 0.3 {
            return Ok(None);
        }
        
        // Determine severity
        let severity = self.determine_severity(&query_pattern, &injection_type);
        
        // Generate remediation guidance
        let remediation = self.generate_remediation(&injection_type, &query_pattern);
        
        Ok(Some(SqlInjectionVulnerability {
            id: format!("sqli_{}_{}", flow.sink.location.line, flow.sink.location.column),
            taint_flow: flow.clone(),
            query_pattern,
            confidence,
            severity,
            injection_type,
            remediation,
        }))
    }
    
    /// Detect SQL injection patterns directly from AST without taint analysis
    fn detect_direct_sql_patterns(&self, tree: &SyntaxTree) -> Result<Vec<SqlInjectionVulnerability>> {
        let mut vulnerabilities = Vec::new();
        self.traverse_for_sql_patterns(tree.inner().root_node(), &mut vulnerabilities)?;
        Ok(vulnerabilities)
    }
    
    /// Recursively traverse AST looking for SQL injection patterns
    fn traverse_for_sql_patterns(&self, node: Node, vulnerabilities: &mut Vec<SqlInjectionVulnerability>) -> Result<()> {
        // Check if this node contains a potential SQL injection
        if let Some(vulnerability) = self.check_node_for_sql_injection(node)? {
            vulnerabilities.push(vulnerability);
        }
        
        // Traverse children
        let mut cursor = node.walk();
        if cursor.goto_first_child() {
            loop {
                self.traverse_for_sql_patterns(cursor.node(), vulnerabilities)?;
                if !cursor.goto_next_sibling() {
                    break;
                }
            }
        }
        
        Ok(())
    }
    
    /// Check a specific node for SQL injection patterns
    fn check_node_for_sql_injection(&self, node: Node) -> Result<Option<SqlInjectionVulnerability>> {
        // Look for string concatenation with SQL keywords
        if self.is_string_concatenation(node) {
            if let Some(sql_content) = self.extract_sql_from_concatenation(node) {
                if self.contains_sql_keywords(&sql_content) {
                    return Ok(Some(self.create_direct_vulnerability(node, SqlInjectionType::StringConcatenation)?));
                }
            }
        }
        
        // Look for format string operations with SQL
        if self.is_format_operation(node) {
            if let Some(format_string) = self.extract_format_string(node) {
                if self.contains_sql_keywords(&format_string) {
                    return Ok(Some(self.create_direct_vulnerability(node, SqlInjectionType::FormatString)?));
                }
            }
        }
        
        // Look for template literals with SQL (JavaScript/TypeScript)
        if self.is_template_literal(node) {
            if let Some(template_content) = self.extract_template_content(node) {
                if self.contains_sql_keywords(&template_content) {
                    return Ok(Some(self.create_direct_vulnerability(node, SqlInjectionType::TemplateLiteral)?));
                }
            }
        }
        
        Ok(None)
    }
    
    /// Analyze SQL query pattern at a specific location
    fn analyze_sql_query_pattern(&self, _tree: &SyntaxTree, _location: &crate::taint_analysis::TaintLocation) -> Result<SqlQueryPattern> {
        // This is a simplified implementation
        // In practice, would need to analyze the actual SQL query structure
        Ok(SqlQueryPattern {
            operation: SqlOperation::Select,
            is_parameterized: false,
            has_direct_concatenation: true,
            has_dynamic_identifiers: false,
            sql_keywords: vec!["SELECT".to_string()],
        })
    }
    
    /// Determine the type of SQL injection based on pattern and flow
    fn determine_injection_type(&self, pattern: &SqlQueryPattern, _flow: &TaintFlow) -> SqlInjectionType {
        if pattern.has_direct_concatenation {
            SqlInjectionType::StringConcatenation
        } else if pattern.has_dynamic_identifiers {
            SqlInjectionType::DynamicQuery
        } else {
            SqlInjectionType::StringConcatenation // Default
        }
    }
    
    /// Calculate confidence level for the vulnerability
    fn calculate_confidence(&self, pattern: &SqlQueryPattern, flow: &TaintFlow) -> f64 {
        let mut confidence = 0.5;
        
        // Higher confidence if direct concatenation is detected
        if pattern.has_direct_concatenation {
            confidence += 0.3;
        }
        
        // Higher confidence if SQL keywords are present
        if !pattern.sql_keywords.is_empty() {
            confidence += 0.2;
        }
        
        // Factor in taint flow confidence
        confidence = (confidence + flow.confidence) / 2.0;
        
        // Lower confidence if sanitization is detected
        if flow.is_sanitized {
            confidence *= 0.3;
        }
        
        confidence.min(1.0)
    }
    
    /// Determine severity based on pattern and injection type
    fn determine_severity(&self, pattern: &SqlQueryPattern, injection_type: &SqlInjectionType) -> SqlInjectionSeverity {
        match injection_type {
            SqlInjectionType::StringConcatenation | SqlInjectionType::FormatString => {
                if pattern.operation == SqlOperation::Delete || pattern.operation == SqlOperation::Drop {
                    SqlInjectionSeverity::Critical
                } else {
                    SqlInjectionSeverity::High
                }
            }
            SqlInjectionType::DynamicQuery => SqlInjectionSeverity::High,
            SqlInjectionType::TemplateLiteral => SqlInjectionSeverity::Medium,
            SqlInjectionType::SecondOrder | SqlInjectionType::Blind => SqlInjectionSeverity::Medium,
        }
    }
    
    /// Generate remediation guidance
    fn generate_remediation(&self, injection_type: &SqlInjectionType, _pattern: &SqlQueryPattern) -> SqlInjectionRemediation {
        match injection_type {
            SqlInjectionType::StringConcatenation => SqlInjectionRemediation {
                primary_fix: "Replace string concatenation with parameterized queries".to_string(),
                steps: vec![
                    "Identify all user inputs in the SQL query".to_string(),
                    "Replace concatenation with parameter placeholders".to_string(),
                    "Pass user inputs as separate parameters".to_string(),
                    "Use prepared statements where possible".to_string(),
                ],
                secure_examples: vec![
                    SecureCodeExample {
                        description: "Use parameterized query instead of concatenation".to_string(),
                        vulnerable_code: "query = \"SELECT * FROM users WHERE id = \" + user_id".to_string(),
                        secure_code: "query = \"SELECT * FROM users WHERE id = ?\"; execute(query, [user_id])".to_string(),
                        language: self.language.clone(),
                    }
                ],
                effort_level: RemediationEffort::Medium,
            },
            _ => SqlInjectionRemediation {
                primary_fix: "Use parameterized queries and input validation".to_string(),
                steps: vec!["Replace dynamic query building with safe alternatives".to_string()],
                secure_examples: vec![],
                effort_level: RemediationEffort::Medium,
            },
        }
    }
    
    /// Check if node represents string concatenation
    fn is_string_concatenation(&self, node: Node) -> bool {
        let node_kind = node.kind();
        match self.language.as_str() {
            "rust" => node_kind == "binary_expression",
            "javascript" | "typescript" => node_kind == "binary_expression",
            "python" => node_kind == "binary_operator",
            "c" | "cpp" | "c++" => node_kind == "binary_expression",
            "go" => node_kind == "binary_expression",
            _ => node_kind.contains("binary") || node_kind.contains("concat"),
        }
    }
    
    /// Check if node represents a format operation
    fn is_format_operation(&self, node: Node) -> bool {
        // Simplified check - would need language-specific implementation
        if let Ok(text) = node.utf8_text(b"") {
            text.contains("format") || text.contains("sprintf") || text.contains("%")
        } else {
            false
        }
    }
    
    /// Check if node represents a template literal
    fn is_template_literal(&self, node: Node) -> bool {
        node.kind() == "template_string" || node.kind() == "template_literal"
    }
    
    /// Extract SQL content from string concatenation
    fn extract_sql_from_concatenation(&self, node: Node) -> Option<String> {
        if let Ok(text) = node.utf8_text(b"") {
            Some(text.to_string())
        } else {
            None
        }
    }
    
    /// Extract format string content
    fn extract_format_string(&self, node: Node) -> Option<String> {
        if let Ok(text) = node.utf8_text(b"") {
            Some(text.to_string())
        } else {
            None
        }
    }
    
    /// Extract template literal content
    fn extract_template_content(&self, node: Node) -> Option<String> {
        if let Ok(text) = node.utf8_text(b"") {
            Some(text.to_string())
        } else {
            None
        }
    }
    
    /// Check if text contains SQL keywords
    fn contains_sql_keywords(&self, text: &str) -> bool {
        let text_upper = text.to_uppercase();
        self.sql_keywords.iter().any(|keyword| text_upper.contains(keyword))
    }
    
    /// Create a vulnerability from direct AST analysis
    fn create_direct_vulnerability(&self, node: Node, injection_type: SqlInjectionType) -> Result<SqlInjectionVulnerability> {
        // This is a simplified implementation
        let query_pattern = SqlQueryPattern {
            operation: SqlOperation::Select,
            is_parameterized: false,
            has_direct_concatenation: true,
            has_dynamic_identifiers: false,
            sql_keywords: vec!["SELECT".to_string()],
        };
        
        let remediation = self.generate_remediation(&injection_type, &query_pattern);
        let severity = self.determine_severity(&query_pattern, &injection_type);
        
        Ok(SqlInjectionVulnerability {
            id: format!("direct_sqli_{}_{}", node.start_position().row, node.start_position().column),
            taint_flow: TaintFlow {
                source: crate::taint_analysis::TaintSource {
                    id: "direct".to_string(),
                    name: "direct_analysis".to_string(),
                    source_type: crate::taint_analysis::TaintSourceType::UserInput,
                    location: crate::taint_analysis::TaintLocation {
                        file: "current_file".to_string(),
                        line: node.start_position().row + 1,
                        column: node.start_position().column,
                        function: None,
                    },
                    confidence: 0.8,
                },
                sink: crate::taint_analysis::TaintSink {
                    id: "direct_sink".to_string(),
                    name: "sql_query".to_string(),
                    sink_type: crate::taint_analysis::TaintSinkType::SqlQuery,
                    location: crate::taint_analysis::TaintLocation {
                        file: "current_file".to_string(),
                        line: node.start_position().row + 1,
                        column: node.start_position().column,
                        function: None,
                    },
                    vulnerability_type: VulnerabilityType::SqlInjection,
                },
                path: vec![],
                confidence: 0.8,
                is_sanitized: false,
                sanitizers: vec![],
            },
            query_pattern,
            confidence: 0.8,
            severity,
            injection_type,
            remediation,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // Parser import removed as it's not used in tests

    #[test]
    fn test_sql_injection_detector_creation() {
        let detector = SqlInjectionDetector::new("javascript");
        assert_eq!(detector.language, "javascript");
        assert!(!detector.sql_keywords.is_empty());
    }

    #[test]
    fn test_sql_keywords_detection() {
        let detector = SqlInjectionDetector::new("python");
        assert!(detector.contains_sql_keywords("SELECT * FROM users"));
        assert!(detector.contains_sql_keywords("select * from users"));
        assert!(!detector.contains_sql_keywords("console.log('hello')"));
    }

    #[test]
    fn test_injection_type_determination() {
        let detector = SqlInjectionDetector::new("rust");
        let pattern = SqlQueryPattern {
            operation: SqlOperation::Select,
            is_parameterized: false,
            has_direct_concatenation: true,
            has_dynamic_identifiers: false,
            sql_keywords: vec!["SELECT".to_string()],
        };
        
        // Create a dummy taint flow for testing
        let flow = TaintFlow {
            source: crate::taint_analysis::TaintSource {
                id: "test".to_string(),
                name: "test".to_string(),
                source_type: crate::taint_analysis::TaintSourceType::UserInput,
                location: crate::taint_analysis::TaintLocation {
                    file: "test.rs".to_string(),
                    line: 1,
                    column: 1,
                    function: None,
                },
                confidence: 0.9,
            },
            sink: crate::taint_analysis::TaintSink {
                id: "test_sink".to_string(),
                name: "query".to_string(),
                sink_type: crate::taint_analysis::TaintSinkType::SqlQuery,
                location: crate::taint_analysis::TaintLocation {
                    file: "test.rs".to_string(),
                    line: 5,
                    column: 1,
                    function: None,
                },
                vulnerability_type: VulnerabilityType::SqlInjection,
            },
            path: vec![],
            confidence: 0.9,
            is_sanitized: false,
            sanitizers: vec![],
        };
        
        let injection_type = detector.determine_injection_type(&pattern, &flow);
        assert_eq!(injection_type, SqlInjectionType::StringConcatenation);
    }
}
