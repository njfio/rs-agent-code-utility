//! Rust-specific AST-based security analyzer
//!
//! This module implements security analysis for Rust code using AST parsing,
//! focusing on detecting common vulnerabilities and unsafe patterns.

use crate::error::{Error, Result};
use crate::languages::Language;
use crate::parser::Parser;
use crate::security::ast_analyzer::{
    CodeContext, FunctionCall, FunctionInfo, InjectionPoint, LanguageSpecificAnalyzer,
    SecurityFinding, SecurityFindingType, SecuritySeverity, SemanticInfo, StringLiteral,
    VariableInfo, VulnerabilityPattern,
};
use crate::tree::{Node, SyntaxTree};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use tracing::{debug, warn};

/// Rust-specific security analyzer
#[derive(Debug)]
pub struct RustAnalyzer {
    vulnerability_patterns: Vec<VulnerabilityPattern>,
}

impl RustAnalyzer {
    pub fn new() -> Self {
        let vulnerability_patterns = Self::initialize_patterns();
        Self {
            vulnerability_patterns,
        }
    }

    /// Initialize Rust-specific vulnerability patterns
    fn initialize_patterns() -> Vec<VulnerabilityPattern> {
        vec![
            VulnerabilityPattern {
                name: "Unsafe Block Usage".to_string(),
                description: "Use of unsafe blocks can lead to memory safety violations"
                    .to_string(),
                node_types: vec!["unsafe_block".to_string()],
                child_patterns: vec![],
                context_requirements: vec![],
                severity: SecuritySeverity::Medium,
                cwe_id: Some("CWE-119".to_string()),
            },
            VulnerabilityPattern {
                name: "Raw Pointer Usage".to_string(),
                description: "Raw pointer operations can bypass Rust's safety guarantees"
                    .to_string(),
                node_types: vec!["pointer_type".to_string(), "raw_pointer_type".to_string()],
                child_patterns: vec![],
                context_requirements: vec![],
                severity: SecuritySeverity::High,
                cwe_id: Some("CWE-119".to_string()),
            },
            VulnerabilityPattern {
                name: "Potential SQL Injection".to_string(),
                description: "String concatenation in SQL queries can lead to injection"
                    .to_string(),
                node_types: vec!["call_expression".to_string()],
                child_patterns: vec!["query".to_string(), "execute".to_string()],
                context_requirements: vec!["sql".to_string()],
                severity: SecuritySeverity::Critical,
                cwe_id: Some("CWE-89".to_string()),
            },
            VulnerabilityPattern {
                name: "Weak Cryptographic Function".to_string(),
                description: "Use of weak cryptographic functions".to_string(),
                node_types: vec!["call_expression".to_string()],
                child_patterns: vec!["md5".to_string(), "sha1".to_string()],
                context_requirements: vec![],
                severity: SecuritySeverity::High,
                cwe_id: Some("CWE-327".to_string()),
            },
            VulnerabilityPattern {
                name: "Hardcoded Secret".to_string(),
                description: "Potential hardcoded secret or credential".to_string(),
                node_types: vec!["string_literal".to_string()],
                child_patterns: vec![],
                context_requirements: vec![
                    "password".to_string(),
                    "secret".to_string(),
                    "key".to_string(),
                ],
                severity: SecuritySeverity::High,
                cwe_id: Some("CWE-798".to_string()),
            },
        ]
    }

    /// Extract semantic information from Rust AST
    fn extract_rust_semantic_info(&self, tree: &SyntaxTree) -> Result<SemanticInfo> {
        let mut functions = Vec::new();
        let mut classes = Vec::new(); // In Rust, these are structs/impl blocks
        let mut variables = HashMap::new();
        let mut imports = Vec::new();
        let mut string_literals = Vec::new();
        let mut function_calls = Vec::new();

        self.extract_functions(&tree.root_node(), &mut functions)?;
        self.extract_structs(&tree.root_node(), &mut classes)?;
        self.extract_variables(&tree.root_node(), &mut variables)?;
        self.extract_imports(&tree.root_node(), &mut imports)?;
        self.extract_string_literals(&tree.root_node(), &mut string_literals)?;
        self.extract_function_calls(&tree.root_node(), &mut function_calls)?;

        Ok(SemanticInfo {
            functions,
            classes,
            variables,
            imports,
            string_literals,
            function_calls,
        })
    }

    /// Extract function definitions from AST
    fn extract_functions(&self, node: &Node, functions: &mut Vec<FunctionInfo>) -> Result<()> {
        if node.kind() == "function_item" {
            let name = self.extract_function_name(node)?;
            let parameters = self.extract_function_parameters(node)?;
            let return_type = self.extract_function_return_type(node)?;
            let is_public = self.is_function_public(node)?;
            let line_number = node.start_position().row;
            let (body_start, body_end) = self.extract_function_body_range(node)?;

            functions.push(FunctionInfo {
                name,
                parameters,
                return_type,
                is_public,
                line_number,
                body_start,
                body_end,
            });
        }

        // Recursively process children
        for child in node.children() {
            self.extract_functions(&child, functions)?;
        }

        Ok(())
    }

    /// Extract struct/impl definitions from AST
    fn extract_structs(
        &self,
        node: &Node,
        classes: &mut Vec<crate::security::ast_analyzer::ClassInfo>,
    ) -> Result<()> {
        if node.kind() == "struct_item" {
            let name = self.extract_struct_name(node)?;
            let fields = self.extract_struct_fields(node)?;
            let methods = Vec::new(); // Will be populated from impl blocks
            let is_public = self.is_struct_public(node)?;
            let line_number = node.start_position().row;

            classes.push(crate::security::ast_analyzer::ClassInfo {
                name,
                fields,
                methods,
                is_public,
                line_number,
            });
        }

        // Recursively process children
        for child in node.children() {
            self.extract_structs(&child, classes)?;
        }

        Ok(())
    }

    /// Extract variables and constants from AST
    fn extract_variables(
        &self,
        node: &Node,
        variables: &mut HashMap<String, VariableInfo>,
    ) -> Result<()> {
        if node.kind() == "let_declaration" {
            if let Some(name) = self.extract_variable_name(node) {
                let var_type = self.extract_variable_type(node);
                let is_constant = self.is_constant_declaration(node);
                let declaration_line = node.start_position().row;
                let usage_locations = Vec::new(); // Will be populated during analysis

                variables.insert(
                    name.clone(),
                    VariableInfo {
                        var_type,
                        is_constant,
                        declaration_line,
                        usage_locations,
                    },
                );
            }
        } else if node.kind() == "const_item" {
            if let Some(name) = self.extract_const_name(node) {
                let var_type = self.extract_const_type(node);
                let declaration_line = node.start_position().row;
                let usage_locations = Vec::new();

                variables.insert(
                    name.clone(),
                    VariableInfo {
                        var_type,
                        is_constant: true,
                        declaration_line,
                        usage_locations,
                    },
                );
            }
        }

        // Recursively process children
        for child in node.children() {
            self.extract_variables(&child, variables)?;
        }

        Ok(())
    }

    /// Extract import statements
    fn extract_imports(&self, node: &Node, imports: &mut Vec<String>) -> Result<()> {
        if node.kind() == "use_declaration" {
            if let Ok(import_text) = node.text() {
                imports.push(import_text.to_string());
            }
        }

        // Recursively process children
        for child in node.children() {
            self.extract_imports(&child, imports)?;
        }

        Ok(())
    }

    /// Extract string literals
    fn extract_string_literals(
        &self,
        node: &Node,
        literals: &mut Vec<StringLiteral>,
    ) -> Result<()> {
        if node.kind() == "string_literal" {
            if let Ok(text) = node.text() {
                let value = self.extract_string_content(&text);
                let line_number = node.start_position().row;
                let is_multiline = text.contains("\\n") || text.lines().count() > 1;
                let context = self.extract_literal_context(node)?;

                literals.push(StringLiteral {
                    value,
                    line_number,
                    is_multiline,
                    context,
                });
            }
        }

        // Recursively process children
        for child in node.children() {
            self.extract_string_literals(&child, literals)?;
        }

        Ok(())
    }

    /// Extract function calls
    fn extract_function_calls(&self, node: &Node, calls: &mut Vec<FunctionCall>) -> Result<()> {
        if node.kind() == "call_expression" {
            let function_name = self.extract_call_function_name(&node)?;
            let arguments = self.extract_call_arguments(node)?;
            let line_number = node.start_position().row;
            let is_method_call = self.is_method_call(node)?;

            calls.push(FunctionCall {
                function_name,
                arguments,
                line_number,
                is_method_call,
            });
        }

        // Recursively process children
        for child in node.children() {
            self.extract_function_calls(&child, calls)?;
        }

        Ok(())
    }

    /// Analyze Rust code for security vulnerabilities
    async fn analyze_rust_code(
        &self,
        tree: &SyntaxTree,
        file_path: &str,
    ) -> Result<Vec<SecurityFinding>> {
        let mut findings = Vec::new();

        // Analyze unsafe blocks
        findings.extend(self.analyze_unsafe_blocks(tree, file_path)?);

        // Analyze raw pointer usage
        findings.extend(self.analyze_raw_pointers(tree, file_path)?);

        // Analyze potential SQL injection
        findings.extend(self.analyze_sql_injection(tree, file_path)?);

        // Analyze weak cryptography
        findings.extend(self.analyze_weak_crypto(tree, file_path)?);

        // Analyze hardcoded secrets
        findings.extend(self.analyze_hardcoded_secrets(tree, file_path)?);

        // Analyze access control
        findings.extend(self.analyze_access_control(tree, file_path)?);

        Ok(findings)
    }

    /// Analyze unsafe blocks
    fn analyze_unsafe_blocks(
        &self,
        tree: &SyntaxTree,
        file_path: &str,
    ) -> Result<Vec<SecurityFinding>> {
        let mut findings = Vec::new();

        for node in tree.find_nodes_by_kind("unsafe_block") {
            let line_number = node.start_position().row;
            let code_snippet = self.extract_code_snippet(&node, tree)?;

            findings.push(SecurityFinding {
                id: uuid::Uuid::new_v4().to_string(),
                finding_type: SecurityFindingType::InsecureDesign,
                severity: SecuritySeverity::Medium,
                title: "Unsafe Block Usage".to_string(),
                description: "Use of unsafe blocks can lead to memory safety violations"
                    .to_string(),
                file_path: file_path.to_string(),
                line_number,
                column_start: node.start_position().column,
                column_end: node.end_position().column,
                code_snippet,
                cwe_id: Some("CWE-119".to_string()),
                remediation: "Review unsafe block usage and ensure proper safety guarantees"
                    .to_string(),
                confidence: 0.8,
                context: CodeContext::default(),
            });
        }

        Ok(findings)
    }

    /// Analyze raw pointer usage
    fn analyze_raw_pointers(
        &self,
        tree: &SyntaxTree,
        file_path: &str,
    ) -> Result<Vec<SecurityFinding>> {
        let mut findings = Vec::new();

        for node in tree.find_nodes_by_kind("pointer_type") {
            let line_number = node.start_position().row;
            let code_snippet = self.extract_code_snippet(&node, tree)?;

            findings.push(SecurityFinding {
                id: uuid::Uuid::new_v4().to_string(),
                finding_type: SecurityFindingType::InsecureDesign,
                severity: SecuritySeverity::High,
                title: "Raw Pointer Usage".to_string(),
                description: "Raw pointer operations can bypass Rust's safety guarantees"
                    .to_string(),
                file_path: file_path.to_string(),
                line_number,
                column_start: node.start_position().column,
                column_end: node.end_position().column,
                code_snippet,
                cwe_id: Some("CWE-119".to_string()),
                remediation: "Consider using safe Rust abstractions instead of raw pointers"
                    .to_string(),
                confidence: 0.9,
                context: CodeContext::default(),
            });
        }

        Ok(findings)
    }

    /// Analyze potential SQL injection
    fn analyze_sql_injection(
        &self,
        tree: &SyntaxTree,
        file_path: &str,
    ) -> Result<Vec<SecurityFinding>> {
        let mut findings = Vec::new();

        for node in tree.find_nodes_by_kind("call_expression") {
            if let Ok(function_name) = self.extract_call_function_name(&node) {
                if self.is_sql_function(&function_name) {
                    let arguments = self.extract_call_arguments(&node)?;

                    // Check for string concatenation in SQL queries
                    for arg in arguments {
                        if arg.contains(" + ") || arg.contains("&") {
                            let line_number = node.start_position().row;
                            let code_snippet = self.extract_code_snippet(&node, tree)?;

                            findings.push(SecurityFinding {
                                id: uuid::Uuid::new_v4().to_string(),
                                finding_type: SecurityFindingType::Injection,
                                severity: SecuritySeverity::Critical,
                                title: "Potential SQL Injection".to_string(),
                                description: format!(
                                    "SQL query with string concatenation in function: {}",
                                    function_name
                                ),
                                file_path: file_path.to_string(),
                                line_number,
                                column_start: node.start_position().column,
                                column_end: node.end_position().column,
                                code_snippet,
                                cwe_id: Some("CWE-89".to_string()),
                                remediation: "Use parameterized queries or prepared statements"
                                    .to_string(),
                                confidence: 0.85,
                                context: CodeContext::default(),
                            });
                            break;
                        }
                    }
                }
            }
        }

        Ok(findings)
    }

    /// Analyze weak cryptographic functions
    fn analyze_weak_crypto(
        &self,
        tree: &SyntaxTree,
        file_path: &str,
    ) -> Result<Vec<SecurityFinding>> {
        let mut findings = Vec::new();
        let weak_functions = ["md5", "sha1"];

        for node in tree.find_nodes_by_kind("call_expression") {
            if let Ok(function_name) = self.extract_call_function_name(&node) {
                if weak_functions.contains(&function_name.as_str()) {
                    let line_number = node.start_position().row;
                    let code_snippet = self.extract_code_snippet(&node, tree)?;

                    findings.push(SecurityFinding {
                        id: uuid::Uuid::new_v4().to_string(),
                        finding_type: SecurityFindingType::CryptographicFailure,
                        severity: SecuritySeverity::High,
                        title: "Weak Cryptographic Function".to_string(),
                        description: format!(
                            "Use of weak cryptographic function: {}",
                            function_name
                        ),
                        file_path: file_path.to_string(),
                        line_number,
                        column_start: node.start_position().column,
                        column_end: node.end_position().column,
                        code_snippet,
                        cwe_id: Some("CWE-327".to_string()),
                        remediation: format!(
                            "Replace {} with a stronger cryptographic function like SHA-256",
                            function_name
                        ),
                        confidence: 0.9,
                        context: CodeContext::default(),
                    });
                }
            }
        }

        Ok(findings)
    }

    /// Analyze hardcoded secrets
    fn analyze_hardcoded_secrets(
        &self,
        tree: &SyntaxTree,
        file_path: &str,
    ) -> Result<Vec<SecurityFinding>> {
        let mut findings = Vec::new();

        for node in tree.find_nodes_by_kind("string_literal") {
            if let Ok(text) = node.text() {
                let content = self.extract_string_content(&text);

                // Check for potential secrets
                if self.is_potential_secret(&content) {
                    let line_number = node.start_position().row;
                    let code_snippet = self.extract_code_snippet(&node, tree)?;

                    findings.push(SecurityFinding {
                        id: uuid::Uuid::new_v4().to_string(),
                        finding_type: SecurityFindingType::HardcodedSecret,
                        severity: SecuritySeverity::High,
                        title: "Potential Hardcoded Secret".to_string(),
                        description:
                            "String literal that may contain a hardcoded secret or credential"
                                .to_string(),
                        file_path: file_path.to_string(),
                        line_number,
                        column_start: node.start_position().column,
                        column_end: node.end_position().column,
                        code_snippet,
                        cwe_id: Some("CWE-798".to_string()),
                        remediation:
                            "Move secrets to environment variables or secure configuration files"
                                .to_string(),
                        confidence: 0.7,
                        context: CodeContext::default(),
                    });
                }
            }
        }

        Ok(findings)
    }

    /// Analyze access control issues
    fn analyze_access_control(
        &self,
        tree: &SyntaxTree,
        file_path: &str,
    ) -> Result<Vec<SecurityFinding>> {
        let mut findings = Vec::new();

        // Look for functions that might perform privileged operations without proper checks
        for node in tree.find_nodes_by_kind("function_item") {
            let function_name = self.extract_function_name(&node)?;

            if self.is_privileged_function(&function_name) {
                // Check if the function has authorization checks
                if !self.has_authorization_checks(&node) {
                    let line_number = node.start_position().row;
                    let code_snippet = self.extract_code_snippet(&node, tree)?;

                    findings.push(SecurityFinding {
                        id: uuid::Uuid::new_v4().to_string(),
                        finding_type: SecurityFindingType::BrokenAccessControl,
                        severity: SecuritySeverity::High,
                        title: "Missing Authorization Check".to_string(),
                        description: format!("Function '{}' performs privileged operations without authorization checks", function_name),
                        file_path: file_path.to_string(),
                        line_number,
                        column_start: node.start_position().column,
                        column_end: node.end_position().column,
                        code_snippet,
                        cwe_id: Some("CWE-862".to_string()),
                        remediation: "Add proper authorization checks before performing privileged operations".to_string(),
                        confidence: 0.6,
                        context: CodeContext::default(),
                    });
                }
            }
        }

        Ok(findings)
    }

    // Helper methods

    fn extract_function_name(&self, node: &Node) -> Result<String> {
        for child in node.children() {
            if child.kind() == "identifier" {
                if let Ok(text) = child.text() {
                    return Ok(text.to_string());
                }
            }
        }
        Ok("unknown_function".to_string())
    }

    fn extract_function_parameters(
        &self,
        node: &Node,
    ) -> Result<Vec<crate::security::ast_analyzer::ParameterInfo>> {
        let mut parameters = Vec::new();

        for child in node.children() {
            if child.kind() == "parameters" {
                for param in child.children() {
                    if param.kind() == "parameter" {
                        let name = self.extract_parameter_name(&param);
                        let param_type = self.extract_parameter_type(&param);

                        parameters.push(crate::security::ast_analyzer::ParameterInfo {
                            name,
                            param_type,
                        });
                    }
                }
            }
        }

        Ok(parameters)
    }

    fn extract_function_return_type(&self, node: &Node) -> Result<Option<String>> {
        for child in node.children() {
            if child.kind() == "return_type" || child.kind() == "type" {
                if let Ok(text) = child.text() {
                    return Ok(Some(text.to_string()));
                }
            }
        }
        Ok(None)
    }

    fn is_function_public(&self, node: &Node) -> Result<bool> {
        for child in node.children() {
            if child.kind() == "visibility_modifier" {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn extract_function_body_range(&self, node: &Node) -> Result<(usize, usize)> {
        for child in node.children() {
            if child.kind() == "block" {
                return Ok((child.start_position().row, child.end_position().row));
            }
        }
        Ok((node.start_position().row, node.end_position().row))
    }

    fn extract_struct_name(&self, node: &Node) -> Result<String> {
        for child in node.children() {
            if child.kind() == "type_identifier" {
                if let Ok(text) = child.text() {
                    return Ok(text.to_string());
                }
            }
        }
        Ok("unknown_struct".to_string())
    }

    fn extract_struct_fields(
        &self,
        node: &Node,
    ) -> Result<Vec<crate::security::ast_analyzer::FieldInfo>> {
        let mut fields = Vec::new();

        for child in node.children() {
            if child.kind() == "field_declaration_list" {
                for field in child.children() {
                    if field.kind() == "field_declaration" {
                        let name = self.extract_field_name(&field);
                        let field_type = self.extract_field_type(&field);
                        let is_public = self.is_field_public(&field);

                        fields.push(crate::security::ast_analyzer::FieldInfo {
                            name,
                            field_type,
                            is_public,
                        });
                    }
                }
            }
        }

        Ok(fields)
    }

    fn is_struct_public(&self, node: &Node) -> Result<bool> {
        for child in node.children() {
            if child.kind() == "visibility_modifier" {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn extract_variable_name(&self, node: &Node) -> Option<String> {
        for child in node.children() {
            if child.kind() == "identifier" {
                if let Ok(text) = child.text() {
                    return Some(text.to_string());
                }
            }
        }
        None
    }

    fn extract_variable_type(&self, node: &Node) -> String {
        for child in node.children() {
            if child.kind() == "type" || child.kind() == "type_identifier" {
                if let Ok(text) = child.text() {
                    return text.to_string();
                }
            }
        }
        "unknown".to_string()
    }

    fn is_constant_declaration(&self, node: &Node) -> bool {
        // In Rust, const declarations are separate from let declarations
        false
    }

    fn extract_const_name(&self, node: &Node) -> Option<String> {
        for child in node.children() {
            if child.kind() == "identifier" {
                if let Ok(text) = child.text() {
                    return Some(text.to_string());
                }
            }
        }
        None
    }

    fn extract_const_type(&self, node: &Node) -> String {
        for child in node.children() {
            if child.kind() == "type" || child.kind() == "type_identifier" {
                if let Ok(text) = child.text() {
                    return text.to_string();
                }
            }
        }
        "unknown".to_string()
    }

    fn extract_string_content(&self, text: &str) -> String {
        // Remove quotes from string literals
        if text.starts_with('"') && text.ends_with('"') {
            text[1..text.len() - 1].to_string()
        } else {
            text.to_string()
        }
    }

    fn extract_literal_context(&self, node: &Node) -> Result<String> {
        // Get some context around the string literal
        if let Some(parent) = node.parent() {
            if let Ok(text) = parent.text() {
                return Ok(text.to_string());
            }
        }
        Ok("unknown_context".to_string())
    }

    fn extract_call_function_name(&self, node: &Node) -> Result<String> {
        for child in node.children() {
            if child.kind() == "identifier" || child.kind() == "field_identifier" {
                if let Ok(text) = child.text() {
                    return Ok(text.to_string());
                }
            }
        }
        Ok("unknown_function".to_string())
    }

    fn extract_call_arguments(&self, node: &Node) -> Result<Vec<String>> {
        let mut arguments = Vec::new();

        for child in node.children() {
            if child.kind() == "arguments" {
                for arg in child.children() {
                    if arg.kind() != "(" && arg.kind() != ")" && arg.kind() != "," {
                        if let Ok(text) = arg.text() {
                            arguments.push(text.to_string());
                        }
                    }
                }
            }
        }

        Ok(arguments)
    }

    fn is_method_call(&self, node: &Node) -> Result<bool> {
        // Check if this is a method call (has a receiver)
        for child in node.children() {
            if child.kind() == "field_expression" || child.kind() == "self" {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn extract_parameter_name(&self, node: &Node) -> String {
        for child in node.children() {
            if child.kind() == "identifier" {
                if let Ok(text) = child.text() {
                    return text.to_string();
                }
            }
        }
        "unknown_param".to_string()
    }

    fn extract_parameter_type(&self, node: &Node) -> Option<String> {
        for child in node.children() {
            if child.kind() == "type" || child.kind() == "type_identifier" {
                if let Ok(text) = child.text() {
                    return Some(text.to_string());
                }
            }
        }
        None
    }

    fn extract_field_name(&self, node: &Node) -> String {
        for child in node.children() {
            if child.kind() == "field_identifier" {
                if let Ok(text) = child.text() {
                    return text.to_string();
                }
            }
        }
        "unknown_field".to_string()
    }

    fn extract_field_type(&self, node: &Node) -> Option<String> {
        for child in node.children() {
            if child.kind() == "type" || child.kind() == "type_identifier" {
                if let Ok(text) = child.text() {
                    return Some(text.to_string());
                }
            }
        }
        None
    }

    fn is_field_public(&self, node: &Node) -> bool {
        for child in node.children() {
            if child.kind() == "visibility_modifier" {
                return true;
            }
        }
        false
    }

    fn extract_code_snippet(&self, node: &Node, tree: &SyntaxTree) -> Result<String> {
        let range = node.byte_range();
        tree.text_for_range(range).map(|s| s.to_string())
    }

    fn is_sql_function(&self, function_name: &str) -> bool {
        let sql_functions = [
            "query",
            "execute",
            "query_one",
            "query_as",
            "execute_unprepared",
        ];
        sql_functions.contains(&function_name)
    }

    fn is_potential_secret(&self, content: &str) -> bool {
        let secret_indicators = [
            "password",
            "secret",
            "key",
            "token",
            "api_key",
            "apikey",
            "auth",
            "credential",
            "private",
            "secret_key",
            "access_token",
            "bearer",
        ];

        let content_lower = content.to_lowercase();
        secret_indicators
            .iter()
            .any(|indicator| content_lower.contains(indicator))
    }

    fn is_privileged_function(&self, function_name: &str) -> bool {
        let privileged_functions = [
            "delete",
            "remove",
            "destroy",
            "admin",
            "sudo",
            "root",
            "superuser",
            "grant",
            "revoke",
            "modify",
            "update",
            "create",
            "drop",
        ];

        let name_lower = function_name.to_lowercase();
        privileged_functions
            .iter()
            .any(|priv_func| name_lower.contains(priv_func))
    }

    fn has_authorization_checks(&self, node: &Node) -> bool {
        // Simple check for authorization-related keywords in the function body
        let auth_keywords = ["auth", "authorize", "permission", "role", "access", "check"];

        // This is a simplified check - in practice, you'd want more sophisticated analysis
        if let Ok(body_text) = node.text() {
            let body_lower = body_text.to_lowercase();
            auth_keywords
                .iter()
                .any(|keyword| body_lower.contains(keyword))
        } else {
            false
        }
    }
}

#[async_trait::async_trait]
impl LanguageSpecificAnalyzer for RustAnalyzer {
    async fn analyze(&self, tree: &SyntaxTree, file_path: &str) -> Result<Vec<SecurityFinding>> {
        self.analyze_rust_code(tree, file_path).await
    }

    fn get_vulnerability_patterns(&self) -> Vec<VulnerabilityPattern> {
        self.vulnerability_patterns.clone()
    }

    fn extract_semantic_info(&self, tree: &SyntaxTree) -> Result<SemanticInfo> {
        self.extract_rust_semantic_info(tree)
    }
}

impl Default for CodeContext {
    fn default() -> Self {
        Self {
            is_test_code: false,
            is_example_code: false,
            is_config_code: false,
            function_context: None,
            class_context: None,
            module_context: None,
            variable_scope: HashMap::new(),
        }
    }
}
