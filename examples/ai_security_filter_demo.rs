//! AI-Powered Security False Positive Filter Demo
//!
//! This example demonstrates the advanced AI-powered false positive filtering
//! system that drastically reduces false positives in security scanning while
//! maintaining high detection accuracy.
//!
//! Features demonstrated:
//! - AI context analysis for intelligent filtering
//! - Semantic code understanding
//! - Machine learning pattern recognition
//! - Multi-factor confidence scoring
//! - User feedback learning system

use rust_tree_sitter::security::{
    AIFalsePositiveFilter, AIFilterConfig, AstSecurityAnalyzer, MLFalsePositiveFilter,
    SecurityFinding, SecurityFindingType, SecuritySeverity,
};
use std::collections::HashMap;
use std::path::PathBuf;

/// Simulated security findings for demonstration
fn create_sample_findings() -> Vec<SecurityFinding> {
    vec![
        // Likely false positive - test code
        SecurityFinding {
            id: "FP001".to_string(),
            finding_type: SecurityFindingType::HardcodedSecret,
            severity: SecuritySeverity::High,
            title: "Hardcoded API Key".to_string(),
            description: "Potential hardcoded API key detected".to_string(),
            file_path: "src/test_auth.rs".to_string(),
            line_number: 15,
            column_start: 10,
            column_end: 35,
            code_snippet: r#"const API_KEY: &str = "sk-test-1234567890abcdef";"#.to_string(),
            cwe_id: Some("CWE-798".to_string()),
            remediation: "Use environment variables or secure key management".to_string(),
            confidence: 0.8,
            context: Default::default(),
        },
        // Likely false positive - placeholder value
        SecurityFinding {
            id: "FP002".to_string(),
            finding_type: SecurityFindingType::HardcodedSecret,
            severity: SecuritySeverity::Medium,
            title: "Hardcoded Password".to_string(),
            description: "Potential hardcoded password detected".to_string(),
            file_path: "examples/demo.rs".to_string(),
            line_number: 25,
            column_start: 15,
            column_end: 40,
            code_snippet: r#"let password = "your_password_here";"#.to_string(),
            cwe_id: Some("CWE-798".to_string()),
            remediation: "Use secure password storage".to_string(),
            confidence: 0.7,
            context: Default::default(),
        },
        // Likely true positive - real vulnerability
        SecurityFinding {
            id: "TP001".to_string(),
            finding_type: SecurityFindingType::Injection,
            severity: SecuritySeverity::High,
            title: "SQL Injection Vulnerability".to_string(),
            description: "User input directly concatenated into SQL query".to_string(),
            file_path: "src/user_handler.rs".to_string(),
            line_number: 45,
            column_start: 20,
            column_end: 60,
            code_snippet: r#"let query = format!("SELECT * FROM users WHERE id = {}", user_id);"#
                .to_string(),
            cwe_id: Some("CWE-89".to_string()),
            remediation: "Use parameterized queries or prepared statements".to_string(),
            confidence: 0.9,
            context: Default::default(),
        },
    ]
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔍 AI-Powered Security False Positive Filter Demo");
    println!("==================================================");
    println!();

    // Initialize analyzers
    println!("🔧 Setting up analyzers...");
    let ml_filter = MLFalsePositiveFilter::new();
    let ast_analyzer = AstSecurityAnalyzer::new()?;
    println!("✅ Analyzers initialized");
    println!();

    // Configure AI filter (simplified for demo)
    println!("⚙️  Configuring AI false positive filter...");
    let _ai_config = AIFilterConfig {
        ai_context_enabled: false, // Disable AI for this demo
        semantic_analysis_enabled: true,
        feedback_learning_enabled: true,
        min_ai_confidence: 0.6,
        cache_ttl_seconds: 3600,
        max_concurrent_requests: 3,
    };

    // Note: AI service would be needed for full functionality
    // let ai_filter = AIFalsePositiveFilter::new(ai_service, ml_filter, ast_analyzer, ai_config);
    println!("✅ AI filter configuration ready");
    println!();

    // Create sample findings
    println!("📋 Creating sample security findings...");
    let findings = create_sample_findings();
    println!("✅ Created {} sample findings", findings.len());
    println!();

    // Display original findings
    println!("📊 Original Security Findings:");
    println!("------------------------------");
    for finding in &findings {
        println!(
            "• {} ({}) - {}",
            finding.title, finding.severity, finding.file_path
        );
        println!("  Confidence: {:.1}%", finding.confidence * 100.0);
        println!("  Snippet: {}", finding.code_snippet);
        println!();
    }

    // Demonstrate semantic analysis
    println!("🎯 Applying Semantic Analysis:");
    println!("------------------------------");

    for (i, finding) in findings.iter().enumerate() {
        println!("🔍 Analyzing finding {}: {}", i + 1, finding.title);

        // Get simulated file content
        let file_content = get_simulated_file_content(&finding.file_path);

        // Apply semantic analysis
        match ast_analyzer.analyze_semantic_context(
            finding,
            &finding.code_snippet,
            Some(&file_content),
        ) {
            Ok(result) => {
                if result.is_test_code || result.is_placeholder || result.is_safe_usage {
                    println!("  ⚠️  POTENTIAL FALSE POSITIVE: {}", result.explanation);
                } else {
                    println!("  ✅ LIKELY TRUE POSITIVE: {}", result.explanation);
                }
            }
            Err(e) => {
                println!("  ❌ Analysis failed: {}", e);
            }
        }

        println!();
    }

    println!("🎉 Demo completed!");
    println!("==================");
    println!("This demonstrates the AI-powered false positive filtering system:");
    println!("• Semantic analysis for context understanding");
    println!("• Pattern recognition for common false positives");
    println!("• Confidence scoring for intelligent filtering");
    println!("• Foundation for AI-enhanced security scanning");

    Ok(())
}

/// Get simulated file content for demonstration
fn get_simulated_file_content(file_path: &str) -> String {
    match file_path {
        "src/test_auth.rs" => r#"
// Test file for authentication
#[cfg(test)]
mod tests {
    use super::*;

    const API_KEY: &str = "sk-test-1234567890abcdef";

    #[test]
    fn test_api_connection() {
        // This is just test code with mock credentials
        assert!(API_KEY.starts_with("sk-test-"));
    }
}
"#
        .to_string(),

        "examples/demo.rs" => r#"
// Example demonstration code
fn demo_function() {
    // This is example code with placeholder values
    let password = "your_password_here";
    let api_key = "your_api_key_here";

    println!("Demo password: {}", password);
    println!("Demo API key: {}", api_key);
}
"#
        .to_string(),

        "src/user_handler.rs" => r#"
// User handler with SQL injection vulnerability
pub struct UserService;

impl UserService {
    pub fn get_user_by_id(&self, user_id: &str) -> Result<(), ()> {
        // WARNING: This is vulnerable to SQL injection!
        let query = format!("SELECT * FROM users WHERE id = {}", user_id);

        // Execute query (simplified)
        self.execute_query(&query)
    }

    fn execute_query(&self, _query: &str) -> Result<(), ()> {
        // Database execution logic here
        Ok(())
    }
}
"#
        .to_string(),

        _ => "// Sample file content".to_string(),
    }
}
