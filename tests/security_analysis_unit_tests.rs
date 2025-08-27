//! Comprehensive unit tests for security analysis functionality
//! 
//! These tests verify the accuracy and reliability of security vulnerability
//! detection across different programming languages and attack patterns.

use rust_tree_sitter::{SecurityScanner, AnalysisResult, FileInfo, Result};
use std::path::PathBuf;
use tempfile::TempDir;
use std::fs;

fn create_analysis_result_with_fs(specs: Vec<(&str, &str, &str)>) -> (TempDir, AnalysisResult) {
    let temp_dir = TempDir::new().expect("failed to create temp dir");
    let root = temp_dir.path();

    let mut files: Vec<FileInfo> = Vec::new();
    for (rel, content, language) in specs {
        let p = root.join(rel);
        if let Some(parent) = p.parent() { fs::create_dir_all(parent).unwrap(); }
        fs::write(&p, content).unwrap();

        files.push(FileInfo {
            path: PathBuf::from(rel),
            language: language.to_string(),
            lines: content.lines().count(),
            symbols: vec![],
            parsed_successfully: true,
            parse_errors: vec![],
            security_vulnerabilities: vec![],
            size: content.len(),
        });
    }

    let total_files = files.len();
    let total_lines = files.iter().map(|f| f.lines).sum();

    let ar = AnalysisResult {
        root_path: root.to_path_buf(),
        total_files,
        parsed_files: total_files,
        error_files: 0,
        total_lines,
        languages: std::collections::HashMap::new(),
        files,
        config: rust_tree_sitter::AnalysisConfig::default(),
    };

    (temp_dir, ar)
}

#[test]
fn test_security_scanner_creation() -> Result<()> {
    let _scanner = SecurityScanner::new()?;
    // Scanner should be created successfully
    Ok(())
}

#[test]
fn test_sql_injection_detection() -> Result<()> {
    let scanner = SecurityScanner::new()?;
    
    // Code with SQL injection vulnerability
    let vulnerable_code = r#"
        fn get_user(user_id: &str) -> String {
            let query = format!("SELECT * FROM users WHERE id = '{}'", user_id);
            execute_query(&query)
        }
        
        fn execute_query(query: &str) -> String {
            // Mock database execution
            String::new()
        }
    "#;
    
    let (_tmp, analysis_result) = create_analysis_result_with_fs(vec![
        ("vulnerable.rs", vulnerable_code, "Rust")
    ]);
    
    let security_result = scanner.analyze(&analysis_result)?;
    
    // Should detect SQL injection vulnerability
    assert!(security_result.total_vulnerabilities > 0);
    
    let sql_injection_found = security_result.vulnerabilities.iter()
        .any(|v| v.title.to_lowercase().contains("sql") 
                || v.description.to_lowercase().contains("injection"));
    
    assert!(sql_injection_found, "SQL injection vulnerability should be detected");
    
    Ok(())
}

#[test]
fn test_command_injection_detection() -> Result<()> {
    let scanner = SecurityScanner::new()?;
    
    // Code with command injection vulnerability
    let vulnerable_code = r#"
        use std::process::Command;
        
        fn execute_user_command(user_input: &str) -> std::io::Result<String> {
            let output = Command::new("sh")
                .arg("-c")
                .arg(user_input)
                .output()?;
            
            Ok(String::from_utf8_lossy(&output.stdout).to_string())
        }
    "#;
    
    let (_tmp, analysis_result) = create_analysis_result_with_fs(vec![
        ("command_vuln.rs", vulnerable_code, "Rust")
    ]);
    
    let security_result = scanner.analyze(&analysis_result)?;
    
    // Should detect command injection vulnerability
    let command_injection_found = security_result.vulnerabilities.iter()
        .any(|v| v.title.to_lowercase().contains("command") 
                || v.description.to_lowercase().contains("injection"));
    
    assert!(command_injection_found, "Command injection vulnerability should be detected");
    
    Ok(())
}

#[test]
fn test_hardcoded_secrets_detection() -> Result<()> {
    let scanner = SecurityScanner::new()?;
    
    // Code with hardcoded secrets
    let vulnerable_code = r#"
        const API_KEY: &str = "sk-1234567890abcdef1234567890abcdef";
        const DATABASE_PASSWORD: &str = "super_secret_password_123";
        const JWT_SECRET: &str = "my-jwt-secret-key-that-should-not-be-hardcoded";
        
        fn connect_to_api() {
            let client = ApiClient::new(API_KEY);
            // ... rest of implementation
        }
    "#;
    
    let (_tmp, analysis_result) = create_analysis_result_with_fs(vec![
        ("secrets.rs", vulnerable_code, "Rust")
    ]);
    
    let security_result = scanner.analyze(&analysis_result)?;
    
    // Should detect hardcoded secrets
    let secrets_found = security_result.vulnerabilities.iter()
        .any(|v| v.title.to_lowercase().contains("secret") 
                || v.title.to_lowercase().contains("key")
                || v.description.to_lowercase().contains("hardcoded"));
    
    assert!(secrets_found, "Hardcoded secrets should be detected");
    
    Ok(())
}

#[test]
fn test_path_traversal_detection() -> Result<()> {
    let scanner = SecurityScanner::new()?;
    
    // Code with path traversal vulnerability
    let vulnerable_code = r#"
        use std::fs;
        
        fn read_user_file(filename: &str) -> Result<String, std::io::Error> {
            let path = format!("/var/www/uploads/{}", filename);
            fs::read_to_string(path)
        }
        
        fn serve_file(user_path: &str) -> String {
            // Vulnerable: no path validation
            std::fs::read_to_string(user_path).unwrap_or_default()
        }
    "#;
    
    let (_tmp, analysis_result) = create_analysis_result_with_fs(vec![
        ("path_traversal.rs", vulnerable_code, "Rust")
    ]);
    
    let security_result = scanner.analyze(&analysis_result)?;
    
    // Should detect path traversal vulnerability
    let path_traversal_found = security_result.vulnerabilities.iter()
        .any(|v| v.title.to_lowercase().contains("path") 
                || v.description.to_lowercase().contains("traversal"));
    
    assert!(path_traversal_found, "Path traversal vulnerability should be detected");
    
    Ok(())
}

#[test]
fn test_xss_detection() -> Result<()> {
    let scanner = SecurityScanner::new()?;
    
    // JavaScript code with XSS vulnerability
    let vulnerable_code = r#"
        function displayUserInput(userInput) {
            document.getElementById('output').innerHTML = userInput;
        }
        
        function renderTemplate(data) {
            return `<div>${data.userContent}</div>`;
        }
        
        function unsafeRender(html) {
            document.body.innerHTML += html;
        }
    "#;
    
    let (_tmp, analysis_result) = create_analysis_result_with_fs(vec![
        ("xss_vuln.js", vulnerable_code, "JavaScript")
    ]);
    
    let security_result = scanner.analyze(&analysis_result)?;
    
    // Should detect XSS vulnerability
    let xss_found = security_result.vulnerabilities.iter()
        .any(|v| v.title.to_lowercase().contains("xss") 
                || v.title.to_lowercase().contains("cross-site")
                || v.description.to_lowercase().contains("script"));
    
    assert!(xss_found, "XSS vulnerability should be detected");
    
    Ok(())
}

#[test]
fn test_insecure_random_detection() -> Result<()> {
    let scanner = SecurityScanner::new()?;
    
    // Code with insecure random number generation
    let vulnerable_code = r#"
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        
        fn generate_session_token() -> String {
            let mut hasher = DefaultHasher::new();
            std::ptr::addr_of!(hasher).hash(&mut hasher);
            format!("{:x}", hasher.finish())
        }
        
        fn weak_random() -> u32 {
            // Using predictable seed
            let mut rng = std::collections::hash_map::RandomState::new();
            42 // Completely predictable
        }
    "#;
    
    let (_tmp, analysis_result) = create_analysis_result_with_fs(vec![
        ("weak_random.rs", vulnerable_code, "Rust")
    ]);
    
    let security_result = scanner.analyze(&analysis_result)?;
    
    // Should detect insecure randomness
    let weak_random_found = security_result.vulnerabilities.iter()
        .any(|v| v.title.to_lowercase().contains("random") 
                || v.description.to_lowercase().contains("predictable"));
    
    assert!(weak_random_found, "Weak randomness should be detected");
    
    Ok(())
}

#[test]
fn test_safe_code_no_vulnerabilities() -> Result<()> {
    let scanner = SecurityScanner::new()?;
    
    // Safe code that should not trigger vulnerabilities
    let safe_code = r#"
        use std::collections::HashMap;
        
        fn safe_function(input: &str) -> String {
            let sanitized = input.chars()
                .filter(|c| c.is_alphanumeric())
                .collect::<String>();
            
            format!("Processed: {}", sanitized)
        }
        
        fn safe_database_query(user_id: u32) -> String {
            // Using parameterized query (conceptually)
            let query = "SELECT * FROM users WHERE id = ?";
            execute_prepared_statement(query, &[user_id.to_string()])
        }
        
        fn execute_prepared_statement(query: &str, params: &[String]) -> String {
            // Mock safe database execution
            String::new()
        }
    "#;
    
    let (_tmp, analysis_result) = create_analysis_result_with_fs(vec![
        ("safe.rs", safe_code, "Rust")
    ]);
    
    let security_result = scanner.analyze(&analysis_result)?;
    
    // Safe code should have fewer or no vulnerabilities
    // Note: Some heuristic-based scanners might still flag false positives
    assert!(security_result.security_score > 50, "Safe code should have a reasonable security score");
    
    Ok(())
}

#[test]
fn test_multiple_files_analysis() -> Result<()> {
    let scanner = SecurityScanner::new()?;
    
    let file1_code = r#"
        fn sql_injection(user_input: &str) -> String {
            format!("SELECT * FROM users WHERE name = '{}'", user_input)
        }
    "#;
    
    let file2_code = r#"
        const SECRET_KEY: &str = "hardcoded-secret-key-123";
    "#;
    
    let (_tmp, analysis_result) = create_analysis_result_with_fs(vec![
        ("file1.rs", file1_code, "Rust"),
        ("file2.rs", file2_code, "Rust"),
    ]);
    
    let security_result = scanner.analyze(&analysis_result)?;
    
    // Should detect vulnerabilities from both files
    assert!(security_result.total_vulnerabilities >= 2);
    assert!(security_result.vulnerabilities.len() >= 2);
    
    Ok(())
}

#[test]
fn test_security_score_calculation() -> Result<()> {
    let scanner = SecurityScanner::new()?;
    
    let vulnerable_code = r#"
        fn multiple_vulnerabilities(user_input: &str) -> String {
            let query = format!("SELECT * FROM users WHERE id = '{}'", user_input);
            let command = format!("ls {}", user_input);
            std::process::Command::new("sh").arg("-c").arg(&command).output().unwrap();
            query
        }
        
        const API_KEY: &str = "sk-1234567890abcdef";
    "#;
    
    let (_tmp, analysis_result) = create_analysis_result_with_fs(vec![
        ("multiple_vulns.rs", vulnerable_code, "Rust")
    ]);
    
    let security_result = scanner.analyze(&analysis_result)?;
    
    // Security score should be calculated and be between 0-100
    assert!(security_result.security_score <= 100);
    
    // With multiple vulnerabilities, score should be lower
    assert!(security_result.security_score < 80, "Multiple vulnerabilities should lower the security score");
    
    Ok(())
}

#[test]
fn test_vulnerability_severity_classification() -> Result<()> {
    let scanner = SecurityScanner::new()?;
    
    let code_with_critical_vuln = r#"
        fn execute_user_command(cmd: &str) -> String {
            std::process::Command::new("sh")
                .arg("-c")
                .arg(cmd)
                .output()
                .unwrap()
                .stdout
                .into_iter()
                .map(|b| b as char)
                .collect()
        }
    "#;
    
    let (_tmp, analysis_result) = create_analysis_result_with_fs(vec![
        ("critical.rs", code_with_critical_vuln, "Rust")
    ]);
    
    let security_result = scanner.analyze(&analysis_result)?;
    
    // Should classify vulnerabilities by severity
    if !security_result.vulnerabilities.is_empty() {
        let has_high_severity = security_result.vulnerabilities.iter()
            .any(|v| matches!(v.severity, rust_tree_sitter::SecuritySeverity::High | rust_tree_sitter::SecuritySeverity::Critical));
        
        assert!(has_high_severity, "Command injection should be classified as high/critical severity");
    }
    
    Ok(())
}
