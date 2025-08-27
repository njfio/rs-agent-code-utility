use rust_tree_sitter::{CodebaseAnalyzer, SecurityScanner, SecurityConfig};
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // First, analyze the codebase
    let mut analyzer = CodebaseAnalyzer::new()?;
    let path = PathBuf::from("./src");
    let analysis_result = analyzer.analyze_directory(&path)?;
    
    println!("=== Codebase Analysis Complete ===");
    println!("Analyzed {} files", analysis_result.total_files);
    
    // Create security scanner with advanced configuration
    let security_config = SecurityConfig {
        owasp_analysis: true,
        secrets_detection: true,
        input_validation: true,
        injection_analysis: true,
        best_practices: true,
        min_severity: rust_tree_sitter::SecuritySeverity::Medium,
        custom_rules: Vec::new(),
    };

    let security_scanner = SecurityScanner::with_config(security_config)?;
    
    // Run comprehensive security scan
    println!("\n=== Running Security Analysis ===");
    let security_result = security_scanner.analyze(&analysis_result)?;
    
    // Display overall security metrics
    println!("\n=== Security Assessment Results ===");
    println!("Overall Security Score: {}/100", security_result.security_score);
    println!("Total Vulnerabilities: {}", security_result.total_vulnerabilities);

    // Count vulnerabilities by severity
    let critical_count = security_result.vulnerabilities_by_severity.get(&rust_tree_sitter::SecuritySeverity::Critical).unwrap_or(&0);
    let high_count = security_result.vulnerabilities_by_severity.get(&rust_tree_sitter::SecuritySeverity::High).unwrap_or(&0);
    let medium_count = security_result.vulnerabilities_by_severity.get(&rust_tree_sitter::SecuritySeverity::Medium).unwrap_or(&0);
    let low_count = security_result.vulnerabilities_by_severity.get(&rust_tree_sitter::SecuritySeverity::Low).unwrap_or(&0);

    println!("Critical Severity: {}", critical_count);
    println!("High Severity: {}", high_count);
    println!("Medium Severity: {}", medium_count);
    println!("Low Severity: {}", low_count);
    
    // Display vulnerability findings
    if !security_result.vulnerabilities.is_empty() {
        println!("\n=== Vulnerability Findings ===");
        for (i, vuln) in security_result.vulnerabilities.iter().enumerate() {
            println!("{}. {} ({:?})", i + 1, vuln.title, vuln.severity);
            println!("   File: {}", vuln.location.file.display());
            println!("   Line: {}", vuln.location.start_line);
            println!("   Confidence: {:?}", vuln.confidence);
            if let Some(cwe) = &vuln.cwe_id {
                println!("   CWE: {}", cwe);
            }
            println!("   OWASP: {:?}", vuln.owasp_category);
            println!("   Description: {}", vuln.description);
            println!("   Remediation: {}", vuln.remediation.summary);
            println!();
        }
    }
    
    // Display secret findings
    if !security_result.secrets.is_empty() {
        println!("\n=== Secret Findings ===");
        for (i, secret) in security_result.secrets.iter().enumerate() {
            println!("{}. {:?} Secret", i + 1, secret.secret_type);
            println!("   File: {}", secret.location.file.display());
            println!("   Line: {}", secret.location.start_line);
            println!("   Entropy: {:.2}", secret.entropy);
            println!("   Confidence: {:?}", secret.confidence);
            println!("   Masked Value: {}", secret.masked_value);
            println!();
        }
    }
    
    // Display injection vulnerabilities
    if !security_result.injection_vulnerabilities.is_empty() {
        println!("\n=== Injection Vulnerability Findings ===");
        for (i, injection) in security_result.injection_vulnerabilities.iter().enumerate() {
            println!("{}. {:?} Injection", i + 1, injection.injection_type);
            println!("   File: {}", injection.location.file.display());
            println!("   Line: {}", injection.location.start_line);
            println!("   Pattern: {}", injection.pattern);
            println!("   Severity: {:?}", injection.severity);
            println!();
        }
    }
    
    // Display compliance assessment
    println!("\n=== Compliance Assessment ===");
    let compliance = &security_result.compliance;
    println!("OWASP Compliance Score: {}/100", compliance.owasp_score);
    println!("Overall Status: {:?}", compliance.overall_status);

    // Display security recommendations
    if !security_result.recommendations.is_empty() {
        println!("\nSecurity Recommendations:");
        for (i, rec) in security_result.recommendations.iter().enumerate() {
            println!("{}. {} (Priority: {:?})", i + 1, rec.recommendation, rec.priority);
            println!("   Category: {}", rec.category);
            println!("   Security Improvement: {:.1}%", rec.security_improvement);
            println!();
        }
    }
    
    // Generate security report
    if security_result.total_vulnerabilities > 0 {
        println!("\n=== Security Report Summary ===");
        println!("⚠️  Security issues found!");
        println!("📊 Security Score: {}/100", security_result.security_score);

        if *high_count > 0 {
            println!("🔴 {} high severity issues require immediate attention", high_count);
        }

        if *medium_count > 0 {
            println!("🟡 {} medium severity issues should be addressed", medium_count);
        }

        println!("\nNext Steps:");
        println!("1. Review and fix high severity vulnerabilities");
        println!("2. Implement missing security controls");
        println!("3. Update vulnerable dependencies");
        println!("4. Remove or secure hardcoded secrets");
        println!("5. Re-run security scan to verify fixes");
    } else {
        println!("\n✅ No security issues found!");
        println!("🎉 Security Score: {}/100", security_result.security_score);
    }
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use std::fs;
    
    #[test]
    fn test_security_analysis_with_vulnerabilities() -> Result<(), Box<dyn std::error::Error>> {
        let temp_dir = TempDir::new()?;
        
        // Create a file with potential security issues
        let vulnerable_code = r#"
            use std::process::Command;
            
            fn execute_command(user_input: &str) {
                // Potential command injection vulnerability
                let output = Command::new("sh")
                    .arg("-c")
                    .arg(user_input)  // Direct user input to shell
                    .output()
                    .expect("Failed to execute command");
            }
            
            fn database_query(user_id: &str) -> String {
                // Potential SQL injection vulnerability
                format!("SELECT * FROM users WHERE id = '{}'", user_id)
            }
            
            const API_KEY: &str = "sk-1234567890abcdef"; // Hardcoded secret
        "#;
        
        fs::write(temp_dir.path().join("vulnerable.rs"), vulnerable_code)?;
        
        // Analyze the code
        let mut analyzer = CodebaseAnalyzer::new()?;
        let analysis_result = analyzer.analyze_directory(temp_dir.path())?;
        
        // Run security scan
        let security_scanner = SecurityScanner::new()?;
        let security_result = security_scanner.analyze(&analysis_result)?;

        // Should find security issues
        assert!(security_result.total_vulnerabilities > 0);
        assert!(security_result.security_score < 100);

        // Should detect command injection
        let has_command_injection = security_result.vulnerabilities
            .iter()
            .any(|v| v.title.to_lowercase().contains("command injection"));
        assert!(has_command_injection);

        // Should detect potential SQL injection
        let has_sql_injection = security_result.vulnerabilities
            .iter()
            .any(|v| v.title.to_lowercase().contains("sql injection"));
        assert!(has_sql_injection);

        // Should detect hardcoded secret
        assert!(!security_result.secrets.is_empty());
        
        Ok(())
    }
    
    #[test]
    fn test_security_analysis_clean_code() -> Result<(), Box<dyn std::error::Error>> {
        let temp_dir = TempDir::new()?;
        
        // Create secure code
        let secure_code = r#"
            use std::process::Command;
            use std::env;
            
            fn execute_safe_command(command: &str, args: &[&str]) -> Result<String, std::io::Error> {
                let output = Command::new(command)
                    .args(args)
                    .output()?;
                
                Ok(String::from_utf8_lossy(&output.stdout).to_string())
            }
            
            fn get_api_key() -> Option<String> {
                env::var("API_KEY").ok()
            }
        "#;
        
        fs::write(temp_dir.path().join("secure.rs"), secure_code)?;
        
        // Analyze the code
        let mut analyzer = CodebaseAnalyzer::new()?;
        let analysis_result = analyzer.analyze_directory(temp_dir.path())?;
        
        // Run security scan
        let security_scanner = SecurityScanner::new()?;
        let security_result = security_scanner.analyze(&analysis_result)?;
        
        // Should have fewer or no security issues
        assert!(security_result.security_score > 80); // Should have a good security score
        
        Ok(())
    }
}
