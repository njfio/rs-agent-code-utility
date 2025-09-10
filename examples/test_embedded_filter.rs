//! Test for Embedded Code Detection in Security Scanner
//!
//! This test demonstrates the embedded code detection functionality
//! that filters out false positives from JavaScript/HTML/CSS code
//! embedded in Rust string literals.

use rust_tree_sitter::security::ast_analyzer::{
    AstSecurityAnalyzer, SecurityFinding, SecurityFindingType, SecuritySeverity,
};

fn main() {
    println!("🧪 Testing Embedded Code Detection in Security Scanner");
    println!("===================================================");

    let analyzer = AstSecurityAnalyzer::new().unwrap();

    // Test case 1: JavaScript code in string literal (should be detected as embedded)
    println!("\n📋 Test 1: JavaScript Code Detection");
    let js_code = r#"
function handleClick() {
    addEventListener('click', function() {
        localStorage.setItem('theme', 'dark');
        document.body.classList.add('dark-mode');
    });
}
"#;

    let finding = SecurityFinding {
        id: "test_js".to_string(),
        finding_type: SecurityFindingType::Injection,
        severity: SecuritySeverity::High,
        title: "Test JavaScript injection".to_string(),
        description: "Testing embedded JS detection".to_string(),
        file_path: "test.rs".to_string(),
        line_number: 1,
        column_start: 0,
        column_end: 10,
        code_snippet: js_code.to_string(),
        cwe_id: Some("CWE-79".to_string()),
        remediation: "Sanitize input".to_string(),
        confidence: 0.8,
        context: Default::default(),
    };

    let result = analyzer
        .analyze_semantic_context(&finding, js_code, None)
        .unwrap();

    println!("JavaScript embedded detection result:");
    println!("  Is embedded: {}", result.is_embedded);
    println!("  Explanation: {}", result.explanation);

    if result.is_embedded && result.explanation.contains("embedded code") {
        println!("✅ Test 1 PASSED: Correctly detected JavaScript as embedded code");
    } else {
        println!("❌ Test 1 FAILED: Did not detect JavaScript as embedded");
    }

    // Test case 2: HTML code in string literal
    println!("\n📋 Test 2: HTML Code Detection");
    let html_code = r#"
<div class="container">
    <button onclick="handleClick()" id="myButton">
        <span class="icon">Click me</span>
    </button>
    <script src="app.js"></script>
</div>
"#;

    let finding = SecurityFinding {
        id: "test_html".to_string(),
        finding_type: SecurityFindingType::Injection,
        severity: SecuritySeverity::High,
        title: "Test HTML injection".to_string(),
        description: "Testing embedded HTML detection".to_string(),
        file_path: "test.rs".to_string(),
        line_number: 1,
        column_start: 0,
        column_end: 10,
        code_snippet: html_code.to_string(),
        cwe_id: Some("CWE-79".to_string()),
        remediation: "Sanitize input".to_string(),
        confidence: 0.8,
        context: Default::default(),
    };

    let result = analyzer
        .analyze_semantic_context(&finding, html_code, None)
        .unwrap();

    println!("HTML embedded detection result:");
    println!("  Is embedded: {}", result.is_embedded);
    println!("  Explanation: {}", result.explanation);

    if result.is_embedded {
        println!("✅ Test 2 PASSED: Correctly detected HTML as embedded code");
    } else {
        println!("❌ Test 2 FAILED: Did not detect HTML as embedded");
    }

    // Test case 3: CSS code in string literal
    println!("\n📋 Test 3: CSS Code Detection");
    let css_code = r#"
.hljs {
    background: #0a1220;
    color: #e6e9ef;
}

.hljs-keyword {
    color: #7aa2f7;
}

.hljs-string {
    color: #a6e3a1;
}
"#;

    let finding = SecurityFinding {
        id: "test_css".to_string(),
        finding_type: SecurityFindingType::Injection,
        severity: SecuritySeverity::High,
        title: "Test CSS injection".to_string(),
        description: "Testing embedded CSS detection".to_string(),
        file_path: "test.rs".to_string(),
        line_number: 1,
        column_start: 0,
        column_end: 10,
        code_snippet: css_code.to_string(),
        cwe_id: Some("CWE-79".to_string()),
        remediation: "Sanitize input".to_string(),
        confidence: 0.8,
        context: Default::default(),
    };

    let result = analyzer
        .analyze_semantic_context(&finding, css_code, None)
        .unwrap();

    println!("CSS embedded detection result:");
    println!("  Is embedded: {}", result.is_embedded);
    println!("  Explanation: {}", result.explanation);

    if result.is_embedded {
        println!("✅ Test 3 PASSED: Correctly detected CSS as embedded code");
    } else {
        println!("❌ Test 3 FAILED: Did not detect CSS as embedded");
    }

    // Test case 4: Real Rust code (should NOT be detected as embedded)
    println!("\n📋 Test 4: Real Rust Code (Should NOT be Embedded)");
    let rust_code = r#"
use std::collections::HashMap;

fn process_data(data: &HashMap<String, String>) -> Result<(), Box<dyn std::error::Error>> {
    for (key, value) in data {
        println!("Processing {}: {}", key, value);
    }
    Ok(())
}
"#;

    let finding = SecurityFinding {
        id: "test_rust".to_string(),
        finding_type: SecurityFindingType::Injection,
        severity: SecuritySeverity::High,
        title: "Test Rust code".to_string(),
        description: "Testing that real Rust code is not flagged as embedded".to_string(),
        file_path: "test.rs".to_string(),
        line_number: 1,
        column_start: 0,
        column_end: 10,
        code_snippet: rust_code.to_string(),
        cwe_id: Some("CWE-79".to_string()),
        remediation: "Sanitize input".to_string(),
        confidence: 0.8,
        context: Default::default(),
    };

    let result = analyzer
        .analyze_semantic_context(&finding, rust_code, None)
        .unwrap();

    println!("Real Rust code detection result:");
    println!("  Is embedded: {}", result.is_embedded);
    println!("  Explanation: {}", result.explanation);

    if !result.is_embedded {
        println!("✅ Test 4 PASSED: Correctly identified real Rust code as NOT embedded");
    } else {
        println!("❌ Test 4 FAILED: Incorrectly flagged real Rust code as embedded");
    }

    // Test case 5: Mixed JavaScript and HTML (strong indicator of embedded code)
    println!("\n📋 Test 5: Mixed JS/HTML Code Detection");
    let mixed_code = r#"
function initTheme() {
    const btn = document.getElementById('themeBtn');
    btn.addEventListener('click', () => {
        document.body.classList.toggle('dark');
        localStorage.setItem('theme', 'dark');
    });
}
"#;

    let finding = SecurityFinding {
        id: "test_mixed".to_string(),
        finding_type: SecurityFindingType::Injection,
        severity: SecuritySeverity::High,
        title: "Test mixed code".to_string(),
        description: "Testing mixed JS/HTML detection".to_string(),
        file_path: "test.rs".to_string(),
        line_number: 1,
        column_start: 0,
        column_end: 10,
        code_snippet: mixed_code.to_string(),
        cwe_id: Some("CWE-79".to_string()),
        remediation: "Sanitize input".to_string(),
        confidence: 0.8,
        context: Default::default(),
    };

    let result = analyzer
        .analyze_semantic_context(&finding, mixed_code, None)
        .unwrap();

    println!("Mixed embedded detection result:");
    println!("  Is embedded: {}", result.is_embedded);
    println!("  Explanation: {}", result.explanation);

    if result.is_embedded {
        println!("✅ Test 5 PASSED: Correctly detected mixed JS/HTML as embedded code");
    } else {
        println!("❌ Test 5 FAILED: Did not detect mixed JS/HTML as embedded");
    }

    println!("\n🎉 Embedded Code Detection Demo Complete!");
    println!("==========================================");
    println!("This example demonstrates how the AST analyzer can distinguish between");
    println!("real security vulnerabilities and embedded code in string literals.");
}
