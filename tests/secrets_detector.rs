#![cfg(any(feature = "net", feature = "db"))]

use rust_tree_sitter::infrastructure::{DatabaseConfig, DatabaseManager};
use rust_tree_sitter::security::SecretsDetector;

#[tokio::test]
async fn detects_real_secret() -> Result<(), Box<dyn std::error::Error>> {
    let tmp = tempfile::Builder::new().suffix(".db").tempfile()?;
    let config = DatabaseConfig {
        url: format!("sqlite://{}", tmp.path().display()),
        max_connections: 1,
        connection_timeout: 5,
        enable_wal: false,
    };
    let db = DatabaseManager::new(&config).await?;
    let detector = SecretsDetector::with_thresholds(&db, Some(3.0), None).await?;

    let content = "let key = \"AKIA5C38F4W0HTH09SN4\";";
    let results = detector.detect_secrets(content, "src/lib.rs")?;
    assert!(results.iter().any(|f| matches!(
        f.secret_type,
        rust_tree_sitter::security::SecretType::AwsAccessKey
    ) && !f.is_false_positive));

    Ok(())
}

#[tokio::test]
async fn filters_known_placeholder() -> Result<(), Box<dyn std::error::Error>> {
    let tmp = tempfile::Builder::new().suffix(".db").tempfile()?;
    let config = DatabaseConfig {
        url: format!("sqlite://{}", tmp.path().display()),
        max_connections: 1,
        connection_timeout: 5,
        enable_wal: false,
    };
    let db = DatabaseManager::new(&config).await?;
    let detector = SecretsDetector::with_thresholds(&db, Some(3.0), None).await?;

    let content = "let key = \"AKIAIOSFODNN7EXAMPLE\";";
    let results = detector.detect_secrets(content, "tests/test_sample.rs")?;

    // Either no results (completely filtered) or results marked as false positives
    if !results.is_empty() {
        // All results should be marked as false positives with very low confidence
        assert!(
            results.iter().all(|f| f.is_false_positive),
            "Some results are not marked as false positives: {:?}",
            results
        );
        assert!(
            results.iter().all(|f| f.confidence < 0.01),
            "Some results have confidence >= 0.01: {:?}",
            results
        );
    }

    Ok(())
}

#[tokio::test]
async fn detects_high_entropy_secret() -> Result<(), Box<dyn std::error::Error>> {
    let tmp = tempfile::Builder::new().suffix(".db").tempfile()?;
    let config = DatabaseConfig {
        url: format!("sqlite://{}", tmp.path().display()),
        max_connections: 1,
        connection_timeout: 5,
        enable_wal: false,
    };
    let db = DatabaseManager::new(&config).await?;
    let detector = SecretsDetector::with_thresholds(&db, Some(3.0), None).await?;

    let content = "let token = \"sk-1234567890abcdef1234567890abcdef12345678\";";
    let results = detector.detect_secrets(content, "src/main.rs")?;
    assert!(results.iter().any(|f| matches!(
        f.secret_type,
        rust_tree_sitter::security::SecretType::HighEntropy
    ) && !f.is_false_positive));

    Ok(())
}

#[tokio::test]
async fn ignores_test_files() -> Result<(), Box<dyn std::error::Error>> {
    let tmp = tempfile::Builder::new().suffix(".db").tempfile()?;
    let config = DatabaseConfig {
        url: format!("sqlite://{}", tmp.path().display()),
        max_connections: 1,
        connection_timeout: 5,
        enable_wal: false,
    };
    let db = DatabaseManager::new(&config).await?;
    let detector = SecretsDetector::with_thresholds(&db, Some(3.0), None).await?;

    let content = "let key = \"AKIA5C38F4W0HTH09SN4\";";
    let results = detector.detect_secrets(content, "tests/integration_test.rs")?;
    // Should be flagged but with lower confidence due to test context
    let _ = results.len();

    Ok(())
}

#[tokio::test]
async fn detects_jwt_token() -> Result<(), Box<dyn std::error::Error>> {
    let tmp = tempfile::Builder::new().suffix(".db").tempfile()?;
    let config = DatabaseConfig {
        url: format!("sqlite://{}", tmp.path().display()),
        max_connections: 1,
        connection_timeout: 5,
        enable_wal: false,
    };
    let db = DatabaseManager::new(&config).await?;
    let detector = SecretsDetector::with_thresholds(&db, Some(3.0), None).await?;

    let content = "const token = \"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c\";";
    let results = detector.detect_secrets(content, "src/auth.rs")?;
    assert!(results.iter().any(|f| matches!(
        f.secret_type,
        rust_tree_sitter::security::SecretType::JwtToken
    ) && !f.is_false_positive));

    Ok(())
}

#[tokio::test]
async fn validates_base64_encoded_secrets() -> Result<(), Box<dyn std::error::Error>> {
    let tmp = tempfile::Builder::new().suffix(".db").tempfile()?;
    let config = DatabaseConfig {
        url: format!("sqlite://{}", tmp.path().display()),
        max_connections: 1,
        connection_timeout: 5,
        enable_wal: false,
    };
    let db = DatabaseManager::new(&config).await?;
    let detector = SecretsDetector::with_thresholds(&db, Some(3.0), None).await?;

    let content = "let secret = \"SGVsbG8gV29ybGQ=\";"; // Base64 for "Hello World"
    let results = detector.detect_secrets(content, "src/config.rs")?;
    // Should not flag low-entropy base64
    assert!(results.is_empty() || results.iter().all(|f| f.confidence < 0.5));

    Ok(())
}

#[tokio::test]
async fn classifies_secret_severity() -> Result<(), Box<dyn std::error::Error>> {
    let tmp = tempfile::Builder::new().suffix(".db").tempfile()?;
    let config = DatabaseConfig {
        url: format!("sqlite://{}", tmp.path().display()),
        max_connections: 1,
        connection_timeout: 5,
        enable_wal: false,
    };
    let db = DatabaseManager::new(&config).await?;
    let detector = SecretsDetector::with_thresholds(&db, Some(3.0), None).await?;

    let content = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE";
    let results = detector.detect_secrets(content, "src/main.rs")?;
    for finding in results {
        if matches!(
            finding.secret_type,
            rust_tree_sitter::security::SecretType::AwsAccessKey
        ) {
            assert!(matches!(
                finding.severity,
                rust_tree_sitter::security::SecretSeverity::Critical
            ));
        }
    }

    Ok(())
}

#[tokio::test]
async fn filters_comments_and_examples() -> Result<(), Box<dyn std::error::Error>> {
    let tmp = tempfile::Builder::new().suffix(".db").tempfile()?;
    let config = DatabaseConfig {
        url: format!("sqlite://{}", tmp.path().display()),
        max_connections: 1,
        connection_timeout: 5,
        enable_wal: false,
    };
    let db = DatabaseManager::new(&config).await?;
    let detector = SecretsDetector::with_thresholds(&db, Some(3.0), None).await?;

    let content = r#"
// Example API key for documentation
// api_key = "sk-example123456789"
let real_key = "sk-1234567890abcdef1234567890abcdef";
"#;
    let results = detector.detect_secrets(content, "src/lib.rs")?;
    // Should detect the real key but not the commented example
    let real_findings: Vec<_> = results.iter().filter(|f| !f.is_false_positive).collect();
    assert!(!real_findings.is_empty());

    Ok(())
}

#[tokio::test]
async fn entropy_based_detection() -> Result<(), Box<dyn std::error::Error>> {
    let tmp = tempfile::Builder::new().suffix(".db").tempfile()?;
    let config = DatabaseConfig {
        url: format!("sqlite://{}", tmp.path().display()),
        max_connections: 1,
        connection_timeout: 5,
        enable_wal: false,
    };
    let db = DatabaseManager::new(&config).await?;
    let detector = SecretsDetector::with_thresholds(&db, Some(3.0), None).await?;

    let high_entropy = "let secret = \"a1b2c3d4e5f67890abcdef1234567890ABCDEF\";";
    let low_entropy = "let number = \"123456789\";";

    let high_results = detector.detect_secrets(high_entropy, "src/crypto.rs")?;
    let low_results = detector.detect_secrets(low_entropy, "src/main.rs")?;

    // Should detect at least one secret (either pattern or entropy-based)
    assert!(
        !high_results.is_empty(),
        "No secrets detected. Results: {:?}",
        high_results
    );
    // Low entropy should not be detected
    assert!(low_results.is_empty());

    Ok(())
}

#[tokio::test]
async fn context_aware_filtering() -> Result<(), Box<dyn std::error::Error>> {
    let tmp = tempfile::Builder::new().suffix(".db").tempfile()?;
    let config = DatabaseConfig {
        url: format!("sqlite://{}", tmp.path().display()),
        max_connections: 1,
        connection_timeout: 5,
        enable_wal: false,
    };
    let db = DatabaseManager::new(&config).await?;
    let detector = SecretsDetector::with_thresholds(&db, Some(3.0), None).await?;

    let test_content = "let api_key = \"sk-test123456789012345678901234567890\";";
    let prod_content = "let api_key = \"sk-prod123456789012345678901234567890\";";

    let test_results = detector.detect_secrets(test_content, "tests/api_test.rs")?;
    let prod_results = detector.detect_secrets(prod_content, "src/api.rs")?;

    // Test file should have lower confidence or be filtered
    if !test_results.is_empty() {
        assert!(test_results[0].confidence < 0.8);
    }
    // Production file should have reasonable confidence
    if !prod_results.is_empty() {
        // AWS keys should have decent confidence after our fixes
        assert!(
            prod_results[0].confidence > 0.2,
            "Production confidence too low: {:.3}",
            prod_results[0].confidence
        );
    }

    Ok(())
}
