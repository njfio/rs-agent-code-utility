// TODO: Re-enable when infrastructure and security modules are implemented
// This test depends on modules that are currently disabled due to infrastructure dependencies

/*
use rust_tree_sitter::infrastructure::{DatabaseConfig, DatabaseManager};
use rust_tree_sitter::security::SecretsDetector;

#[tokio::test]
async fn detects_real_secret() {
    let tmp = tempfile::Builder::new().suffix(".db").tempfile().unwrap();
    let config = DatabaseConfig { url: format!("sqlite://{}", tmp.path().display()), ..DatabaseConfig::default() };
    let db = DatabaseManager::new(&config).await.unwrap();
    let detector = SecretsDetector::with_thresholds(&db, Some(3.0), None).await.unwrap();

    let content = "let key = \"AKIA5C38F4W0HTH09SN4\";";
    let results = detector.detect_secrets(content, "src/lib.rs").unwrap();
    assert!(results.iter().any(|f| matches!(f.secret_type, rust_tree_sitter::security::SecretType::AwsAccessKey) && !f.is_false_positive));
}

#[tokio::test]
async fn filters_known_placeholder() {
    let tmp = tempfile::Builder::new().suffix(".db").tempfile().unwrap();
    let config = DatabaseConfig { url: format!("sqlite://{}", tmp.path().display()), ..DatabaseConfig::default() };
    let db = DatabaseManager::new(&config).await.unwrap();
    let detector = SecretsDetector::with_thresholds(&db, Some(3.0), None).await.unwrap();

    let content = "let key = \"AKIAIOSFODNN7EXAMPLE\";";
    let results = detector.detect_secrets(content, "tests/test_sample.rs").unwrap();
    assert!(results.is_empty());
}
*/
