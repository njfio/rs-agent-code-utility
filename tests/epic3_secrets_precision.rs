#![cfg(any(feature = "net", feature = "db"))]

use rust_tree_sitter::infrastructure::{DatabaseConfig, DatabaseManager};
use rust_tree_sitter::security::SecretsDetector;

#[tokio::test]
async fn inline_suppression_ignores_finding() -> Result<(), Box<dyn std::error::Error>> {
    let tmp = tempfile::Builder::new().suffix(".db").tempfile()?;
    let config = DatabaseConfig {
        url: format!("sqlite://{}", tmp.path().display()),
        max_connections: 1,
        connection_timeout: 5,
        enable_wal: false,
    };
    let db = DatabaseManager::new(&config).await?;
    let detector = SecretsDetector::with_thresholds(&db, Some(3.0), None).await?;

    // Suppression on same line
    let content = "let key = \"AKIA5C38F4W0HTH09SN4\"; // secret-scan:ignore example";
    let results = detector.detect_secrets(content, "src/lib.rs")?;
    assert!(
        results.is_empty(),
        "Suppressed findings should be dropped: {:?}",
        results
    );

    Ok(())
}

#[tokio::test]
async fn ignores_code_fences_in_docs() -> Result<(), Box<dyn std::error::Error>> {
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
Here is an example:

```
const KEY = "AKIA5C38F4W0HTH09SN4";
```

This should not be flagged when scanning docs.
"#;
    let results = detector.detect_secrets(content, "docs/README.md")?;
    assert!(
        results.is_empty(),
        "Code fences in docs should be ignored: {:?}",
        results
    );

    Ok(())
}

#[tokio::test]
async fn aws_pair_boosts_confidence() -> Result<(), Box<dyn std::error::Error>> {
    let tmp = tempfile::Builder::new().suffix(".db").tempfile()?;
    let config = DatabaseConfig {
        url: format!("sqlite://{}", tmp.path().display()),
        max_connections: 1,
        connection_timeout: 5,
        enable_wal: false,
    };
    let db = DatabaseManager::new(&config).await?;
    let detector = SecretsDetector::with_thresholds(&db, Some(3.0), None).await?;

    let solo = "let id = \"AKIA5C38F4W0HTH09SN4\";";
    let paired = r#"
AWS_ACCESS_KEY_ID=AKIA5C38F4W0HTH09SN4
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
"#;

    let solo_findings = detector.detect_secrets(solo, "src/config.rs")?;
    let paired_findings = detector.detect_secrets(paired, "src/config.rs")?;

    let solo_conf = solo_findings
        .iter()
        .filter(|f| {
            matches!(
                f.secret_type,
                rust_tree_sitter::security::SecretType::AwsAccessKey
            )
        })
        .map(|f| f.confidence)
        .next();
    let pair_conf = paired_findings
        .iter()
        .filter(|f| {
            matches!(
                f.secret_type,
                rust_tree_sitter::security::SecretType::AwsAccessKey
            )
        })
        .map(|f| f.confidence)
        .next();

    if let (Some(s), Some(p)) = (solo_conf, pair_conf) {
        assert!(
            p >= s,
            "Expected paired confidence >= solo: solo={s}, pair={p}"
        );
    }

    Ok(())
}
