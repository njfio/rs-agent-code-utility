// TODO: Re-enable when infrastructure module is implemented
// This test depends on modules that are currently disabled due to infrastructure dependencies

/*
use rust_tree_sitter::security::vulnerability_db::{VulnerabilityDatabase, NvdConfig, OsvConfig, GitHubConfig};
use rust_tree_sitter::infrastructure::{DatabaseConfig, DatabaseManager, CacheConfig, Cache};
use rust_tree_sitter::infrastructure::rate_limiter::RateLimiterFactory;
use wiremock::{Mock, MockServer, ResponseTemplate};
use wiremock::matchers::{method, path};
use tempfile::NamedTempFile;
use anyhow::Result;

#[tokio::test]
async fn test_vulnerability_database_end_to_end() -> Result<()> {
    // Mock OSV API
    let osv_server = MockServer::start().await;
    let osv_body = serde_json::json!({
        "vulns": [{
            "id": "CVE-2023-11111",
            "summary": "OSV vuln",
            "details": "details",
            "aliases": ["CVE-2023-11111"],
            "modified": "2024-01-01T00:00:00Z",
            "published": "2023-12-31T00:00:00Z",
            "severity": [{"type": "CVSS_V3", "score": "9.8"}],
            "affected": null,
            "references": [{"type": "ADVISORY", "url": "http://example.com/osv"}]
        }]
    });
    Mock::given(method("POST")).and(path("/v1/query"))
        .respond_with(ResponseTemplate::new(200).set_body_json(osv_body))
        .mount(&osv_server)
        .await;

    // Mock NVD API
    let nvd_server = MockServer::start().await;
    let nvd_body = serde_json::json!({
        "vulnerabilities": [{"cve": {
            "id": "CVE-2023-11111",
            "sourceIdentifier": "nvd",
            "published": "2023-12-30T00:00:00Z",
            "lastModified": "2024-01-01T00:00:00Z",
            "descriptions": [{"lang": "en", "value": "NVD desc"}],
            "metrics": {"cvssMetricV31": [{"source": "nvd", "type": "Primary", "cvssData": {"version": "3.1", "vectorString": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "baseScore": 9.8, "baseSeverity": "CRITICAL"}}]},
            "references": [{"url": "http://example.com/nvd"}]
        }}],
        "totalResults": 1,
        "resultsPerPage": 1,
        "startIndex": 0
    });
    Mock::given(method("GET")).and(path("/cves/2.0"))
        .respond_with(ResponseTemplate::new(200).set_body_json(nvd_body))
        .mount(&nvd_server)
        .await;

    // Mock GitHub API
    let gh_server = MockServer::start().await;
    let gh_body = serde_json::json!({
        "advisories": [{
            "ghsa_id": "GHSA-xxxx-xxxx",
            "cve_id": "CVE-2023-11111",
            "summary": "GH vuln",
            "severity": "HIGH",
            "cvss_score": 7.5,
            "references": ["http://example.com/gh"],
            "cwes": ["CWE-79"],
            "published_at": "2023-12-25T00:00:00Z",
            "updated_at": "2024-01-02T00:00:00Z"
        }]
    });
    Mock::given(method("GET")).and(path("/advisories"))
        .respond_with(ResponseTemplate::new(200).set_body_json(gh_body))
        .mount(&gh_server)
        .await;

    // Infrastructure setup
    let db_file = NamedTempFile::new()?;
    let db_config = DatabaseConfig {
        url: format!("sqlite://{}", db_file.path().display()),
        max_connections: 1,
        connection_timeout: 30,
        enable_wal: false,
    };
    let database = DatabaseManager::new(&db_config).await?;
    let cache_config = CacheConfig {
        enable_memory: true,
        enable_disk: false,
        memory_max_entries: 100,
        disk_cache_dir: None,
        default_ttl: std::time::Duration::from_secs(3600),
        cleanup_interval: std::time::Duration::from_secs(3600),
    };
    let cache = Cache::new(cache_config)?;
    let rate_limiter = RateLimiterFactory::create_default_multi_limiter().await?;

    let vuln_db = VulnerabilityDatabase::new(
        database.clone(),
        cache.clone(),
        rate_limiter,
        NvdConfig { base_url: nvd_server.uri(), api_key: None, enabled: true },
        OsvConfig { base_url: osv_server.uri(), enabled: true },
        GitHubConfig { base_url: gh_server.uri(), token: None, enabled: true },
    ).await?;

    // First call performs API requests
    let vulns = vuln_db.check_package_vulnerabilities("example", Some("1.0.0"), "npm").await?;
    assert_eq!(vulns.len(), 1);
    assert_eq!(vulns[0].cve_id, "CVE-2023-11111");

    let stored = database.get_vulnerabilities_for_package("example").await?;
    assert_eq!(stored.len(), 1);

    // Second call should use cache (no extra HTTP requests)
    let _ = vuln_db.check_package_vulnerabilities("example", Some("1.0.0"), "npm").await?;
    assert_eq!(osv_server.received_requests().await.unwrap().len(), 1);
    assert_eq!(nvd_server.received_requests().await.unwrap().len(), 1);
    assert_eq!(gh_server.received_requests().await.unwrap().len(), 1);

    Ok(())
}
*/