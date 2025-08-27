//! Real database infrastructure for caching and persistence
//! 
//! Provides SQLite-based storage for vulnerability data, analysis results,
//! and caching with proper schema management and migrations.

use sqlx::{SqlitePool, migrate::MigrateDatabase, Sqlite};
use chrono::{DateTime, Utc};
use serde::{Serialize, Deserialize};
use uuid::Uuid;
use std::path::Path;
use tracing::{info, debug};
use crate::infrastructure::config::DatabaseConfig;

/// Database manager for handling all database operations
#[derive(Clone)]
pub struct DatabaseManager {
    pool: SqlitePool,
}

/// Vulnerability data stored in database
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct VulnerabilityRecord {
    pub id: String,
    pub cve_id: String,
    pub package_name: String,
    pub affected_versions: String,
    pub severity: String,
    pub cvss_score: Option<f64>,
    pub description: String,
    pub published_date: DateTime<Utc>,
    pub last_modified: DateTime<Utc>,
    pub references: String, // JSON array of URLs
    pub cwe_ids: String,    // JSON array of CWE IDs
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Analysis result cache entry
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct AnalysisCacheEntry {
    pub id: String,
    pub file_path: String,
    pub file_hash: String,
    pub analysis_type: String,
    pub result_data: String, // JSON serialized result
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

/// Secret pattern for detection
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct SecretPattern {
    pub id: String,
    pub name: String,
    pub pattern: String,
    pub entropy_threshold: Option<f64>,
    pub confidence: f64,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl DatabaseManager {
    /// Create a new database manager with the given configuration
    pub async fn new(config: &DatabaseConfig) -> Result<Self, sqlx::Error> {
        // Ensure database directory exists
        if let Some(parent) = Path::new(&config.url.replace("sqlite://", "")).parent() {
            if !parent.exists() {
                std::fs::create_dir_all(parent).map_err(|e| {
                    sqlx::Error::Io(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("Failed to create database directory: {}", e)
                    ))
                })?;
            }
        }

        // Create database if it doesn't exist
        if !Sqlite::database_exists(&config.url).await.unwrap_or(false) {
            info!("Creating database: {}", config.url);
            Sqlite::create_database(&config.url).await?;
        }

        // Create connection pool
        let pool = SqlitePool::connect(&config.url).await?;

        // Run migrations
        let manager = Self { pool };
        manager.run_migrations().await?;

        info!("Database initialized successfully");
        Ok(manager)
    }

    /// Run database migrations
    async fn run_migrations(&self) -> Result<(), sqlx::Error> {
        info!("Running database migrations");

        // Create vulnerabilities table
        sqlx::query(r#"
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id TEXT PRIMARY KEY,
                cve_id TEXT NOT NULL UNIQUE,
                package_name TEXT NOT NULL,
                affected_versions TEXT NOT NULL,
                severity TEXT NOT NULL,
                cvss_score REAL,
                description TEXT NOT NULL,
                published_date TEXT NOT NULL,
                last_modified TEXT NOT NULL,
                "references" TEXT NOT NULL,
                cwe_ids TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        "#)
        .execute(&self.pool)
        .await?;

        // Create analysis cache table
        sqlx::query(r#"
            CREATE TABLE IF NOT EXISTS analysis_cache (
                id TEXT PRIMARY KEY,
                file_path TEXT NOT NULL,
                file_hash TEXT NOT NULL,
                analysis_type TEXT NOT NULL,
                result_data TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL
            )
        "#)
        .execute(&self.pool)
        .await?;

        // Create secret patterns table
        sqlx::query(r#"
            CREATE TABLE IF NOT EXISTS secret_patterns (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL UNIQUE,
                pattern TEXT NOT NULL,
                entropy_threshold REAL,
                confidence REAL NOT NULL,
                enabled BOOLEAN NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        "#)
        .execute(&self.pool)
        .await?;

        // Create indexes for better performance
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_vulnerabilities_package ON vulnerabilities(package_name)")
            .execute(&self.pool)
            .await?;

        sqlx::query("CREATE INDEX IF NOT EXISTS idx_vulnerabilities_cve ON vulnerabilities(cve_id)")
            .execute(&self.pool)
            .await?;

        sqlx::query("CREATE INDEX IF NOT EXISTS idx_cache_file_hash ON analysis_cache(file_hash)")
            .execute(&self.pool)
            .await?;

        sqlx::query("CREATE INDEX IF NOT EXISTS idx_cache_expires ON analysis_cache(expires_at)")
            .execute(&self.pool)
            .await?;

        // Insert default secret patterns
        self.insert_default_secret_patterns().await?;

        info!("Database migrations completed");
        Ok(())
    }

    /// Insert default secret patterns
    async fn insert_default_secret_patterns(&self) -> Result<(), sqlx::Error> {
        let patterns = vec![
            ("AWS Access Key", r"AKIA[0-9A-Z]{16}", None, 0.9),
            ("AWS Secret Key", r"[0-9a-zA-Z/+]{40}", Some(4.5), 0.8),
            ("GitHub Token", r"ghp_[0-9a-zA-Z]{36}", None, 0.95),
            ("API Key Generic", r#"[aA][pP][iI][_]?[kK][eE][yY].*['"][0-9a-zA-Z]{32,45}['"]"#, Some(4.0), 0.7),
            ("JWT Token", r"eyJ[0-9a-zA-Z_-]*\.[0-9a-zA-Z_-]*\.[0-9a-zA-Z_-]*", None, 0.85),
            ("Private Key", r"-----BEGIN [A-Z ]+PRIVATE KEY-----", None, 0.95),
            ("Database URL", r"(mysql|postgres|mongodb)://[^\s]+", None, 0.8),
        ];

        for (name, pattern, entropy_threshold, confidence) in patterns {
            let id = Uuid::new_v4().to_string();
            let now = Utc::now();

            sqlx::query(r#"
                INSERT OR IGNORE INTO secret_patterns 
                (id, name, pattern, entropy_threshold, confidence, enabled, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, 1, ?, ?)
            "#)
            .bind(&id)
            .bind(name)
            .bind(pattern)
            .bind(entropy_threshold)
            .bind(confidence)
            .bind(now.to_rfc3339())
            .bind(now.to_rfc3339())
            .execute(&self.pool)
            .await?;
        }

        Ok(())
    }

    /// Store vulnerability data
    pub async fn store_vulnerability(&self, vuln: &VulnerabilityRecord) -> Result<(), sqlx::Error> {
        sqlx::query(r#"
            INSERT OR REPLACE INTO vulnerabilities 
            (id, cve_id, package_name, affected_versions, severity, cvss_score, description,
             published_date, last_modified, "references", cwe_ids, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#)
        .bind(&vuln.id)
        .bind(&vuln.cve_id)
        .bind(&vuln.package_name)
        .bind(&vuln.affected_versions)
        .bind(&vuln.severity)
        .bind(vuln.cvss_score)
        .bind(&vuln.description)
        .bind(vuln.published_date.to_rfc3339())
        .bind(vuln.last_modified.to_rfc3339())
        .bind(&vuln.references)
        .bind(&vuln.cwe_ids)
        .bind(vuln.created_at.to_rfc3339())
        .bind(vuln.updated_at.to_rfc3339())
        .execute(&self.pool)
        .await?;

        debug!("Stored vulnerability: {}", vuln.cve_id);
        Ok(())
    }

    /// Get vulnerabilities for a package
    pub async fn get_vulnerabilities_for_package(&self, package_name: &str) -> Result<Vec<VulnerabilityRecord>, sqlx::Error> {
        let rows = sqlx::query_as::<_, VulnerabilityRecord>(
            "SELECT * FROM vulnerabilities WHERE package_name = ? ORDER BY published_date DESC"
        )
        .bind(package_name)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows)
    }

    /// Store analysis result in cache
    pub async fn store_analysis_cache(&self, entry: &AnalysisCacheEntry) -> Result<(), sqlx::Error> {
        sqlx::query(r#"
            INSERT OR REPLACE INTO analysis_cache 
            (id, file_path, file_hash, analysis_type, result_data, created_at, expires_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        "#)
        .bind(&entry.id)
        .bind(&entry.file_path)
        .bind(&entry.file_hash)
        .bind(&entry.analysis_type)
        .bind(&entry.result_data)
        .bind(entry.created_at.to_rfc3339())
        .bind(entry.expires_at.to_rfc3339())
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Get cached analysis result
    pub async fn get_analysis_cache(&self, file_hash: &str, analysis_type: &str) -> Result<Option<AnalysisCacheEntry>, sqlx::Error> {
        let now = Utc::now();
        
        let row = sqlx::query_as::<_, AnalysisCacheEntry>(
            "SELECT * FROM analysis_cache WHERE file_hash = ? AND analysis_type = ? AND expires_at > ?"
        )
        .bind(file_hash)
        .bind(analysis_type)
        .bind(now.to_rfc3339())
        .fetch_optional(&self.pool)
        .await?;

        Ok(row)
    }

    /// Get all secret patterns
    pub async fn get_secret_patterns(&self) -> Result<Vec<SecretPattern>, sqlx::Error> {
        let rows = sqlx::query_as::<_, SecretPattern>(
            "SELECT * FROM secret_patterns WHERE enabled = 1 ORDER BY confidence DESC"
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows)
    }

    /// Clean expired cache entries
    pub async fn clean_expired_cache(&self) -> Result<u64, sqlx::Error> {
        let now = Utc::now();
        
        let result = sqlx::query("DELETE FROM analysis_cache WHERE expires_at < ?")
            .bind(now.to_rfc3339())
            .execute(&self.pool)
            .await?;

        let deleted_count = result.rows_affected();
        if deleted_count > 0 {
            info!("Cleaned {} expired cache entries", deleted_count);
        }

        Ok(deleted_count)
    }

    /// Get database statistics
    pub async fn get_stats(&self) -> Result<DatabaseStats, sqlx::Error> {
        let vuln_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM vulnerabilities")
            .fetch_one(&self.pool)
            .await?;

        let cache_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM analysis_cache")
            .fetch_one(&self.pool)
            .await?;

        let pattern_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM secret_patterns WHERE enabled = 1")
            .fetch_one(&self.pool)
            .await?;

        Ok(DatabaseStats {
            vulnerability_count: vuln_count as u64,
            cache_entry_count: cache_count as u64,
            secret_pattern_count: pattern_count as u64,
        })
    }

    /// Close the database connection
    pub async fn close(&self) {
        self.pool.close().await;
        info!("Database connection closed");
    }
}

/// Database statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseStats {
    pub vulnerability_count: u64,
    pub cache_entry_count: u64,
    pub secret_pattern_count: u64,
}
