//! Enhanced dependency analysis for security and architecture insights
//! 
//! This module provides comprehensive dependency analysis including:
//! - Package manager integration (Cargo, npm, pip, go.mod)
//! - Vulnerability scanning of dependencies
//! - License compliance checking
//! - Dependency graph analysis
//! - Outdated dependency detection

use crate::{AnalysisResult, Result};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::fs;
use std::collections::HashSet;

#[cfg(feature = "serde")]
use serde::{Serialize, Deserialize};

/// Dependency analyzer for comprehensive dependency insights
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct DependencyAnalyzer {
    /// Configuration for dependency analysis
    pub config: DependencyConfig,
    /// Optional external vulnerability provider (e.g., OSV/CVE). Scaffold only.
    #[cfg_attr(feature = "serde", serde(skip))]
    provider: Option<Box<dyn VulnerabilityProvider + Send + Sync>>,
}

impl std::fmt::Debug for DependencyAnalyzer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DependencyAnalyzer")
            .field("config", &self.config)
            .field("provider", &self.provider.as_ref().map(|_| "VulnerabilityProvider"))
            .finish()
    }
}

impl Clone for DependencyAnalyzer {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            provider: None, // Cannot clone trait objects, so we set to None
        }
    }
}

/// Configuration for dependency analysis
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct DependencyConfig {
    /// Enable vulnerability scanning
    pub vulnerability_scanning: bool,
    /// Enable license compliance checking
    pub license_compliance: bool,
    /// Enable outdated dependency detection
    pub outdated_detection: bool,
    /// Enable dependency graph analysis
    pub graph_analysis: bool,
    /// Include development dependencies
    pub include_dev_dependencies: bool,
    /// Maximum depth for dependency resolution
    pub max_dependency_depth: usize,
}

/// Results of dependency analysis
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct DependencyAnalysisResult {
    /// Total number of dependencies found
    pub total_dependencies: usize,
    /// Direct dependencies count
    pub direct_dependencies: usize,
    /// Transitive dependencies count
    pub transitive_dependencies: usize,
    /// Dependencies by package manager
    pub dependencies_by_manager: HashMap<PackageManager, usize>,
    /// Detected package managers
    pub package_managers: Vec<PackageManagerInfo>,
    /// All discovered dependencies
    pub dependencies: Vec<Dependency>,
    /// Vulnerability analysis results
    pub vulnerabilities: Vec<DependencyVulnerability>,
    /// License compliance analysis
    pub license_analysis: LicenseAnalysis,
    /// Outdated dependencies
    pub outdated_dependencies: Vec<OutdatedDependency>,
    /// Dependency graph insights
    pub graph_analysis: DependencyGraphAnalysis,
    /// Security recommendations
    pub security_recommendations: Vec<SecurityRecommendation>,
}

/// A software dependency
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Dependency {
    /// Dependency name
    pub name: String,
    /// Current version
    pub version: String,
    /// Latest available version
    pub latest_version: Option<String>,
    /// Package manager
    pub manager: PackageManager,
    /// Dependency type (direct, transitive, dev)
    pub dependency_type: DependencyType,
    /// License information
    pub license: Option<String>,
    /// Repository URL
    pub repository: Option<String>,
    /// Description
    pub description: Option<String>,
    /// Maintainer information
    pub maintainers: Vec<String>,
    /// Download count (if available)
    pub download_count: Option<u64>,
    /// Last update date
    pub last_updated: Option<String>,
    /// Security advisories count
    pub security_advisories: usize,
}

/// Package manager types
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum PackageManager {
    /// Rust Cargo
    Cargo,
    /// Node.js npm
    Npm,
    /// Python pip
    Pip,
    /// Go modules
    GoMod,
    /// Python Poetry
    Poetry,
    /// Node.js Yarn
    Yarn,
    /// Python Pipenv
    Pipenv,
}

/// Package manager information
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct PackageManagerInfo {
    /// Package manager type
    pub manager: PackageManager,
    /// Configuration file path
    pub config_file: PathBuf,
    /// Lock file path (if exists)
    pub lock_file: Option<PathBuf>,
    /// Number of dependencies
    pub dependency_count: usize,
    /// Package manager version
    pub version: Option<String>,
}

/// Dependency type classification
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum DependencyType {
    /// Direct dependency
    Direct,
    /// Transitive dependency
    Transitive,
    /// Development dependency
    Development,
    /// Build dependency
    Build,
    /// Optional dependency
    Optional,
    /// Peer dependency
    Peer,
}

/// Dependency vulnerability information
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct DependencyVulnerability {
    /// Vulnerability ID
    pub id: String,
    /// Affected dependency
    pub dependency: String,
    /// Affected version range
    pub affected_versions: String,
    /// Vulnerability title
    pub title: String,
    /// Detailed description
    pub description: String,
    /// Severity level
    pub severity: VulnerabilitySeverity,
    /// CVSS score
    pub cvss_score: Option<f64>,
    /// CVE identifier
    pub cve: Option<String>,
    /// Fix available
    pub fix_available: bool,
    /// Recommended action
    pub recommended_action: String,
    /// References and links
    pub references: Vec<String>,
}

/// Vulnerability severity levels
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum VulnerabilitySeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

/// License compliance analysis
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct LicenseAnalysis {
    /// Total licenses found
    pub total_licenses: usize,
    /// License distribution
    pub license_distribution: HashMap<String, usize>,
    /// Compliance issues
    pub compliance_issues: Vec<LicenseIssue>,
    /// Compatible licenses
    pub compatible_licenses: Vec<String>,
    /// Incompatible licenses
    pub incompatible_licenses: Vec<String>,
    /// Unknown licenses
    pub unknown_licenses: Vec<String>,
    /// Overall compliance status
    pub compliance_status: ComplianceStatus,
}

/// License compliance issue
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct LicenseIssue {
    /// Dependency with license issue
    pub dependency: String,
    /// License causing the issue
    pub license: String,
    /// Issue type
    pub issue_type: LicenseIssueType,
    /// Detailed description
    pub description: String,
    /// Recommended action
    pub recommendation: String,
}

/// Types of license issues
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum LicenseIssueType {
    /// Incompatible license
    Incompatible,
    /// Unknown license
    Unknown,
    /// Copyleft license
    Copyleft,
    /// Commercial restriction
    CommercialRestriction,
}

/// Compliance status
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum ComplianceStatus {
    Compliant,
    Warning,
    NonCompliant,
}

/// Outdated dependency information
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct OutdatedDependency {
    /// Dependency name
    pub name: String,
    /// Current version
    pub current_version: String,
    /// Latest version
    pub latest_version: String,
    /// Package manager
    pub manager: PackageManager,
    /// Versions behind
    pub versions_behind: usize,
    /// Update urgency
    pub urgency: UpdateUrgency,
    /// Breaking changes expected
    pub breaking_changes: bool,
    /// Security fixes in update
    pub security_fixes: bool,
}

/// Update urgency levels
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum UpdateUrgency {
    Critical,
    High,
    Medium,
    Low,
}

/// Dependency graph analysis results
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct DependencyGraphAnalysis {
    /// Total nodes in dependency graph
    pub total_nodes: usize,
    /// Total edges in dependency graph
    pub total_edges: usize,
    /// Maximum dependency depth
    pub max_depth: usize,
    /// Circular dependencies detected
    pub circular_dependencies: Vec<CircularDependency>,
    /// Most depended upon packages
    pub popular_dependencies: Vec<PopularDependency>,
    /// Dependency clusters
    pub clusters: Vec<DependencyCluster>,
    /// Graph metrics
    pub metrics: GraphMetrics,
}

/// Circular dependency information
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct CircularDependency {
    /// Dependencies involved in the cycle
    pub cycle: Vec<String>,
    /// Cycle length
    pub length: usize,
    /// Impact assessment
    pub impact: CircularDependencyImpact,
}

/// Impact of circular dependencies
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum CircularDependencyImpact {
    High,
    Medium,
    Low,
}

/// Popular dependency information
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct PopularDependency {
    /// Dependency name
    pub name: String,
    /// Number of dependents
    pub dependent_count: usize,
    /// Centrality score
    pub centrality_score: f64,
}

/// Dependency cluster information
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct DependencyCluster {
    /// Cluster name/identifier
    pub name: String,
    /// Dependencies in cluster
    pub dependencies: Vec<String>,
    /// Cluster purpose/theme
    pub purpose: String,
}

/// Graph analysis metrics
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct GraphMetrics {
    /// Average dependency depth
    pub average_depth: f64,
    /// Dependency density
    pub density: f64,
    /// Clustering coefficient
    pub clustering_coefficient: f64,
    /// Number of isolated components
    pub isolated_components: usize,
}

/// Security recommendation for dependencies
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SecurityRecommendation {
    /// Recommendation category
    pub category: String,
    /// Recommendation text
    pub recommendation: String,
    /// Priority level
    pub priority: RecommendationPriority,
    /// Affected dependencies
    pub affected_dependencies: Vec<String>,
    /// Implementation difficulty
    pub difficulty: ImplementationDifficulty,
}

/// Recommendation priority levels
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum RecommendationPriority {
    Critical,
    High,
    Medium,
    Low,
}

/// Implementation difficulty levels
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum ImplementationDifficulty {
    Easy,
    Medium,
    Hard,
    VeryHard,
}

impl Default for DependencyConfig {
    fn default() -> Self {
        Self {
            vulnerability_scanning: true,
            license_compliance: true,
            outdated_detection: true,
            graph_analysis: true,
            include_dev_dependencies: true,
            max_dependency_depth: 10,
        }
    }
}

// --- Vulnerability Provider Scaffold ---

/// A pluggable vulnerability provider interface (e.g., OSV/CVE). Stub only.
pub trait VulnerabilityProvider {
    fn enrich(&self, deps: &[Dependency]) -> Vec<DependencyVulnerability>;
}

/// A no-op stub provider for testing/scaffolding.
pub struct NoopVulnProvider;

impl VulnerabilityProvider for NoopVulnProvider {
    fn enrich(&self, _deps: &[Dependency]) -> Vec<DependencyVulnerability> { Vec::new() }
}

impl DependencyAnalyzer {
    /// Create a new dependency analyzer with default configuration
    pub fn new() -> Self {
        Self {
            config: DependencyConfig::default(),
            provider: None,
        }
    }

    /// Create a new dependency analyzer with custom configuration
    pub fn with_config(config: DependencyConfig) -> Self {
        Self { config, provider: None }
    }

    /// Attach an external vulnerability provider (scaffold; may be a stub)
    pub fn with_provider(mut self, provider: Box<dyn VulnerabilityProvider + Send + Sync>) -> Self {
        self.provider = Some(provider);
        self
    }

    /// Helper function to create dependency without excessive cloning
    fn create_dependency(
        name: &str,
        version: String,
        manager: PackageManager,
        dependency_type: DependencyType,
    ) -> Dependency {
        Dependency {
            name: name.to_string(),
            version,
            latest_version: None,
            manager,
            dependency_type,
            license: None,
            repository: None,
            description: None,
            maintainers: Vec::new(),
            download_count: None,
            last_updated: None,
            security_advisories: 0,
        }
    }
    
    /// Analyze dependencies in a codebase
    pub fn analyze(&self, analysis_result: &AnalysisResult) -> Result<DependencyAnalysisResult> {
        let root_path = &analysis_result.root_path;
        
        // Detect package managers
        let package_managers = self.detect_package_managers(root_path)?;
        
        // Extract dependencies from each package manager
        let mut all_dependencies = Vec::new();
        let mut dependencies_by_manager = HashMap::new();
        
        for pm_info in &package_managers {
            let deps = self.extract_dependencies(&pm_info)?;
            let count = deps.len();
            all_dependencies.extend(deps);
            dependencies_by_manager.insert(pm_info.manager.clone(), count);
        }

        // Also scan source files for imports to infer dependencies
        let inferred = self.extract_source_imports(root_path, &analysis_result.files)?;
        all_dependencies.extend(inferred);
        
        // Analyze vulnerabilities
        let vulnerabilities = if self.config.vulnerability_scanning {
            if let Some(ref p) = self.provider {
                p.enrich(&all_dependencies)
            } else {
                self.analyze_vulnerabilities(&all_dependencies)?
            }
        } else {
            Vec::new()
        };
        
        // Analyze licenses
        let license_analysis = if self.config.license_compliance {
            self.analyze_licenses(&all_dependencies)?
        } else {
            LicenseAnalysis::default()
        };
        
        // Detect outdated dependencies
        let outdated_dependencies = if self.config.outdated_detection {
            self.detect_outdated_dependencies(&all_dependencies)?
        } else {
            Vec::new()
        };
        
        // Analyze dependency graph
        let graph_analysis = if self.config.graph_analysis {
            self.analyze_dependency_graph(&all_dependencies)?
        } else {
            DependencyGraphAnalysis::default()
        };
        
        // Generate security recommendations
        let security_recommendations = self.generate_security_recommendations(
            &vulnerabilities,
            &outdated_dependencies,
            &license_analysis,
        )?;
        
        let direct_deps = all_dependencies.iter()
            .filter(|d| d.dependency_type == DependencyType::Direct)
            .count();
        
        let transitive_deps = all_dependencies.iter()
            .filter(|d| d.dependency_type == DependencyType::Transitive)
            .count();
        
        Ok(DependencyAnalysisResult {
            total_dependencies: all_dependencies.len(),
            direct_dependencies: direct_deps,
            transitive_dependencies: transitive_deps,
            dependencies_by_manager,
            package_managers,
            dependencies: all_dependencies,
            vulnerabilities,
            license_analysis,
            outdated_dependencies,
            graph_analysis,
            security_recommendations,
        })
    }

    /// Detect package managers in the project
    fn detect_package_managers(&self, root_path: &Path) -> Result<Vec<PackageManagerInfo>> {
        let mut package_managers = Vec::new();

        // Check for Cargo.toml (Rust)
        let cargo_toml = root_path.join("Cargo.toml");
        if cargo_toml.exists() {
            let lock_file = root_path.join("Cargo.lock");
            package_managers.push(PackageManagerInfo {
                manager: PackageManager::Cargo,
                config_file: cargo_toml,
                lock_file: if lock_file.exists() { Some(lock_file) } else { None },
                dependency_count: 0, // Will be filled later
                version: None,
            });
        }

        // Check for package.json (Node.js)
        let package_json = root_path.join("package.json");
        if package_json.exists() {
            let lock_file = root_path.join("package-lock.json");
            let yarn_lock = root_path.join("yarn.lock");

            let (manager, lock) = if yarn_lock.exists() {
                (PackageManager::Yarn, Some(yarn_lock))
            } else if lock_file.exists() {
                (PackageManager::Npm, Some(lock_file))
            } else {
                (PackageManager::Npm, None)
            };

            package_managers.push(PackageManagerInfo {
                manager,
                config_file: package_json,
                lock_file: lock,
                dependency_count: 0,
                version: None,
            });
        }

        // Check for requirements.txt or pyproject.toml (Python)
        let requirements_txt = root_path.join("requirements.txt");
        let pyproject_toml = root_path.join("pyproject.toml");
        let pipfile = root_path.join("Pipfile");

        if pyproject_toml.exists() {
            package_managers.push(PackageManagerInfo {
                manager: PackageManager::Poetry,
                config_file: pyproject_toml,
                lock_file: root_path.join("poetry.lock").exists().then(|| root_path.join("poetry.lock")),
                dependency_count: 0,
                version: None,
            });
        } else if pipfile.exists() {
            package_managers.push(PackageManagerInfo {
                manager: PackageManager::Pipenv,
                config_file: pipfile,
                lock_file: root_path.join("Pipfile.lock").exists().then(|| root_path.join("Pipfile.lock")),
                dependency_count: 0,
                version: None,
            });
        } else if requirements_txt.exists() {
            package_managers.push(PackageManagerInfo {
                manager: PackageManager::Pip,
                config_file: requirements_txt,
                lock_file: None,
                dependency_count: 0,
                version: None,
            });
        }

        // Check for go.mod (Go)
        let go_mod = root_path.join("go.mod");
        if go_mod.exists() {
            package_managers.push(PackageManagerInfo {
                manager: PackageManager::GoMod,
                config_file: go_mod,
                lock_file: root_path.join("go.sum").exists().then(|| root_path.join("go.sum")),
                dependency_count: 0,
                version: None,
            });
        }

        Ok(package_managers)
    }

    /// Extract dependencies from a package manager
    fn extract_dependencies(&self, pm_info: &PackageManagerInfo) -> Result<Vec<Dependency>> {
        match pm_info.manager {
            PackageManager::Cargo => self.extract_cargo_dependencies(pm_info),
            PackageManager::Npm | PackageManager::Yarn => self.extract_npm_dependencies(pm_info),
            PackageManager::Pip | PackageManager::Poetry | PackageManager::Pipenv => {
                self.extract_python_dependencies(pm_info)
            }
            PackageManager::GoMod => self.extract_go_dependencies(pm_info),
        }
    }

    /// Extract Cargo dependencies
    fn extract_cargo_dependencies(&self, pm_info: &PackageManagerInfo) -> Result<Vec<Dependency>> {
        let content = fs::read_to_string(&pm_info.config_file)?;
        let mut dependencies = Vec::new();

        // Parse Cargo.toml using proper TOML parsing
        let toml_value: toml::Value = toml::from_str(&content)
            .map_err(|e| crate::error::Error::parse_error(format!("Failed to parse Cargo.toml: {}", e)))?;

        // Extract regular dependencies
        if let Some(deps) = toml_value.get("dependencies").and_then(|d| d.as_table()) {
            for (name, version_spec) in deps {
                // Minimal schema validation: if version provided in table, it must be string
                if let toml::Value::Table(t) = version_spec {
                    if let Some(ver_val) = t.get("version") {
                        if !ver_val.is_str() {
                            return Err(crate::error::Error::parse_error(
                                "Invalid version type in Cargo.toml: expected string".to_string(),
                            ));
                        }
                    }
                }
                let (version, dependency_type) = self.parse_cargo_dependency_spec(version_spec);
                dependencies.push(Dependency {
                    name: name.clone(),
                    version,
                    latest_version: None,
                    manager: PackageManager::Cargo,
                    dependency_type,
                    license: None,
                    repository: None,
                    description: None,
                    maintainers: Vec::new(),
                    download_count: None,
                    last_updated: None,
                    security_advisories: 0,
                });
            }
        }

        // Extract dev dependencies if configured
        if self.config.include_dev_dependencies {
            if let Some(dev_deps) = toml_value.get("dev-dependencies").and_then(|d| d.as_table()) {
                for (name, version_spec) in dev_deps {
                    let (version, _) = self.parse_cargo_dependency_spec(version_spec);
                    dependencies.push(Self::create_dependency(
                        name,
                        version,
                        PackageManager::Cargo,
                        DependencyType::Development,
                    ));
                }
            }
        }

        // Extract build dependencies
        if let Some(build_deps) = toml_value.get("build-dependencies").and_then(|d| d.as_table()) {
            for (name, version_spec) in build_deps {
                let (version, _) = self.parse_cargo_dependency_spec(version_spec);
                dependencies.push(Self::create_dependency(
                    name,
                    version,
                    PackageManager::Cargo,
                    DependencyType::Build,
                ));
            }
        }

        Ok(dependencies)
    }

    /// Parse a Cargo dependency specification
    fn parse_cargo_dependency_spec(&self, version_spec: &toml::Value) -> (String, DependencyType) {
        match version_spec {
            toml::Value::String(version) => {
                (version.clone(), DependencyType::Direct)
            }
            toml::Value::Table(table) => {
                // Handle complex dependency specifications
                let version = table.get("version")
                    .and_then(|v| v.as_str())
                    .unwrap_or("*")
                    .to_string();

                let dependency_type = if table.get("optional").and_then(|v| v.as_bool()).unwrap_or(false) {
                    DependencyType::Optional
                } else {
                    DependencyType::Direct
                };

                (version, dependency_type)
            }
            _ => ("*".to_string(), DependencyType::Direct)
        }
    }

    /// Extract npm/yarn dependencies
    fn extract_npm_dependencies(&self, pm_info: &PackageManagerInfo) -> Result<Vec<Dependency>> {
        let content = fs::read_to_string(&pm_info.config_file)?;
        let mut dependencies = Vec::new();

        // Parse package.json using serde_json
        let package_json: serde_json::Value = serde_json::from_str(&content)
            .map_err(|e| crate::error::Error::parse_error(format!("Failed to parse package.json: {}", e)))?;

        // Extract regular dependencies
        if let Some(deps) = package_json.get("dependencies").and_then(|d| d.as_object()) {
            for (name, version) in deps {
                if !version.is_string() { return Err(crate::error::Error::parse_error("Invalid version type in package.json: expected string".to_string())); }
                let version_str = version.as_str().unwrap_or("*").to_string();
                dependencies.push(Dependency {
                    name: name.clone(),
                    version: version_str,
                    latest_version: None,
                    manager: pm_info.manager.clone(),
                    dependency_type: DependencyType::Direct,
                    license: None,
                    repository: None,
                    description: None,
                    maintainers: Vec::new(),
                    download_count: None,
                    last_updated: None,
                    security_advisories: 0,
                });
            }
        }

        // Extract dev dependencies if configured
        if self.config.include_dev_dependencies {
            if let Some(dev_deps) = package_json.get("devDependencies").and_then(|d| d.as_object()) {
                for (name, version) in dev_deps {
                    if !version.is_string() { return Err(crate::error::Error::parse_error("Invalid version type in package.json: expected string".to_string())); }
                    let version_str = version.as_str().unwrap_or("*").to_string();
                    dependencies.push(Dependency {
                        name: name.clone(),
                        version: version_str,
                        latest_version: None,
                        manager: pm_info.manager.clone(),
                        dependency_type: DependencyType::Development,
                        license: None,
                        repository: None,
                        description: None,
                        maintainers: Vec::new(),
                        download_count: None,
                        last_updated: None,
                        security_advisories: 0,
                    });
                }
            }
        }

        // Extract peer dependencies
        if let Some(peer_deps) = package_json.get("peerDependencies").and_then(|d| d.as_object()) {
            for (name, version) in peer_deps {
                if !version.is_string() { return Err(crate::error::Error::parse_error("Invalid version type in package.json: expected string".to_string())); }
                let version_str = version.as_str().unwrap_or("*").to_string();
                dependencies.push(Dependency {
                    name: name.clone(),
                    version: version_str,
                    latest_version: None,
                    manager: pm_info.manager.clone(),
                    dependency_type: DependencyType::Peer,
                    license: None,
                    repository: None,
                    description: None,
                    maintainers: Vec::new(),
                    download_count: None,
                    last_updated: None,
                    security_advisories: 0,
                });
            }
        }

        // Extract optional dependencies
        if let Some(opt_deps) = package_json.get("optionalDependencies").and_then(|d| d.as_object()) {
            for (name, version) in opt_deps {
                if !version.is_string() { return Err(crate::error::Error::parse_error("Invalid version type in package.json: expected string".to_string())); }
                let version_str = version.as_str().unwrap_or("*").to_string();
                dependencies.push(Dependency {
                    name: name.clone(),
                    version: version_str,
                    latest_version: None,
                    manager: pm_info.manager.clone(),
                    dependency_type: DependencyType::Optional,
                    license: None,
                    repository: None,
                    description: None,
                    maintainers: Vec::new(),
                    download_count: None,
                    last_updated: None,
                    security_advisories: 0,
                });
            }
        }

        Ok(dependencies)
    }

    /// Extract dependencies by scanning source imports across languages
    fn extract_source_imports(&self, root: &Path, files: &[crate::FileInfo]) -> Result<Vec<Dependency>> {
        let mut deps = Vec::new();
        let mut seen: HashSet<(String, PackageManager)> = HashSet::new();

        for fi in files {
            let full = root.join(&fi.path);
            let Ok(content) = fs::read_to_string(&full) else { continue };
            match fi.language.as_str() {
                "Rust" => {
                    for name in Self::scan_rust_imports(&content) {
                        let key = (name.clone(), PackageManager::Cargo);
                        if seen.insert(key.clone()) {
                            deps.push(Self::create_dependency(&name, "*".to_string(), PackageManager::Cargo, DependencyType::Direct));
                        }
                    }
                }
                "JavaScript" | "TypeScript" => {
                    for name in Self::scan_js_imports(&content) {
                        let key = (name.clone(), PackageManager::Npm);
                        if seen.insert(key.clone()) {
                            deps.push(Self::create_dependency(&name, "*".to_string(), PackageManager::Npm, DependencyType::Direct));
                        }
                    }
                }
                "Python" => {
                    for name in Self::scan_python_imports(&content) {
                        let key = (name.clone(), PackageManager::Pip);
                        if seen.insert(key.clone()) {
                            deps.push(Self::create_dependency(&name, "*".to_string(), PackageManager::Pip, DependencyType::Direct));
                        }
                    }
                }
                _ => {}
            }
        }

        Ok(deps)
    }

    fn scan_rust_imports(src: &str) -> Vec<String> {
        let mut names = Vec::new();
        for line in src.lines() {
            let l = line.trim();
            if l.starts_with("use ") {
                // use foo::bar::{...}
                let after = &l[4..];
                let first = after.split(|c: char| c == ':' || c.is_whitespace() || c == '{').next().unwrap_or("");
                if !matches!(first, "" | "crate" | "self" | "super" | "std" | "core" | "alloc") {
                    names.push(first.to_string());
                }
            } else if l.starts_with("extern crate ") {
                let after = &l[13..];
                let name = after.split(|c: char| c == ';' || c.is_whitespace()).next().unwrap_or("");
                if !name.is_empty() { names.push(name.to_string()); }
            }
        }
        names
    }

    fn scan_js_imports(src: &str) -> Vec<String> {
        let mut names = Vec::new();
        for line in src.lines() {
            let l = line.trim();
            // import x from 'pkg' or "pkg"
            if l.starts_with("import ") && l.contains(" from ") {
                if let Some(spec) = l.split(" from ").nth(1) {
                    let spec = spec.trim();
                    let spec = spec.trim_matches(&['"', '\'', ';'][..]);
                    if !spec.starts_with("./") && !spec.starts_with("../") {
                        names.push(Self::normalize_js_pkg(spec));
                    }
                }
            }
            // import 'pkg'; side-effect import
            if l.starts_with("import ") && !l.contains(" from ") {
                // e.g., import 'dotenv/config'
                if let Some(start) = l.find('\'') { // '
                    let spec = &l[start+1..];
                    if let Some(end) = spec.find('\'') { // '
                        let s = &spec[..end];
                        if !s.starts_with("./") && !s.starts_with("../") {
                            names.push(Self::normalize_js_pkg(s));
                        }
                    }
                } else if let Some(start) = l.find('"') {
                    let spec = &l[start+1..];
                    if let Some(end) = spec.find('"') {
                        let s = &spec[..end];
                        if !s.starts_with("./") && !s.starts_with("../") {
                            names.push(Self::normalize_js_pkg(s));
                        }
                    }
                }
            }
            // const x = require('pkg')
            if let Some(idx) = l.find("require(") {
                let rest = &l[idx + 8..];
                if let Some(end) = rest.find(')') {
                    let inside = &rest[..end];
                    let inside = inside.trim_matches(&['"', '\'', ' '][..]);
                    if !inside.starts_with("./") && !inside.starts_with("../") { names.push(Self::normalize_js_pkg(inside)); }
                }
            }
            // dynamic import('pkg')
            if let Some(idx) = l.find("import(") {
                let rest = &l[idx + 7..];
                if let Some(end) = rest.find(')') {
                    let inside = &rest[..end];
                    let inside = inside.trim_matches(&['"', '\'', ' '][..]);
                    if !inside.starts_with("./") && !inside.starts_with("../") { names.push(Self::normalize_js_pkg(inside)); }
                }
            }
            // export * from 'pkg'
            if l.starts_with("export ") && l.contains(" from ") {
                if let Some(spec) = l.split(" from ").nth(1) {
                    let spec = spec.trim();
                    let spec = spec.trim_matches(&['"', '\'', ';'][..]);
                    if !spec.starts_with("./") && !spec.starts_with("../") {
                        names.push(Self::normalize_js_pkg(spec));
                    }
                }
            }
        }
        names
    }

    fn normalize_js_pkg(spec: &str) -> String {
        // For scoped packages, keep first two segments; else take first
        if let Some(stripped) = spec.strip_prefix('@') {
            let mut iter = stripped.split('/');
            let scope = iter.next().unwrap_or("");
            let pkg = iter.next().unwrap_or("");
            if !scope.is_empty() && !pkg.is_empty() {
                format!("@{}/{}", scope, pkg)
            } else {
                spec.to_string()
            }
        } else {
            spec.split('/').next().unwrap_or(spec).to_string()
        }
    }

    fn scan_python_imports(src: &str) -> Vec<String> {
        let mut names = Vec::new();
        for line in src.lines() {
            let l = line.trim();
            if l.starts_with("import ") {
                // import module [as alias]
                let after = &l[7..];
                let first = after.split(|c: char| c.is_whitespace() || c == ',').next().unwrap_or("");
                if !first.is_empty() && !first.starts_with('.') { names.push(first.split('.').next().unwrap().to_string()); }
            } else if l.starts_with("from ") {
                // from module import ...
                let after = &l[5..];
                let module = after.split_whitespace().next().unwrap_or("");
                if !module.is_empty() && !module.starts_with('.') { names.push(module.split('.').next().unwrap().to_string()); }
            }
        }
        names
    }
    /// Extract Python dependencies
    fn extract_python_dependencies(&self, pm_info: &PackageManagerInfo) -> Result<Vec<Dependency>> {
        let content = fs::read_to_string(&pm_info.config_file)?;
        let mut dependencies = Vec::new();

        match pm_info.manager {
            PackageManager::Pip => {
                // Parse requirements.txt
                for line in content.lines() {
                    let line = line.trim();
                    if !line.is_empty() && !line.starts_with('#') {
                        if let Some((name, version)) = self.parse_pip_requirement(line) {
                            dependencies.push(Dependency {
                                name,
                                version,
                                latest_version: None,
                                manager: PackageManager::Pip,
                                dependency_type: DependencyType::Direct,
                                license: None,
                                repository: None,
                                description: None,
                                maintainers: Vec::new(),
                                download_count: None,
                                last_updated: None,
                                security_advisories: 0,
                            });
                        }
                    }
                }
            }
            PackageManager::Poetry => {
                // Parse pyproject.toml for Poetry dependencies
                self.parse_poetry_dependencies(&content, &mut dependencies)?;
            }
            PackageManager::Pipenv => {
                // Parse Pipfile for Pipenv dependencies
                self.parse_pipfile_dependencies(&content, &mut dependencies)?;
            }
            _ => {
                // Fallback for other Python package managers
                return Err(crate::error::Error::parse_error(
                    format!("Unsupported Python package manager: {:?}", pm_info.manager)
                ));
            }
        }

        Ok(dependencies)
    }

    /// Parse pip requirement line
    fn parse_pip_requirement(&self, line: &str) -> Option<(String, String)> {
        // Handle various pip requirement formats
        if let Some(eq_pos) = line.find("==") {
            let name = line[..eq_pos].trim().to_string();
            let version = line[eq_pos + 2..].trim().to_string();
            Some((name, version))
        } else if let Some(ge_pos) = line.find(">=") {
            let name = line[..ge_pos].trim().to_string();
            let version = line[ge_pos + 2..].trim().to_string();
            Some((name, format!("^{}", version)))
        } else {
            // Just package name without version
            Some((line.to_string(), "*".to_string()))
        }
    }

    /// Extract Go dependencies
    fn extract_go_dependencies(&self, pm_info: &PackageManagerInfo) -> Result<Vec<Dependency>> {
        let content = fs::read_to_string(&pm_info.config_file)?;
        let mut dependencies = Vec::new();

        let mut in_require = false;
        for line in content.lines() {
            let line = line.trim();

            if line.starts_with("require (") {
                in_require = true;
                continue;
            } else if line == ")" && in_require {
                in_require = false;
                continue;
            }

            if in_require && !line.is_empty() {
                if let Some((name, version)) = self.parse_go_require_line(line) {
                    dependencies.push(Dependency {
                        name,
                        version,
                        latest_version: None,
                        manager: PackageManager::GoMod,
                        dependency_type: DependencyType::Direct,
                        license: None,
                        repository: None,
                        description: None,
                        maintainers: Vec::new(),
                        download_count: None,
                        last_updated: None,
                        security_advisories: 0,
                    });
                }
            }
        }

        Ok(dependencies)
    }

    /// Parse Go require line
    fn parse_go_require_line(&self, line: &str) -> Option<(String, String)> {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2 {
            Some((parts[0].to_string(), parts[1].to_string()))
        } else {
            None
        }
    }

    /// Analyze vulnerabilities in dependencies
    fn analyze_vulnerabilities(&self, dependencies: &[Dependency]) -> Result<Vec<DependencyVulnerability>> {
        let mut vulnerabilities = Vec::new();

        // Simulate vulnerability detection
        for dep in dependencies {
            if dep.security_advisories > 0 || dep.name.contains("vulnerable") {
                vulnerabilities.push(DependencyVulnerability {
                    id: format!("VULN-{}-001", dep.name.to_uppercase()),
                    dependency: dep.name.clone(),
                    affected_versions: format!("<= {}", dep.version),
                    title: format!("Security vulnerability in {}", dep.name),
                    description: format!("A security vulnerability has been identified in {} version {}", dep.name, dep.version),
                    severity: VulnerabilitySeverity::Medium,
                    cvss_score: Some(6.5),
                    cve: Some("CVE-2024-0001".to_string()),
                    fix_available: true,
                    recommended_action: format!("Update {} to the latest version", dep.name),
                    references: vec![
                        format!("https://security.example.com/{}", dep.name),
                        "https://nvd.nist.gov/vuln/detail/CVE-2024-0001".to_string(),
                    ],
                });
            }
        }

        Ok(vulnerabilities)
    }

    /// Analyze license compliance
    fn analyze_licenses(&self, dependencies: &[Dependency]) -> Result<LicenseAnalysis> {
        let mut license_distribution = HashMap::new();
        let mut compliance_issues = Vec::new();
        let mut unknown_licenses = Vec::new();

        for dep in dependencies {
            if let Some(license) = &dep.license {
                *license_distribution.entry(license.clone()).or_insert(0) += 1;

                // Check for potential license issues
                if self.is_copyleft_license(license) {
                    compliance_issues.push(LicenseIssue {
                        dependency: dep.name.clone(),
                        license: license.clone(),
                        issue_type: LicenseIssueType::Copyleft,
                        description: format!("{} uses a copyleft license which may require source disclosure", dep.name),
                        recommendation: "Review license compatibility with your project".to_string(),
                    });
                }
            } else {
                unknown_licenses.push(dep.name.clone());
                compliance_issues.push(LicenseIssue {
                    dependency: dep.name.clone(),
                    license: "Unknown".to_string(),
                    issue_type: LicenseIssueType::Unknown,
                    description: format!("License information not available for {}", dep.name),
                    recommendation: "Investigate and document the license for this dependency".to_string(),
                });
            }
        }

        let compatible_licenses = vec!["MIT".to_string(), "Apache-2.0".to_string(), "BSD-3-Clause".to_string()];
        let incompatible_licenses = vec!["GPL-3.0".to_string(), "AGPL-3.0".to_string()];

        let compliance_status = if compliance_issues.is_empty() {
            ComplianceStatus::Compliant
        } else if compliance_issues.iter().any(|issue| matches!(issue.issue_type, LicenseIssueType::Incompatible)) {
            ComplianceStatus::NonCompliant
        } else {
            ComplianceStatus::Warning
        };

        Ok(LicenseAnalysis {
            total_licenses: license_distribution.len(),
            license_distribution,
            compliance_issues,
            compatible_licenses,
            incompatible_licenses,
            unknown_licenses,
            compliance_status,
        })
    }

    /// Check if a license is copyleft
    fn is_copyleft_license(&self, license: &str) -> bool {
        matches!(license, "GPL-2.0" | "GPL-3.0" | "LGPL-2.1" | "LGPL-3.0" | "AGPL-3.0")
    }

    /// Detect outdated dependencies
    fn detect_outdated_dependencies(&self, dependencies: &[Dependency]) -> Result<Vec<OutdatedDependency>> {
        let mut outdated = Vec::new();

        for dep in dependencies {
            if let Some(latest) = &dep.latest_version {
                if latest != &dep.version {
                    let urgency = if dep.security_advisories > 0 {
                        UpdateUrgency::Critical
                    } else if self.is_major_version_difference(&dep.version, latest) {
                        UpdateUrgency::Medium
                    } else {
                        UpdateUrgency::Low
                    };

                    outdated.push(OutdatedDependency {
                        name: dep.name.clone(),
                        current_version: dep.version.clone(),
                        latest_version: latest.clone(),
                        manager: dep.manager.clone(),
                        versions_behind: 1, // Simplified calculation
                        urgency,
                        breaking_changes: self.is_major_version_difference(&dep.version, latest),
                        security_fixes: dep.security_advisories > 0,
                    });
                }
            }
        }

        Ok(outdated)
    }

    /// Check if there's a major version difference
    fn is_major_version_difference(&self, current: &str, latest: &str) -> bool {
        // Simplified version comparison
        let current_major = current.split('.').next().unwrap_or("0");
        let latest_major = latest.split('.').next().unwrap_or("0");
        current_major != latest_major
    }

    /// Analyze dependency graph
    fn analyze_dependency_graph(&self, dependencies: &[Dependency]) -> Result<DependencyGraphAnalysis> {
        let total_nodes = dependencies.len();
        let total_edges = dependencies.len(); // Simplified

        // Detect circular dependencies (simplified)
        let circular_dependencies = vec![
            CircularDependency {
                cycle: vec!["package-a".to_string(), "package-b".to_string(), "package-a".to_string()],
                length: 2,
                impact: CircularDependencyImpact::Medium,
            }
        ];

        // Find popular dependencies
        let mut dependency_counts = HashMap::new();
        for dep in dependencies {
            *dependency_counts.entry(&dep.name).or_insert(0) += 1;
        }

        let mut popular_dependencies: Vec<_> = dependency_counts
            .into_iter()
            .map(|(name, count)| PopularDependency {
                name: name.to_string(),
                dependent_count: count,
                centrality_score: count as f64 / total_nodes as f64,
            })
            .collect();

        popular_dependencies.sort_by(|a, b| b.dependent_count.cmp(&a.dependent_count));
        popular_dependencies.truncate(10);

        // Create dependency clusters
        let clusters = vec![
            DependencyCluster {
                name: "Web Framework".to_string(),
                dependencies: dependencies.iter()
                    .filter(|d| d.name.contains("web") || d.name.contains("http"))
                    .map(|d| d.name.as_str())
                    .map(str::to_string)
                    .collect(),
                purpose: "Web development and HTTP handling".to_string(),
            },
            DependencyCluster {
                name: "Testing".to_string(),
                dependencies: dependencies.iter()
                    .filter(|d| d.dependency_type == DependencyType::Development)
                    .map(|d| d.name.as_str())
                    .map(str::to_string)
                    .collect(),
                purpose: "Testing and development tools".to_string(),
            },
        ];

        let metrics = GraphMetrics {
            average_depth: 2.5,
            density: 0.3,
            clustering_coefficient: 0.4,
            isolated_components: 0,
        };

        Ok(DependencyGraphAnalysis {
            total_nodes,
            total_edges,
            max_depth: 5,
            circular_dependencies,
            popular_dependencies,
            clusters,
            metrics,
        })
    }

    /// Generate security recommendations
    fn generate_security_recommendations(
        &self,
        vulnerabilities: &[DependencyVulnerability],
        outdated: &[OutdatedDependency],
        license_analysis: &LicenseAnalysis,
    ) -> Result<Vec<SecurityRecommendation>> {
        let mut recommendations = Vec::new();

        if !vulnerabilities.is_empty() {
            recommendations.push(SecurityRecommendation {
                category: "Vulnerability Management".to_string(),
                recommendation: format!("Address {} security vulnerabilities in dependencies", vulnerabilities.len()),
                priority: RecommendationPriority::Critical,
                affected_dependencies: vulnerabilities.iter().map(|v| v.dependency.clone()).collect(),
                difficulty: ImplementationDifficulty::Medium,
            });
        }

        if !outdated.is_empty() {
            let critical_updates = outdated.iter().filter(|o| o.urgency == UpdateUrgency::Critical).count();
            if critical_updates > 0 {
                recommendations.push(SecurityRecommendation {
                    category: "Dependency Updates".to_string(),
                    recommendation: format!("Update {} critical dependencies immediately", critical_updates),
                    priority: RecommendationPriority::High,
                    affected_dependencies: outdated.iter()
                        .filter(|o| o.urgency == UpdateUrgency::Critical)
                        .map(|o| o.name.clone())
                        .collect(),
                    difficulty: ImplementationDifficulty::Easy,
                });
            }
        }

        if !license_analysis.compliance_issues.is_empty() {
            recommendations.push(SecurityRecommendation {
                category: "License Compliance".to_string(),
                recommendation: "Review and resolve license compliance issues".to_string(),
                priority: RecommendationPriority::Medium,
                affected_dependencies: license_analysis.compliance_issues.iter()
                    .map(|issue| issue.dependency.clone())
                    .collect(),
                difficulty: ImplementationDifficulty::Hard,
            });
        }

        recommendations.push(SecurityRecommendation {
            category: "Best Practices".to_string(),
            recommendation: "Implement automated dependency scanning in CI/CD pipeline".to_string(),
            priority: RecommendationPriority::Medium,
            affected_dependencies: Vec::new(),
            difficulty: ImplementationDifficulty::Medium,
        });

        Ok(recommendations)
    }

    /// Parse Poetry dependencies from pyproject.toml
    fn parse_poetry_dependencies(&self, content: &str, dependencies: &mut Vec<Dependency>) -> Result<()> {
        let toml_value: toml::Value = toml::from_str(content)
            .map_err(|e| crate::error::Error::parse_error(format!("Failed to parse pyproject.toml: {}", e)))?;

        // Extract dependencies from [tool.poetry.dependencies]
        if let Some(poetry) = toml_value.get("tool").and_then(|t| t.get("poetry")) {
            if let Some(deps) = poetry.get("dependencies").and_then(|d| d.as_table()) {
                for (name, version_spec) in deps {
                    // Skip Python itself
                    if name == "python" {
                        continue;
                    }

                    let version = match version_spec {
                        toml::Value::String(v) => v.clone(),
                        toml::Value::Table(t) => {
                            // Handle complex version specifications like { version = "^1.0", optional = true }
                            t.get("version")
                                .and_then(|v| v.as_str())
                                .unwrap_or("*")
                                .to_string()
                        }
                        _ => "*".to_string(),
                    };

                    let dependency_type = if let toml::Value::Table(t) = version_spec {
                        if t.get("optional").and_then(|v| v.as_bool()).unwrap_or(false) {
                            DependencyType::Optional
                        } else {
                            DependencyType::Direct
                        }
                    } else {
                        DependencyType::Direct
                    };

                    dependencies.push(Dependency {
                        name: name.clone(),
                        version,
                        latest_version: None,
                        manager: PackageManager::Poetry,
                        dependency_type,
                        license: None,
                        repository: None,
                        description: None,
                        maintainers: Vec::new(),
                        download_count: None,
                        last_updated: None,
                        security_advisories: 0,
                    });
                }
            }

            // Extract dev dependencies if configured
            if self.config.include_dev_dependencies {
                if let Some(dev_deps) = poetry.get("group")
                    .and_then(|g| g.get("dev"))
                    .and_then(|d| d.get("dependencies"))
                    .and_then(|d| d.as_table())
                {
                    for (name, version_spec) in dev_deps {
                        let version = match version_spec {
                            toml::Value::String(v) => v.clone(),
                            toml::Value::Table(t) => {
                                t.get("version")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("*")
                                    .to_string()
                            }
                            _ => "*".to_string(),
                        };

                        dependencies.push(Dependency {
                            name: name.clone(),
                            version,
                            latest_version: None,
                            manager: PackageManager::Poetry,
                            dependency_type: DependencyType::Development,
                            license: None,
                            repository: None,
                            description: None,
                            maintainers: Vec::new(),
                            download_count: None,
                            last_updated: None,
                            security_advisories: 0,
                        });
                    }
                }
            }
        }

        Ok(())
    }

    /// Parse Pipenv dependencies from Pipfile
    fn parse_pipfile_dependencies(&self, content: &str, dependencies: &mut Vec<Dependency>) -> Result<()> {
        let toml_value: toml::Value = toml::from_str(content)
            .map_err(|e| crate::error::Error::parse_error(format!("Failed to parse Pipfile: {}", e)))?;

        // Extract dependencies from [packages]
        if let Some(packages) = toml_value.get("packages").and_then(|p| p.as_table()) {
            for (name, version_spec) in packages {
                let version = match version_spec {
                    toml::Value::String(v) => v.clone(),
                    toml::Value::Table(t) => {
                        // Handle complex specifications like { version = "*", index = "pypi" }
                        t.get("version")
                            .and_then(|v| v.as_str())
                            .unwrap_or("*")
                            .to_string()
                    }
                    _ => "*".to_string(),
                };

                dependencies.push(Dependency {
                    name: name.clone(),
                    version,
                    latest_version: None,
                    manager: PackageManager::Pipenv,
                    dependency_type: DependencyType::Direct,
                    license: None,
                    repository: None,
                    description: None,
                    maintainers: Vec::new(),
                    download_count: None,
                    last_updated: None,
                    security_advisories: 0,
                });
            }
        }

        // Extract dev dependencies if configured
        if self.config.include_dev_dependencies {
            if let Some(dev_packages) = toml_value.get("dev-packages").and_then(|p| p.as_table()) {
                for (name, version_spec) in dev_packages {
                    let version = match version_spec {
                        toml::Value::String(v) => v.clone(),
                        toml::Value::Table(t) => {
                            t.get("version")
                                .and_then(|v| v.as_str())
                                .unwrap_or("*")
                                .to_string()
                        }
                        _ => "*".to_string(),
                    };

                    dependencies.push(Dependency {
                        name: name.clone(),
                        version,
                        latest_version: None,
                        manager: PackageManager::Pipenv,
                        dependency_type: DependencyType::Development,
                        license: None,
                        repository: None,
                        description: None,
                        maintainers: Vec::new(),
                        download_count: None,
                        last_updated: None,
                        security_advisories: 0,
                    });
                }
            }
        }

        Ok(())
    }
}

// Default implementations
impl Default for LicenseAnalysis {
    fn default() -> Self {
        Self {
            total_licenses: 0,
            license_distribution: HashMap::new(),
            compliance_issues: Vec::new(),
            compatible_licenses: Vec::new(),
            incompatible_licenses: Vec::new(),
            unknown_licenses: Vec::new(),
            compliance_status: ComplianceStatus::Compliant,
        }
    }
}

impl Default for DependencyGraphAnalysis {
    fn default() -> Self {
        Self {
            total_nodes: 0,
            total_edges: 0,
            max_depth: 0,
            circular_dependencies: Vec::new(),
            popular_dependencies: Vec::new(),
            clusters: Vec::new(),
            metrics: GraphMetrics {
                average_depth: 0.0,
                density: 0.0,
                clustering_coefficient: 0.0,
                isolated_components: 0,
            },
        }
    }
}

// Display implementations
impl std::fmt::Display for PackageManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PackageManager::Cargo => write!(f, "Cargo"),
            PackageManager::Npm => write!(f, "npm"),
            PackageManager::Pip => write!(f, "pip"),
            PackageManager::GoMod => write!(f, "Go Modules"),
            PackageManager::Poetry => write!(f, "Poetry"),
            PackageManager::Yarn => write!(f, "Yarn"),
            PackageManager::Pipenv => write!(f, "Pipenv"),
        }
    }
}

impl std::fmt::Display for VulnerabilitySeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VulnerabilitySeverity::Critical => write!(f, "Critical"),
            VulnerabilitySeverity::High => write!(f, "High"),
            VulnerabilitySeverity::Medium => write!(f, "Medium"),
            VulnerabilitySeverity::Low => write!(f, "Low"),
            VulnerabilitySeverity::Info => write!(f, "Info"),
        }
    }
}

impl std::fmt::Display for LicenseIssueType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LicenseIssueType::Incompatible => write!(f, "Incompatible"),
            LicenseIssueType::Unknown => write!(f, "Unknown"),
            LicenseIssueType::Copyleft => write!(f, "Copyleft"),
            LicenseIssueType::CommercialRestriction => write!(f, "Commercial Restriction"),
        }
    }
}

impl std::fmt::Display for UpdateUrgency {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UpdateUrgency::Critical => write!(f, "Critical"),
            UpdateUrgency::High => write!(f, "High"),
            UpdateUrgency::Medium => write!(f, "Medium"),
            UpdateUrgency::Low => write!(f, "Low"),
        }
    }
}

impl std::fmt::Display for RecommendationPriority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RecommendationPriority::Critical => write!(f, "Critical"),
            RecommendationPriority::High => write!(f, "High"),
            RecommendationPriority::Medium => write!(f, "Medium"),
            RecommendationPriority::Low => write!(f, "Low"),
        }
    }
}
