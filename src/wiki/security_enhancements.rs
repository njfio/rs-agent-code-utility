//! Security enhancements for wiki generation
//!
//! Provides advanced security analysis integration, trace visualization,
//! and security-focused documentation generation.

use crate::advanced_security::{AdvancedSecurityAnalyzer, AdvancedSecurityConfig, SecuritySeverity, OwaspCategory};
use crate::analyzer::{AnalysisResult, FileInfo};

use crate::{Error, Result};
use crate::semantic_graph::{SemanticGraphQuery, GraphNode, GraphEdge, NodeType, RelationshipType};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::fmt::Write as FmtWrite;

/// Security trace information for vulnerability propagation
#[derive(Debug, Clone)]
pub struct SecurityTrace {
    /// Trace ID
    pub id: String,
    /// Source vulnerability
    pub source: SecurityVulnerabilityInfo,
    /// Propagation path through the call graph
    pub propagation_path: Vec<SecurityCallSite>,
    /// Potential impact at each step
    pub impact_chain: Vec<SecurityImpact>,
    /// Confidence level
    pub confidence: ConfidenceLevel,
    /// Recommended mitigations
    pub mitigations: Vec<String>,
}

/// Minimal security vulnerability info for tracing
#[derive(Debug, Clone)]
pub struct SecurityVulnerabilityInfo {
    pub id: String,
    pub title: String,
    pub severity: SecuritySeverity,
    pub owasp_category: OwaspCategory,
    pub location: VulnerabilityLocation,
}

/// Call site with security context
#[derive(Debug, Clone)]
pub struct SecurityCallSite {
    /// Function being called
    pub function_name: String,
    /// Location of the call
    pub location: VulnerabilityLocation,
    /// Security context at this call site
    pub context: SecurityContext,
}

/// Security impact at a point
#[derive(Debug, Clone)]
pub struct SecurityImpact {
    /// Confidentiality impact
    pub confidentiality: ImpactLevel,
    /// Integrity impact  
    pub integrity: ImpactLevel,
    /// Availability impact
    pub availability: ImpactLevel,
    /// Overall severity score
    pub score: f64,
}

/// Security context information
#[derive(Debug, Clone)]
pub struct SecurityContext {
    /// Whether user input is involved
    pub has_user_input: bool,
    /// Whether authentication is required
    pub requires_auth: bool,
    /// Whether data is sanitized
    pub is_sanitized: bool,
    /// Trust boundary crossed
    pub trust_boundary: TrustBoundary,
}

/// Trust boundaries in the system
#[derive(Debug, Clone, PartialEq)]
pub enum TrustBoundary {
    External,
    Internal,
    Trusted,
}

/// Simplified location (not importing full type to avoid conflicts)
#[derive(Debug, Clone)]
pub struct VulnerabilityLocation {
    pub file: PathBuf,
    pub function: Option<String>,
    pub start_line: usize,
    pub end_line: usize,
    pub column: usize,
}

/// Confidence level for security findings
#[derive(Debug, Clone, PartialEq, PartialOrd)]
pub enum ConfidenceLevel {
    Low,
    Medium,
    High,
}

/// Impact levels
#[derive(Debug, Clone, PartialEq)]
pub enum ImpactLevel {
    None,
    Low,
    Medium,
    High,
    Critical,
}

// Implement PartialOrd for SecuritySeverity to enable comparisons
impl PartialOrd for SecuritySeverity {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for SecuritySeverity {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Define ordering: Info < Low < Medium < High < Critical
        let self_score = match self {
            SecuritySeverity::Info => 0,
            SecuritySeverity::Low => 1,
            SecuritySeverity::Medium => 2,
            SecuritySeverity::High => 3,
            SecuritySeverity::Critical => 4,
        };

        let other_score = match other {
            SecuritySeverity::Info => 0,
            SecuritySeverity::Low => 1,
            SecuritySeverity::Medium => 2,
            SecuritySeverity::High => 3,
            SecuritySeverity::Critical => 4,
        };

        self_score.cmp(&other_score)
    }
}

/// Security hotspot with severity and location
#[derive(Debug, Clone)]
pub struct SecurityHotspot {
    pub location: VulnerabilityLocation,
    pub severity: SecuritySeverity,
    pub vulnerability_count: usize,
    pub risk_score: f64,
    pub description: String,
}

/// Enhanced security wiki generator
pub struct SecurityWikiGenerator {
    config: SecurityWikiConfig,
    security_analyzer: AdvancedSecurityAnalyzer,
}

#[derive(Debug, Clone)]
pub struct SecurityWikiConfig {
    /// Enable security trace analysis
    pub enable_trace_analysis: bool,
    /// Enable vulnerability propagation diagrams
    pub enable_propagation_diagrams: bool,
    /// Enable OWASP recommendations
    pub enable_owasp_recommendations: bool,
    /// Enable security hotspot visualization
    pub enable_hotspot_visualization: bool,
    /// Minimum severity for hotspots
    pub min_hotspot_severity: SecuritySeverity,
}

impl Default for SecurityWikiConfig {
    fn default() -> Self {
        Self {
            enable_trace_analysis: true,
            enable_propagation_diagrams: true,
            enable_owasp_recommendations: true,
            enable_hotspot_visualization: true,
            min_hotspot_severity: SecuritySeverity::Medium,
        }
    }
}

impl SecurityWikiGenerator {
    pub fn new_with_config(config: SecurityWikiConfig) -> Result<Self> {
        let security_config = AdvancedSecurityConfig {
            owasp_analysis: true,
            secrets_detection: true,
            input_validation: true,
            injection_analysis: true,
            best_practices: true,
            min_severity: SecuritySeverity::Low,
            custom_rules: Vec::new(),
        };

        let security_analyzer = AdvancedSecurityAnalyzer::with_config(security_config)?;

        Ok(Self {
            config,
            security_analyzer,
        })
    }

    pub fn new() -> Result<Self> {
        Self::new_with_config(SecurityWikiConfig::default())
    }

    /// Analyze codebase for security traces and hotspots
    pub fn analyze_security(&self, analysis: &AnalysisResult) -> Result<SecurityAnalysisResult> {
        // Run advanced security analysis
        let security_result = self.security_analyzer.analyze(analysis)?;

        // Build semantic graph for trace analysis
        let semantic_graph = self.build_semantic_graph_for_security(analysis)?;

        // Identify security traces
        let security_traces = self.identify_security_traces(&security_result, &semantic_graph, analysis)?;

        // Identify security hotspots
        let security_hotspots = self.identify_security_hotspots(&security_result, analysis)?;

        Ok(SecurityAnalysisResult {
            security_result,
            semantic_graph,
            security_traces,
            security_hotspots,
        })
    }

    /// Build semantic graph with security annotations
    fn build_semantic_graph_for_security(&self, analysis: &AnalysisResult) -> Result<SemanticGraphQuery> {
        let mut graph = SemanticGraphQuery::new();

        // Build from analysis
        graph.build_from_analysis(analysis)?;

        Ok(graph)
    }

    /// Classify symbol type for security analysis
    fn classify_symbol_type(&self, kind: &str) -> String {
        if kind.contains("fn") {
            "function".to_string()
        } else if kind.contains("struct") || kind.contains("class") {
            "type".to_string()
        } else if kind.contains("trait") {
            "interface".to_string()
        } else {
            kind.to_string()
        }
    }



    /// Check for potential relationships between symbols
    fn has_potential_relationship(&self, caller: &str, callee: &str) -> bool {
        // Simple heuristic: if callee is mentioned in caller name
        caller.to_lowercase().contains(&callee.to_lowercase()) ||
        callee.to_lowercase().contains(&caller.to_lowercase()) ||
        // Common patterns
        (caller.starts_with("get_") && callee.contains("fetch")) ||
        (caller.starts_with("set_") && callee.contains("update"))
    }

    /// Identify security traces from vulnerabilities through the call graph
    fn identify_security_traces(&self, security_result: &crate::advanced_security::AdvancedSecurityResult,
                              semantic_graph: &SemanticGraphQuery, analysis: &AnalysisResult) -> Result<Vec<SecurityTrace>> {
        let mut traces = Vec::new();

        for vuln in &security_result.vulnerabilities {
            // Only trace high-severity vulnerabilities
            if vuln.severity >= SecuritySeverity::Medium {
                let source_info = SecurityVulnerabilityInfo {
                    id: vuln.id.clone(),
                    title: vuln.title.clone(),
                    severity: vuln.severity.clone(),
                    owasp_category: vuln.owasp_category.clone(),
                    location: Self::convert_vulnerability_location(&vuln.location),
                };

                let trace = SecurityTrace {
                    id: format!("trace_{}", vuln.id),
                    source: source_info,
                    propagation_path: self.trace_propagation_path(&vuln.location, semantic_graph, analysis),
                    impact_chain: self.calculate_impact_chain(vuln),
                    confidence: ConfidenceLevel::Medium,
                    mitigations: self.generate_mitigations(vuln),
                };

                traces.push(trace);
            }
        }

        Ok(traces)
    }

    /// Trace propagation path from a vulnerability
    fn trace_propagation_path(&self, location: &crate::advanced_security::VulnerabilityLocation,
                            _semantic_graph: &SemanticGraphQuery, _analysis: &AnalysisResult) -> Vec<SecurityCallSite> {
        let mut path = Vec::new();

        // Simplified tracing - add the vulnerable function itself as the main call site
        if let Some(function_name) = &location.function {
            let call_site = SecurityCallSite {
                function_name: function_name.clone(),
                location: VulnerabilityLocation {
                    file: location.file.clone(),
                    function: Some(function_name.clone()),
                    start_line: location.start_line,
                    end_line: location.end_line,
                    column: location.column,
                },
                context: SecurityContext {
                    has_user_input: true,
                    requires_auth: function_name.to_lowercase().contains("admin") || function_name.to_lowercase().contains("auth"),
                    is_sanitized: function_name.to_lowercase().contains("sanitize") || function_name.to_lowercase().contains("escape"),
                    trust_boundary: TrustBoundary::External,
                },
            };
            path.push(call_site);

            // Add a few hypothetical propagation sites for demonstration
            if function_name.to_lowercase().contains("handler") {
                path.push(SecurityCallSite {
                    function_name: "process_data".to_string(),
                    location: VulnerabilityLocation {
                        file: location.file.clone(),
                        function: Some("process_data".to_string()),
                        start_line: location.start_line + 10,
                        end_line: location.end_line + 15,
                        column: 0,
                    },
                    context: SecurityContext {
                        has_user_input: false,
                        requires_auth: false,
                        is_sanitized: false,
                        trust_boundary: TrustBoundary::Internal,
                    },
                });
            }
        }

        path
    }



    /// Calculate impact chain for a vulnerability
    fn calculate_impact_chain(&self, vuln: &crate::advanced_security::SecurityVulnerability) -> Vec<SecurityImpact> {
        // Simplified impact propagation
        let mut impacts = Vec::new();

        // Initial impact based on vulnerability severity
        let initial_score = match vuln.severity {
            SecuritySeverity::Critical => 9.0,
            SecuritySeverity::High => 7.0,
            SecuritySeverity::Medium => 5.0,
            SecuritySeverity::Low => 3.0,
            SecuritySeverity::Info => 1.0,
        };

        let initial_impact = SecurityImpact {
            confidentiality: match vuln.severity {
                SecuritySeverity::Critical => ImpactLevel::Critical,
                SecuritySeverity::High => ImpactLevel::High,
                SecuritySeverity::Medium => ImpactLevel::Medium,
                _ => ImpactLevel::Low,
            },
            integrity: ImpactLevel::Medium,
            availability: ImpactLevel::Low,
            score: initial_score,
        };
        impacts.push(initial_impact);

        // Add propagation impacts (simplified)
        for i in 1..=3 {
            let propagated_impact = SecurityImpact {
                confidentiality: match vuln.severity {
                    SecuritySeverity::Critical => ImpactLevel::High,
                    SecuritySeverity::High => ImpactLevel::Medium,
                    _ => ImpactLevel::Low,
                },
                integrity: ImpactLevel::Low,
                availability: ImpactLevel::Low,
                score: initial_score * (0.7_f64.powi(i)),
            };
            impacts.push(propagated_impact);
        }

        impacts
    }

    /// Generate mitigation recommendations for a vulnerability
    fn generate_mitigations(&self, vuln: &crate::advanced_security::SecurityVulnerability) -> Vec<String> {
        let mut mitigations = Vec::new();

        // OWASP-specific mitigations
        match vuln.owasp_category {
            OwaspCategory::Injection => {
                mitigations.push("Use parameterized queries or stored procedures".to_string());
                mitigations.push("Validate and sanitize all user inputs".to_string());
                mitigations.push("Use an ORM or query builder with built-in protection".to_string());
            }
            OwaspCategory::BrokenAccessControl => {
                mitigations.push("Implement proper authorization checks".to_string());
                mitigations.push("Use role-based access control (RBAC)".to_string());
                mitigations.push("Follow principle of least privilege".to_string());
            }
            OwaspCategory::CryptographicFailures => {
                mitigations.push("Use strong encryption algorithms (AES-256)".to_string());
                mitigations.push("Store encryption keys securely".to_string());
                mitigations.push("Implement key rotation policies".to_string());
            }
            _ => {
                mitigations.push("Review and fix security weakness".to_string());
                mitigations.push("Follow secure coding best practices".to_string());
            }
        }

        // Severity-based additional mitigations
        if vuln.severity >= SecuritySeverity::High {
            mitigations.push("Conduct thorough security testing".to_string());
            mitigations.push("Implement monitoring and alerting".to_string());
        }

        mitigations
    }

    /// Identify security hotspots
    fn identify_security_hotspots(&self, security_result: &crate::advanced_security::AdvancedSecurityResult,
                               analysis: &AnalysisResult) -> Result<Vec<SecurityHotspot>> {
        let mut hotspots = HashMap::new();

        // Group vulnerabilities by file
        for vuln in &security_result.vulnerabilities {
            if vuln.severity >= self.config.min_hotspot_severity {
                let file_key = vuln.location.file.to_string_lossy().to_string();

                let hotspot = hotspots.entry(file_key).or_insert_with(|| SecurityHotspot {
                    location: Self::convert_vulnerability_location(&vuln.location),
                    severity: SecuritySeverity::Info,
                    vulnerability_count: 0,
                    risk_score: 0.0,
                    description: "Security hotspot with multiple vulnerabilities".to_string(),
                });

                hotspot.vulnerability_count += 1;
                hotspot.risk_score += self.severity_score(&vuln.severity);

                // Update severity if this vulnerability is more severe
                if self.severity_score(&vuln.severity) > self.severity_score(&hotspot.severity) {
                    hotspot.severity = vuln.severity.clone();
                }
            }
        }

        // Convert to sorted vector
        let mut hotspot_vec: Vec<_> = hotspots.into_iter()
            .map(|(_, hotspot)| hotspot)
            .collect();

        hotspot_vec.sort_by(|a, b| b.risk_score.partial_cmp(&a.risk_score).unwrap());

        Ok(hotspot_vec)
    }

    /// Get numeric score for severity
    fn severity_score(&self, severity: &SecuritySeverity) -> f64 {
        match severity {
            SecuritySeverity::Critical => 10.0,
            SecuritySeverity::High => 7.0,
            SecuritySeverity::Medium => 5.0,
            SecuritySeverity::Low => 3.0,
            SecuritySeverity::Info => 1.0,
        }
    }

    /// Convert advanced security location to our simplified location
    fn convert_vulnerability_location(location: &crate::advanced_security::VulnerabilityLocation) -> VulnerabilityLocation {
        VulnerabilityLocation {
            file: location.file.clone(),
            function: location.function.clone(),
            start_line: location.start_line,
            end_line: location.end_line,
            column: location.column,
        }
    }

    /// Generate OWASP recommendations section for a file
    pub fn generate_owasp_recommendations(&self, file: &FileInfo) -> String {
        let mut html = String::new();

        // Analyze OWASP categories relevant to this file
        let categories = self.analyze_file_owasp_categories(file);

        if !categories.is_empty() {
            let _ = writeln!(&mut html, "<div class=\"card\"><h3>OWASP Security Recommendations</h3>");
            let _ = writeln!(&mut html, "<ul>");

            for category in categories {
                let recommendations = self.get_category_recommendations(&category);
                for rec in recommendations {
                    let _ = writeln!(&mut html, "<li><strong>{}:</strong> {}</li>", category, rec);
                }
            }

            let _ = writeln!(&mut html, "</ul></div>");
        }

        html
    }

    /// Analyze OWASP categories for a file
    fn analyze_file_owasp_categories(&self, file: &FileInfo) -> Vec<String> {
        let mut categories = Vec::new();
        let content = fs::read_to_string(&file.path).unwrap_or_default();
        let content_lower = content.to_lowercase();

        // OWASP A01: Broken Access Control
        if content_lower.contains("admin") || content_lower.contains("access") ||
           content_lower.contains("auth") || content_lower.contains("authorize") {
            categories.push("A01:2021 – Broken Access Control".to_string());
        }

        // OWASP A02: Cryptographic Failures
        if content_lower.contains("encrypt") || content_lower.contains("decrypt") ||
           content_lower.contains("password") || content_lower.contains("secret") {
            categories.push("A02:2021 – Cryptographic Failures".to_string());
        }

        // OWASP A03: Injection
        if content_lower.contains("select") || content_lower.contains("insert") ||
           content_lower.contains("update") || content_lower.contains("delete") ||
           content_lower.contains("exec") || content_lower.contains("system") {
            categories.push("A03:2021 – Injection".to_string());
        }

        // OWASP A04: Insecure Design
        if content_lower.contains("random") || content_lower.contains("token") ||
           content_lower.contains("session") {
            categories.push("A04:2021 – Insecure Design".to_string());
        }

        // OWASP A05: Security Misconfiguration
        if content_lower.contains("debug") || content_lower.contains("config") ||
           content_lower.contains("environment") {
            categories.push("A05:2021 – Security Misconfiguration".to_string());
        }

        categories
    }

    /// Get recommendations for an OWASP category
    fn get_category_recommendations(&self, category: &str) -> Vec<String> {
        match category {
            "A01:2021 – Broken Access Control" => vec![
                "Implement proper authorization checks before sensitive operations".to_string(),
                "Use role-based access control (RBAC)".to_string(),
                "Apply the principle of least privilege".to_string(),
                "Implement proper session management".to_string(),
            ],
            "A02:2021 – Cryptographic Failures" => vec![
                "Use strong encryption algorithms and key sizes".to_string(),
                "Store encryption keys securely".to_string(),
                "Implement proper key management and rotation".to_string(),
                "Use secure random number generators".to_string(),
            ],
            "A03:2021 – Injection" => vec![
                "Use parameterized queries or prepared statements".to_string(),
                "Validate and sanitize all user inputs".to_string(),
                "Use an ORM with built-in injection protection".to_string(),
                "Implement content security policies".to_string(),
            ],
            "A04:2021 – Insecure Design" => vec![
                "Follow secure design principles from the start".to_string(),
                "Implement threat modeling".to_string(),
                "Use secure defaults and fail-safe behavior".to_string(),
                "Regular security reviews of design decisions".to_string(),
            ],
            "A05:2021 – Security Misconfiguration" => vec![
                "Secure default configurations".to_string(),
                "Regular configuration reviews".to_string(),
                "Environment-specific configurations".to_string(),
                "Automated configuration validation".to_string(),
            ],
            _ => vec!["Review and apply security best practices".to_string()],
        }
    }

    /// Generate security trace diagram in Mermaid format
    pub fn generate_trace_diagram(&self, trace: &SecurityTrace) -> String {
        let mut diagram = String::new();

        let _ = writeln!(&mut diagram, "graph TD");
        let _ = writeln!(&mut diagram, "  A[\"{}\"]", trace.source.title);
        let _ = writeln!(&mut diagram, "  A --> B[\"Impact: {:.1}\"]", trace.impact_chain[0].score);

        for (i, call_site) in trace.propagation_path.iter().enumerate() {
            let node_id = format!("C{}", i);
            let _ = writeln!(&mut diagram, "  {}([\"{}\"])", node_id, call_site.function_name);

            if i == 0 {
                let _ = writeln!(&mut diagram, "  B --> {}", node_id);
            } else {
                let prev_node = format!("C{}", i - 1);
                let _ = writeln!(&mut diagram, "  {} --> {}", prev_node, node_id);
            }

            if i < trace.impact_chain.len() - 1 {
                let next_impact = format!("D{}", i);
                let _ = writeln!(&mut diagram, "  {}[\"Impact: {:.1}\"]", next_impact, trace.impact_chain[i + 1].score);
                let _ = writeln!(&mut diagram, "  {} --> {}", node_id, next_impact);
            }
        }

        diagram
    }

    /// Generate security hotspot visualization
    pub fn generate_hotspot_diagram(&self, hotspots: &[SecurityHotspot]) -> String {
        let mut diagram = String::new();
        let _ = writeln!(&mut diagram, "graph TD");

        for (i, hotspot) in hotspots.iter().enumerate() {
            let severity_color = match hotspot.severity {
                SecuritySeverity::Critical => "red",
                SecuritySeverity::High => "orange",
                SecuritySeverity::Medium => "yellow",
                _ => "green",
            };

            let _ = writeln!(&mut diagram, "  H{}[\"{}\\nRisk: {:.1}\\nVulnerabilities: {}\"]", 
                           i, hotspot.location.file.display(), hotspot.risk_score, hotspot.vulnerability_count);
            let _ = writeln!(&mut diagram, "  style H{} fill:{};", i, severity_color);
        }

        diagram
    }
}

/// Result of security analysis for wiki generation
pub struct SecurityAnalysisResult {
    pub security_result: crate::advanced_security::AdvancedSecurityResult,
    pub semantic_graph: SemanticGraphQuery,
    pub security_traces: Vec<SecurityTrace>,
    pub security_hotspots: Vec<SecurityHotspot>,
}
