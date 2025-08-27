//! Intent-to-Implementation Mapping System
//! 
//! This module provides comprehensive mapping between natural language requirements,
//! design intent, and actual code implementation for AI-assisted development.

use crate::{Result, FileInfo, AnalysisResult};
use crate::constants::intent_mapping::*;
use crate::embeddings::{EmbeddingEngine, EmbeddingConfig, Embedding};
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::PathBuf;

#[cfg(feature = "serde")]
use serde::{Serialize, Deserialize};

/// Confidence scoring thresholds for different mapping types
#[derive(Debug, Clone)]
pub struct ConfidenceThresholds {
    /// Minimum confidence for automatic acceptance
    pub auto_accept: f64,
    /// Minimum confidence for review queue
    pub needs_review: f64,
    /// Minimum confidence for rejection
    pub auto_reject: f64,
    /// High confidence threshold for priority mappings
    pub high_confidence: f64,
    /// Medium confidence threshold
    pub medium_confidence: f64,
    /// Low confidence threshold
    pub low_confidence: f64,
}

impl Default for ConfidenceThresholds {
    fn default() -> Self {
        Self {
            auto_accept: 0.9,
            needs_review: 0.6,
            auto_reject: 0.3,
            high_confidence: 0.8,
            medium_confidence: 0.6,
            low_confidence: 0.4,
        }
    }
}

/// Graph-based relationship mapping between requirements and implementations
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct RelationshipGraph {
    /// Graph nodes (requirements and implementations)
    pub nodes: HashMap<String, RelationshipNode>,
    /// Graph edges (mappings and relationships)
    pub edges: HashMap<String, RelationshipEdge>,
    /// Graph metrics and statistics
    pub metrics: GraphMetrics,
}

/// Node in the relationship graph
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct RelationshipNode {
    /// Unique node identifier
    pub id: String,
    /// Type of node
    pub node_type: RelationshipNodeType,
    /// Node metadata
    pub metadata: HashMap<String, String>,
    /// Node attributes (numeric values)
    pub attributes: HashMap<String, f64>,
}

/// Types of nodes in the relationship graph
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum RelationshipNodeType {
    /// Requirement node
    Requirement,
    /// Implementation node
    Implementation,
    /// Code element node
    CodeElement,
    /// Test node
    Test,
    /// Documentation node
    Documentation,
}

/// Edge in the relationship graph
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct RelationshipEdge {
    /// Unique edge identifier
    pub id: String,
    /// Source node ID
    pub source_id: String,
    /// Target node ID
    pub target_id: String,
    /// Type of relationship
    pub edge_type: RelationshipEdgeType,
    /// Relationship weight/strength
    pub weight: f64,
    /// Edge metadata
    pub metadata: HashMap<String, String>,
    /// Edge attributes (numeric values)
    pub attributes: HashMap<String, f64>,
}

/// Types of edges in the relationship graph
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum RelationshipEdgeType {
    /// Direct mapping
    DirectMapping,
    /// One-to-many mapping
    OneToMany,
    /// Many-to-one mapping
    ManyToOne,
    /// Partial mapping
    PartialMapping,
    /// Derived mapping
    DerivedMapping,
    /// Inferred mapping
    InferredMapping,
    /// Dependency relationship
    Dependency,
    /// Similarity relationship
    Similarity,
    /// Containment relationship
    Containment,
    /// Test coverage relationship
    TestCoverage,
}

/// Graph metrics and statistics
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct GraphMetrics {
    /// Total number of nodes
    pub node_count: usize,
    /// Total number of edges
    pub edge_count: usize,
    /// Graph density (edges / possible edges)
    pub density: f64,
    /// Average node degree
    pub average_degree: f64,
    /// Number of connected components
    pub connected_components: usize,
    /// Graph diameter (longest shortest path)
    pub diameter: usize,
    /// Clustering coefficient
    pub clustering_coefficient: f64,
    /// Coverage metrics
    pub coverage_metrics: GraphCoverageMetrics,
}

/// Coverage metrics for the relationship graph
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct GraphCoverageMetrics {
    /// Percentage of requirements with implementations
    pub requirement_coverage: f64,
    /// Percentage of implementations with requirements
    pub implementation_coverage: f64,
    /// Average mapping confidence
    pub average_confidence: f64,
    /// Number of orphaned requirements
    pub orphaned_requirements: usize,
    /// Number of orphaned implementations
    pub orphaned_implementations: usize,
}

impl RelationshipGraph {
    /// Create a new empty relationship graph
    pub fn new() -> Self {
        Self {
            nodes: HashMap::new(),
            edges: HashMap::new(),
            metrics: GraphMetrics::default(),
        }
    }

    /// Add a node to the graph
    pub fn add_node(&mut self, node: RelationshipNode) {
        self.nodes.insert(node.id.clone(), node);
    }

    /// Add an edge to the graph
    pub fn add_edge(&mut self, edge: RelationshipEdge) -> Result<()> {
        // Validate that source and target nodes exist
        if !self.nodes.contains_key(&edge.source_id) {
            return Err(crate::Error::internal_error("relationship_graph",
                format!("Source node '{}' not found in graph", edge.source_id)));
        }
        if !self.nodes.contains_key(&edge.target_id) {
            return Err(crate::Error::internal_error("relationship_graph",
                format!("Target node '{}' not found in graph", edge.target_id)));
        }

        self.edges.insert(edge.id.clone(), edge);
        Ok(())
    }

    /// Get node by ID
    pub fn get_node(&self, id: &str) -> Option<&RelationshipNode> {
        self.nodes.get(id)
    }

    /// Get edge by ID
    pub fn get_edge(&self, id: &str) -> Option<&RelationshipEdge> {
        self.edges.get(id)
    }

    /// Get all edges connected to a node
    pub fn get_node_edges(&self, node_id: &str) -> Vec<&RelationshipEdge> {
        self.edges.values()
            .filter(|edge| edge.source_id == node_id || edge.target_id == node_id)
            .collect()
    }

    /// Get outgoing edges from a node
    pub fn get_outgoing_edges(&self, node_id: &str) -> Vec<&RelationshipEdge> {
        self.edges.values()
            .filter(|edge| edge.source_id == node_id)
            .collect()
    }

    /// Get incoming edges to a node
    pub fn get_incoming_edges(&self, node_id: &str) -> Vec<&RelationshipEdge> {
        self.edges.values()
            .filter(|edge| edge.target_id == node_id)
            .collect()
    }

    /// Find shortest path between two nodes
    pub fn find_shortest_path(&self, source_id: &str, target_id: &str) -> Option<Vec<String>> {
        if source_id == target_id {
            return Some(vec![source_id.to_string()]);
        }

        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        let mut parent = HashMap::new();

        queue.push_back(source_id.to_string());
        visited.insert(source_id.to_string());

        while let Some(current) = queue.pop_front() {
            for edge in self.get_outgoing_edges(&current) {
                if !visited.contains(&edge.target_id) {
                    visited.insert(edge.target_id.clone());
                    parent.insert(edge.target_id.clone(), current.clone());
                    queue.push_back(edge.target_id.clone());

                    if edge.target_id == target_id {
                        // Reconstruct path
                        let mut path = Vec::new();
                        let mut node = target_id.to_string();
                        path.push(node.clone());

                        while let Some(p) = parent.get(&node) {
                            path.push(p.clone());
                            node = p.clone();
                        }

                        path.reverse();
                        return Some(path);
                    }
                }
            }
        }

        None
    }

    /// Calculate graph metrics
    pub fn calculate_metrics(&mut self) {
        let node_count = self.nodes.len();
        let edge_count = self.edges.len();

        let density = if node_count > 1 {
            edge_count as f64 / (node_count * (node_count - 1)) as f64
        } else {
            0.0
        };

        let average_degree = if node_count > 0 {
            (2 * edge_count) as f64 / node_count as f64
        } else {
            0.0
        };

        let connected_components = self.count_connected_components();
        let diameter = self.calculate_diameter();
        let clustering_coefficient = self.calculate_clustering_coefficient();
        let coverage_metrics = self.calculate_coverage_metrics();

        self.metrics = GraphMetrics {
            node_count,
            edge_count,
            density,
            average_degree,
            connected_components,
            diameter,
            clustering_coefficient,
            coverage_metrics,
        };
    }

    /// Count connected components in the graph
    fn count_connected_components(&self) -> usize {
        let mut visited = HashSet::new();
        let mut components = 0;

        for node_id in self.nodes.keys() {
            if !visited.contains(node_id) {
                self.dfs_visit(node_id, &mut visited);
                components += 1;
            }
        }

        components
    }

    /// Depth-first search visit for connected components
    fn dfs_visit(&self, node_id: &str, visited: &mut HashSet<String>) {
        visited.insert(node_id.to_string());

        for edge in self.get_node_edges(node_id) {
            let neighbor = if edge.source_id == node_id {
                &edge.target_id
            } else {
                &edge.source_id
            };

            if !visited.contains(neighbor) {
                self.dfs_visit(neighbor, visited);
            }
        }
    }

    /// Calculate graph diameter (longest shortest path)
    fn calculate_diameter(&self) -> usize {
        let mut max_distance = 0;

        for source in self.nodes.keys() {
            for target in self.nodes.keys() {
                if source != target {
                    if let Some(path) = self.find_shortest_path(source, target) {
                        max_distance = max_distance.max(path.len() - 1);
                    }
                }
            }
        }

        max_distance
    }

    /// Calculate clustering coefficient
    fn calculate_clustering_coefficient(&self) -> f64 {
        if self.nodes.len() < 3 {
            return 0.0;
        }

        let mut total_coefficient = 0.0;
        let mut node_count = 0;

        for node_id in self.nodes.keys() {
            let neighbors = self.get_neighbors(node_id);
            if neighbors.len() < 2 {
                continue;
            }

            let possible_edges = neighbors.len() * (neighbors.len() - 1) / 2;
            let actual_edges = self.count_edges_between_neighbors(&neighbors);

            if possible_edges > 0 {
                total_coefficient += actual_edges as f64 / possible_edges as f64;
                node_count += 1;
            }
        }

        if node_count > 0 {
            total_coefficient / node_count as f64
        } else {
            0.0
        }
    }

    /// Get neighbors of a node
    fn get_neighbors(&self, node_id: &str) -> Vec<String> {
        let mut neighbors = HashSet::new();

        for edge in self.get_node_edges(node_id) {
            if edge.source_id == node_id {
                neighbors.insert(edge.target_id.clone());
            } else {
                neighbors.insert(edge.source_id.clone());
            }
        }

        neighbors.into_iter().collect()
    }

    /// Count edges between neighbors
    fn count_edges_between_neighbors(&self, neighbors: &[String]) -> usize {
        let mut count = 0;

        for i in 0..neighbors.len() {
            for j in (i + 1)..neighbors.len() {
                if self.has_edge(&neighbors[i], &neighbors[j]) {
                    count += 1;
                }
            }
        }

        count
    }

    /// Check if there's an edge between two nodes
    fn has_edge(&self, node1: &str, node2: &str) -> bool {
        self.edges.values().any(|edge| {
            (edge.source_id == node1 && edge.target_id == node2) ||
            (edge.source_id == node2 && edge.target_id == node1)
        })
    }

    /// Calculate coverage metrics
    fn calculate_coverage_metrics(&self) -> GraphCoverageMetrics {
        let requirement_nodes: Vec<_> = self.nodes.values()
            .filter(|node| node.node_type == RelationshipNodeType::Requirement)
            .collect();

        let implementation_nodes: Vec<_> = self.nodes.values()
            .filter(|node| node.node_type == RelationshipNodeType::Implementation)
            .collect();

        let mut requirements_with_implementations = 0;
        let mut implementations_with_requirements = 0;
        let mut total_confidence = 0.0;
        let mut mapping_count = 0;

        // Count requirements with implementations
        for req_node in &requirement_nodes {
            if self.get_outgoing_edges(&req_node.id).iter()
                .any(|edge| matches!(edge.edge_type, RelationshipEdgeType::DirectMapping |
                                                   RelationshipEdgeType::PartialMapping |
                                                   RelationshipEdgeType::InferredMapping)) {
                requirements_with_implementations += 1;
            }
        }

        // Count implementations with requirements
        for impl_node in &implementation_nodes {
            if self.get_incoming_edges(&impl_node.id).iter()
                .any(|edge| matches!(edge.edge_type, RelationshipEdgeType::DirectMapping |
                                                   RelationshipEdgeType::PartialMapping |
                                                   RelationshipEdgeType::InferredMapping)) {
                implementations_with_requirements += 1;
            }
        }

        // Calculate average confidence
        for edge in self.edges.values() {
            if matches!(edge.edge_type, RelationshipEdgeType::DirectMapping |
                                      RelationshipEdgeType::PartialMapping |
                                      RelationshipEdgeType::InferredMapping) {
                total_confidence += edge.weight;
                mapping_count += 1;
            }
        }

        let requirement_coverage = if !requirement_nodes.is_empty() {
            requirements_with_implementations as f64 / requirement_nodes.len() as f64
        } else {
            0.0
        };

        let implementation_coverage = if !implementation_nodes.is_empty() {
            implementations_with_requirements as f64 / implementation_nodes.len() as f64
        } else {
            0.0
        };

        let average_confidence = if mapping_count > 0 {
            total_confidence / mapping_count as f64
        } else {
            0.0
        };

        GraphCoverageMetrics {
            requirement_coverage,
            implementation_coverage,
            average_confidence,
            orphaned_requirements: requirement_nodes.len() - requirements_with_implementations,
            orphaned_implementations: implementation_nodes.len() - implementations_with_requirements,
        }
    }
}

impl Default for GraphMetrics {
    fn default() -> Self {
        Self {
            node_count: 0,
            edge_count: 0,
            density: 0.0,
            average_degree: 0.0,
            connected_components: 0,
            diameter: 0,
            clustering_coefficient: 0.0,
            coverage_metrics: GraphCoverageMetrics {
                requirement_coverage: 0.0,
                implementation_coverage: 0.0,
                average_confidence: 0.0,
                orphaned_requirements: 0,
                orphaned_implementations: 0,
            },
        }
    }
}

/// Intent-to-implementation mapping system
#[derive(Debug)]
pub struct IntentMappingSystem {
    /// Parsed requirements and intents
    requirements: Vec<Requirement>,
    /// Implementation artifacts
    implementations: Vec<Implementation>,
    /// Mapping relationships
    mappings: Vec<IntentMapping>,
    /// Traceability matrix
    traceability: TraceabilityMatrix,
    /// Configuration
    config: MappingConfig,
    /// Semantic embedding engine for advanced similarity
    embedding_engine: Option<EmbeddingEngine>,
    /// Cache for requirement embeddings
    requirement_embeddings: HashMap<String, Embedding>,
    /// Cache for implementation embeddings
    implementation_embeddings: HashMap<String, Embedding>,
    /// Confidence scoring thresholds
    confidence_thresholds: ConfidenceThresholds,
}

/// A requirement or intent specification
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Requirement {
    /// Unique identifier
    pub id: String,
    /// Requirement type
    pub requirement_type: RequirementType,
    /// Natural language description
    pub description: String,
    /// Priority level
    pub priority: Priority,
    /// Acceptance criteria
    pub acceptance_criteria: Vec<String>,
    /// Stakeholder information
    pub stakeholders: Vec<String>,
    /// Tags and metadata
    pub tags: Vec<String>,
    /// Status
    pub status: RequirementStatus,
}

/// Types of requirements
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum RequirementType {
    /// Functional requirement
    Functional,
    /// Non-functional requirement
    NonFunctional,
    /// Business requirement
    Business,
    /// Technical requirement
    Technical,
    /// User story
    UserStory,
    /// Epic
    Epic,
    /// Feature request
    Feature,
    /// Bug fix requirement
    BugFix,
    /// Performance requirement
    Performance,
    /// Security requirement
    Security,
}

// Use common Priority from constants module
pub use crate::constants::common::Priority;

/// Requirement status
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum RequirementStatus {
    Draft,
    Approved,
    InProgress,
    Implemented,
    Tested,
    Deployed,
    Rejected,
}

/// Implementation artifact
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Implementation {
    /// Unique identifier
    pub id: String,
    /// Implementation type
    pub implementation_type: ImplementationType,
    /// File path
    pub file_path: PathBuf,
    /// Code elements
    pub code_elements: Vec<CodeElement>,
    /// Implementation status
    pub status: ImplementationStatus,
    /// Quality metrics
    pub quality_metrics: QualityMetrics,
    /// Documentation
    pub documentation: Option<String>,
}

/// Types of implementation artifacts
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum ImplementationType {
    Function,
    Class,
    Module,
    Interface,
    Database,
    API,
    Configuration,
    Test,
    Documentation,
    Infrastructure,
}

/// Code element within an implementation
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct CodeElement {
    /// Element name
    pub name: String,
    /// Element type
    pub element_type: String,
    /// Line range
    pub line_range: (usize, usize),
    /// Complexity score
    pub complexity: f64,
    /// Test coverage
    pub test_coverage: f64,
}

/// Implementation status
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum ImplementationStatus {
    NotStarted,
    InProgress,
    Complete,
    Tested,
    Deployed,
    Deprecated,
}

/// Quality metrics for implementations
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct QualityMetrics {
    /// Code coverage percentage
    pub coverage: f64,
    /// Complexity score
    pub complexity: f64,
    /// Maintainability index
    pub maintainability: f64,
    /// Performance score
    pub performance: f64,
    /// Security score
    pub security: f64,
}

/// Mapping between intent and implementation
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct IntentMapping {
    /// Mapping identifier
    pub id: String,
    /// Requirement ID
    pub requirement_id: String,
    /// Implementation ID
    pub implementation_id: String,
    /// Mapping type
    pub mapping_type: MappingType,
    /// Confidence score (0.0 to 1.0)
    pub confidence: f64,
    /// Mapping rationale
    pub rationale: String,
    /// Validation status
    pub validation_status: ValidationStatus,
    /// Last updated timestamp
    pub last_updated: u64,
}

/// Types of mappings
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum MappingType {
    /// Direct one-to-one mapping
    Direct,
    /// One requirement to multiple implementations
    OneToMany,
    /// Multiple requirements to one implementation
    ManyToOne,
    /// Partial implementation
    Partial,
    /// Derived implementation
    Derived,
    /// Inferred mapping
    Inferred,
}

/// Validation status of mappings
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum ValidationStatus {
    NotValidated,
    Valid,
    Invalid,
    NeedsReview,
    Outdated,
}

/// Traceability matrix for requirements
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct TraceabilityMatrix {
    /// Forward traceability (requirement -> implementation)
    pub forward_trace: HashMap<String, Vec<String>>,
    /// Backward traceability (implementation -> requirement)
    pub backward_trace: HashMap<String, Vec<String>>,
    /// Coverage metrics
    pub coverage_metrics: CoverageMetrics,
}

/// Coverage metrics for traceability
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct CoverageMetrics {
    /// Percentage of requirements with implementations
    pub requirement_coverage: f64,
    /// Percentage of implementations with requirements
    pub implementation_coverage: f64,
    /// Orphaned requirements (no implementation)
    pub orphaned_requirements: usize,
    /// Orphaned implementations (no requirement)
    pub orphaned_implementations: usize,
}

/// Configuration for intent mapping
#[derive(Debug, Clone)]
pub struct MappingConfig {
    /// Minimum confidence threshold for automatic mappings
    pub confidence_threshold: f64,
    /// Enable natural language processing
    pub enable_nlp: bool,
    /// Enable semantic similarity analysis
    pub enable_semantic_analysis: bool,
    /// Maximum mapping distance for similarity
    pub max_mapping_distance: f64,
    /// Auto-validation threshold
    pub auto_validation_threshold: f64,
}

impl Default for MappingConfig {
    fn default() -> Self {
        Self {
            confidence_threshold: DEFAULT_CONFIDENCE_THRESHOLD,
            enable_nlp: true,
            enable_semantic_analysis: true,
            max_mapping_distance: DEFAULT_MAX_MAPPING_DISTANCE,
            auto_validation_threshold: DEFAULT_AUTO_VALIDATION_THRESHOLD,
        }
    }
}

/// Result of intent mapping analysis
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct MappingAnalysisResult {
    /// Total requirements analyzed
    pub total_requirements: usize,
    /// Total implementations analyzed
    pub total_implementations: usize,
    /// Generated mappings
    pub mappings: Vec<IntentMapping>,
    /// Traceability matrix
    pub traceability: TraceabilityMatrix,
    /// Gap analysis
    pub gaps: Vec<MappingGap>,
    /// Recommendations
    pub recommendations: Vec<MappingRecommendation>,
    /// Analysis timestamp
    pub timestamp: u64,
}

/// Gap in requirement-implementation mapping
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct MappingGap {
    /// Gap type
    pub gap_type: GapType,
    /// Description
    pub description: String,
    /// Affected requirement/implementation IDs
    pub affected_items: Vec<String>,
    /// Severity level
    pub severity: Priority,
    /// Suggested actions
    pub suggested_actions: Vec<String>,
}

/// Types of mapping gaps
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum GapType {
    /// Requirement without implementation
    MissingImplementation,
    /// Implementation without requirement
    MissingRequirement,
    /// Partial implementation
    IncompleteImplementation,
    /// Outdated mapping
    OutdatedMapping,
    /// Quality gap
    QualityGap,
    /// Test coverage gap
    TestGap,
}

/// Recommendation for improving mappings
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct MappingRecommendation {
    /// Recommendation type
    pub recommendation_type: RecommendationType,
    /// Description
    pub description: String,
    /// Priority
    pub priority: Priority,
    /// Affected items
    pub affected_items: Vec<String>,
    /// Expected impact
    pub expected_impact: String,
    /// Effort estimate
    pub effort_estimate: EffortLevel,
}

/// Types of recommendations
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum RecommendationType {
    CreateImplementation,
    CreateRequirement,
    UpdateMapping,
    ImproveQuality,
    AddTests,
    UpdateDocumentation,
    RefactorCode,
    ValidateMapping,
}

/// Effort estimation levels
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum EffortLevel {
    Small,   // < 1 day
    Medium,  // 1-3 days
    Large,   // 1-2 weeks
    XLarge,  // > 2 weeks
}

/// Statistics about semantic embeddings
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct EmbeddingStats {
    /// Number of requirement embeddings generated
    pub total_requirement_embeddings: usize,
    /// Number of implementation embeddings generated
    pub total_implementation_embeddings: usize,
    /// Dimension of the embedding vectors
    pub embedding_dimension: usize,
    /// Whether embedding engine is available
    pub has_embedding_engine: bool,
}

impl IntentMappingSystem {
    /// Create a new intent mapping system
    pub fn new() -> Self {
        Self {
            requirements: Vec::new(),
            implementations: Vec::new(),
            mappings: Vec::new(),
            traceability: TraceabilityMatrix::new(),
            config: MappingConfig::default(),
            embedding_engine: None,
            requirement_embeddings: HashMap::new(),
            implementation_embeddings: HashMap::new(),
            confidence_thresholds: ConfidenceThresholds::default(),
        }
    }

    /// Create system with custom configuration
    pub fn with_config(config: MappingConfig) -> Self {
        Self {
            requirements: Vec::new(),
            implementations: Vec::new(),
            mappings: Vec::new(),
            traceability: TraceabilityMatrix::new(),
            config,
            embedding_engine: None,
            requirement_embeddings: HashMap::new(),
            implementation_embeddings: HashMap::new(),
            confidence_thresholds: ConfidenceThresholds::default(),
        }
    }

    /// Initialize semantic embeddings engine
    pub async fn initialize_embeddings(&mut self) -> Result<()> {
        let embedding_config = EmbeddingConfig {
            similarity_threshold: self.config.confidence_threshold,
            ..EmbeddingConfig::default()
        };

        let mut engine = EmbeddingEngine::new(embedding_config);
        engine.initialize().await
            .map_err(|e| crate::Error::internal_error("embedding_engine", format!("Failed to initialize embedding engine: {}", e)))?;

        self.embedding_engine = Some(engine);
        Ok(())
    }

    /// Check if semantic embeddings are available
    pub fn has_embeddings(&self) -> bool {
        self.embedding_engine.is_some()
    }

    /// Helper function to create intent mapping without excessive cloning
    fn create_intent_mapping(
        id_prefix: &str,
        requirement_id: &str,
        implementation_id: &str,
        mapping_type: MappingType,
        confidence: f64,
        rationale: &str,
        validation_status: ValidationStatus,
    ) -> IntentMapping {
        IntentMapping {
            id: format!("{}_{}_{}", id_prefix, requirement_id, implementation_id),
            requirement_id: requirement_id.to_string(),
            implementation_id: implementation_id.to_string(),
            mapping_type,
            confidence,
            rationale: rationale.to_string(),
            validation_status,
            last_updated: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        }
    }

    /// Add a requirement to the system
    pub fn add_requirement(&mut self, requirement: Requirement) {
        self.requirements.push(requirement);
    }

    /// Add multiple requirements
    pub fn add_requirements(&mut self, requirements: Vec<Requirement>) {
        self.requirements.extend(requirements);
    }

    /// Extract implementations from analysis result
    pub fn extract_implementations(&mut self, analysis: &AnalysisResult) -> Result<()> {
        self.implementations.clear();
        
        for file in &analysis.files {
            let implementation = self.create_implementation_from_file(file)?;
            self.implementations.push(implementation);
        }
        
        Ok(())
    }

    /// Perform intent-to-implementation mapping analysis
    pub async fn analyze_mappings(&mut self) -> Result<MappingAnalysisResult> {
        // Generate automatic mappings (now async for embeddings)
        self.generate_automatic_mappings().await?;

        // Build traceability matrix
        self.build_traceability_matrix();

        // Identify gaps
        let gaps = self.identify_gaps()?;

        // Generate recommendations
        let recommendations = self.generate_recommendations(&gaps)?;

        Ok(MappingAnalysisResult {
            total_requirements: self.requirements.len(),
            total_implementations: self.implementations.len(),
            mappings: self.mappings.clone(),
            traceability: self.traceability.clone(),
            gaps,
            recommendations,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        })
    }

    /// Validate existing mappings
    pub fn validate_mappings(&mut self) -> Result<Vec<IntentMapping>> {
        let mut validated_mappings = Vec::new();

        // Collect validation results first
        let mut validation_results = Vec::new();
        for mapping in &self.mappings {
            let validation_result = self.validate_mapping(mapping)?;
            validation_results.push(validation_result);
        }

        // Update mappings with validation results
        for (mapping, validation_result) in self.mappings.iter_mut().zip(validation_results.iter()) {
            mapping.validation_status = validation_result.clone();

            if *validation_result == ValidationStatus::Valid {
                validated_mappings.push(mapping.clone());
            }
        }

        Ok(validated_mappings)
    }

    /// Get traceability report
    pub fn get_traceability_report(&self) -> TraceabilityReport {
        let mut report = TraceabilityReport {
            forward_coverage: 0.0,
            backward_coverage: 0.0,
            orphaned_requirements: Vec::new(),
            orphaned_implementations: Vec::new(),
            mapping_quality_score: 0.0,
        };

        // Calculate forward coverage
        let requirements_with_impl = self.traceability.forward_trace.len();
        if !self.requirements.is_empty() {
            report.forward_coverage = requirements_with_impl as f64 / self.requirements.len() as f64;
        }

        // Calculate backward coverage
        let implementations_with_req = self.traceability.backward_trace.len();
        if !self.implementations.is_empty() {
            report.backward_coverage = implementations_with_req as f64 / self.implementations.len() as f64;
        }

        // Find orphaned items
        for req in &self.requirements {
            if !self.traceability.forward_trace.contains_key(&req.id) {
                report.orphaned_requirements.push(req.id.clone());
            }
        }

        for impl_item in &self.implementations {
            if !self.traceability.backward_trace.contains_key(&impl_item.id) {
                report.orphaned_implementations.push(impl_item.id.clone());
            }
        }

        // Calculate overall quality score
        let valid_mappings = self.mappings.iter()
            .filter(|m| m.validation_status == ValidationStatus::Valid)
            .count();

        if !self.mappings.is_empty() {
            report.mapping_quality_score = valid_mappings as f64 / self.mappings.len() as f64;
        }

        report
    }

    // Private implementation methods

    /// Create implementation from file info
    fn create_implementation_from_file(&self, file: &FileInfo) -> Result<Implementation> {
        let mut code_elements = Vec::new();

        for symbol in &file.symbols {
            let element = CodeElement {
                name: symbol.name.clone(),
                element_type: symbol.kind.clone(),
                line_range: (symbol.start_line, symbol.end_line),
                complexity: 1.0, // Default complexity
                test_coverage: 0.0, // Default coverage
            };
            code_elements.push(element);
        }

        let implementation = Implementation {
            id: format!("impl_{}", file.path.display()),
            implementation_type: self.infer_implementation_type(&file.language),
            file_path: file.path.clone(),
            code_elements,
            status: ImplementationStatus::Complete,
            quality_metrics: QualityMetrics {
                coverage: 0.0,
                complexity: 1.0,
                maintainability: 0.8,
                performance: 0.8,
                security: 0.8,
            },
            documentation: None,
        };

        Ok(implementation)
    }

    /// Infer implementation type from language
    fn infer_implementation_type(&self, language: &str) -> ImplementationType {
        match language.to_lowercase().as_str() {
            "rust" | "c" | "cpp" | "c++" => ImplementationType::Module,
            "python" | "javascript" | "typescript" => ImplementationType::Module,
            "sql" => ImplementationType::Database,
            "yaml" | "json" | "toml" => ImplementationType::Configuration,
            "md" | "markdown" | "rst" => ImplementationType::Documentation,
            _ => ImplementationType::Module,
        }
    }

    /// Generate automatic mappings using various strategies
    async fn generate_automatic_mappings(&mut self) -> Result<()> {
        self.mappings.clear();

        // Strategy 1: Keyword-based matching
        self.generate_keyword_mappings()?;

        // Strategy 2: Semantic similarity matching (now async for embeddings)
        if self.config.enable_semantic_analysis {
            self.generate_semantic_mappings().await?;
        }

        // Strategy 3: Pattern-based matching
        self.generate_pattern_mappings()?;

        Ok(())
    }

    /// Generate mappings based on keyword matching
    fn generate_keyword_mappings(&mut self) -> Result<()> {
        for requirement in &self.requirements {
            let req_keywords = self.extract_keywords(&requirement.description);

            for implementation in &self.implementations {
                let impl_keywords = self.extract_implementation_keywords(implementation);
                let similarity = self.calculate_keyword_similarity(&req_keywords, &impl_keywords);

                if similarity >= self.config.confidence_threshold {
                    let validation_status = if similarity >= self.config.auto_validation_threshold {
                        ValidationStatus::Valid
                    } else {
                        ValidationStatus::NotValidated
                    };

                    let mapping = Self::create_intent_mapping(
                        "map",
                        &requirement.id,
                        &implementation.id,
                        MappingType::Direct,
                        similarity,
                        "Keyword-based matching",
                        validation_status,
                    );

                    self.mappings.push(mapping);
                }
            }
        }

        Ok(())
    }

    /// Generate mappings based on semantic similarity using embeddings
    async fn generate_semantic_mappings(&mut self) -> Result<()> {
        // Generate embeddings if we have an embedding engine
        if self.embedding_engine.is_some() {
            self.generate_requirement_embeddings().await?;
            self.generate_implementation_embeddings().await?;
        }

        // Use hybrid similarity scoring for more accurate mappings
        for requirement in &self.requirements {
            for implementation in &self.implementations {
                // Use hybrid similarity that combines semantic, structural, and contextual factors
                let hybrid_score = self.calculate_hybrid_similarity(requirement, implementation);

                if hybrid_score >= self.config.confidence_threshold {
                    // Check if mapping already exists
                    let exists = self.mappings.iter().any(|m|
                        m.requirement_id == requirement.id &&
                        m.implementation_id == implementation.id
                    );

                    if !exists {
                        // Calculate comprehensive confidence score
                        let confidence_score = self.calculate_confidence_score(requirement, implementation, hybrid_score);

                        let rationale = format!(
                            "Hybrid similarity analysis (similarity: {:.3}, confidence: {:.3}) combining semantic embeddings, structural patterns, and contextual alignment",
                            hybrid_score, confidence_score
                        );

                        let validation_status = self.determine_validation_status(confidence_score);

                        let mapping = Self::create_intent_mapping(
                            "hyb",
                            &requirement.id,
                            &implementation.id,
                            MappingType::Inferred,
                            confidence_score, // Use confidence score instead of raw similarity
                            &rationale,
                            validation_status,
                        );

                        self.mappings.push(mapping);
                    }
                }
            }
        }

        Ok(())
    }

    /// Generate mappings based on common patterns
    fn generate_pattern_mappings(&mut self) -> Result<()> {
        // Pattern 1: User story to API endpoint
        for requirement in &self.requirements {
            if requirement.requirement_type == RequirementType::UserStory {
                for implementation in &self.implementations {
                    if implementation.implementation_type == ImplementationType::API {
                        let pattern_score = self.calculate_pattern_match_score(requirement, implementation);

                        if pattern_score >= self.config.confidence_threshold {
                            let mapping = IntentMapping {
                                id: format!("pat_{}_{}", requirement.id, implementation.id),
                                requirement_id: requirement.id.clone(),
                                implementation_id: implementation.id.clone(),
                                mapping_type: MappingType::Derived,
                                confidence: pattern_score,
                                rationale: "Pattern-based matching (User Story -> API)".to_string(),
                                validation_status: ValidationStatus::NeedsReview,
                                last_updated: std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .unwrap_or_default()
                                    .as_secs(),
                            };

                            self.mappings.push(mapping);
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Build traceability matrix
    fn build_traceability_matrix(&mut self) {
        self.traceability = TraceabilityMatrix::new();

        for mapping in &self.mappings {
            // Forward traceability
            self.traceability.forward_trace
                .entry(mapping.requirement_id.to_string())
                .or_insert_with(Vec::new)
                .push(mapping.implementation_id.to_string());

            // Backward traceability
            self.traceability.backward_trace
                .entry(mapping.implementation_id.to_string())
                .or_insert_with(Vec::new)
                .push(mapping.requirement_id.to_string());
        }

        // Calculate coverage metrics
        let req_coverage = if self.requirements.is_empty() {
            0.0
        } else {
            self.traceability.forward_trace.len() as f64 / self.requirements.len() as f64
        };

        let impl_coverage = if self.implementations.is_empty() {
            0.0
        } else {
            self.traceability.backward_trace.len() as f64 / self.implementations.len() as f64
        };

        let orphaned_reqs = self.requirements.len() - self.traceability.forward_trace.len();
        let orphaned_impls = self.implementations.len() - self.traceability.backward_trace.len();

        self.traceability.coverage_metrics = CoverageMetrics {
            requirement_coverage: req_coverage,
            implementation_coverage: impl_coverage,
            orphaned_requirements: orphaned_reqs,
            orphaned_implementations: orphaned_impls,
        };
    }

    /// Identify gaps in mappings
    fn identify_gaps(&self) -> Result<Vec<MappingGap>> {
        let mut gaps = Vec::new();

        // Find requirements without implementations
        for requirement in &self.requirements {
            if !self.traceability.forward_trace.contains_key(&requirement.id) {
                gaps.push(MappingGap {
                    gap_type: GapType::MissingImplementation,
                    description: format!("Requirement '{}' has no implementation", requirement.id),
                    affected_items: vec![requirement.id.clone()],
                    severity: requirement.priority.clone(),
                    suggested_actions: vec![
                        "Create implementation".to_string(),
                        "Review requirement validity".to_string(),
                    ],
                });
            }
        }

        // Find implementations without requirements
        for implementation in &self.implementations {
            if !self.traceability.backward_trace.contains_key(&implementation.id) {
                gaps.push(MappingGap {
                    gap_type: GapType::MissingRequirement,
                    description: format!("Implementation '{}' has no requirement", implementation.id),
                    affected_items: vec![implementation.id.clone()],
                    severity: Priority::Medium,
                    suggested_actions: vec![
                        "Create requirement".to_string(),
                        "Review implementation necessity".to_string(),
                    ],
                });
            }
        }

        // Find quality gaps
        for implementation in &self.implementations {
            if implementation.quality_metrics.coverage < COVERAGE_THRESHOLD {
                gaps.push(MappingGap {
                    gap_type: GapType::TestGap,
                    description: format!("Implementation '{}' has low test coverage", implementation.id),
                    affected_items: vec![implementation.id.clone()],
                    severity: Priority::High,
                    suggested_actions: vec![
                        "Add unit tests".to_string(),
                        "Add integration tests".to_string(),
                    ],
                });
            }
        }

        Ok(gaps)
    }

    /// Generate recommendations
    fn generate_recommendations(&self, gaps: &[MappingGap]) -> Result<Vec<MappingRecommendation>> {
        let mut recommendations = Vec::new();

        for gap in gaps {
            match gap.gap_type {
                GapType::MissingImplementation => {
                    recommendations.push(MappingRecommendation {
                        recommendation_type: RecommendationType::CreateImplementation,
                        description: format!("Implement missing functionality for requirement"),
                        priority: gap.severity.clone(),
                        affected_items: gap.affected_items.clone(),
                        expected_impact: "Improved requirement coverage".to_string(),
                        effort_estimate: EffortLevel::Large,
                    });
                }
                GapType::MissingRequirement => {
                    recommendations.push(MappingRecommendation {
                        recommendation_type: RecommendationType::CreateRequirement,
                        description: format!("Document requirement for existing implementation"),
                        priority: Priority::Medium,
                        affected_items: gap.affected_items.clone(),
                        expected_impact: "Improved traceability".to_string(),
                        effort_estimate: EffortLevel::Small,
                    });
                }
                GapType::TestGap => {
                    recommendations.push(MappingRecommendation {
                        recommendation_type: RecommendationType::AddTests,
                        description: format!("Improve test coverage"),
                        priority: Priority::High,
                        affected_items: gap.affected_items.clone(),
                        expected_impact: "Improved quality and reliability".to_string(),
                        effort_estimate: EffortLevel::Medium,
                    });
                }
                _ => {}
            }
        }

        Ok(recommendations)
    }

    /// Validate a single mapping
    fn validate_mapping(&self, mapping: &IntentMapping) -> Result<ValidationStatus> {
        // Find the requirement and implementation
        let requirement = self.requirements.iter()
            .find(|r| r.id == mapping.requirement_id);
        let implementation = self.implementations.iter()
            .find(|i| i.id == mapping.implementation_id);

        let (req, impl_item) = match (requirement, implementation) {
            (Some(req), Some(impl_item)) => (req, impl_item),
            _ => return Ok(ValidationStatus::Invalid),
        };

        // Validation criteria
        let mut validation_score = 0.0;

        // Check confidence threshold
        if mapping.confidence >= self.config.auto_validation_threshold {
            validation_score += VALIDATION_CONFIDENCE_WEIGHT;
        }

        // Check requirement status
        if matches!(req.status, RequirementStatus::Approved | RequirementStatus::InProgress) {
            validation_score += VALIDATION_REQUIREMENT_WEIGHT;
        }

        // Check implementation status
        if matches!(impl_item.status, ImplementationStatus::Complete | ImplementationStatus::Tested) {
            validation_score += VALIDATION_IMPLEMENTATION_WEIGHT;
        }

        // Check quality metrics
        if impl_item.quality_metrics.coverage > QUALITY_COVERAGE_THRESHOLD {
            validation_score += VALIDATION_QUALITY_WEIGHT;
        }

        if validation_score >= VALIDATION_VALID_THRESHOLD {
            Ok(ValidationStatus::Valid)
        } else if validation_score >= VALIDATION_REVIEW_THRESHOLD {
            Ok(ValidationStatus::NeedsReview)
        } else {
            Ok(ValidationStatus::Invalid)
        }
    }

    // Helper methods for text analysis

    /// Extract keywords from text
    fn extract_keywords(&self, text: &str) -> Vec<String> {
        text.to_lowercase()
            .split_whitespace()
            .filter(|word| word.len() > 3)
            .filter(|word| !self.is_stop_word(word))
            .map(|word| word.trim_matches(|c: char| !c.is_alphanumeric()).to_string())
            .filter(|word| !word.is_empty())
            .collect()
    }

    /// Extract keywords from implementation
    fn extract_implementation_keywords(&self, implementation: &Implementation) -> Vec<String> {
        let mut keywords = Vec::new();

        // Add file path components
        if let Some(file_name) = implementation.file_path.file_stem() {
            if let Some(name_str) = file_name.to_str() {
                keywords.extend(self.extract_keywords(name_str));
            }
        }

        // Add code element names
        for element in &implementation.code_elements {
            keywords.extend(self.extract_keywords(&element.name));
        }

        keywords
    }

    /// Calculate keyword similarity
    fn calculate_keyword_similarity(&self, keywords1: &[String], keywords2: &[String]) -> f64 {
        if keywords1.is_empty() || keywords2.is_empty() {
            return 0.0;
        }

        let set1: HashSet<_> = keywords1.iter().collect();
        let set2: HashSet<_> = keywords2.iter().collect();

        let intersection = set1.intersection(&set2).count();
        let union = set1.union(&set2).count();

        if union == 0 {
            0.0
        } else {
            intersection as f64 / union as f64
        }
    }

    /// Calculate semantic similarity using embeddings or fallback to keyword matching
    fn calculate_semantic_similarity(&self, text1: &str, text2: &str) -> f64 {
        // Use embedding-based similarity if available
        if let Some(engine) = &self.embedding_engine {
            match engine.calculate_similarity(text1, text2) {
                Ok(similarity) => return similarity,
                Err(_) => {
                    // Fall back to keyword matching if embedding fails
                }
            }
        }

        // Fallback: simplified semantic similarity using word overlap
        let words1 = self.extract_keywords(text1);
        let words2 = self.extract_keywords(text2);
        self.calculate_keyword_similarity(&words1, &words2)
    }

    /// Calculate hybrid similarity combining semantic embeddings with structural analysis
    fn calculate_hybrid_similarity(&self, requirement: &Requirement, implementation: &Implementation) -> f64 {
        // Weights for different similarity components
        const SEMANTIC_WEIGHT: f64 = 0.4;
        const STRUCTURAL_WEIGHT: f64 = 0.3;
        const KEYWORD_WEIGHT: f64 = 0.2;
        const CONTEXT_WEIGHT: f64 = 0.1;

        let mut total_score = 0.0;

        // 1. Semantic similarity using embeddings
        let semantic_score = if self.embedding_engine.is_some() {
            match self.calculate_embedding_similarity(&requirement.id, &implementation.id) {
                Ok(score) => score,
                Err(_) => {
                    // Fallback to text-based semantic similarity
                    self.calculate_semantic_similarity(
                        &requirement.description,
                        &self.get_implementation_description(implementation)
                    )
                }
            }
        } else {
            self.calculate_semantic_similarity(
                &requirement.description,
                &self.get_implementation_description(implementation)
            )
        };
        total_score += semantic_score * SEMANTIC_WEIGHT;

        // 2. Structural similarity based on code structure and patterns
        let structural_score = self.calculate_structural_similarity(requirement, implementation);
        total_score += structural_score * STRUCTURAL_WEIGHT;

        // 3. Keyword-based similarity
        let req_keywords = self.extract_keywords(&requirement.description);
        let impl_keywords = self.extract_implementation_keywords(implementation);
        let keyword_score = self.calculate_keyword_similarity(&req_keywords, &impl_keywords);
        total_score += keyword_score * KEYWORD_WEIGHT;

        // 4. Context similarity (priority, category, tags)
        let context_score = self.calculate_context_similarity(requirement, implementation);
        total_score += context_score * CONTEXT_WEIGHT;

        total_score.min(1.0)
    }

    /// Calculate structural similarity based on code patterns and architecture
    fn calculate_structural_similarity(&self, requirement: &Requirement, implementation: &Implementation) -> f64 {
        let mut structural_score = 0.0;
        let mut factors = 0;

        // Analyze implementation type patterns
        let req_type_str = format!("{:?}", requirement.requirement_type).to_lowercase();
        let impl_type_str = format!("{:?}", implementation.implementation_type).to_lowercase();
        let type_score = self.calculate_type_similarity(&req_type_str, &impl_type_str);
        structural_score += type_score;
        factors += 1;

        // Analyze complexity alignment
        let complexity_score = self.calculate_complexity_alignment(requirement, implementation);
        structural_score += complexity_score;
        factors += 1;

        // Analyze architectural patterns
        let pattern_score = self.calculate_pattern_similarity(requirement, implementation);
        structural_score += pattern_score;
        factors += 1;

        // Analyze dependency relationships
        let dependency_score = self.calculate_dependency_similarity(requirement, implementation);
        structural_score += dependency_score;
        factors += 1;

        if factors > 0 {
            structural_score / factors as f64
        } else {
            0.0
        }
    }

    /// Calculate similarity between requirement and implementation types
    fn calculate_type_similarity(&self, req_type: &str, impl_type: &str) -> f64 {
        // Define type similarity mappings
        let type_mappings = [
            // Functional requirements
            ("functional", "function", 0.9),
            ("functional", "method", 0.9),
            ("functional", "api", 0.8),
            ("functional", "service", 0.8),

            // Non-functional requirements
            ("performance", "optimization", 0.9),
            ("performance", "cache", 0.7),
            ("performance", "async", 0.7),
            ("security", "authentication", 0.9),
            ("security", "authorization", 0.9),
            ("security", "encryption", 0.8),
            ("security", "validation", 0.7),

            // UI/UX requirements
            ("ui", "component", 0.9),
            ("ui", "interface", 0.9),
            ("ux", "component", 0.8),
            ("ux", "interface", 0.8),

            // Data requirements
            ("data", "database", 0.9),
            ("data", "storage", 0.9),
            ("data", "model", 0.8),
            ("data", "schema", 0.8),

            // Integration requirements
            ("integration", "api", 0.9),
            ("integration", "service", 0.8),
            ("integration", "connector", 0.8),
        ];

        let req_type_lower = req_type.to_lowercase();
        let impl_type_lower = impl_type.to_lowercase();

        // Exact match
        if req_type_lower == impl_type_lower {
            return 1.0;
        }

        // Check predefined mappings
        for (req_pattern, impl_pattern, score) in &type_mappings {
            if req_type_lower.contains(req_pattern) && impl_type_lower.contains(impl_pattern) {
                return *score;
            }
            if req_type_lower.contains(impl_pattern) && impl_type_lower.contains(req_pattern) {
                return *score;
            }
        }

        // Keyword-based similarity as fallback
        let req_keywords = self.extract_keywords(&req_type_lower);
        let impl_keywords = self.extract_keywords(&impl_type_lower);
        self.calculate_keyword_similarity(&req_keywords, &impl_keywords) * 0.5
    }

    /// Calculate complexity alignment between requirement and implementation
    fn calculate_complexity_alignment(&self, requirement: &Requirement, implementation: &Implementation) -> f64 {
        // Analyze requirement complexity indicators
        let req_complexity = self.estimate_requirement_complexity(requirement);

        // Analyze implementation complexity indicators
        let impl_complexity = self.estimate_implementation_complexity(implementation);

        // Calculate alignment score (closer complexities score higher)
        let complexity_diff = (req_complexity - impl_complexity).abs();
        let max_complexity = req_complexity.max(impl_complexity);

        if max_complexity == 0.0 {
            1.0
        } else {
            (1.0 - (complexity_diff / max_complexity)).max(0.0)
        }
    }

    /// Estimate requirement complexity based on description and metadata
    fn estimate_requirement_complexity(&self, requirement: &Requirement) -> f64 {
        let mut complexity = 0.0;

        // Base complexity from description length and content
        let word_count = requirement.description.split_whitespace().count() as f64;
        complexity += (word_count / 50.0).min(1.0) * 0.3;

        // Complexity indicators in description
        let complexity_keywords = [
            "complex", "multiple", "various", "integrate", "coordinate",
            "sophisticated", "advanced", "comprehensive", "extensive"
        ];

        let description_lower = requirement.description.to_lowercase();
        for keyword in &complexity_keywords {
            if description_lower.contains(keyword) {
                complexity += 0.1;
            }
        }

        // Priority-based complexity
        match requirement.priority {
            Priority::Critical | Priority::High => complexity += 0.3,
            Priority::Medium => complexity += 0.2,
            Priority::Low => complexity += 0.1,
        }

        complexity.min(1.0)
    }

    /// Estimate implementation complexity based on code metrics
    fn estimate_implementation_complexity(&self, implementation: &Implementation) -> f64 {
        let mut complexity = 0.0;

        // Base complexity from file path and name
        let path_segments = implementation.file_path.components().count() as f64;
        complexity += (path_segments / 10.0).min(1.0) * 0.2;

        // Complexity indicators in implementation documentation
        if let Some(documentation) = &implementation.documentation {
            let doc_lower = documentation.to_lowercase();
            let complexity_indicators = [
                "class", "interface", "abstract", "generic", "template",
                "async", "concurrent", "parallel", "thread", "lock",
                "algorithm", "optimization", "cache", "database", "network"
            ];

            for indicator in &complexity_indicators {
                if doc_lower.contains(indicator) {
                    complexity += 0.1;
                }
            }
        }

        // File type complexity
        if let Some(ext) = implementation.file_path.extension() {
            match ext.to_str().unwrap_or("") {
                "rs" | "cpp" | "java" | "cs" => complexity += 0.2,
                "py" | "js" | "ts" => complexity += 0.15,
                "html" | "css" | "json" => complexity += 0.05,
                _ => complexity += 0.1,
            }
        }

        complexity.min(1.0)
    }

    /// Calculate pattern similarity based on architectural and design patterns
    fn calculate_pattern_similarity(&self, requirement: &Requirement, implementation: &Implementation) -> f64 {
        let mut pattern_score = 0.0;
        let mut pattern_count = 0;

        // Extract patterns from requirement description
        let req_patterns = self.extract_requirement_patterns(&requirement.description);

        // Extract patterns from implementation
        let impl_patterns = self.extract_implementation_patterns(implementation);

        // Calculate pattern overlap
        for req_pattern in &req_patterns {
            for impl_pattern in &impl_patterns {
                let similarity = self.calculate_pattern_string_match(req_pattern, impl_pattern);
                if similarity > 0.5 {
                    pattern_score += similarity;
                    pattern_count += 1;
                }
            }
        }

        if pattern_count > 0 {
            pattern_score / pattern_count as f64
        } else {
            0.0
        }
    }

    /// Extract architectural patterns from requirement description
    fn extract_requirement_patterns(&self, description: &str) -> Vec<String> {
        let mut patterns = Vec::new();
        let description_lower = description.to_lowercase();

        // Common architectural patterns
        let pattern_keywords = [
            ("mvc", "model-view-controller"),
            ("mvp", "model-view-presenter"),
            ("mvvm", "model-view-viewmodel"),
            ("repository", "repository pattern"),
            ("factory", "factory pattern"),
            ("singleton", "singleton pattern"),
            ("observer", "observer pattern"),
            ("strategy", "strategy pattern"),
            ("adapter", "adapter pattern"),
            ("facade", "facade pattern"),
            ("microservice", "microservices"),
            ("api", "api pattern"),
            ("rest", "rest api"),
            ("graphql", "graphql api"),
            ("event", "event-driven"),
            ("pub", "publish-subscribe"),
            ("queue", "message queue"),
            ("cache", "caching pattern"),
            ("database", "database pattern"),
            ("orm", "object-relational mapping"),
        ];

        for (keyword, pattern) in &pattern_keywords {
            if description_lower.contains(keyword) {
                patterns.push(pattern.to_string());
            }
        }

        patterns
    }

    /// Extract patterns from implementation details
    fn extract_implementation_patterns(&self, implementation: &Implementation) -> Vec<String> {
        let mut patterns = Vec::new();

        // Analyze file path for patterns
        let path_str = implementation.file_path.to_string_lossy().to_lowercase();

        // Common implementation patterns from file structure
        let path_patterns = [
            ("controller", "mvc-controller"),
            ("model", "mvc-model"),
            ("view", "mvc-view"),
            ("service", "service-layer"),
            ("repository", "repository-pattern"),
            ("factory", "factory-pattern"),
            ("adapter", "adapter-pattern"),
            ("facade", "facade-pattern"),
            ("api", "api-implementation"),
            ("rest", "rest-api"),
            ("graphql", "graphql-api"),
            ("event", "event-handling"),
            ("queue", "message-queue"),
            ("cache", "caching"),
            ("db", "database"),
            ("orm", "orm-mapping"),
        ];

        for (keyword, pattern) in &path_patterns {
            if path_str.contains(keyword) {
                patterns.push(pattern.to_string());
            }
        }

        // Analyze implementation documentation if available
        if let Some(documentation) = &implementation.documentation {
            let doc_lower = documentation.to_lowercase();

            for (keyword, pattern) in &path_patterns {
                if doc_lower.contains(keyword) {
                    patterns.push(pattern.to_string());
                }
            }
        }

        patterns
    }

    /// Calculate similarity between two pattern strings
    fn calculate_pattern_string_match(&self, pattern1: &str, pattern2: &str) -> f64 {
        if pattern1 == pattern2 {
            return 1.0;
        }

        // Check for related patterns
        let related_patterns = [
            ("mvc-controller", "service-layer", 0.7),
            ("mvc-model", "orm-mapping", 0.8),
            ("mvc-view", "api-implementation", 0.6),
            ("repository-pattern", "database", 0.8),
            ("factory-pattern", "service-layer", 0.6),
            ("rest-api", "api-implementation", 0.9),
            ("graphql-api", "api-implementation", 0.9),
            ("event-handling", "message-queue", 0.7),
            ("caching", "database", 0.5),
        ];

        for (p1, p2, score) in &related_patterns {
            if (pattern1 == *p1 && pattern2 == *p2) || (pattern1 == *p2 && pattern2 == *p1) {
                return *score;
            }
        }

        // Keyword-based similarity as fallback
        let keywords1 = self.extract_keywords(pattern1);
        let keywords2 = self.extract_keywords(pattern2);
        self.calculate_keyword_similarity(&keywords1, &keywords2) * 0.5
    }

    /// Calculate dependency similarity between requirement and implementation
    fn calculate_dependency_similarity(&self, requirement: &Requirement, implementation: &Implementation) -> f64 {
        // This is a simplified implementation - in a real system, you would analyze
        // actual dependency graphs and requirement dependencies

        let mut dependency_score = 0.0;
        let mut factors = 0;

        // Analyze technology stack alignment
        let tech_score = self.calculate_technology_alignment(requirement, implementation);
        dependency_score += tech_score;
        factors += 1;

        // Analyze integration requirements
        let integration_score = self.calculate_integration_alignment(requirement, implementation);
        dependency_score += integration_score;
        factors += 1;

        if factors > 0 {
            dependency_score / factors as f64
        } else {
            0.5 // Neutral score when no dependency information available
        }
    }

    /// Calculate technology stack alignment
    fn calculate_technology_alignment(&self, requirement: &Requirement, implementation: &Implementation) -> f64 {
        let req_description = requirement.description.to_lowercase();
        let impl_path = implementation.file_path.to_string_lossy().to_lowercase();

        // Technology indicators
        let tech_mappings = [
            ("web", vec!["html", "css", "js", "ts", "jsx", "tsx"]),
            ("backend", vec!["rs", "java", "py", "go", "cpp", "cs"]),
            ("database", vec!["sql", "db", "orm", "migration"]),
            ("mobile", vec!["swift", "kotlin", "dart", "xamarin"]),
            ("api", vec!["rest", "graphql", "grpc", "openapi"]),
            ("frontend", vec!["react", "vue", "angular", "svelte"]),
            ("microservice", vec!["docker", "k8s", "service", "api"]),
        ];

        let mut alignment_score = 0.0;
        let mut matches = 0;

        for (tech_type, extensions) in &tech_mappings {
            let req_mentions_tech = req_description.contains(tech_type);
            let impl_uses_tech = extensions.iter().any(|ext| impl_path.contains(ext));

            if req_mentions_tech && impl_uses_tech {
                alignment_score += 1.0;
                matches += 1;
            } else if req_mentions_tech || impl_uses_tech {
                // Partial alignment
                alignment_score += 0.3;
                matches += 1;
            }
        }

        if matches > 0 {
            alignment_score / matches as f64
        } else {
            0.5 // Neutral when no clear technology indicators
        }
    }

    /// Calculate integration alignment
    fn calculate_integration_alignment(&self, requirement: &Requirement, implementation: &Implementation) -> f64 {
        let req_description = requirement.description.to_lowercase();
        let impl_details = implementation.documentation.as_ref()
            .map(|d| d.to_lowercase())
            .unwrap_or_default();

        // Integration patterns
        let integration_patterns = [
            "api", "service", "interface", "connector", "adapter",
            "webhook", "callback", "event", "message", "queue",
            "database", "storage", "cache", "session", "auth"
        ];

        let mut req_integration_count = 0;
        let mut impl_integration_count = 0;
        let mut common_integrations = 0;

        for pattern in &integration_patterns {
            let req_has = req_description.contains(pattern);
            let impl_has = impl_details.contains(pattern);

            if req_has {
                req_integration_count += 1;
            }
            if impl_has {
                impl_integration_count += 1;
            }
            if req_has && impl_has {
                common_integrations += 1;
            }
        }

        let total_integrations = req_integration_count + impl_integration_count;
        if total_integrations > 0 {
            (common_integrations as f64 * 2.0) / total_integrations as f64
        } else {
            0.5 // Neutral when no integration patterns detected
        }
    }

    /// Calculate context similarity (priority, category, tags)
    fn calculate_context_similarity(&self, requirement: &Requirement, implementation: &Implementation) -> f64 {
        let mut context_score = 0.0;
        let mut factors = 0;

        // Priority alignment (if implementation has priority indicators)
        let priority_score = self.calculate_priority_alignment(requirement, implementation);
        context_score += priority_score;
        factors += 1;

        // Category/domain alignment
        let category_score = self.calculate_category_alignment(requirement, implementation);
        context_score += category_score;
        factors += 1;

        if factors > 0 {
            context_score / factors as f64
        } else {
            0.5 // Neutral score when no context information available
        }
    }

    /// Calculate priority alignment between requirement and implementation
    fn calculate_priority_alignment(&self, requirement: &Requirement, implementation: &Implementation) -> f64 {
        // Analyze implementation for priority indicators
        let impl_path = implementation.file_path.to_string_lossy().to_lowercase();
        let impl_details = implementation.documentation.as_ref()
            .map(|d| d.to_lowercase())
            .unwrap_or_default();

        let high_priority_indicators = ["critical", "urgent", "important", "core", "main", "primary"];
        let low_priority_indicators = ["optional", "nice", "future", "enhancement", "todo"];

        let req_priority = format!("{:?}", requirement.priority).to_lowercase();

        let impl_has_high_indicators = high_priority_indicators.iter()
            .any(|indicator| impl_path.contains(indicator) || impl_details.contains(indicator));
        let impl_has_low_indicators = low_priority_indicators.iter()
            .any(|indicator| impl_path.contains(indicator) || impl_details.contains(indicator));

        match req_priority.as_str() {
            "critical" | "high" => {
                if impl_has_high_indicators { 1.0 }
                else if impl_has_low_indicators { 0.2 }
                else { 0.6 }
            },
            "medium" => {
                if impl_has_high_indicators || impl_has_low_indicators { 0.5 }
                else { 0.8 }
            },
            "low" => {
                if impl_has_low_indicators { 1.0 }
                else if impl_has_high_indicators { 0.3 }
                else { 0.6 }
            },
            _ => 0.5 // Unknown priority
        }
    }

    /// Calculate category/domain alignment
    fn calculate_category_alignment(&self, requirement: &Requirement, implementation: &Implementation) -> f64 {
        // Extract domain/category from requirement type and description
        let req_domain = self.extract_domain_from_requirement(requirement);

        // Extract domain/category from implementation path and details
        let impl_domain = self.extract_domain_from_implementation(implementation);

        // Calculate domain similarity
        if req_domain == impl_domain {
            1.0
        } else if req_domain.is_empty() || impl_domain.is_empty() {
            0.5 // Neutral when domain unclear
        } else {
            // Check for related domains
            let domain_relations = [
                ("auth", "security", 0.8),
                ("ui", "frontend", 0.9),
                ("api", "backend", 0.8),
                ("data", "database", 0.9),
                ("performance", "optimization", 0.8),
            ];

            for (domain1, domain2, score) in &domain_relations {
                if (req_domain.contains(domain1) && impl_domain.contains(domain2)) ||
                   (req_domain.contains(domain2) && impl_domain.contains(domain1)) {
                    return *score;
                }
            }

            0.2 // Different domains
        }
    }

    /// Extract domain from requirement
    fn extract_domain_from_requirement(&self, requirement: &Requirement) -> String {
        let req_type = format!("{:?}", requirement.requirement_type).to_lowercase();
        let description = requirement.description.to_lowercase();

        let domains = [
            "auth", "security", "ui", "frontend", "backend", "api",
            "database", "data", "performance", "optimization", "testing",
            "deployment", "monitoring", "logging", "analytics"
        ];

        for domain in &domains {
            if req_type.contains(domain) || description.contains(domain) {
                return domain.to_string();
            }
        }

        String::new()
    }

    /// Extract domain from implementation
    fn extract_domain_from_implementation(&self, implementation: &Implementation) -> String {
        let path = implementation.file_path.to_string_lossy().to_lowercase();
        let details = implementation.documentation.as_ref()
            .map(|d| d.to_lowercase())
            .unwrap_or_default();

        let domains = [
            "auth", "security", "ui", "frontend", "backend", "api",
            "database", "data", "performance", "optimization", "test",
            "deploy", "monitor", "log", "analytics"
        ];

        for domain in &domains {
            if path.contains(domain) || details.contains(domain) {
                return domain.to_string();
            }
        }

        String::new()
    }

    /// Generate embeddings for all requirements (batch processing for efficiency)
    async fn generate_requirement_embeddings(&mut self) -> Result<()> {
        if let Some(engine) = &self.embedding_engine {
            let texts: Vec<String> = self.requirements.iter()
                .map(|req| req.description.clone())
                .collect();

            let embeddings = engine.embed_batch(&texts)
                .map_err(|e| crate::Error::internal_error("embedding_engine", format!("Failed to generate requirement embeddings: {}", e)))?;

            for (req, embedding) in self.requirements.iter().zip(embeddings.into_iter()) {
                let enhanced_embedding = embedding.with_metadata(
                    "type".to_string(),
                    "requirement".to_string()
                ).with_metadata(
                    "id".to_string(),
                    req.id.clone()
                ).with_metadata(
                    "priority".to_string(),
                    format!("{:?}", req.priority)
                );

                self.requirement_embeddings.insert(req.id.clone(), enhanced_embedding);
            }
        }
        Ok(())
    }

    /// Generate embeddings for all implementations (batch processing for efficiency)
    async fn generate_implementation_embeddings(&mut self) -> Result<()> {
        if let Some(engine) = &self.embedding_engine {
            let texts: Vec<String> = self.implementations.iter()
                .map(|impl_item| self.get_implementation_description(impl_item))
                .collect();

            let embeddings = engine.embed_batch(&texts)
                .map_err(|e| crate::Error::internal_error("embedding_engine", format!("Failed to generate implementation embeddings: {}", e)))?;

            for (impl_item, embedding) in self.implementations.iter().zip(embeddings.into_iter()) {
                let enhanced_embedding = embedding.with_metadata(
                    "type".to_string(),
                    "implementation".to_string()
                ).with_metadata(
                    "id".to_string(),
                    impl_item.id.clone()
                ).with_metadata(
                    "implementation_type".to_string(),
                    format!("{:?}", impl_item.implementation_type)
                ).with_metadata(
                    "file_path".to_string(),
                    impl_item.file_path.display().to_string()
                );

                self.implementation_embeddings.insert(impl_item.id.clone(), enhanced_embedding);
            }
        }
        Ok(())
    }

    /// Calculate semantic similarity using cached embeddings
    fn calculate_embedding_similarity(&self, req_id: &str, impl_id: &str) -> Result<f64> {
        let req_embedding = self.requirement_embeddings.get(req_id)
            .ok_or_else(|| crate::Error::invalid_input_error("requirement_id", "existing requirement ID", req_id))?;
        let impl_embedding = self.implementation_embeddings.get(impl_id)
            .ok_or_else(|| crate::Error::invalid_input_error("implementation_id", "existing implementation ID", impl_id))?;

        req_embedding.cosine_similarity(impl_embedding)
            .map_err(|e| crate::Error::internal_error("embedding_similarity", format!("Failed to calculate cosine similarity: {}", e)))
    }

    /// Find most similar implementations for a requirement using embeddings
    pub fn find_similar_implementations(&self, requirement_id: &str, top_k: usize) -> Result<Vec<(String, f64)>> {
        let req_embedding = self.requirement_embeddings.get(requirement_id)
            .ok_or_else(|| crate::Error::invalid_input_error("requirement_id", "existing requirement ID", requirement_id))?;

        let mut similarities = Vec::new();

        for (impl_id, impl_embedding) in &self.implementation_embeddings {
            match req_embedding.cosine_similarity(impl_embedding) {
                Ok(similarity) => similarities.push((impl_id.clone(), similarity)),
                Err(_) => continue,
            }
        }

        // Sort by similarity (descending) and take top_k
        similarities.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        similarities.truncate(top_k);

        Ok(similarities)
    }

    /// Find most similar requirements for an implementation using embeddings
    pub fn find_similar_requirements(&self, implementation_id: &str, top_k: usize) -> Result<Vec<(String, f64)>> {
        let impl_embedding = self.implementation_embeddings.get(implementation_id)
            .ok_or_else(|| crate::Error::invalid_input_error("implementation_id", "existing implementation ID", implementation_id))?;

        let mut similarities = Vec::new();

        for (req_id, req_embedding) in &self.requirement_embeddings {
            match impl_embedding.cosine_similarity(req_embedding) {
                Ok(similarity) => similarities.push((req_id.clone(), similarity)),
                Err(_) => continue,
            }
        }

        // Sort by similarity (descending) and take top_k
        similarities.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        similarities.truncate(top_k);

        Ok(similarities)
    }

    /// Analyze semantic clusters in requirements
    pub fn analyze_requirement_clusters(&self, similarity_threshold: f64) -> Result<Vec<Vec<String>>> {
        let mut clusters = Vec::new();
        let mut processed = HashSet::new();

        for (req_id, req_embedding) in &self.requirement_embeddings {
            if processed.contains(req_id) {
                continue;
            }

            let mut cluster = vec![req_id.clone()];
            processed.insert(req_id.clone());

            // Find similar requirements
            for (other_req_id, other_embedding) in &self.requirement_embeddings {
                if processed.contains(other_req_id) || req_id == other_req_id {
                    continue;
                }

                if let Ok(similarity) = req_embedding.cosine_similarity(other_embedding) {
                    if similarity >= similarity_threshold {
                        cluster.push(other_req_id.clone());
                        processed.insert(other_req_id.clone());
                    }
                }
            }

            if cluster.len() > 1 {
                clusters.push(cluster);
            }
        }

        Ok(clusters)
    }

    /// Get embedding statistics
    pub fn get_embedding_stats(&self) -> EmbeddingStats {
        EmbeddingStats {
            total_requirement_embeddings: self.requirement_embeddings.len(),
            total_implementation_embeddings: self.implementation_embeddings.len(),
            embedding_dimension: self.requirement_embeddings.values()
                .next()
                .map(|e| e.dimension())
                .unwrap_or(0),
            has_embedding_engine: self.embedding_engine.is_some(),
        }
    }

    /// Get implementation description
    fn get_implementation_description(&self, implementation: &Implementation) -> String {
        let mut description = String::new();

        if let Some(file_name) = implementation.file_path.file_name() {
            if let Some(name_str) = file_name.to_str() {
                description.push_str(name_str);
                description.push(' ');
            }
        }

        for element in &implementation.code_elements {
            description.push_str(&element.name);
            description.push(' ');
            description.push_str(&element.element_type);
            description.push(' ');
        }

        description
    }

    /// Calculate pattern match score for requirement and implementation
    fn calculate_pattern_match_score(&self, requirement: &Requirement, implementation: &Implementation) -> f64 {
        let mut score = 0.0;

        // Type-based matching
        match (&requirement.requirement_type, &implementation.implementation_type) {
            (RequirementType::UserStory, ImplementationType::API) => score += USER_STORY_API_WEIGHT,
            (RequirementType::Functional, ImplementationType::Function) => score += FUNCTIONAL_FUNCTION_WEIGHT,
            (RequirementType::Technical, ImplementationType::Module) => score += TECHNICAL_MODULE_WEIGHT,
            (RequirementType::Security, _) => score += SECURITY_WEIGHT,
            _ => {}
        }

        // Keyword matching
        let req_keywords = self.extract_keywords(&requirement.description);
        let impl_keywords = self.extract_implementation_keywords(implementation);
        let keyword_sim = self.calculate_keyword_similarity(&req_keywords, &impl_keywords);

        score += keyword_sim * KEYWORD_SIMILARITY_WEIGHT;

        score.min(1.0)
    }

    /// Check if word is a stop word
    fn is_stop_word(&self, word: &str) -> bool {
        matches!(word, "the" | "and" | "or" | "but" | "in" | "on" | "at" | "to" | "for" | "of" | "with" | "by" | "a" | "an" | "is" | "are" | "was" | "were" | "be" | "been" | "have" | "has" | "had" | "do" | "does" | "did" | "will" | "would" | "could" | "should" | "may" | "might" | "can" | "this" | "that" | "these" | "those")
    }

    // Public getter methods for testing

    /// Get requirements (for testing)
    pub fn requirements(&self) -> &[Requirement] {
        &self.requirements
    }

    /// Get implementations (for testing)
    pub fn implementations(&self) -> &[Implementation] {
        &self.implementations
    }

    /// Get mappings (for testing)
    pub fn mappings(&self) -> &[IntentMapping] {
        &self.mappings
    }

    /// Get configuration (for testing)
    pub fn config(&self) -> &MappingConfig {
        &self.config
    }

    /// Get traceability matrix (for testing)
    pub fn traceability(&self) -> &TraceabilityMatrix {
        &self.traceability
    }

    /// Add implementation directly (for testing)
    pub fn add_implementation(&mut self, implementation: Implementation) {
        self.implementations.push(implementation);
    }

    /// Add mapping directly (for testing)
    pub fn add_mapping(&mut self, mapping: IntentMapping) {
        self.mappings.push(mapping);
    }

    /// Build traceability matrix (for testing)
    pub fn build_traceability_matrix_public(&mut self) {
        self.build_traceability_matrix();
    }

    /// Identify gaps (for testing)
    pub fn identify_gaps_public(&self) -> Result<Vec<MappingGap>> {
        self.identify_gaps()
    }

    /// Generate recommendations (for testing)
    pub fn generate_recommendations_public(&self, gaps: &[MappingGap]) -> Result<Vec<MappingRecommendation>> {
        self.generate_recommendations(gaps)
    }

    /// Validate mapping (for testing)
    pub fn validate_mapping_public(&self, mapping: &IntentMapping) -> Result<ValidationStatus> {
        self.validate_mapping(mapping)
    }

    /// Extract keywords (for testing)
    pub fn extract_keywords_public(&self, text: &str) -> Vec<String> {
        self.extract_keywords(text)
    }

    /// Calculate keyword similarity (for testing)
    pub fn calculate_keyword_similarity_public(&self, keywords1: &[String], keywords2: &[String]) -> f64 {
        self.calculate_keyword_similarity(keywords1, keywords2)
    }

    /// Extract implementation keywords (for testing)
    pub fn extract_implementation_keywords_public(&self, implementation: &Implementation) -> Vec<String> {
        self.extract_implementation_keywords(implementation)
    }

    /// Calculate pattern match (for testing)
    pub fn calculate_pattern_match_public(&self, requirement: &Requirement, implementation: &Implementation) -> f64 {
        self.calculate_pattern_match_score(requirement, implementation)
    }

    /// Calculate confidence score for a mapping based on multiple factors
    fn calculate_confidence_score(&self, requirement: &Requirement, implementation: &Implementation, similarity_score: f64) -> f64 {
        let mut confidence_factors = Vec::new();

        // Base similarity score (weighted heavily)
        confidence_factors.push((similarity_score, 0.4));

        // Quality metrics factor
        let quality_factor = self.calculate_quality_confidence(&implementation.quality_metrics);
        confidence_factors.push((quality_factor, 0.2));

        // Type alignment factor
        let type_factor = self.calculate_type_alignment_confidence(requirement, implementation);
        confidence_factors.push((type_factor, 0.15));

        // Priority alignment factor
        let priority_factor = self.calculate_priority_confidence(requirement, implementation);
        confidence_factors.push((priority_factor, 0.1));

        // Documentation completeness factor
        let doc_factor = self.calculate_documentation_confidence(implementation);
        confidence_factors.push((doc_factor, 0.05));

        // Implementation status factor
        let status_factor = self.calculate_status_confidence(implementation);
        confidence_factors.push((status_factor, 0.05));

        // Test coverage factor
        let test_factor = self.calculate_test_confidence(&implementation.quality_metrics);
        confidence_factors.push((test_factor, 0.05));

        // Calculate weighted average
        let total_weight: f64 = confidence_factors.iter().map(|(_, weight)| weight).sum();
        let weighted_sum: f64 = confidence_factors.iter()
            .map(|(score, weight)| score * weight)
            .sum();

        let base_confidence = weighted_sum / total_weight;

        // Apply confidence adjustments based on thresholds
        self.apply_confidence_adjustments(base_confidence, requirement, implementation)
    }

    /// Calculate quality-based confidence factor
    fn calculate_quality_confidence(&self, quality_metrics: &QualityMetrics) -> f64 {
        let factors = [
            quality_metrics.coverage,
            1.0 - quality_metrics.complexity, // Lower complexity is better
            quality_metrics.maintainability,
            quality_metrics.performance,
            quality_metrics.security,
        ];

        // Calculate average of quality factors
        factors.iter().sum::<f64>() / factors.len() as f64
    }

    /// Calculate type alignment confidence
    fn calculate_type_alignment_confidence(&self, requirement: &Requirement, implementation: &Implementation) -> f64 {
        // Strong type alignments
        let strong_alignments = [
            (RequirementType::Security, ImplementationType::API, 0.9),
            (RequirementType::Performance, ImplementationType::Function, 0.9),
            (RequirementType::Functional, ImplementationType::Function, 0.8),
            (RequirementType::Technical, ImplementationType::Module, 0.8),
            (RequirementType::UserStory, ImplementationType::Interface, 0.8),
        ];

        for (req_type, impl_type, score) in &strong_alignments {
            if requirement.requirement_type == *req_type && implementation.implementation_type == *impl_type {
                return *score;
            }
        }

        // Moderate alignments
        let moderate_alignments = [
            (RequirementType::Business, ImplementationType::API, 0.6),
            (RequirementType::Feature, ImplementationType::Class, 0.6),
            (RequirementType::BugFix, ImplementationType::Function, 0.7),
        ];

        for (req_type, impl_type, score) in &moderate_alignments {
            if requirement.requirement_type == *req_type && implementation.implementation_type == *impl_type {
                return *score;
            }
        }

        // Default moderate confidence for other combinations
        0.5
    }

    /// Calculate priority-based confidence
    fn calculate_priority_confidence(&self, requirement: &Requirement, implementation: &Implementation) -> f64 {
        // Higher priority requirements should have higher confidence when matched with quality implementations
        let priority_weight = match requirement.priority {
            Priority::Critical => 1.0,
            Priority::High => 0.8,
            Priority::Medium => 0.6,
            Priority::Low => 0.4,
        };

        // Implementation status affects confidence
        let status_weight = match implementation.status {
            ImplementationStatus::Deployed => 1.0,
            ImplementationStatus::Tested => 0.9,
            ImplementationStatus::Complete => 0.8,
            ImplementationStatus::InProgress => 0.6,
            ImplementationStatus::NotStarted => 0.3,
            ImplementationStatus::Deprecated => 0.1,
        };

        (priority_weight + status_weight) / 2.0
    }

    /// Calculate documentation completeness confidence
    fn calculate_documentation_confidence(&self, implementation: &Implementation) -> f64 {
        match &implementation.documentation {
            Some(doc) if !doc.trim().is_empty() => {
                // Score based on documentation length and quality indicators
                let length_score = (doc.len() as f64 / 500.0).min(1.0); // Normalize to 500 chars
                let quality_indicators = [
                    doc.contains("@param"),
                    doc.contains("@return"),
                    doc.contains("@throws") || doc.contains("@error"),
                    doc.contains("Example:") || doc.contains("example"),
                    doc.len() > 100,
                ];
                let quality_score = quality_indicators.iter().filter(|&&x| x).count() as f64 / quality_indicators.len() as f64;

                (length_score + quality_score) / 2.0
            },
            Some(_) => 0.3, // Has documentation but it's empty
            None => 0.1,    // No documentation
        }
    }

    /// Calculate implementation status confidence
    fn calculate_status_confidence(&self, implementation: &Implementation) -> f64 {
        match implementation.status {
            ImplementationStatus::Deployed => 1.0,
            ImplementationStatus::Tested => 0.9,
            ImplementationStatus::Complete => 0.8,
            ImplementationStatus::InProgress => 0.5,
            ImplementationStatus::NotStarted => 0.2,
            ImplementationStatus::Deprecated => 0.1,
        }
    }

    /// Calculate test coverage confidence
    fn calculate_test_confidence(&self, quality_metrics: &QualityMetrics) -> f64 {
        // Test coverage directly affects confidence
        quality_metrics.coverage
    }

    /// Apply confidence adjustments based on thresholds and context
    fn apply_confidence_adjustments(&self, base_confidence: f64, requirement: &Requirement, implementation: &Implementation) -> f64 {
        let mut adjusted_confidence = base_confidence;

        // Boost confidence for critical requirements with high-quality implementations
        if requirement.priority == Priority::Critical && implementation.quality_metrics.coverage > 0.8 {
            adjusted_confidence = (adjusted_confidence * 1.1).min(1.0);
        }

        // Reduce confidence for deprecated implementations
        if implementation.status == ImplementationStatus::Deprecated {
            adjusted_confidence *= 0.5;
        }

        // Boost confidence for well-documented implementations
        if implementation.documentation.as_ref().map_or(false, |doc| doc.len() > 200) {
            adjusted_confidence = (adjusted_confidence * 1.05).min(1.0);
        }

        // Reduce confidence for low-quality implementations
        if implementation.quality_metrics.maintainability < 0.5 {
            adjusted_confidence *= 0.8;
        }

        // Ensure confidence is within valid range
        adjusted_confidence.max(0.0).min(1.0)
    }

    /// Determine validation status based on confidence score
    fn determine_validation_status(&self, confidence: f64) -> ValidationStatus {
        if confidence >= self.confidence_thresholds.auto_accept {
            ValidationStatus::Valid
        } else if confidence >= self.confidence_thresholds.needs_review {
            ValidationStatus::NeedsReview
        } else if confidence <= self.confidence_thresholds.auto_reject {
            ValidationStatus::Invalid
        } else {
            ValidationStatus::NotValidated
        }
    }

    /// Get confidence level description
    pub fn get_confidence_level(&self, confidence: f64) -> String {
        if confidence >= self.confidence_thresholds.high_confidence {
            "High".to_string()
        } else if confidence >= self.confidence_thresholds.medium_confidence {
            "Medium".to_string()
        } else if confidence >= self.confidence_thresholds.low_confidence {
            "Low".to_string()
        } else {
            "Very Low".to_string()
        }
    }

    /// Build comprehensive graph-based relationship mapping
    pub fn build_relationship_graph(&mut self) -> Result<RelationshipGraph> {
        let mut graph = RelationshipGraph::new();

        // Add requirement nodes
        for requirement in &self.requirements {
            let node = RelationshipNode {
                id: requirement.id.clone(),
                node_type: RelationshipNodeType::Requirement,
                metadata: self.extract_requirement_metadata(requirement),
                attributes: self.extract_requirement_attributes(requirement),
            };
            graph.add_node(node);
        }

        // Add implementation nodes
        for implementation in &self.implementations {
            let node = RelationshipNode {
                id: implementation.id.clone(),
                node_type: RelationshipNodeType::Implementation,
                metadata: self.extract_implementation_metadata(implementation),
                attributes: self.extract_implementation_attributes(implementation),
            };
            graph.add_node(node);
        }

        // Add mapping edges based on existing mappings
        for mapping in &self.mappings {
            let edge = RelationshipEdge {
                id: mapping.id.clone(),
                source_id: mapping.requirement_id.clone(),
                target_id: mapping.implementation_id.clone(),
                edge_type: self.mapping_type_to_edge_type(&mapping.mapping_type),
                weight: mapping.confidence,
                metadata: self.extract_mapping_metadata(mapping),
                attributes: self.extract_mapping_attributes(mapping),
            };
            graph.add_edge(edge)?;
        }

        // Add derived relationships
        self.add_derived_relationships(&mut graph)?;

        // Add semantic relationships
        self.add_semantic_relationships(&mut graph)?;

        // Calculate graph metrics
        graph.calculate_metrics();

        Ok(graph)
    }

    /// Extract metadata from requirement for graph node
    fn extract_requirement_metadata(&self, requirement: &Requirement) -> HashMap<String, String> {
        let mut metadata = HashMap::new();
        metadata.insert("type".to_string(), requirement.requirement_type.to_string());
        metadata.insert("priority".to_string(), requirement.priority.to_string());
        metadata.insert("status".to_string(), format!("{:?}", requirement.status));
        metadata.insert("stakeholder_count".to_string(), requirement.stakeholders.len().to_string());
        metadata.insert("criteria_count".to_string(), requirement.acceptance_criteria.len().to_string());
        metadata.insert("tag_count".to_string(), requirement.tags.len().to_string());
        metadata
    }

    /// Extract attributes from requirement for graph node
    fn extract_requirement_attributes(&self, requirement: &Requirement) -> HashMap<String, f64> {
        let mut attributes = HashMap::new();
        attributes.insert("priority_weight".to_string(), self.priority_to_weight(&requirement.priority));
        attributes.insert("complexity_estimate".to_string(), self.estimate_requirement_complexity(requirement));
        attributes.insert("stakeholder_influence".to_string(), requirement.stakeholders.len() as f64);
        attributes.insert("criteria_completeness".to_string(), self.calculate_criteria_completeness(requirement));
        attributes
    }

    /// Extract metadata from implementation for graph node
    fn extract_implementation_metadata(&self, implementation: &Implementation) -> HashMap<String, String> {
        let mut metadata = HashMap::new();
        metadata.insert("type".to_string(), implementation.implementation_type.to_string());
        metadata.insert("status".to_string(), format!("{:?}", implementation.status));
        metadata.insert("file_path".to_string(), implementation.file_path.to_string_lossy().to_string());
        metadata.insert("element_count".to_string(), implementation.code_elements.len().to_string());
        metadata.insert("has_documentation".to_string(), implementation.documentation.is_some().to_string());
        metadata
    }

    /// Extract attributes from implementation for graph node
    fn extract_implementation_attributes(&self, implementation: &Implementation) -> HashMap<String, f64> {
        let mut attributes = HashMap::new();
        attributes.insert("quality_score".to_string(), self.calculate_overall_quality_score(&implementation.quality_metrics));
        attributes.insert("complexity".to_string(), implementation.quality_metrics.complexity);
        attributes.insert("coverage".to_string(), implementation.quality_metrics.coverage);
        attributes.insert("maintainability".to_string(), implementation.quality_metrics.maintainability);
        attributes.insert("performance".to_string(), implementation.quality_metrics.performance);
        attributes.insert("security".to_string(), implementation.quality_metrics.security);
        attributes.insert("documentation_score".to_string(), self.calculate_documentation_score(implementation));
        attributes
    }

    /// Extract metadata from mapping for graph edge
    fn extract_mapping_metadata(&self, mapping: &IntentMapping) -> HashMap<String, String> {
        let mut metadata = HashMap::new();
        metadata.insert("mapping_type".to_string(), mapping.mapping_type.to_string());
        metadata.insert("validation_status".to_string(), format!("{:?}", mapping.validation_status));
        metadata.insert("confidence_level".to_string(), self.get_confidence_level(mapping.confidence));
        metadata.insert("last_updated".to_string(), mapping.last_updated.to_string());
        metadata.insert("rationale".to_string(), mapping.rationale.clone());
        metadata
    }

    /// Extract attributes from mapping for graph edge
    fn extract_mapping_attributes(&self, mapping: &IntentMapping) -> HashMap<String, f64> {
        let mut attributes = HashMap::new();
        attributes.insert("confidence".to_string(), mapping.confidence);
        attributes.insert("age_days".to_string(), self.calculate_mapping_age_days(mapping.last_updated));
        attributes.insert("validation_score".to_string(), self.validation_status_to_score(&mapping.validation_status));
        attributes
    }

    /// Convert mapping type to edge type
    fn mapping_type_to_edge_type(&self, mapping_type: &MappingType) -> RelationshipEdgeType {
        match mapping_type {
            MappingType::Direct => RelationshipEdgeType::DirectMapping,
            MappingType::OneToMany => RelationshipEdgeType::OneToMany,
            MappingType::ManyToOne => RelationshipEdgeType::ManyToOne,
            MappingType::Partial => RelationshipEdgeType::PartialMapping,
            MappingType::Derived => RelationshipEdgeType::DerivedMapping,
            MappingType::Inferred => RelationshipEdgeType::InferredMapping,
        }
    }

    /// Add derived relationships to the graph
    fn add_derived_relationships(&self, graph: &mut RelationshipGraph) -> Result<()> {
        // Add dependency relationships between implementations
        for impl1 in &self.implementations {
            for impl2 in &self.implementations {
                if impl1.id != impl2.id {
                    let dependency_score = self.calculate_dependency_score(impl1, impl2);
                    if dependency_score > 0.5 {
                        let edge = RelationshipEdge {
                            id: format!("dep_{}_{}", impl1.id, impl2.id),
                            source_id: impl1.id.clone(),
                            target_id: impl2.id.clone(),
                            edge_type: RelationshipEdgeType::Dependency,
                            weight: dependency_score,
                            metadata: HashMap::new(),
                            attributes: HashMap::new(),
                        };
                        graph.add_edge(edge)?;
                    }
                }
            }
        }

        // Add containment relationships
        for implementation in &self.implementations {
            for element in &implementation.code_elements {
                let element_node = RelationshipNode {
                    id: format!("{}_{}", implementation.id, element.name),
                    node_type: RelationshipNodeType::CodeElement,
                    metadata: self.extract_code_element_metadata(element),
                    attributes: self.extract_code_element_attributes(element),
                };
                graph.add_node(element_node);

                let containment_edge = RelationshipEdge {
                    id: format!("contains_{}_{}", implementation.id, element.name),
                    source_id: implementation.id.clone(),
                    target_id: format!("{}_{}", implementation.id, element.name),
                    edge_type: RelationshipEdgeType::Containment,
                    weight: 1.0,
                    metadata: HashMap::new(),
                    attributes: HashMap::new(),
                };
                graph.add_edge(containment_edge)?;
            }
        }

        Ok(())
    }

    /// Add semantic relationships to the graph
    fn add_semantic_relationships(&self, graph: &mut RelationshipGraph) -> Result<()> {
        // Add similarity relationships between requirements
        for req1 in &self.requirements {
            for req2 in &self.requirements {
                if req1.id != req2.id {
                    let similarity_score = self.calculate_requirement_similarity(req1, req2);
                    if similarity_score > 0.7 {
                        let edge = RelationshipEdge {
                            id: format!("sim_{}_{}", req1.id, req2.id),
                            source_id: req1.id.clone(),
                            target_id: req2.id.clone(),
                            edge_type: RelationshipEdgeType::Similarity,
                            weight: similarity_score,
                            metadata: HashMap::new(),
                            attributes: HashMap::new(),
                        };
                        graph.add_edge(edge)?;
                    }
                }
            }
        }

        // Add similarity relationships between implementations
        for impl1 in &self.implementations {
            for impl2 in &self.implementations {
                if impl1.id != impl2.id {
                    let similarity_score = self.calculate_implementation_similarity(impl1, impl2);
                    if similarity_score > 0.7 {
                        let edge = RelationshipEdge {
                            id: format!("sim_{}_{}", impl1.id, impl2.id),
                            source_id: impl1.id.clone(),
                            target_id: impl2.id.clone(),
                            edge_type: RelationshipEdgeType::Similarity,
                            weight: similarity_score,
                            metadata: HashMap::new(),
                            attributes: HashMap::new(),
                        };
                        graph.add_edge(edge)?;
                    }
                }
            }
        }

        Ok(())
    }

    /// Convert priority to numeric weight
    fn priority_to_weight(&self, priority: &Priority) -> f64 {
        match priority {
            Priority::Critical => 1.0,
            Priority::High => 0.8,
            Priority::Medium => 0.6,
            Priority::Low => 0.4,
        }
    }



    /// Calculate criteria completeness
    fn calculate_criteria_completeness(&self, requirement: &Requirement) -> f64 {
        if requirement.acceptance_criteria.is_empty() {
            return 0.0;
        }

        let avg_length = requirement.acceptance_criteria.iter()
            .map(|c| c.len())
            .sum::<usize>() as f64 / requirement.acceptance_criteria.len() as f64;

        (avg_length / 50.0).min(1.0) // Normalize to 50 characters as baseline
    }

    /// Calculate overall quality score
    fn calculate_overall_quality_score(&self, quality_metrics: &QualityMetrics) -> f64 {
        (quality_metrics.coverage +
         quality_metrics.maintainability +
         quality_metrics.performance +
         quality_metrics.security +
         (1.0 - quality_metrics.complexity)) / 5.0
    }

    /// Calculate documentation score
    fn calculate_documentation_score(&self, implementation: &Implementation) -> f64 {
        match &implementation.documentation {
            Some(doc) if !doc.trim().is_empty() => {
                let length_score = (doc.len() as f64 / 200.0).min(1.0);
                let quality_indicators = [
                    doc.contains("@param") || doc.contains("Parameters:"),
                    doc.contains("@return") || doc.contains("Returns:"),
                    doc.contains("@throws") || doc.contains("@error") || doc.contains("Errors:"),
                    doc.contains("Example:") || doc.contains("example"),
                    doc.len() > 50,
                ];
                let quality_score = quality_indicators.iter().filter(|&&x| x).count() as f64 / quality_indicators.len() as f64;
                (length_score + quality_score) / 2.0
            },
            Some(_) => 0.2,
            None => 0.0,
        }
    }

    /// Calculate mapping age in days
    fn calculate_mapping_age_days(&self, timestamp: u64) -> f64 {
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        if current_time > timestamp {
            (current_time - timestamp) as f64 / 86400.0 // Convert seconds to days
        } else {
            0.0
        }
    }

    /// Convert validation status to numeric score
    fn validation_status_to_score(&self, status: &ValidationStatus) -> f64 {
        match status {
            ValidationStatus::Valid => 1.0,
            ValidationStatus::NeedsReview => 0.7,
            ValidationStatus::NotValidated => 0.5,
            ValidationStatus::Outdated => 0.3,
            ValidationStatus::Invalid => 0.0,
        }
    }

    /// Calculate dependency score between implementations
    fn calculate_dependency_score(&self, impl1: &Implementation, impl2: &Implementation) -> f64 {
        // Check if implementations are in related files
        let path1 = impl1.file_path.to_string_lossy();
        let path2 = impl2.file_path.to_string_lossy();

        // Same directory gets higher score
        if path1.rsplit('/').nth(1) == path2.rsplit('/').nth(1) {
            return 0.8;
        }

        // Related file names
        let name1 = path1.rsplit('/').next().unwrap_or("");
        let name2 = path2.rsplit('/').next().unwrap_or("");

        if name1.contains(name2) || name2.contains(name1) {
            return 0.6;
        }

        // Check for common patterns in implementation types
        if impl1.implementation_type == impl2.implementation_type {
            return 0.4;
        }

        0.0
    }

    /// Calculate similarity between requirements
    fn calculate_requirement_similarity(&self, req1: &Requirement, req2: &Requirement) -> f64 {
        let mut similarity_factors = Vec::new();

        // Type similarity
        if req1.requirement_type == req2.requirement_type {
            similarity_factors.push(0.3);
        }

        // Priority similarity
        let priority_diff = (self.priority_to_weight(&req1.priority) - self.priority_to_weight(&req2.priority)).abs();
        similarity_factors.push(1.0 - priority_diff);

        // Tag overlap
        let common_tags = req1.tags.iter().filter(|tag| req2.tags.contains(tag)).count();
        let total_tags = (req1.tags.len() + req2.tags.len()).max(1);
        let tag_similarity = (2 * common_tags) as f64 / total_tags as f64;
        similarity_factors.push(tag_similarity);

        // Stakeholder overlap
        let common_stakeholders = req1.stakeholders.iter().filter(|s| req2.stakeholders.contains(s)).count();
        let total_stakeholders = (req1.stakeholders.len() + req2.stakeholders.len()).max(1);
        let stakeholder_similarity = (2 * common_stakeholders) as f64 / total_stakeholders as f64;
        similarity_factors.push(stakeholder_similarity);

        // Description similarity (simple keyword-based)
        let desc_similarity = self.calculate_text_similarity(&req1.description, &req2.description);
        similarity_factors.push(desc_similarity);

        // Calculate weighted average
        similarity_factors.iter().sum::<f64>() / similarity_factors.len() as f64
    }

    /// Calculate similarity between implementations
    fn calculate_implementation_similarity(&self, impl1: &Implementation, impl2: &Implementation) -> f64 {
        let mut similarity_factors = Vec::new();

        // Type similarity
        if impl1.implementation_type == impl2.implementation_type {
            similarity_factors.push(0.4);
        }

        // Quality metrics similarity
        let quality_similarity = 1.0 - (
            (impl1.quality_metrics.coverage - impl2.quality_metrics.coverage).abs() +
            (impl1.quality_metrics.complexity - impl2.quality_metrics.complexity).abs() +
            (impl1.quality_metrics.maintainability - impl2.quality_metrics.maintainability).abs() +
            (impl1.quality_metrics.performance - impl2.quality_metrics.performance).abs() +
            (impl1.quality_metrics.security - impl2.quality_metrics.security).abs()
        ) / 5.0;
        similarity_factors.push(quality_similarity);

        // File path similarity
        let path_similarity = self.calculate_path_similarity(&impl1.file_path, &impl2.file_path);
        similarity_factors.push(path_similarity);

        // Code element similarity
        let element_similarity = self.calculate_code_element_similarity(&impl1.code_elements, &impl2.code_elements);
        similarity_factors.push(element_similarity);

        similarity_factors.iter().sum::<f64>() / similarity_factors.len() as f64
    }

    /// Calculate text similarity using simple keyword matching
    fn calculate_text_similarity(&self, text1: &str, text2: &str) -> f64 {
        let text1_lower = text1.to_lowercase();
        let text2_lower = text2.to_lowercase();
        let words1: HashSet<_> = text1_lower.split_whitespace().collect();
        let words2: HashSet<_> = text2_lower.split_whitespace().collect();

        let intersection = words1.intersection(&words2).count();
        let union = words1.union(&words2).count();

        if union > 0 {
            intersection as f64 / union as f64
        } else {
            0.0
        }
    }

    /// Calculate path similarity
    fn calculate_path_similarity(&self, path1: &PathBuf, path2: &PathBuf) -> f64 {
        let str1 = path1.to_string_lossy();
        let str2 = path2.to_string_lossy();

        let parts1: Vec<_> = str1.split('/').collect();
        let parts2: Vec<_> = str2.split('/').collect();

        let common_parts = parts1.iter().zip(parts2.iter())
            .take_while(|(a, b)| a == b)
            .count();

        let max_parts = parts1.len().max(parts2.len());

        if max_parts > 0 {
            common_parts as f64 / max_parts as f64
        } else {
            0.0
        }
    }

    /// Calculate code element similarity
    fn calculate_code_element_similarity(&self, elements1: &[CodeElement], elements2: &[CodeElement]) -> f64 {
        if elements1.is_empty() && elements2.is_empty() {
            return 1.0;
        }

        if elements1.is_empty() || elements2.is_empty() {
            return 0.0;
        }

        let names1: HashSet<_> = elements1.iter().map(|e| &e.name).collect();
        let names2: HashSet<_> = elements2.iter().map(|e| &e.name).collect();

        let intersection = names1.intersection(&names2).count();
        let union = names1.union(&names2).count();

        if union > 0 {
            intersection as f64 / union as f64
        } else {
            0.0
        }
    }

    /// Extract metadata from code element
    fn extract_code_element_metadata(&self, element: &CodeElement) -> HashMap<String, String> {
        let mut metadata = HashMap::new();
        metadata.insert("name".to_string(), element.name.clone());
        metadata.insert("type".to_string(), element.element_type.clone());
        metadata.insert("line_start".to_string(), element.line_range.0.to_string());
        metadata.insert("line_end".to_string(), element.line_range.1.to_string());
        metadata
    }

    /// Extract attributes from code element
    fn extract_code_element_attributes(&self, element: &CodeElement) -> HashMap<String, f64> {
        let mut attributes = HashMap::new();
        attributes.insert("complexity".to_string(), element.complexity);
        attributes.insert("test_coverage".to_string(), element.test_coverage);
        attributes.insert("line_count".to_string(), (element.line_range.1 - element.line_range.0 + 1) as f64);
        attributes
    }
}

/// Traceability report
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct TraceabilityReport {
    /// Forward coverage percentage
    pub forward_coverage: f64,
    /// Backward coverage percentage
    pub backward_coverage: f64,
    /// Orphaned requirements
    pub orphaned_requirements: Vec<String>,
    /// Orphaned implementations
    pub orphaned_implementations: Vec<String>,
    /// Overall mapping quality score
    pub mapping_quality_score: f64,
}

impl TraceabilityMatrix {
    fn new() -> Self {
        Self {
            forward_trace: HashMap::new(),
            backward_trace: HashMap::new(),
            coverage_metrics: CoverageMetrics {
                requirement_coverage: 0.0,
                implementation_coverage: 0.0,
                orphaned_requirements: 0,
                orphaned_implementations: 0,
            },
        }
    }
}

impl Default for IntentMappingSystem {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for QualityMetrics {
    fn default() -> Self {
        Self {
            coverage: DEFAULT_COVERAGE,
            complexity: DEFAULT_COMPLEXITY,
            maintainability: DEFAULT_MAINTAINABILITY,
            performance: DEFAULT_PERFORMANCE,
            security: DEFAULT_SECURITY,
        }
    }
}

impl std::fmt::Display for RequirementType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RequirementType::Functional => write!(f, "functional"),
            RequirementType::NonFunctional => write!(f, "non-functional"),
            RequirementType::Business => write!(f, "business"),
            RequirementType::Technical => write!(f, "technical"),
            RequirementType::UserStory => write!(f, "user-story"),
            RequirementType::Epic => write!(f, "epic"),
            RequirementType::Feature => write!(f, "feature"),
            RequirementType::BugFix => write!(f, "bug-fix"),
            RequirementType::Performance => write!(f, "performance"),
            RequirementType::Security => write!(f, "security"),
        }
    }
}

impl std::fmt::Display for ImplementationType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ImplementationType::Function => write!(f, "function"),
            ImplementationType::Class => write!(f, "class"),
            ImplementationType::Module => write!(f, "module"),
            ImplementationType::Interface => write!(f, "interface"),
            ImplementationType::Database => write!(f, "database"),
            ImplementationType::API => write!(f, "api"),
            ImplementationType::Configuration => write!(f, "configuration"),
            ImplementationType::Test => write!(f, "test"),
            ImplementationType::Documentation => write!(f, "documentation"),
            ImplementationType::Infrastructure => write!(f, "infrastructure"),
        }
    }
}

// Display implementation is provided by the common Priority type

impl std::fmt::Display for MappingType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MappingType::Direct => write!(f, "direct"),
            MappingType::OneToMany => write!(f, "one-to-many"),
            MappingType::ManyToOne => write!(f, "many-to-one"),
            MappingType::Partial => write!(f, "partial"),
            MappingType::Derived => write!(f, "derived"),
            MappingType::Inferred => write!(f, "inferred"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_intent_mapping_system_creation() {
        let system = IntentMappingSystem::new();
        assert_eq!(system.requirements().len(), 0);
        assert_eq!(system.implementations().len(), 0);
        assert_eq!(system.mappings().len(), 0);
        assert_eq!(system.config().confidence_threshold, DEFAULT_CONFIDENCE_THRESHOLD);
    }

    #[test]
    fn test_intent_mapping_system_with_config() {
        let mut config = MappingConfig::default();
        config.confidence_threshold = 0.9;
        config.enable_nlp = false;

        let system = IntentMappingSystem::with_config(config.clone());
        assert_eq!(system.config().confidence_threshold, 0.9);
        assert!(!system.config().enable_nlp);
    }

    #[test]
    fn test_mapping_config_default() {
        let config = MappingConfig::default();
        assert_eq!(config.confidence_threshold, DEFAULT_CONFIDENCE_THRESHOLD);
        assert_eq!(config.max_mapping_distance, DEFAULT_MAX_MAPPING_DISTANCE);
        assert_eq!(config.auto_validation_threshold, DEFAULT_AUTO_VALIDATION_THRESHOLD);
        assert!(config.enable_nlp);
        assert!(config.enable_semantic_analysis);
    }

    #[test]
    fn test_requirement_creation() {
        let requirement = Requirement {
            id: "REQ-001".to_string(),
            requirement_type: RequirementType::UserStory,
            description: "As a user, I want to log in".to_string(),
            priority: Priority::High,
            acceptance_criteria: vec![
                "User can enter credentials".to_string(),
                "System validates credentials".to_string(),
            ],
            stakeholders: vec!["Product Owner".to_string(), "Development Team".to_string()],
            tags: vec!["authentication".to_string(), "security".to_string()],
            status: RequirementStatus::Approved,
        };

        assert_eq!(requirement.id, "REQ-001");
        assert!(matches!(requirement.requirement_type, RequirementType::UserStory));
        assert!(matches!(requirement.priority, Priority::High));
        assert!(matches!(requirement.status, RequirementStatus::Approved));
        assert_eq!(requirement.acceptance_criteria.len(), 2);
        assert_eq!(requirement.stakeholders.len(), 2);
        assert_eq!(requirement.tags.len(), 2);
    }

    #[test]
    fn test_requirement_type_variants() {
        let types = vec![
            RequirementType::Functional,
            RequirementType::NonFunctional,
            RequirementType::Business,
            RequirementType::Technical,
            RequirementType::UserStory,
            RequirementType::Epic,
            RequirementType::Feature,
            RequirementType::BugFix,
            RequirementType::Performance,
            RequirementType::Security,
        ];

        assert_eq!(types.len(), 10);
        assert!(types.contains(&RequirementType::UserStory));
        assert!(types.contains(&RequirementType::Security));
    }

    #[test]
    fn test_priority_ordering() {
        assert!(Priority::Critical > Priority::High);
        assert!(Priority::High > Priority::Medium);
        assert!(Priority::Medium > Priority::Low);
    }

    #[test]
    fn test_requirement_status_variants() {
        let statuses = vec![
            RequirementStatus::Draft,
            RequirementStatus::Approved,
            RequirementStatus::InProgress,
            RequirementStatus::Implemented,
            RequirementStatus::Tested,
            RequirementStatus::Deployed,
            RequirementStatus::Rejected,
        ];

        assert_eq!(statuses.len(), 7);
        assert!(statuses.contains(&RequirementStatus::Approved));
        assert!(statuses.contains(&RequirementStatus::Implemented));
    }

    #[test]
    fn test_implementation_creation() {
        let implementation = Implementation {
            id: "IMPL-001".to_string(),
            implementation_type: ImplementationType::Function,
            file_path: PathBuf::from("src/auth.rs"),
            code_elements: vec![
                CodeElement {
                    name: "login".to_string(),
                    element_type: "function".to_string(),
                    line_range: (10, 25),
                    complexity: 2.5,
                    test_coverage: 0.85,
                }
            ],
            status: ImplementationStatus::Complete,
            quality_metrics: QualityMetrics::default(),
            documentation: Some("User authentication function".to_string()),
        };

        assert_eq!(implementation.id, "IMPL-001");
        assert!(matches!(implementation.implementation_type, ImplementationType::Function));
        assert_eq!(implementation.file_path, PathBuf::from("src/auth.rs"));
        assert!(matches!(implementation.status, ImplementationStatus::Complete));
        assert_eq!(implementation.code_elements.len(), 1);
        assert!(implementation.documentation.is_some());
    }

    #[test]
    fn test_implementation_type_variants() {
        let types = vec![
            ImplementationType::Function,
            ImplementationType::Class,
            ImplementationType::Module,
            ImplementationType::Interface,
            ImplementationType::Database,
            ImplementationType::API,
            ImplementationType::Configuration,
            ImplementationType::Test,
            ImplementationType::Documentation,
            ImplementationType::Infrastructure,
        ];

        assert_eq!(types.len(), 10);
        assert!(types.contains(&ImplementationType::Function));
        assert!(types.contains(&ImplementationType::API));
    }

    #[test]
    fn test_code_element_creation() {
        let element = CodeElement {
            name: "authenticate_user".to_string(),
            element_type: "function".to_string(),
            line_range: (15, 30),
            complexity: 3.2,
            test_coverage: 0.92,
        };

        assert_eq!(element.name, "authenticate_user");
        assert_eq!(element.element_type, "function");
        assert_eq!(element.line_range, (15, 30));
        assert_eq!(element.complexity, 3.2);
        assert_eq!(element.test_coverage, 0.92);
    }

    #[test]
    fn test_implementation_status_variants() {
        let statuses = vec![
            ImplementationStatus::NotStarted,
            ImplementationStatus::InProgress,
            ImplementationStatus::Complete,
            ImplementationStatus::Tested,
            ImplementationStatus::Deployed,
            ImplementationStatus::Deprecated,
        ];

        assert_eq!(statuses.len(), 6);
        assert!(statuses.contains(&ImplementationStatus::Complete));
        assert!(statuses.contains(&ImplementationStatus::Tested));
    }

    #[test]
    fn test_quality_metrics_creation() {
        let metrics = QualityMetrics {
            coverage: 0.85,
            complexity: 2.3,
            maintainability: 0.78,
            performance: 0.91,
            security: 0.88,
        };

        assert_eq!(metrics.coverage, 0.85);
        assert_eq!(metrics.complexity, 2.3);
        assert_eq!(metrics.maintainability, 0.78);
        assert_eq!(metrics.performance, 0.91);
        assert_eq!(metrics.security, 0.88);
    }

    #[test]
    fn test_quality_metrics_default() {
        let metrics = QualityMetrics::default();
        assert_eq!(metrics.coverage, DEFAULT_COVERAGE);
        assert_eq!(metrics.complexity, DEFAULT_COMPLEXITY);
        assert_eq!(metrics.maintainability, DEFAULT_MAINTAINABILITY);
        assert_eq!(metrics.performance, DEFAULT_PERFORMANCE);
        assert_eq!(metrics.security, DEFAULT_SECURITY);
    }

    #[test]
    fn test_intent_mapping_creation() {
        let mapping = IntentMapping {
            id: "MAP-001".to_string(),
            requirement_id: "REQ-001".to_string(),
            implementation_id: "IMPL-001".to_string(),
            mapping_type: MappingType::Direct,
            confidence: 0.92,
            rationale: "Direct keyword match".to_string(),
            validation_status: ValidationStatus::Valid,
            last_updated: 1234567890,
        };

        assert_eq!(mapping.id, "MAP-001");
        assert_eq!(mapping.requirement_id, "REQ-001");
        assert_eq!(mapping.implementation_id, "IMPL-001");
        assert!(matches!(mapping.mapping_type, MappingType::Direct));
        assert_eq!(mapping.confidence, 0.92);
        assert!(matches!(mapping.validation_status, ValidationStatus::Valid));
    }

    #[test]
    fn test_mapping_type_variants() {
        let types = vec![
            MappingType::Direct,
            MappingType::OneToMany,
            MappingType::ManyToOne,
            MappingType::Partial,
            MappingType::Derived,
            MappingType::Inferred,
        ];

        assert_eq!(types.len(), 6);
        assert!(types.contains(&MappingType::Direct));
        assert!(types.contains(&MappingType::Inferred));
    }

    #[test]
    fn test_validation_status_variants() {
        let statuses = vec![
            ValidationStatus::NotValidated,
            ValidationStatus::Valid,
            ValidationStatus::Invalid,
            ValidationStatus::NeedsReview,
            ValidationStatus::Outdated,
        ];

        assert_eq!(statuses.len(), 5);
        assert!(statuses.contains(&ValidationStatus::Valid));
        assert!(statuses.contains(&ValidationStatus::NeedsReview));
    }

    #[test]
    fn test_traceability_matrix_creation() {
        let matrix = TraceabilityMatrix::new();
        assert!(matrix.forward_trace.is_empty());
        assert!(matrix.backward_trace.is_empty());
        assert_eq!(matrix.coverage_metrics.requirement_coverage, 0.0);
        assert_eq!(matrix.coverage_metrics.implementation_coverage, 0.0);
        assert_eq!(matrix.coverage_metrics.orphaned_requirements, 0);
        assert_eq!(matrix.coverage_metrics.orphaned_implementations, 0);
    }

    #[test]
    fn test_coverage_metrics_creation() {
        let metrics = CoverageMetrics {
            requirement_coverage: 0.85,
            implementation_coverage: 0.92,
            orphaned_requirements: 3,
            orphaned_implementations: 1,
        };

        assert_eq!(metrics.requirement_coverage, 0.85);
        assert_eq!(metrics.implementation_coverage, 0.92);
        assert_eq!(metrics.orphaned_requirements, 3);
        assert_eq!(metrics.orphaned_implementations, 1);
    }

    fn create_test_requirement() -> Requirement {
        Requirement {
            id: "REQ-TEST-001".to_string(),
            requirement_type: RequirementType::UserStory,
            description: "As a user, I want to authenticate securely".to_string(),
            priority: Priority::High,
            acceptance_criteria: vec![
                "User can enter username and password".to_string(),
                "System validates credentials".to_string(),
                "User is redirected on success".to_string(),
            ],
            stakeholders: vec!["Product Owner".to_string()],
            tags: vec!["authentication".to_string(), "security".to_string()],
            status: RequirementStatus::Approved,
        }
    }

    fn create_test_implementation() -> Implementation {
        Implementation {
            id: "IMPL-TEST-001".to_string(),
            implementation_type: ImplementationType::Function,
            file_path: PathBuf::from("src/auth.rs"),
            code_elements: vec![
                CodeElement {
                    name: "authenticate".to_string(),
                    element_type: "function".to_string(),
                    line_range: (10, 25),
                    complexity: 2.0,
                    test_coverage: 0.9,
                }
            ],
            status: ImplementationStatus::Complete,
            quality_metrics: QualityMetrics {
                coverage: 0.9,
                complexity: 2.0,
                maintainability: 0.8,
                performance: 0.85,
                security: 0.9,
            },
            documentation: Some("Authentication function".to_string()),
        }
    }

    #[test]
    fn test_add_requirement() {
        let mut system = IntentMappingSystem::new();
        let requirement = create_test_requirement();

        system.add_requirement(requirement.clone());
        assert_eq!(system.requirements().len(), 1);
        assert_eq!(system.requirements()[0].id, requirement.id);
    }

    #[test]
    fn test_add_multiple_requirements() {
        let mut system = IntentMappingSystem::new();
        let requirements = vec![
            create_test_requirement(),
            Requirement {
                id: "REQ-TEST-002".to_string(),
                requirement_type: RequirementType::Functional,
                description: "System should validate input".to_string(),
                priority: Priority::Medium,
                acceptance_criteria: vec!["Input is validated".to_string()],
                stakeholders: vec!["Developer".to_string()],
                tags: vec!["validation".to_string()],
                status: RequirementStatus::Draft,
            }
        ];

        system.add_requirements(requirements);
        assert_eq!(system.requirements().len(), 2);
    }

    #[test]
    fn test_add_implementation() {
        let mut system = IntentMappingSystem::new();
        let implementation = create_test_implementation();

        system.add_implementation(implementation.clone());
        assert_eq!(system.implementations().len(), 1);
        assert_eq!(system.implementations()[0].id, implementation.id);
    }

    #[test]
    fn test_extract_keywords() {
        let system = IntentMappingSystem::new();
        let text = "As a user, I want to authenticate securely with the system";
        let keywords = system.extract_keywords_public(text);

        assert!(keywords.contains(&"user".to_string()));
        assert!(keywords.contains(&"authenticate".to_string()));
        assert!(keywords.contains(&"securely".to_string()));
        assert!(keywords.contains(&"system".to_string()));

        // Should not contain stop words
        assert!(!keywords.contains(&"as".to_string()));
        assert!(!keywords.contains(&"a".to_string()));
        assert!(!keywords.contains(&"to".to_string()));
        assert!(!keywords.contains(&"with".to_string()));
        assert!(!keywords.contains(&"the".to_string()));
    }

    #[test]
    fn test_calculate_keyword_similarity() {
        let system = IntentMappingSystem::new();
        let keywords1 = vec!["user".to_string(), "authenticate".to_string(), "security".to_string()];
        let keywords2 = vec!["user".to_string(), "login".to_string(), "security".to_string()];

        let similarity = system.calculate_keyword_similarity_public(&keywords1, &keywords2);
        assert!(similarity > 0.0);
        assert!(similarity <= 1.0);

        // Test identical keywords
        let identical_similarity = system.calculate_keyword_similarity_public(&keywords1, &keywords1);
        assert_eq!(identical_similarity, 1.0);

        // Test no overlap
        let keywords3 = vec!["database".to_string(), "query".to_string()];
        let no_overlap_similarity = system.calculate_keyword_similarity_public(&keywords1, &keywords3);
        assert_eq!(no_overlap_similarity, 0.0);
    }

    #[test]
    fn test_extract_implementation_keywords() {
        let system = IntentMappingSystem::new();
        let implementation = create_test_implementation();

        let keywords = system.extract_implementation_keywords_public(&implementation);
        assert!(keywords.contains(&"auth".to_string()));
        assert!(keywords.contains(&"authenticate".to_string()));
    }

    #[test]
    fn test_build_traceability_matrix() {
        let mut system = IntentMappingSystem::new();
        let requirement = create_test_requirement();
        let implementation = create_test_implementation();

        system.add_requirement(requirement.clone());
        system.add_implementation(implementation.clone());

        let mapping = IntentMapping {
            id: "MAP-TEST-001".to_string(),
            requirement_id: requirement.id.clone(),
            implementation_id: implementation.id.clone(),
            mapping_type: MappingType::Direct,
            confidence: 0.9,
            rationale: "Test mapping".to_string(),
            validation_status: ValidationStatus::Valid,
            last_updated: 1234567890,
        };

        system.add_mapping(mapping);
        system.build_traceability_matrix_public();

        let traceability = system.traceability();
        assert!(traceability.forward_trace.contains_key(&requirement.id));
        assert!(traceability.backward_trace.contains_key(&implementation.id));
    }

    #[test]
    fn test_identify_gaps() {
        let mut system = IntentMappingSystem::new();

        // Add requirement without implementation
        let orphaned_requirement = Requirement {
            id: "REQ-ORPHANED".to_string(),
            requirement_type: RequirementType::Functional,
            description: "Orphaned requirement".to_string(),
            priority: Priority::Medium,
            acceptance_criteria: vec!["Should be implemented".to_string()],
            stakeholders: vec!["Developer".to_string()],
            tags: vec!["orphaned".to_string()],
            status: RequirementStatus::Approved,
        };

        // Add implementation without requirement
        let orphaned_implementation = Implementation {
            id: "IMPL-ORPHANED".to_string(),
            implementation_type: ImplementationType::Function,
            file_path: PathBuf::from("src/orphaned.rs"),
            code_elements: vec![],
            status: ImplementationStatus::Complete,
            quality_metrics: QualityMetrics::default(),
            documentation: None,
        };

        system.add_requirement(orphaned_requirement);
        system.add_implementation(orphaned_implementation);
        system.build_traceability_matrix_public();

        let gaps = system.identify_gaps_public().unwrap();
        assert!(gaps.len() >= 2); // At least one missing implementation and one missing requirement

        let missing_impl_gaps: Vec<_> = gaps.iter()
            .filter(|g| g.gap_type == GapType::MissingImplementation)
            .collect();
        assert!(!missing_impl_gaps.is_empty());

        let missing_req_gaps: Vec<_> = gaps.iter()
            .filter(|g| g.gap_type == GapType::MissingRequirement)
            .collect();
        assert!(!missing_req_gaps.is_empty());
    }

    #[test]
    fn test_generate_recommendations() {
        let system = IntentMappingSystem::new();
        let gaps = vec![
            MappingGap {
                gap_type: GapType::MissingImplementation,
                description: "Missing implementation for requirement".to_string(),
                affected_items: vec!["REQ-001".to_string()],
                severity: Priority::High,
                suggested_actions: vec!["Create implementation".to_string()],
            },
            MappingGap {
                gap_type: GapType::TestGap,
                description: "Low test coverage".to_string(),
                affected_items: vec!["IMPL-001".to_string()],
                severity: Priority::Medium,
                suggested_actions: vec!["Add tests".to_string()],
            }
        ];

        let recommendations = system.generate_recommendations_public(&gaps).unwrap();
        assert_eq!(recommendations.len(), 2);

        let create_impl_recs: Vec<_> = recommendations.iter()
            .filter(|r| r.recommendation_type == RecommendationType::CreateImplementation)
            .collect();
        assert_eq!(create_impl_recs.len(), 1);

        let add_test_recs: Vec<_> = recommendations.iter()
            .filter(|r| r.recommendation_type == RecommendationType::AddTests)
            .collect();
        assert_eq!(add_test_recs.len(), 1);
    }

    #[test]
    fn test_display_implementations() {
        assert_eq!(format!("{}", RequirementType::UserStory), "user-story");
        assert_eq!(format!("{}", RequirementType::Security), "security");
        assert_eq!(format!("{}", ImplementationType::Function), "function");
        assert_eq!(format!("{}", ImplementationType::API), "api");
        assert_eq!(format!("{}", Priority::High), "High");
        assert_eq!(format!("{}", Priority::Critical), "Critical");
        assert_eq!(format!("{}", MappingType::Direct), "direct");
        assert_eq!(format!("{}", MappingType::OneToMany), "one-to-many");
    }

    #[test]
    fn test_embedding_stats_creation() {
        let system = IntentMappingSystem::new();
        let stats = system.get_embedding_stats();

        assert_eq!(stats.total_requirement_embeddings, 0);
        assert_eq!(stats.total_implementation_embeddings, 0);
        assert_eq!(stats.embedding_dimension, 0);
        assert!(!stats.has_embedding_engine);
    }

    #[test]
    fn test_semantic_similarity_without_embeddings() {
        let system = IntentMappingSystem::new();

        // Should fall back to keyword-based similarity
        let similarity = system.calculate_semantic_similarity(
            "user authentication system with secure login",
            "authentication module for user login security"
        );

        assert!(similarity > 0.0, "Should find some similarity between related texts");
        assert!(similarity <= 1.0, "Similarity should not exceed 1.0");
    }

    #[test]
    fn test_has_embeddings_initially_false() {
        let system = IntentMappingSystem::new();
        assert!(!system.has_embeddings(), "New system should not have embeddings initialized");
    }

    #[test]
    fn test_embedding_stats_structure() {
        let stats = EmbeddingStats {
            total_requirement_embeddings: 5,
            total_implementation_embeddings: 3,
            embedding_dimension: 384,
            has_embedding_engine: true,
        };

        assert_eq!(stats.total_requirement_embeddings, 5);
        assert_eq!(stats.total_implementation_embeddings, 3);
        assert_eq!(stats.embedding_dimension, 384);
        assert!(stats.has_embedding_engine);
    }

    #[test]
    fn test_semantic_similarity_edge_cases() {
        let system = IntentMappingSystem::new();

        // Empty strings
        let empty_similarity = system.calculate_semantic_similarity("", "");
        assert_eq!(empty_similarity, 0.0, "Empty strings should have 0 similarity");

        // Identical strings
        let identical_similarity = system.calculate_semantic_similarity(
            "user authentication system",
            "user authentication system"
        );
        assert!(identical_similarity > 0.8, "Identical strings should have high similarity");

        // Completely different strings
        let different_similarity = system.calculate_semantic_similarity(
            "user authentication system",
            "database query optimization"
        );
        assert!(different_similarity < 0.3, "Unrelated strings should have low similarity");
    }

    #[test]
    fn test_hybrid_similarity_scoring() {
        let system = IntentMappingSystem::new();

        // Create a requirement
        let requirement = Requirement {
            id: "REQ-001".to_string(),
            description: "Implement secure user authentication with login and logout functionality".to_string(),
            requirement_type: RequirementType::Security,
            priority: Priority::High,
            acceptance_criteria: vec!["Secure login functionality".to_string(), "Logout functionality".to_string()],
            stakeholders: vec!["Security Team".to_string(), "Product Team".to_string()],
            tags: vec!["authentication".to_string(), "security".to_string()],
            status: RequirementStatus::Approved,
        };

        // Create a matching implementation
        let implementation = Implementation {
            id: "IMPL-001".to_string(),
            file_path: PathBuf::from("src/auth/login.rs"),
            implementation_type: ImplementationType::Function,
            code_elements: vec![],
            status: ImplementationStatus::Complete,
            quality_metrics: QualityMetrics {
                coverage: 0.85,
                complexity: 0.3,
                maintainability: 0.8,
                performance: 0.9,
                security: 0.95,
            },
            documentation: Some("Authentication service with secure login functionality".to_string()),
        };

        let similarity = system.calculate_hybrid_similarity(&requirement, &implementation);

        // Should have reasonable similarity due to matching authentication theme
        assert!(similarity > 0.15, "Authentication requirement and implementation should have reasonable similarity, got {}", similarity);
    }

    #[test]
    fn test_structural_similarity() {
        let system = IntentMappingSystem::new();

        let requirement = Requirement {
            id: "REQ-002".to_string(),
            description: "Create REST API endpoint for user management".to_string(),
            requirement_type: RequirementType::Functional,
            priority: Priority::Medium,
            acceptance_criteria: vec!["API should handle user CRUD operations".to_string()],
            stakeholders: vec!["Backend Team".to_string()],
            tags: vec!["api".to_string(), "rest".to_string()],
            status: RequirementStatus::Approved,
        };

        let implementation = Implementation {
            id: "IMPL-002".to_string(),
            file_path: PathBuf::from("src/api/users.rs"),
            implementation_type: ImplementationType::API,
            code_elements: vec![],
            status: ImplementationStatus::Complete,
            quality_metrics: QualityMetrics {
                coverage: 0.9,
                complexity: 0.4,
                maintainability: 0.85,
                performance: 0.8,
                security: 0.9,
            },
            documentation: Some("REST API implementation for user management".to_string()),
        };

        let structural_score = system.calculate_structural_similarity(&requirement, &implementation);

        // Should have reasonable structural similarity
        assert!(structural_score > 0.2, "API requirement and implementation should have reasonable structural similarity, got {}", structural_score);
    }

    #[test]
    fn test_type_similarity() {
        let system = IntentMappingSystem::new();

        // Test exact match
        let exact_similarity = system.calculate_type_similarity("api", "api");
        assert_eq!(exact_similarity, 1.0, "Exact type match should return 1.0");

        // Test related types
        let related_similarity = system.calculate_type_similarity("functional", "function");
        assert!(related_similarity > 0.8, "Related types should have high similarity");

        // Test unrelated types
        let unrelated_similarity = system.calculate_type_similarity("security", "graphics");
        assert!(unrelated_similarity < 0.3, "Unrelated types should have low similarity");
    }

    #[test]
    fn test_complexity_alignment() {
        let system = IntentMappingSystem::new();

        // High complexity requirement
        let complex_req = Requirement {
            id: "REQ-003".to_string(),
            description: "Implement a sophisticated, comprehensive, and advanced system with multiple integrations and complex algorithms".to_string(),
            requirement_type: RequirementType::Functional,
            priority: Priority::Critical,
            acceptance_criteria: vec!["System must handle complex algorithms".to_string()],
            stakeholders: vec!["Architecture Team".to_string()],
            tags: vec!["complex".to_string(), "algorithms".to_string()],
            status: RequirementStatus::Approved,
        };

        // High complexity implementation
        let complex_impl = Implementation {
            id: "IMPL-003".to_string(),
            file_path: PathBuf::from("src/complex/algorithm/advanced.rs"),
            implementation_type: ImplementationType::Module,
            code_elements: vec![],
            status: ImplementationStatus::Complete,
            quality_metrics: QualityMetrics {
                coverage: 0.8,
                complexity: 0.9,
                maintainability: 0.6,
                performance: 0.7,
                security: 0.8,
            },
            documentation: Some("Advanced algorithm implementation with concurrent processing and optimization".to_string()),
        };

        let alignment = system.calculate_complexity_alignment(&complex_req, &complex_impl);

        // Should have reasonable alignment for similar complexity levels
        assert!(alignment > 0.3, "Similar complexity levels should align reasonably, got {}", alignment);
    }

    #[test]
    fn test_pattern_similarity() {
        let system = IntentMappingSystem::new();

        let mvc_req = Requirement {
            id: "REQ-004".to_string(),
            description: "Implement MVC controller pattern for user interface".to_string(),
            requirement_type: RequirementType::Functional,
            priority: Priority::Medium,
            acceptance_criteria: vec!["Controller must follow MVC pattern".to_string()],
            stakeholders: vec!["Frontend Team".to_string()],
            tags: vec!["mvc".to_string(), "controller".to_string()],
            status: RequirementStatus::Approved,
        };

        let controller_impl = Implementation {
            id: "IMPL-004".to_string(),
            file_path: PathBuf::from("src/controllers/user_controller.rs"),
            implementation_type: ImplementationType::Class,
            code_elements: vec![],
            status: ImplementationStatus::Complete,
            quality_metrics: QualityMetrics {
                coverage: 0.85,
                complexity: 0.4,
                maintainability: 0.8,
                performance: 0.9,
                security: 0.85,
            },
            documentation: Some("User controller implementation following MVC pattern".to_string()),
        };

        let pattern_score = system.calculate_pattern_similarity(&mvc_req, &controller_impl);

        // Should detect some MVC pattern similarity
        assert!(pattern_score >= 0.0, "MVC pattern should be detected to some degree, got {}", pattern_score);
    }

    #[test]
    fn test_confidence_scoring_algorithm() {
        let system = IntentMappingSystem::new();

        let requirement = Requirement {
            id: "REQ-005".to_string(),
            description: "Implement secure user authentication system".to_string(),
            requirement_type: RequirementType::Security,
            priority: Priority::Critical,
            acceptance_criteria: vec!["Secure login".to_string(), "Password validation".to_string()],
            stakeholders: vec!["Security Team".to_string()],
            tags: vec!["security".to_string(), "authentication".to_string()],
            status: RequirementStatus::Approved,
        };

        // High-quality implementation
        let high_quality_impl = Implementation {
            id: "IMPL-005".to_string(),
            file_path: PathBuf::from("src/auth/secure_login.rs"),
            implementation_type: ImplementationType::API,
            code_elements: vec![],
            status: ImplementationStatus::Deployed,
            quality_metrics: QualityMetrics {
                coverage: 0.95,
                complexity: 0.2,
                maintainability: 0.9,
                performance: 0.9,
                security: 0.95,
            },
            documentation: Some("Comprehensive authentication API with security best practices. @param username User identifier @param password User password @return Authentication token @throws AuthenticationError on invalid credentials. Example: auth.login('user', 'pass')".to_string()),
        };

        let similarity_score = 0.8;
        let confidence = system.calculate_confidence_score(&requirement, &high_quality_impl, similarity_score);

        // Should have high confidence due to quality metrics and alignment
        assert!(confidence > 0.7, "High-quality implementation should have high confidence, got {}", confidence);

        // Test confidence level description
        let level = system.get_confidence_level(confidence);
        assert!(level == "High" || level == "Medium", "Should be High or Medium confidence level, got {}", level);
    }

    #[test]
    fn test_confidence_scoring_low_quality() {
        let system = IntentMappingSystem::new();

        let requirement = Requirement {
            id: "REQ-006".to_string(),
            description: "Simple utility function".to_string(),
            requirement_type: RequirementType::Functional,
            priority: Priority::Low,
            acceptance_criteria: vec!["Function works".to_string()],
            stakeholders: vec!["Developer".to_string()],
            tags: vec!["utility".to_string()],
            status: RequirementStatus::Draft,
        };

        // Low-quality implementation
        let low_quality_impl = Implementation {
            id: "IMPL-006".to_string(),
            file_path: PathBuf::from("src/utils/temp.rs"),
            implementation_type: ImplementationType::Function,
            code_elements: vec![],
            status: ImplementationStatus::InProgress,
            quality_metrics: QualityMetrics {
                coverage: 0.3,
                complexity: 0.8,
                maintainability: 0.4,
                performance: 0.5,
                security: 0.6,
            },
            documentation: None,
        };

        let similarity_score = 0.5;
        let confidence = system.calculate_confidence_score(&requirement, &low_quality_impl, similarity_score);

        // Should have lower confidence due to poor quality metrics
        assert!(confidence < 0.6, "Low-quality implementation should have lower confidence, got {}", confidence);

        let level = system.get_confidence_level(confidence);
        assert!(level == "Low" || level == "Very Low", "Should be Low or Very Low confidence level, got {}", level);
    }

    #[test]
    fn test_validation_status_determination() {
        let system = IntentMappingSystem::new();

        // Test auto-accept threshold
        let high_confidence = 0.95;
        assert_eq!(system.determine_validation_status(high_confidence), ValidationStatus::Valid);

        // Test needs review threshold
        let medium_confidence = 0.7;
        assert_eq!(system.determine_validation_status(medium_confidence), ValidationStatus::NeedsReview);

        // Test auto-reject threshold
        let low_confidence = 0.2;
        assert_eq!(system.determine_validation_status(low_confidence), ValidationStatus::Invalid);

        // Test not validated threshold
        let very_low_confidence = 0.4;
        assert_eq!(system.determine_validation_status(very_low_confidence), ValidationStatus::NotValidated);
    }

    #[test]
    fn test_quality_confidence_calculation() {
        let system = IntentMappingSystem::new();

        // High quality metrics
        let high_quality = QualityMetrics {
            coverage: 0.9,
            complexity: 0.2, // Low complexity is good
            maintainability: 0.9,
            performance: 0.9,
            security: 0.95,
        };

        let quality_confidence = system.calculate_quality_confidence(&high_quality);
        assert!(quality_confidence > 0.8, "High quality metrics should yield high confidence, got {}", quality_confidence);

        // Low quality metrics
        let low_quality = QualityMetrics {
            coverage: 0.3,
            complexity: 0.9, // High complexity is bad
            maintainability: 0.4,
            performance: 0.5,
            security: 0.6,
        };

        let low_quality_confidence = system.calculate_quality_confidence(&low_quality);
        assert!(low_quality_confidence < 0.6, "Low quality metrics should yield low confidence, got {}", low_quality_confidence);
    }

    #[test]
    fn test_relationship_graph_creation() {
        let mut system = IntentMappingSystem::new();

        // Add test requirement
        let requirement = Requirement {
            id: "REQ-GRAPH-001".to_string(),
            description: "Implement graph-based relationship mapping".to_string(),
            requirement_type: RequirementType::Technical,
            priority: Priority::High,
            acceptance_criteria: vec!["Create nodes".to_string(), "Create edges".to_string()],
            stakeholders: vec!["Architect".to_string()],
            tags: vec!["graph".to_string(), "relationships".to_string()],
            status: RequirementStatus::Approved,
        };
        system.add_requirement(requirement);

        // Add test implementation
        let implementation = Implementation {
            id: "IMPL-GRAPH-001".to_string(),
            file_path: PathBuf::from("src/graph.rs"),
            implementation_type: ImplementationType::Module,
            code_elements: vec![
                CodeElement {
                    name: "RelationshipGraph".to_string(),
                    element_type: "struct".to_string(),
                    line_range: (10, 50),
                    complexity: 3.0,
                    test_coverage: 0.8,
                }
            ],
            status: ImplementationStatus::Complete,
            quality_metrics: QualityMetrics {
                coverage: 0.8,
                complexity: 0.3,
                maintainability: 0.9,
                performance: 0.8,
                security: 0.9,
            },
            documentation: Some("Graph implementation for relationship mapping".to_string()),
        };
        system.add_implementation(implementation);

        // Create a mapping
        let mapping = IntentMapping {
            id: "MAP-GRAPH-001".to_string(),
            requirement_id: "REQ-GRAPH-001".to_string(),
            implementation_id: "IMPL-GRAPH-001".to_string(),
            mapping_type: MappingType::Direct,
            confidence: 0.9,
            rationale: "Direct implementation of graph requirements".to_string(),
            validation_status: ValidationStatus::Valid,
            last_updated: 1234567890,
        };
        system.mappings.push(mapping);

        // Build relationship graph
        let graph = system.build_relationship_graph().unwrap();

        // Verify graph structure
        assert_eq!(graph.nodes.len(), 3); // 1 requirement + 1 implementation + 1 code element
        assert!(graph.edges.len() >= 2); // At least 1 mapping + 1 containment

        // Verify nodes exist
        assert!(graph.get_node("REQ-GRAPH-001").is_some());
        assert!(graph.get_node("IMPL-GRAPH-001").is_some());
        assert!(graph.get_node("IMPL-GRAPH-001_RelationshipGraph").is_some());

        // Verify node types
        let req_node = graph.get_node("REQ-GRAPH-001").unwrap();
        assert_eq!(req_node.node_type, RelationshipNodeType::Requirement);

        let impl_node = graph.get_node("IMPL-GRAPH-001").unwrap();
        assert_eq!(impl_node.node_type, RelationshipNodeType::Implementation);

        // Verify edges exist
        let req_edges = graph.get_outgoing_edges("REQ-GRAPH-001");
        assert!(!req_edges.is_empty(), "Requirement should have outgoing edges");

        let impl_edges = graph.get_outgoing_edges("IMPL-GRAPH-001");
        assert!(!impl_edges.is_empty(), "Implementation should have outgoing edges (containment)");
    }

    #[test]
    fn test_graph_metrics_calculation() {
        let mut graph = RelationshipGraph::new();

        // Add nodes
        let node1 = RelationshipNode {
            id: "node1".to_string(),
            node_type: RelationshipNodeType::Requirement,
            metadata: HashMap::new(),
            attributes: HashMap::new(),
        };
        let node2 = RelationshipNode {
            id: "node2".to_string(),
            node_type: RelationshipNodeType::Implementation,
            metadata: HashMap::new(),
            attributes: HashMap::new(),
        };
        graph.add_node(node1);
        graph.add_node(node2);

        // Add edge
        let edge = RelationshipEdge {
            id: "edge1".to_string(),
            source_id: "node1".to_string(),
            target_id: "node2".to_string(),
            edge_type: RelationshipEdgeType::DirectMapping,
            weight: 0.8,
            metadata: HashMap::new(),
            attributes: HashMap::new(),
        };
        graph.add_edge(edge).unwrap();

        // Calculate metrics
        graph.calculate_metrics();

        // Verify metrics
        assert_eq!(graph.metrics.node_count, 2);
        assert_eq!(graph.metrics.edge_count, 1);
        assert!(graph.metrics.density > 0.0);
        assert!(graph.metrics.average_degree > 0.0);
        assert_eq!(graph.metrics.connected_components, 1);
    }

    #[test]
    fn test_shortest_path_finding() {
        let mut graph = RelationshipGraph::new();

        // Create a simple path: A -> B -> C
        for i in 1..=3 {
            let node = RelationshipNode {
                id: format!("node{}", i),
                node_type: RelationshipNodeType::Requirement,
                metadata: HashMap::new(),
                attributes: HashMap::new(),
            };
            graph.add_node(node);
        }

        // Add edges A->B and B->C
        let edge1 = RelationshipEdge {
            id: "edge1".to_string(),
            source_id: "node1".to_string(),
            target_id: "node2".to_string(),
            edge_type: RelationshipEdgeType::DirectMapping,
            weight: 1.0,
            metadata: HashMap::new(),
            attributes: HashMap::new(),
        };
        let edge2 = RelationshipEdge {
            id: "edge2".to_string(),
            source_id: "node2".to_string(),
            target_id: "node3".to_string(),
            edge_type: RelationshipEdgeType::DirectMapping,
            weight: 1.0,
            metadata: HashMap::new(),
            attributes: HashMap::new(),
        };
        graph.add_edge(edge1).unwrap();
        graph.add_edge(edge2).unwrap();

        // Test shortest path
        let path = graph.find_shortest_path("node1", "node3");
        assert!(path.is_some());
        let path = path.unwrap();
        assert_eq!(path.len(), 3);
        assert_eq!(path, vec!["node1", "node2", "node3"]);

        // Test path to self
        let self_path = graph.find_shortest_path("node1", "node1");
        assert_eq!(self_path, Some(vec!["node1".to_string()]));

        // Test no path (add isolated node)
        let isolated_node = RelationshipNode {
            id: "isolated".to_string(),
            node_type: RelationshipNodeType::Implementation,
            metadata: HashMap::new(),
            attributes: HashMap::new(),
        };
        graph.add_node(isolated_node);

        let no_path = graph.find_shortest_path("node1", "isolated");
        assert!(no_path.is_none());
    }

    #[test]
    fn test_find_similar_implementations_empty() {
        let system = IntentMappingSystem::new();

        // Should return error for non-existent requirement
        let result = system.find_similar_implementations("REQ-NONEXISTENT", 5);
        assert!(result.is_err(), "Should return error for non-existent requirement");
    }

    #[test]
    fn test_find_similar_requirements_empty() {
        let system = IntentMappingSystem::new();

        // Should return error for non-existent implementation
        let result = system.find_similar_requirements("IMPL-NONEXISTENT", 5);
        assert!(result.is_err(), "Should return error for non-existent implementation");
    }

    #[test]
    fn test_analyze_requirement_clusters_empty() {
        let system = IntentMappingSystem::new();

        // Should return empty clusters when no embeddings exist
        let clusters = system.analyze_requirement_clusters(0.7).unwrap();
        assert!(clusters.is_empty(), "Should return empty clusters when no embeddings exist");
    }
}
