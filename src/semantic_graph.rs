//! Semantic Knowledge Graph Query System
//! 
//! This module provides graph query interface with relationship traversal
//! and similarity search capabilities for code semantic analysis.

use crate::{AnalysisResult, Result, FileInfo};
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::PathBuf;

#[cfg(feature = "serde")]
use serde::{Serialize, Deserialize};

/// Graph query system for semantic code analysis
#[derive(Debug, Clone)]
pub struct SemanticGraphQuery {
    /// Graph nodes representing code entities
    nodes: HashMap<String, GraphNode>,
    /// Graph edges representing relationships
    edges: HashMap<String, Vec<GraphEdge>>,
    /// Index for fast lookups
    index: GraphIndex,
}

/// A node in the semantic graph representing a code entity
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct GraphNode {
    /// Unique identifier
    pub id: String,
    /// Node type (function, class, module, etc.)
    pub node_type: NodeType,
    /// Display name
    pub name: String,
    /// File path where this entity is defined
    pub file_path: PathBuf,
    /// Line number in the file
    pub line_number: usize,
    /// Additional metadata
    pub metadata: HashMap<String, String>,
    /// Semantic properties
    pub properties: NodeProperties,
}

/// An edge in the semantic graph representing a relationship
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct GraphEdge {
    /// Source node ID
    pub from: String,
    /// Target node ID
    pub to: String,
    /// Relationship type
    pub relationship: RelationshipType,
    /// Relationship strength (0.0 to 1.0)
    pub weight: f64,
    /// Additional context
    pub context: Option<String>,
}

/// Types of nodes in the semantic graph
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum NodeType {
    Function,
    Class,
    Module,
    Variable,
    Constant,
    Interface,
    Struct,
    Enum,
    Trait,
    Namespace,
    Package,
}

/// Types of relationships between nodes
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum RelationshipType {
    /// Function calls another function
    Calls,
    /// Class inherits from another class
    Inherits,
    /// Module imports another module
    Imports,
    /// Function uses a variable
    Uses,
    /// Class implements an interface
    Implements,
    /// Function is defined in a class
    DefinedIn,
    /// Variable is of a certain type
    HasType,
    /// Generic dependency relationship
    DependsOn,
    /// Semantic similarity
    SimilarTo,
}

/// Properties of a graph node
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct NodeProperties {
    /// Complexity score
    pub complexity: f64,
    /// Importance score in the codebase
    pub importance: f64,
    /// Number of incoming relationships
    pub in_degree: usize,
    /// Number of outgoing relationships
    pub out_degree: usize,
    /// Semantic tags
    pub tags: Vec<String>,
}

/// Index for fast graph queries
#[derive(Debug, Clone)]
struct GraphIndex {
    /// Index by node type
    by_type: HashMap<NodeType, HashSet<String>>,
    /// Index by file path
    by_file: HashMap<PathBuf, HashSet<String>>,
    /// Index by name
    by_name: HashMap<String, HashSet<String>>,
}

/// Query result containing matching nodes and relationships
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct QueryResult {
    /// Matching nodes
    pub nodes: Vec<GraphNode>,
    /// Relevant edges
    pub edges: Vec<GraphEdge>,
    /// Query execution metadata
    pub metadata: QueryMetadata,
}

/// Metadata about query execution
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct QueryMetadata {
    /// Number of nodes examined
    pub nodes_examined: usize,
    /// Number of edges traversed
    pub edges_traversed: usize,
    /// Query execution time in milliseconds
    pub execution_time_ms: u64,
    /// Whether the query was truncated due to limits
    pub truncated: bool,
}

/// Configuration for graph queries
#[derive(Debug, Clone)]
pub struct QueryConfig {
    /// Maximum number of results to return
    pub max_results: usize,
    /// Maximum depth for traversal queries
    pub max_depth: usize,
    /// Minimum similarity threshold for similarity queries
    pub similarity_threshold: f64,
    /// Whether to include metadata in results
    pub include_metadata: bool,
}

impl Default for QueryConfig {
    fn default() -> Self {
        Self {
            max_results: 100,
            max_depth: 5,
            similarity_threshold: 0.5,
            include_metadata: true,
        }
    }
}

impl SemanticGraphQuery {
    /// Create a new semantic graph query system
    pub fn new() -> Self {
        Self {
            nodes: HashMap::new(),
            edges: HashMap::new(),
            index: GraphIndex::new(),
        }
    }

    /// Helper function to create graph node without excessive cloning
    fn create_graph_node(
        id: String,
        node_type: NodeType,
        name: String,
        file_path: std::path::PathBuf,
        line_number: usize,
    ) -> GraphNode {
        GraphNode {
            id,
            node_type,
            name,
            file_path,
            line_number,
            metadata: HashMap::new(),
            properties: NodeProperties {
                complexity: 1.0,
                importance: 1.0,
                in_degree: 0,
                out_degree: 0,
                tags: Vec::new(),
            },
        }
    }

    /// Helper function to create graph edge without excessive cloning
    fn create_graph_edge(
        from: &str,
        to: &str,
        relationship: RelationshipType,
        weight: f64,
        context: Option<&str>,
    ) -> GraphEdge {
        GraphEdge {
            from: from.to_string(),
            to: to.to_string(),
            relationship,
            weight,
            context: context.map(|s| s.to_string()),
        }
    }

    /// Build the semantic graph from analysis results
    pub fn build_from_analysis(&mut self, analysis: &AnalysisResult) -> Result<()> {
        // Clear existing data
        self.nodes.clear();
        self.edges.clear();
        self.index = GraphIndex::new();

        // Build nodes from symbols
        for file in &analysis.files {
            self.add_file_nodes(file)?;
        }

        // Build relationships
        self.build_relationships(analysis)?;

        // Update index
        self.rebuild_index();

        Ok(())
    }

    /// Find nodes by type
    pub fn find_by_type(&self, node_type: NodeType, config: &QueryConfig) -> QueryResult {
        let start_time = std::time::Instant::now();
        let mut nodes = Vec::new();
        let mut edges = Vec::new();

        if let Some(node_ids) = self.index.by_type.get(&node_type) {
            for node_id in node_ids.iter().take(config.max_results) {
                if let Some(node) = self.nodes.get(node_id) {
                    nodes.push(node.clone());
                    
                    // Add related edges if requested
                    if let Some(node_edges) = self.edges.get(node_id) {
                        edges.extend(node_edges.clone());
                    }
                }
            }
        }

        let execution_time = start_time.elapsed().as_millis() as u64;
        let edges_count = edges.len();

        QueryResult {
            nodes,
            edges,
            metadata: QueryMetadata {
                nodes_examined: self.nodes.len(),
                edges_traversed: edges_count,
                execution_time_ms: execution_time,
                truncated: false,
            },
        }
    }

    /// Find nodes by name pattern
    pub fn find_by_name(&self, pattern: &str, config: &QueryConfig) -> QueryResult {
        let start_time = std::time::Instant::now();
        let mut nodes = Vec::new();
        let mut edges = Vec::new();
        let mut examined = 0;

        for (_, node) in &self.nodes {
            examined += 1;
            if node.name.contains(pattern) {
                nodes.push(node.clone());
                
                if let Some(node_edges) = self.edges.get(&node.id) {
                    edges.extend(node_edges.clone());
                }

                if nodes.len() >= config.max_results {
                    break;
                }
            }
        }

        let execution_time = start_time.elapsed().as_millis() as u64;
        let edges_count = edges.len();
        let nodes_count = nodes.len();
        let is_truncated = nodes_count >= config.max_results;

        QueryResult {
            nodes,
            edges,
            metadata: QueryMetadata {
                nodes_examined: examined,
                edges_traversed: edges_count,
                execution_time_ms: execution_time,
                truncated: is_truncated,
            },
        }
    }

    /// Traverse relationships from a starting node
    pub fn traverse_relationships(
        &self,
        start_node_id: &str,
        relationship_types: &[RelationshipType],
        config: &QueryConfig,
    ) -> QueryResult {
        let start_time = std::time::Instant::now();
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        let mut result_nodes = Vec::new();
        let mut result_edges = Vec::new();
        let mut edges_traversed = 0;

        queue.push_back((start_node_id.to_string(), 0));
        visited.insert(start_node_id.to_string());

        while let Some((node_id, depth)) = queue.pop_front() {
            if depth >= config.max_depth || result_nodes.len() >= config.max_results {
                break;
            }

            if let Some(node) = self.nodes.get(&node_id) {
                result_nodes.push(node.clone());
            }

            if let Some(edges) = self.edges.get(&node_id) {
                for edge in edges {
                    edges_traversed += 1;
                    
                    if relationship_types.is_empty() || relationship_types.contains(&edge.relationship) {
                        result_edges.push(edge.clone());
                        
                        if !visited.contains(&edge.to) && depth + 1 < config.max_depth {
                            visited.insert(edge.to.clone());
                            queue.push_back((edge.to.clone(), depth + 1));
                        }
                    }
                }
            }
        }

        let execution_time = start_time.elapsed().as_millis() as u64;
        
        QueryResult {
            nodes: result_nodes,
            edges: result_edges,
            metadata: QueryMetadata {
                nodes_examined: visited.len(),
                edges_traversed,
                execution_time_ms: execution_time,
                truncated: queue.len() > 0,
            },
        }
    }

    /// Find similar nodes based on properties and relationships
    pub fn find_similar(&self, target_node_id: &str, config: &QueryConfig) -> QueryResult {
        let start_time = std::time::Instant::now();
        let mut similar_nodes = Vec::new();
        let mut edges = Vec::new();

        if let Some(target_node) = self.nodes.get(target_node_id) {
            let mut similarities = Vec::new();

            for (node_id, node) in &self.nodes {
                if node_id != target_node_id {
                    let similarity = self.calculate_similarity(target_node, node);
                    if similarity >= config.similarity_threshold {
                        similarities.push((node.clone(), similarity));
                    }
                }
            }

            // Sort by similarity score
            similarities.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

            // Take top results
            for (node, _) in similarities.into_iter().take(config.max_results) {
                similar_nodes.push(node.clone());
                
                if let Some(node_edges) = self.edges.get(&node.id) {
                    edges.extend(node_edges.clone());
                }
            }
        }

        let execution_time = start_time.elapsed().as_millis() as u64;
        let edges_count = edges.len();

        QueryResult {
            nodes: similar_nodes,
            edges,
            metadata: QueryMetadata {
                nodes_examined: self.nodes.len(),
                edges_traversed: edges_count,
                execution_time_ms: execution_time,
                truncated: false,
            },
        }
    }

    /// Get graph statistics
    pub fn get_statistics(&self) -> GraphStatistics {
        let mut type_counts = HashMap::new();
        let mut relationship_counts = HashMap::new();

        for node in self.nodes.values() {
            *type_counts.entry(node.node_type.clone()).or_insert(0) += 1;
        }

        for edges in self.edges.values() {
            for edge in edges {
                *relationship_counts.entry(edge.relationship.clone()).or_insert(0) += 1;
            }
        }

        GraphStatistics {
            total_nodes: self.nodes.len(),
            total_edges: self.edges.values().map(|v| v.len()).sum(),
            node_type_distribution: type_counts,
            relationship_type_distribution: relationship_counts,
        }
    }

    // Private helper methods

    /// Add nodes from a file's symbols
    fn add_file_nodes(&mut self, file: &FileInfo) -> Result<()> {
        for symbol in &file.symbols {
            let node_id = format!("{}:{}:{}", file.path.display(), symbol.name, symbol.start_line);
            let node_type = self.symbol_to_node_type(&symbol.kind);

            let node = Self::create_graph_node(
                node_id.clone(),
                node_type,
                symbol.name.clone(),
                file.path.clone(),
                symbol.start_line,
            );

            self.nodes.insert(node_id, node);
        }
        Ok(())
    }

    /// Convert symbol kind to node type
    fn symbol_to_node_type(&self, symbol_kind: &str) -> NodeType {
        match symbol_kind.to_lowercase().as_str() {
            "function" | "method" => NodeType::Function,
            "class" | "type" => NodeType::Class,
            "module" | "namespace" => NodeType::Module,
            "variable" | "field" => NodeType::Variable,
            "constant" | "const" => NodeType::Constant,
            "interface" => NodeType::Interface,
            "struct" => NodeType::Struct,
            "enum" => NodeType::Enum,
            "trait" => NodeType::Trait,
            "impl" => NodeType::Class, // Treat impl blocks as class-like
            _ => NodeType::Function, // Default fallback
        }
    }

    /// Build relationships between nodes
    fn build_relationships(&mut self, analysis: &AnalysisResult) -> Result<()> {
        // Build basic file-level relationships
        for file in &analysis.files {
            self.build_file_relationships(file)?;
        }

        // Calculate node degrees
        self.calculate_node_degrees();

        Ok(())
    }

    /// Build relationships within a file
    fn build_file_relationships(&mut self, file: &FileInfo) -> Result<()> {
        let file_symbols: Vec<_> = file.symbols.iter().collect();

        // Create relationships between symbols in the same file
        for (i, symbol1) in file_symbols.iter().enumerate() {
            let node1_id = format!("{}:{}:{}", file.path.display(), symbol1.name, symbol1.start_line);
            let mut edges_for_node1 = Vec::new();

            for symbol2 in file_symbols.iter().skip(i + 1) {
                let node2_id = format!("{}:{}:{}", file.path.display(), symbol2.name, symbol2.start_line);

                // Create a basic "defined in same file" relationship
                let edge = Self::create_graph_edge(
                    &node1_id,
                    &node2_id,
                    RelationshipType::DependsOn,
                    0.3, // Low weight for same-file relationships
                    Some("same_file"),
                );

                edges_for_node1.push(edge);
            }

            if !edges_for_node1.is_empty() {
                self.edges.entry(node1_id).or_insert_with(Vec::new).extend(edges_for_node1);
            }
        }

        Ok(())
    }

    /// Calculate in-degree and out-degree for all nodes
    fn calculate_node_degrees(&mut self) {
        let mut in_degrees: HashMap<String, usize> = HashMap::new();
        let mut out_degrees: HashMap<String, usize> = HashMap::new();

        // Count degrees
        for (from_id, edges) in &self.edges {
            out_degrees.insert(from_id.to_string(), edges.len());

            for edge in edges {
                *in_degrees.entry(edge.to.to_string()).or_insert(0) += 1;
            }
        }

        // Update node properties
        for (node_id, node) in &mut self.nodes {
            node.properties.in_degree = in_degrees.get(node_id).copied().unwrap_or(0);
            node.properties.out_degree = out_degrees.get(node_id).copied().unwrap_or(0);
        }
    }

    /// Calculate similarity between two nodes
    fn calculate_similarity(&self, node1: &GraphNode, node2: &GraphNode) -> f64 {
        let mut similarity = 0.0;

        // Type similarity
        if node1.node_type == node2.node_type {
            similarity += 0.3;
        }

        // Name similarity (simple string similarity)
        let name_similarity = self.string_similarity(&node1.name, &node2.name);
        similarity += name_similarity * 0.2;

        // File similarity
        if node1.file_path == node2.file_path {
            similarity += 0.2;
        }

        // Property similarity
        let complexity_diff = (node1.properties.complexity - node2.properties.complexity).abs();
        let complexity_similarity = 1.0 - (complexity_diff / 10.0).min(1.0);
        similarity += complexity_similarity * 0.1;

        // Degree similarity
        let degree_diff = (node1.properties.in_degree as f64 - node2.properties.in_degree as f64).abs();
        let degree_similarity = 1.0 - (degree_diff / 10.0).min(1.0);
        similarity += degree_similarity * 0.1;

        // Tag similarity
        let common_tags = node1.properties.tags.iter()
            .filter(|tag| node2.properties.tags.contains(tag))
            .count();
        let total_tags = (node1.properties.tags.len() + node2.properties.tags.len()).max(1);
        let tag_similarity = common_tags as f64 / total_tags as f64;
        similarity += tag_similarity * 0.1;

        similarity.min(1.0)
    }

    /// Calculate string similarity using simple character overlap
    fn string_similarity(&self, s1: &str, s2: &str) -> f64 {
        if s1 == s2 {
            return 1.0;
        }

        let s1_chars: HashSet<char> = s1.chars().collect();
        let s2_chars: HashSet<char> = s2.chars().collect();

        let intersection = s1_chars.intersection(&s2_chars).count();
        let union = s1_chars.union(&s2_chars).count();

        if union == 0 {
            0.0
        } else {
            intersection as f64 / union as f64
        }
    }

    /// Rebuild the search index
    fn rebuild_index(&mut self) {
        self.index = GraphIndex::new();

        for (node_id, node) in &self.nodes {
            // Index by type
            self.index.by_type
                .entry(node.node_type.clone())
                .or_insert_with(HashSet::new)
                .insert(node_id.to_string());

            // Index by file
            self.index.by_file
                .entry(node.file_path.to_path_buf())
                .or_insert_with(HashSet::new)
                .insert(node_id.to_string());

            // Index by name
            self.index.by_name
                .entry(node.name.to_string())
                .or_insert_with(HashSet::new)
                .insert(node_id.to_string());
        }
    }
}

/// Graph statistics for analysis
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct GraphStatistics {
    /// Total number of nodes
    pub total_nodes: usize,
    /// Total number of edges
    pub total_edges: usize,
    /// Distribution of node types
    pub node_type_distribution: HashMap<NodeType, usize>,
    /// Distribution of relationship types
    pub relationship_type_distribution: HashMap<RelationshipType, usize>,
}

impl GraphIndex {
    fn new() -> Self {
        Self {
            by_type: HashMap::new(),
            by_file: HashMap::new(),
            by_name: HashMap::new(),
        }
    }
}

impl Default for SemanticGraphQuery {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for NodeProperties {
    fn default() -> Self {
        Self {
            complexity: 1.0,
            importance: 1.0,
            in_degree: 0,
            out_degree: 0,
            tags: Vec::new(),
        }
    }
}

impl std::fmt::Display for NodeType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NodeType::Function => write!(f, "function"),
            NodeType::Class => write!(f, "class"),
            NodeType::Module => write!(f, "module"),
            NodeType::Variable => write!(f, "variable"),
            NodeType::Constant => write!(f, "constant"),
            NodeType::Interface => write!(f, "interface"),
            NodeType::Struct => write!(f, "struct"),
            NodeType::Enum => write!(f, "enum"),
            NodeType::Trait => write!(f, "trait"),
            NodeType::Namespace => write!(f, "namespace"),
            NodeType::Package => write!(f, "package"),
        }
    }
}

impl std::fmt::Display for RelationshipType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RelationshipType::Calls => write!(f, "calls"),
            RelationshipType::Inherits => write!(f, "inherits"),
            RelationshipType::Imports => write!(f, "imports"),
            RelationshipType::Uses => write!(f, "uses"),
            RelationshipType::Implements => write!(f, "implements"),
            RelationshipType::DefinedIn => write!(f, "defined_in"),
            RelationshipType::HasType => write!(f, "has_type"),
            RelationshipType::DependsOn => write!(f, "depends_on"),
            RelationshipType::SimilarTo => write!(f, "similar_to"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Symbol};
    use std::collections::HashMap;

    fn create_test_analysis_result() -> AnalysisResult {
        let mut symbols = Vec::new();
        symbols.push(Symbol {
            name: "test_function".to_string(),
            kind: "function".to_string(),
            start_line: 1,
            end_line: 5,
            start_column: 0,
            end_column: 10,
            visibility: "public".to_string(),
            documentation: Some("Test function".to_string()),
        });

        symbols.push(Symbol {
            name: "TestClass".to_string(),
            kind: "class".to_string(),
            start_line: 10,
            end_line: 20,
            start_column: 0,
            end_column: 15,
            visibility: "public".to_string(),
            documentation: Some("Test class".to_string()),
        });

        let file = FileInfo {
            path: PathBuf::from("test.rs"),
            language: "rust".to_string(),
            size: 100,
            lines: 25,
            parsed_successfully: true,
            parse_errors: Vec::new(),
            symbols,
            security_vulnerabilities: Vec::new(),
        };

        AnalysisResult {
            root_path: PathBuf::from("."),
            total_files: 1,
            parsed_files: 1,
            error_files: 0,
            total_lines: 25,
            languages: HashMap::new(),
            files: vec![file],
            config: crate::AnalysisConfig::default(),
        }
    }

    #[test]
    fn test_semantic_graph_creation() {
        let graph = SemanticGraphQuery::new();

        assert!(graph.nodes.is_empty());
        assert!(graph.edges.is_empty());
    }

    #[test]
    fn test_build_graph_from_analysis() {
        let analysis = create_test_analysis_result();
        let mut graph = SemanticGraphQuery::new();

        let result = graph.build_from_analysis(&analysis);
        assert!(result.is_ok());

        // Should have created nodes for the function and class
        assert_eq!(graph.nodes.len(), 2);

        // Check that nodes were created correctly
        let function_nodes: Vec<_> = graph.nodes.values()
            .filter(|n| n.node_type == NodeType::Function)
            .collect();
        assert_eq!(function_nodes.len(), 1);
        assert_eq!(function_nodes[0].name, "test_function");

        let class_nodes: Vec<_> = graph.nodes.values()
            .filter(|n| n.node_type == NodeType::Class)
            .collect();
        assert_eq!(class_nodes.len(), 1);
        assert_eq!(class_nodes[0].name, "TestClass");
    }

    #[test]
    fn test_find_by_type() {
        let analysis = create_test_analysis_result();
        let mut graph = SemanticGraphQuery::new();
        graph.build_from_analysis(&analysis).unwrap();

        let config = QueryConfig::default();

        // Find functions
        let function_result = graph.find_by_type(NodeType::Function, &config);
        assert_eq!(function_result.nodes.len(), 1);
        assert_eq!(function_result.nodes[0].name, "test_function");

        // Find classes
        let class_result = graph.find_by_type(NodeType::Class, &config);
        assert_eq!(class_result.nodes.len(), 1);
        assert_eq!(class_result.nodes[0].name, "TestClass");

        // Find non-existent type
        let module_result = graph.find_by_type(NodeType::Module, &config);
        assert_eq!(module_result.nodes.len(), 0);
    }

    #[test]
    fn test_find_by_name() {
        let analysis = create_test_analysis_result();
        let mut graph = SemanticGraphQuery::new();
        graph.build_from_analysis(&analysis).unwrap();

        let config = QueryConfig::default();

        // Find by exact name
        let result = graph.find_by_name("test_function", &config);
        assert_eq!(result.nodes.len(), 1);
        assert_eq!(result.nodes[0].name, "test_function");

        // Find by partial name
        let result = graph.find_by_name("Test", &config);
        assert_eq!(result.nodes.len(), 1);
        assert_eq!(result.nodes[0].name, "TestClass");

        // Find non-existent name
        let result = graph.find_by_name("nonexistent", &config);
        assert_eq!(result.nodes.len(), 0);
    }

    #[test]
    fn test_symbol_to_node_type_conversion() {
        let graph = SemanticGraphQuery::new();

        assert_eq!(graph.symbol_to_node_type("function"), NodeType::Function);
        assert_eq!(graph.symbol_to_node_type("method"), NodeType::Function);
        assert_eq!(graph.symbol_to_node_type("class"), NodeType::Class);
        assert_eq!(graph.symbol_to_node_type("type"), NodeType::Class);
        assert_eq!(graph.symbol_to_node_type("module"), NodeType::Module);
        assert_eq!(graph.symbol_to_node_type("variable"), NodeType::Variable);
        assert_eq!(graph.symbol_to_node_type("constant"), NodeType::Constant);
        assert_eq!(graph.symbol_to_node_type("interface"), NodeType::Interface);
        assert_eq!(graph.symbol_to_node_type("struct"), NodeType::Struct);
        assert_eq!(graph.symbol_to_node_type("enum"), NodeType::Enum);
        assert_eq!(graph.symbol_to_node_type("trait"), NodeType::Trait);
        assert_eq!(graph.symbol_to_node_type("unknown"), NodeType::Function); // Default fallback
    }

    #[test]
    fn test_string_similarity() {
        let graph = SemanticGraphQuery::new();

        // Identical strings
        assert_eq!(graph.string_similarity("test", "test"), 1.0);

        // Completely different strings
        assert_eq!(graph.string_similarity("abc", "xyz"), 0.0);

        // Partial overlap
        let similarity = graph.string_similarity("test_function", "test_method");
        assert!(similarity > 0.0 && similarity < 1.0);
    }

    #[test]
    fn test_get_statistics() {
        let analysis = create_test_analysis_result();
        let mut graph = SemanticGraphQuery::new();
        graph.build_from_analysis(&analysis).unwrap();

        let stats = graph.get_statistics();

        assert_eq!(stats.total_nodes, 2);
        assert!(stats.total_edges > 0); // Should have some relationships
        assert_eq!(stats.node_type_distribution.get(&NodeType::Function), Some(&1));
        assert_eq!(stats.node_type_distribution.get(&NodeType::Class), Some(&1));
    }

    #[test]
    fn test_query_config_default() {
        let config = QueryConfig::default();

        assert_eq!(config.max_results, 100);
        assert_eq!(config.max_depth, 5);
        assert_eq!(config.similarity_threshold, 0.5);
        assert!(config.include_metadata);
    }

    #[test]
    fn test_node_properties_default() {
        let props = NodeProperties::default();

        assert_eq!(props.complexity, 1.0);
        assert_eq!(props.importance, 1.0);
        assert_eq!(props.in_degree, 0);
        assert_eq!(props.out_degree, 0);
        assert!(props.tags.is_empty());
    }
}
