//! Semantic Knowledge Graph Query System
//!
//! This module provides graph query interface with relationship traversal
//! and similarity search capabilities for code semantic analysis.
#![allow(clippy::vec_init_then_push)]

use crate::{AnalysisResult, FileInfo, Result, Symbol};
use regex::Regex;
use std::collections::{HashMap, HashSet, VecDeque};
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::sync::OnceLock;

use serde::{Deserialize, Serialize};

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
#[derive(Debug, Clone, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Serialize, Deserialize)]
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
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
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
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryResult {
    /// Matching nodes
    pub nodes: Vec<GraphNode>,
    /// Relevant edges
    pub edges: Vec<GraphEdge>,
    /// Query execution metadata
    pub metadata: QueryMetadata,
}

/// Metadata about query execution
#[derive(Debug, Clone, Serialize, Deserialize)]
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

#[derive(Debug, Clone)]
struct ImportedSymbolBinding {
    alias: String,
    target_path: PathBuf,
    target_symbol: String,
}

#[derive(Debug, Clone)]
struct ImportedModuleBinding {
    alias: String,
    target_path: PathBuf,
}

#[derive(Debug, Clone)]
struct ResolvedCallTarget {
    line_number: usize,
    target_path: PathBuf,
    target_symbol: String,
}

type SymbolLocation = (PathBuf, String);
type ReexportLookup = HashMap<SymbolLocation, SymbolLocation>;

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

    fn symbol_node_id(file_path: &Path, symbol: &Symbol) -> String {
        Self::symbol_node_id_from_parts(file_path, &symbol.name, symbol.start_line)
    }

    fn symbol_node_id_from_parts(file_path: &Path, symbol_name: &str, start_line: usize) -> String {
        format!("{}:{}:{}", file_path.display(), symbol_name, start_line)
    }

    fn is_callable_symbol_kind(symbol_kind: &str) -> bool {
        matches!(symbol_kind.to_lowercase().as_str(), "function" | "method")
    }

    fn find_enclosing_callable_symbol(file: &FileInfo, line_number: usize) -> Option<&Symbol> {
        file.symbols
            .iter()
            .filter(|symbol| {
                Self::is_callable_symbol_kind(&symbol.kind)
                    && symbol.start_line <= line_number
                    && line_number <= symbol.end_line
            })
            .min_by_key(|symbol| symbol.end_line.saturating_sub(symbol.start_line))
    }

    fn add_unique_edge(&mut self, edge: GraphEdge) {
        let edges = self.edges.entry(edge.from.clone()).or_default();
        if !edges.iter().any(|existing| {
            existing.to == edge.to
                && existing.relationship == edge.relationship
                && existing.context == edge.context
        }) {
            edges.push(edge);
        }
    }

    fn module_node_id(file_path: &Path) -> String {
        format!("module:{}", file_path.display())
    }

    fn module_node_name(file_path: &Path) -> String {
        file_path
            .file_stem()
            .and_then(|name| name.to_str())
            .filter(|name| !name.is_empty())
            .map(ToString::to_string)
            .unwrap_or_else(|| file_path.to_string_lossy().into_owned())
    }

    fn normalize_path(path: PathBuf) -> PathBuf {
        let mut normalized = PathBuf::new();
        for component in path.components() {
            match component {
                Component::CurDir => {}
                Component::ParentDir => {
                    normalized.pop();
                }
                Component::Normal(part) => normalized.push(part),
                Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
                Component::RootDir => normalized.push(component.as_os_str()),
            }
        }
        normalized
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

        for node in self.nodes.values() {
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

    /// Find callable nodes that invoke the named symbol in the given file.
    pub fn find_callers(
        &self,
        symbol_name: &str,
        file_path: &Path,
        config: &QueryConfig,
    ) -> QueryResult {
        let start_time = std::time::Instant::now();
        let target_ids = self.find_symbol_node_ids(symbol_name, file_path);
        let target_ids: HashSet<_> = target_ids.into_iter().collect();
        let mut nodes = Vec::new();
        let mut edges = Vec::new();
        let mut seen_nodes = HashSet::new();
        let mut edges_traversed = 0;

        if !target_ids.is_empty() {
            for node_edges in self.edges.values() {
                for edge in node_edges {
                    edges_traversed += 1;
                    if edge.relationship == RelationshipType::Calls && target_ids.contains(&edge.to)
                    {
                        edges.push(edge.clone());
                        if let Some(node) = self.nodes.get(&edge.from) {
                            if seen_nodes.insert(node.id.clone()) {
                                nodes.push(node.clone());
                            }
                        }
                    }
                }
            }
        }

        let truncated = nodes.len() > config.max_results;
        if truncated {
            nodes.truncate(config.max_results);
        }

        QueryResult {
            nodes,
            edges,
            metadata: QueryMetadata {
                nodes_examined: self.nodes.len(),
                edges_traversed,
                execution_time_ms: start_time.elapsed().as_millis() as u64,
                truncated,
            },
        }
    }

    /// Find callable nodes invoked by the named symbol in the given file.
    pub fn find_callees(
        &self,
        symbol_name: &str,
        file_path: &Path,
        config: &QueryConfig,
    ) -> QueryResult {
        let start_time = std::time::Instant::now();
        let source_ids = self.find_symbol_node_ids(symbol_name, file_path);
        let mut nodes = Vec::new();
        let mut edges = Vec::new();
        let mut seen_nodes = HashSet::new();
        let mut edges_traversed = 0;

        for source_id in source_ids {
            if let Some(node_edges) = self.edges.get(&source_id) {
                for edge in node_edges {
                    edges_traversed += 1;
                    if edge.relationship == RelationshipType::Calls {
                        edges.push(edge.clone());
                        if let Some(node) = self.nodes.get(&edge.to) {
                            if seen_nodes.insert(node.id.clone()) {
                                nodes.push(node.clone());
                            }
                        }
                    }
                }
            }
        }

        let truncated = nodes.len() > config.max_results;
        if truncated {
            nodes.truncate(config.max_results);
        }

        QueryResult {
            nodes,
            edges,
            metadata: QueryMetadata {
                nodes_examined: self.nodes.len(),
                edges_traversed,
                execution_time_ms: start_time.elapsed().as_millis() as u64,
                truncated,
            },
        }
    }

    /// Trace a relationship path between entities in the source and sink files.
    pub fn trace_data_flow(
        &self,
        source_file: &Path,
        sink_file: &Path,
        config: &QueryConfig,
    ) -> QueryResult {
        let start_time = std::time::Instant::now();
        let primary_starts = self.node_ids_for_file(source_file, false);
        let primary_targets: HashSet<_> = self
            .node_ids_for_file(sink_file, false)
            .into_iter()
            .collect();

        let primary_search = if primary_starts.is_empty() || primary_targets.is_empty() {
            None
        } else {
            self.find_shortest_path(primary_starts, &primary_targets, config)
        };

        let fallback = if primary_search.is_none() {
            let all_starts = self.node_ids_for_file(source_file, true);
            let all_targets: HashSet<_> = self
                .node_ids_for_file(sink_file, true)
                .into_iter()
                .collect();
            if all_starts.is_empty() || all_targets.is_empty() {
                None
            } else {
                self.find_shortest_path(all_starts, &all_targets, config)
            }
        } else {
            None
        };

        let (nodes, edges, edges_traversed, truncated) = primary_search
            .or(fallback)
            .unwrap_or_else(|| (Vec::new(), Vec::new(), 0, false));

        QueryResult {
            nodes,
            edges,
            metadata: QueryMetadata {
                nodes_examined: self.nodes.len(),
                edges_traversed,
                execution_time_ms: start_time.elapsed().as_millis() as u64,
                truncated,
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

                    if relationship_types.is_empty()
                        || relationship_types.contains(&edge.relationship)
                    {
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
                truncated: !queue.is_empty(),
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
                *relationship_counts
                    .entry(edge.relationship.clone())
                    .or_insert(0) += 1;
            }
        }

        GraphStatistics {
            total_nodes: self.nodes.len(),
            total_edges: self.edges.values().map(|v| v.len()).sum(),
            node_type_distribution: type_counts,
            relationship_type_distribution: relationship_counts,
        }
    }

    /// Export a stable snapshot of the graph for serialization.
    pub fn snapshot(&self) -> SemanticGraphSnapshot {
        let mut nodes: Vec<_> = self.nodes.values().cloned().collect();
        nodes.sort_by(|a, b| a.id.cmp(&b.id).then_with(|| a.name.cmp(&b.name)));

        let mut edges: Vec<_> = self
            .edges
            .values()
            .flat_map(|node_edges| node_edges.iter().cloned())
            .collect();
        edges.sort_by(|a, b| {
            a.from
                .cmp(&b.from)
                .then_with(|| a.to.cmp(&b.to))
                .then_with(|| a.relationship.to_string().cmp(&b.relationship.to_string()))
                .then_with(|| a.context.cmp(&b.context))
        });

        SemanticGraphSnapshot {
            nodes,
            edges,
            statistics: self.get_statistics(),
        }
    }

    // Private helper methods

    /// Add nodes from a file's symbols
    fn add_file_nodes(&mut self, file: &FileInfo) -> Result<()> {
        let module_id = Self::module_node_id(&file.path);
        if !self.nodes.contains_key(&module_id) {
            let mut module_node = Self::create_graph_node(
                module_id.clone(),
                NodeType::Module,
                Self::module_node_name(&file.path),
                file.path.clone(),
                1,
            );
            module_node
                .metadata
                .insert("language".to_string(), file.language.clone());
            module_node
                .metadata
                .insert("kind".to_string(), "file".to_string());
            self.nodes.insert(module_id.clone(), module_node);
        }

        for symbol in &file.symbols {
            let node_id = Self::symbol_node_id(&file.path, symbol);
            let node_type = self.symbol_to_node_type(&symbol.kind);

            let mut node = Self::create_graph_node(
                node_id.clone(),
                node_type,
                symbol.name.clone(),
                file.path.clone(),
                symbol.start_line,
            );
            node.metadata
                .insert("kind".to_string(), symbol.kind.clone());
            node.metadata
                .insert("visibility".to_string(), symbol.visibility.clone());
            node.metadata
                .insert("end_line".to_string(), symbol.end_line.to_string());

            self.nodes.insert(node_id, node);
            self.add_unique_edge(Self::create_graph_edge(
                &Self::symbol_node_id(&file.path, symbol),
                &module_id,
                RelationshipType::DefinedIn,
                1.0,
                Some("file"),
            ));
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
            _ => NodeType::Function,   // Default fallback
        }
    }

    /// Build relationships between nodes
    fn build_relationships(&mut self, analysis: &AnalysisResult) -> Result<()> {
        let file_sources = Self::read_analysis_sources(analysis);
        let known_paths: HashSet<PathBuf> = analysis
            .files
            .iter()
            .map(|file| file.path.clone())
            .collect();

        // Build basic file-level relationships
        for file in &analysis.files {
            self.build_file_relationships(file)?;
        }

        self.build_cross_file_import_relationships(analysis, &file_sources, &known_paths)?;
        self.build_cross_file_call_relationships(analysis, &file_sources, &known_paths)?;

        // Calculate node degrees
        self.calculate_node_degrees();

        Ok(())
    }

    fn read_analysis_sources(analysis: &AnalysisResult) -> HashMap<PathBuf, String> {
        analysis
            .files
            .iter()
            .filter_map(|file| {
                fs::read_to_string(analysis.root_path.join(&file.path))
                    .ok()
                    .map(|content| (file.path.clone(), content))
            })
            .collect()
    }

    fn build_cross_file_import_relationships(
        &mut self,
        analysis: &AnalysisResult,
        file_sources: &HashMap<PathBuf, String>,
        known_paths: &HashSet<PathBuf>,
    ) -> Result<()> {
        for file in &analysis.files {
            let Some(content) = file_sources.get(&file.path) else {
                continue;
            };

            let imported_paths = match file.language.as_str() {
                "Rust" => Self::resolve_rust_import_targets(&file.path, content, known_paths),
                "JavaScript" | "TypeScript" => {
                    Self::resolve_js_import_targets(&file.path, content, known_paths)
                }
                _ => Vec::new(),
            };

            let source_module_id = Self::module_node_id(&file.path);
            for target_path in imported_paths {
                if target_path == file.path {
                    continue;
                }

                let target_module_id = Self::module_node_id(&target_path);
                if self.nodes.contains_key(&source_module_id)
                    && self.nodes.contains_key(&target_module_id)
                {
                    self.add_unique_edge(Self::create_graph_edge(
                        &source_module_id,
                        &target_module_id,
                        RelationshipType::Imports,
                        1.0,
                        Some(&target_path.display().to_string()),
                    ));
                }
            }
        }

        Ok(())
    }

    fn build_symbol_node_lookup(&self) -> HashMap<(PathBuf, String), String> {
        let mut lookup = HashMap::new();
        for (node_id, node) in &self.nodes {
            if node.node_type != NodeType::Module {
                lookup
                    .entry((node.file_path.clone(), node.name.clone()))
                    .or_insert_with(|| node_id.clone());
            }
        }
        lookup
    }

    fn rust_crate_root(current_file: &Path) -> PathBuf {
        let mut components = current_file.components();
        if let Some(first) = components.next() {
            if first.as_os_str() == "src" {
                return PathBuf::from("src");
            }
        }

        PathBuf::new()
    }

    fn extract_rust_mod_declaration(line: &str) -> Option<Vec<String>> {
        let trimmed = line.trim();
        let after = trimmed
            .strip_prefix("mod ")
            .or_else(|| trimmed.strip_prefix("pub mod "))?;
        let name = after
            .split(|c: char| c == ';' || c.is_whitespace() || c == '{')
            .next()
            .unwrap_or("")
            .trim();
        if name.is_empty() {
            None
        } else {
            Some(vec![name.to_string()])
        }
    }

    fn extract_rust_use_segments(line: &str) -> Option<(PathBuf, Vec<String>)> {
        let trimmed = line.trim();
        let after = trimmed
            .strip_prefix("use ")
            .or_else(|| trimmed.strip_prefix("pub use "))?;
        let path = after
            .split(|c: char| c == ';' || c.is_whitespace() || c == '{')
            .next()
            .unwrap_or("")
            .trim_end_matches(':')
            .trim();
        if path.is_empty() {
            return None;
        }

        let mut segments: Vec<String> = path
            .split("::")
            .filter(|segment| !segment.is_empty())
            .map(ToString::to_string)
            .collect();
        if segments.is_empty() {
            return None;
        }

        let base_dir = match segments.first().map(String::as_str) {
            Some("crate") => {
                segments.remove(0);
                PathBuf::new()
            }
            Some("self") => {
                segments.remove(0);
                PathBuf::from(".")
            }
            Some("super") => {
                segments.remove(0);
                PathBuf::from("..")
            }
            Some("std" | "core" | "alloc") => return None,
            _ => PathBuf::from("."),
        };

        if segments.is_empty() {
            None
        } else {
            Some((base_dir, segments))
        }
    }

    fn resolve_rust_module_path(
        base_dir: &Path,
        segments: &[String],
        known_paths: &HashSet<PathBuf>,
    ) -> Option<PathBuf> {
        for end in (1..=segments.len()).rev() {
            let mut module_base = base_dir.to_path_buf();
            for segment in &segments[..end] {
                module_base.push(segment);
            }
            let module_base = Self::normalize_path(module_base);

            let file_candidate = module_base.with_extension("rs");
            if known_paths.contains(&file_candidate) {
                return Some(file_candidate);
            }

            let mod_candidate = module_base.join("mod.rs");
            if known_paths.contains(&mod_candidate) {
                return Some(mod_candidate);
            }
        }

        None
    }

    fn resolve_exact_rust_module_path(
        base_dir: &Path,
        segments: &[String],
        known_paths: &HashSet<PathBuf>,
    ) -> Option<PathBuf> {
        if segments.is_empty() {
            return None;
        }

        let mut module_base = base_dir.to_path_buf();
        for segment in segments {
            module_base.push(segment);
        }
        let module_base = Self::normalize_path(module_base);

        let file_candidate = module_base.with_extension("rs");
        if known_paths.contains(&file_candidate) {
            return Some(file_candidate);
        }

        let mod_candidate = module_base.join("mod.rs");
        if known_paths.contains(&mod_candidate) {
            return Some(mod_candidate);
        }

        None
    }

    fn resolve_rust_import_targets(
        current_file: &Path,
        content: &str,
        known_paths: &HashSet<PathBuf>,
    ) -> Vec<PathBuf> {
        let mut targets = HashSet::new();
        let current_parent = current_file.parent().unwrap_or_else(|| Path::new(""));
        let crate_root = Self::rust_crate_root(current_file);

        for line in content.lines() {
            if let Some(segments) = Self::extract_rust_mod_declaration(line) {
                if let Some(target) =
                    Self::resolve_rust_module_path(current_parent, &segments, known_paths)
                {
                    targets.insert(target);
                }
            }

            if let Some((relative_base, segments)) = Self::extract_rust_use_segments(line) {
                let resolved_base = if relative_base.as_os_str().is_empty() {
                    crate_root.clone()
                } else if relative_base == PathBuf::from("..") {
                    current_parent
                        .parent()
                        .map(Path::to_path_buf)
                        .unwrap_or_default()
                } else {
                    current_parent.to_path_buf()
                };

                if let Some(target) =
                    Self::resolve_rust_module_path(&resolved_base, &segments, known_paths)
                {
                    targets.insert(target);
                }
            }
        }

        let mut sorted: Vec<_> = targets.into_iter().collect();
        sorted.sort();
        sorted
    }

    fn extract_js_relative_imports(content: &str) -> Vec<String> {
        let mut specs = Vec::new();
        for line in content.lines() {
            let trimmed = line.trim();

            if trimmed.starts_with("import ") && trimmed.contains(" from ") {
                if let Some(spec) = trimmed.split(" from ").nth(1) {
                    let spec = spec.trim().trim_matches(&['"', '\'', ';'][..]);
                    if spec.starts_with("./") || spec.starts_with("../") {
                        specs.push(spec.to_string());
                    }
                }
            }

            if trimmed.starts_with("import ") && !trimmed.contains(" from ") {
                if let Some(start) = trimmed.find('\'') {
                    let spec = &trimmed[start + 1..];
                    if let Some(end) = spec.find('\'') {
                        let value = &spec[..end];
                        if value.starts_with("./") || value.starts_with("../") {
                            specs.push(value.to_string());
                        }
                    }
                } else if let Some(start) = trimmed.find('"') {
                    let spec = &trimmed[start + 1..];
                    if let Some(end) = spec.find('"') {
                        let value = &spec[..end];
                        if value.starts_with("./") || value.starts_with("../") {
                            specs.push(value.to_string());
                        }
                    }
                }
            }

            if let Some(idx) = trimmed.find("require(") {
                let rest = &trimmed[idx + 8..];
                if let Some(end) = rest.find(')') {
                    let inside = rest[..end].trim_matches(&['"', '\'', ' '][..]);
                    if inside.starts_with("./") || inside.starts_with("../") {
                        specs.push(inside.to_string());
                    }
                }
            }

            if trimmed.starts_with("export ") && trimmed.contains(" from ") {
                if let Some(spec) = trimmed.split(" from ").nth(1) {
                    let spec = spec.trim().trim_matches(&['"', '\'', ';'][..]);
                    if spec.starts_with("./") || spec.starts_with("../") {
                        specs.push(spec.to_string());
                    }
                }
            }
        }

        specs
    }

    fn resolve_js_relative_spec(
        current_file: &Path,
        spec: &str,
        known_paths: &HashSet<PathBuf>,
    ) -> Option<PathBuf> {
        let base = current_file.parent().unwrap_or_else(|| Path::new(""));
        let joined = Self::normalize_path(base.join(spec));
        let mut candidates = Vec::new();

        if joined.extension().is_some() {
            candidates.push(joined);
        } else {
            for ext in ["js", "jsx", "ts", "tsx", "mjs", "cjs"] {
                candidates.push(joined.with_extension(ext));
            }
            for index_file in ["index.js", "index.jsx", "index.ts", "index.tsx"] {
                candidates.push(joined.join(index_file));
            }
        }

        candidates
            .into_iter()
            .map(Self::normalize_path)
            .find(|candidate| known_paths.contains(candidate))
    }

    fn resolve_js_import_targets(
        current_file: &Path,
        content: &str,
        known_paths: &HashSet<PathBuf>,
    ) -> Vec<PathBuf> {
        let mut targets = HashSet::new();
        for spec in Self::extract_js_relative_imports(content) {
            if let Some(target) = Self::resolve_js_relative_spec(current_file, &spec, known_paths) {
                targets.insert(target);
            }
        }

        let mut sorted: Vec<_> = targets.into_iter().collect();
        sorted.sort();
        sorted
    }

    fn find_symbol_node_ids(&self, symbol_name: &str, file_path: &Path) -> Vec<String> {
        let mut node_ids: Vec<_> = self
            .nodes
            .values()
            .filter(|node| {
                node.node_type != NodeType::Module
                    && node.name == symbol_name
                    && node.file_path == file_path
            })
            .map(|node| node.id.clone())
            .collect();
        node_ids.sort();
        node_ids
    }

    fn node_ids_for_file(&self, file_path: &Path, include_modules: bool) -> Vec<String> {
        let mut node_ids: Vec<_> = self
            .nodes
            .values()
            .filter(|node| {
                node.file_path == file_path
                    && (include_modules || node.node_type != NodeType::Module)
            })
            .map(|node| node.id.clone())
            .collect();
        node_ids.sort();
        node_ids
    }

    fn find_shortest_path(
        &self,
        start_ids: Vec<String>,
        target_ids: &HashSet<String>,
        config: &QueryConfig,
    ) -> Option<(Vec<GraphNode>, Vec<GraphEdge>, usize, bool)> {
        let mut queue = VecDeque::new();
        let mut visited = HashSet::new();
        let mut parents: HashMap<String, (String, GraphEdge)> = HashMap::new();
        let mut edges_traversed = 0;
        let mut found_target = None;
        let mut truncated = false;

        for start_id in start_ids {
            if visited.insert(start_id.clone()) {
                if target_ids.contains(&start_id) {
                    found_target = Some(start_id);
                    break;
                }
                queue.push_back((start_id, 0usize));
            }
        }

        while let Some((node_id, depth)) = queue.pop_front() {
            if depth >= config.max_depth {
                truncated |= self
                    .edges
                    .get(&node_id)
                    .map(|node_edges| !node_edges.is_empty())
                    .unwrap_or(false);
                continue;
            }

            if let Some(node_edges) = self.edges.get(&node_id) {
                for edge in node_edges {
                    edges_traversed += 1;
                    if visited.insert(edge.to.clone()) {
                        parents.insert(edge.to.clone(), (node_id.clone(), edge.clone()));
                        if target_ids.contains(&edge.to) {
                            found_target = Some(edge.to.clone());
                            queue.clear();
                            break;
                        }
                        queue.push_back((edge.to.clone(), depth + 1));
                    }
                }
            }
        }

        let found_target = found_target?;
        let mut path_node_ids = vec![found_target.clone()];
        let mut path_edges = Vec::new();
        let mut current_id = found_target;

        while let Some((previous_id, edge)) = parents.get(&current_id) {
            path_edges.push(edge.clone());
            path_node_ids.push(previous_id.clone());
            current_id = previous_id.clone();
        }

        path_node_ids.reverse();
        path_edges.reverse();

        let nodes = path_node_ids
            .into_iter()
            .filter_map(|node_id| self.nodes.get(&node_id).cloned())
            .collect();

        Some((nodes, path_edges, edges_traversed, truncated))
    }

    fn resolve_rust_base_dir(current_file: &Path, segments: &mut Vec<String>) -> Option<PathBuf> {
        let current_parent = current_file.parent().unwrap_or_else(|| Path::new(""));
        match segments.first().map(String::as_str) {
            Some("crate") => {
                segments.remove(0);
                Some(Self::rust_crate_root(current_file))
            }
            Some("self") => {
                segments.remove(0);
                Some(current_parent.to_path_buf())
            }
            Some("super") => {
                segments.remove(0);
                Some(
                    current_parent
                        .parent()
                        .map(Path::to_path_buf)
                        .unwrap_or_default(),
                )
            }
            Some("std" | "core" | "alloc") => None,
            _ => Some(current_parent.to_path_buf()),
        }
    }

    fn parse_rust_use_statement(line: &str) -> Option<(Vec<String>, Option<String>)> {
        let trimmed = line.trim();
        let after = trimmed
            .strip_prefix("use ")
            .or_else(|| trimmed.strip_prefix("pub use "))?;
        let statement = after.split(';').next().unwrap_or("").trim();
        if statement.is_empty() || statement.contains('{') {
            return None;
        }

        let mut parts = statement.splitn(2, " as ");
        let path = parts.next()?.trim();
        let alias = parts
            .next()
            .map(str::trim)
            .filter(|alias| !alias.is_empty())
            .map(ToString::to_string);
        let segments: Vec<String> = path
            .split("::")
            .filter(|segment| !segment.is_empty())
            .map(ToString::to_string)
            .collect();
        if segments.is_empty() {
            None
        } else {
            Some((segments, alias))
        }
    }

    fn resolve_rust_import_bindings(
        current_file: &Path,
        content: &str,
        known_paths: &HashSet<PathBuf>,
    ) -> (Vec<ImportedSymbolBinding>, Vec<ImportedModuleBinding>) {
        let current_parent = current_file.parent().unwrap_or_else(|| Path::new(""));
        let mut symbol_bindings = Vec::new();
        let mut module_bindings = Vec::new();

        for line in content.lines() {
            if let Some(segments) = Self::extract_rust_mod_declaration(line) {
                if let Some(target_path) =
                    Self::resolve_exact_rust_module_path(current_parent, &segments, known_paths)
                {
                    if let Some(alias) = segments.last() {
                        module_bindings.push(ImportedModuleBinding {
                            alias: alias.clone(),
                            target_path,
                        });
                    }
                }
            }

            if let Some((mut segments, alias)) = Self::parse_rust_use_statement(line) {
                let Some(base_dir) = Self::resolve_rust_base_dir(current_file, &mut segments)
                else {
                    continue;
                };
                if segments.is_empty() {
                    continue;
                }

                if let Some(target_path) =
                    Self::resolve_exact_rust_module_path(&base_dir, &segments, known_paths)
                {
                    let alias =
                        alias.unwrap_or_else(|| segments.last().cloned().unwrap_or_default());
                    module_bindings.push(ImportedModuleBinding { alias, target_path });
                    continue;
                }

                if segments.len() >= 2 {
                    let target_symbol = segments.last().cloned().unwrap_or_default();
                    let target_segments = &segments[..segments.len() - 1];
                    if let Some(target_path) =
                        Self::resolve_rust_module_path(&base_dir, target_segments, known_paths)
                    {
                        let alias = alias.unwrap_or_else(|| target_symbol.clone());
                        symbol_bindings.push(ImportedSymbolBinding {
                            alias,
                            target_path,
                            target_symbol,
                        });
                    }
                }
            }
        }

        (symbol_bindings, module_bindings)
    }

    fn resolve_js_import_bindings(
        current_file: &Path,
        content: &str,
        known_paths: &HashSet<PathBuf>,
    ) -> (Vec<ImportedSymbolBinding>, Vec<ImportedModuleBinding>) {
        let mut symbol_bindings = Vec::new();
        let mut module_bindings = Vec::new();

        for line in content.lines() {
            let trimmed = line.trim();

            if trimmed.starts_with("import {") && trimmed.contains("} from ") {
                let Some(open) = trimmed.find('{') else {
                    continue;
                };
                let Some(close) = trimmed.find('}') else {
                    continue;
                };
                let Some(spec) = trimmed.split(" from ").nth(1) else {
                    continue;
                };
                let spec = spec.trim().trim_matches(&['"', '\'', ';'][..]);
                let Some(target_path) =
                    Self::resolve_js_relative_spec(current_file, spec, known_paths)
                else {
                    continue;
                };

                for binding in trimmed[open + 1..close].split(',') {
                    let binding = binding.trim();
                    if binding.is_empty() {
                        continue;
                    }

                    let mut parts = binding.splitn(2, " as ");
                    let original = parts.next().unwrap_or("").trim();
                    let alias = parts.next().map(str::trim).unwrap_or(original);
                    if !original.is_empty() && !alias.is_empty() {
                        symbol_bindings.push(ImportedSymbolBinding {
                            alias: alias.to_string(),
                            target_path: target_path.clone(),
                            target_symbol: original.to_string(),
                        });
                    }
                }

                continue;
            }

            if trimmed.starts_with("import * as ") && trimmed.contains(" from ") {
                let alias = trimmed
                    .trim_start_matches("import * as ")
                    .split(" from ")
                    .next()
                    .unwrap_or("")
                    .trim();
                let Some(spec) = trimmed.split(" from ").nth(1) else {
                    continue;
                };
                let spec = spec.trim().trim_matches(&['"', '\'', ';'][..]);
                if !alias.is_empty() {
                    if let Some(target_path) =
                        Self::resolve_js_relative_spec(current_file, spec, known_paths)
                    {
                        module_bindings.push(ImportedModuleBinding {
                            alias: alias.to_string(),
                            target_path,
                        });
                    }
                }

                continue;
            }

            if (trimmed.starts_with("const {")
                || trimmed.starts_with("let {")
                || trimmed.starts_with("var {"))
                && trimmed.contains("= require(")
            {
                let Some(open) = trimmed.find('{') else {
                    continue;
                };
                let Some(close) = trimmed.find('}') else {
                    continue;
                };
                let Some(require_start) = trimmed.find("require(") else {
                    continue;
                };
                let Some(require_end) = trimmed[require_start + 8..].find(')') else {
                    continue;
                };
                let spec = trimmed[require_start + 8..require_start + 8 + require_end]
                    .trim()
                    .trim_matches(&['"', '\''][..]);
                let Some(target_path) =
                    Self::resolve_js_relative_spec(current_file, spec, known_paths)
                else {
                    continue;
                };

                for binding in trimmed[open + 1..close].split(',') {
                    let binding = binding.trim();
                    if binding.is_empty() {
                        continue;
                    }

                    let mut parts = binding.splitn(2, ':');
                    let original = parts.next().unwrap_or("").trim();
                    let alias = parts.next().map(str::trim).unwrap_or(original);
                    if !original.is_empty() && !alias.is_empty() {
                        symbol_bindings.push(ImportedSymbolBinding {
                            alias: alias.to_string(),
                            target_path: target_path.clone(),
                            target_symbol: original.to_string(),
                        });
                    }
                }

                continue;
            }

            if (trimmed.starts_with("const ")
                || trimmed.starts_with("let ")
                || trimmed.starts_with("var "))
                && trimmed.contains("= require(")
            {
                let Some(eq_index) = trimmed.find('=') else {
                    continue;
                };
                let alias = trimmed[..eq_index]
                    .trim_start_matches("const ")
                    .trim_start_matches("let ")
                    .trim_start_matches("var ")
                    .trim();
                let Some(require_start) = trimmed.find("require(") else {
                    continue;
                };
                let Some(require_end) = trimmed[require_start + 8..].find(')') else {
                    continue;
                };
                let spec = trimmed[require_start + 8..require_start + 8 + require_end]
                    .trim()
                    .trim_matches(&['"', '\''][..]);
                if !alias.is_empty() {
                    if let Some(target_path) =
                        Self::resolve_js_relative_spec(current_file, spec, known_paths)
                    {
                        module_bindings.push(ImportedModuleBinding {
                            alias: alias.to_string(),
                            target_path,
                        });
                    }
                }
            }
        }

        (symbol_bindings, module_bindings)
    }

    fn resolve_rust_reexport_bindings(
        current_file: &Path,
        content: &str,
        known_paths: &HashSet<PathBuf>,
    ) -> Vec<ImportedSymbolBinding> {
        let mut symbol_bindings = Vec::new();

        for line in content.lines() {
            if !line.trim().starts_with("pub use ") {
                continue;
            }

            let Some((mut segments, alias)) = Self::parse_rust_use_statement(line) else {
                continue;
            };
            let Some(base_dir) = Self::resolve_rust_base_dir(current_file, &mut segments) else {
                continue;
            };
            if segments.len() < 2 {
                continue;
            }

            let target_symbol = segments.last().cloned().unwrap_or_default();
            let target_segments = &segments[..segments.len() - 1];
            if let Some(target_path) =
                Self::resolve_rust_module_path(&base_dir, target_segments, known_paths)
            {
                let alias = alias.unwrap_or_else(|| target_symbol.clone());
                symbol_bindings.push(ImportedSymbolBinding {
                    alias,
                    target_path,
                    target_symbol,
                });
            }
        }

        symbol_bindings
    }

    fn resolve_js_reexport_bindings(
        current_file: &Path,
        content: &str,
        known_paths: &HashSet<PathBuf>,
    ) -> Vec<ImportedSymbolBinding> {
        let mut symbol_bindings = Vec::new();

        for line in content.lines() {
            let trimmed = line.trim();
            if !(trimmed.starts_with("export {") && trimmed.contains("} from ")) {
                continue;
            }

            let Some(open) = trimmed.find('{') else {
                continue;
            };
            let Some(close) = trimmed.find('}') else {
                continue;
            };
            let Some(spec) = trimmed.split(" from ").nth(1) else {
                continue;
            };
            let spec = spec.trim().trim_matches(&['"', '\'', ';'][..]);
            let Some(target_path) = Self::resolve_js_relative_spec(current_file, spec, known_paths)
            else {
                continue;
            };

            for binding in trimmed[open + 1..close].split(',') {
                let binding = binding.trim();
                if binding.is_empty() {
                    continue;
                }

                let mut parts = binding.splitn(2, " as ");
                let original = parts.next().unwrap_or("").trim();
                let alias = parts.next().map(str::trim).unwrap_or(original);
                if !original.is_empty() && !alias.is_empty() {
                    symbol_bindings.push(ImportedSymbolBinding {
                        alias: alias.to_string(),
                        target_path: target_path.clone(),
                        target_symbol: original.to_string(),
                    });
                }
            }
        }

        symbol_bindings
    }

    fn build_symbol_reexport_lookup(
        analysis: &AnalysisResult,
        file_sources: &HashMap<PathBuf, String>,
        known_paths: &HashSet<PathBuf>,
    ) -> ReexportLookup {
        let mut reexports = HashMap::new();

        for file in &analysis.files {
            let Some(content) = file_sources.get(&file.path) else {
                continue;
            };

            let bindings = match file.language.as_str() {
                "Rust" => Self::resolve_rust_reexport_bindings(&file.path, content, known_paths),
                "JavaScript" | "TypeScript" => {
                    Self::resolve_js_reexport_bindings(&file.path, content, known_paths)
                }
                _ => Vec::new(),
            };

            for binding in bindings {
                reexports.insert(
                    (file.path.clone(), binding.alias),
                    (binding.target_path, binding.target_symbol),
                );
            }
        }

        reexports
    }

    fn resolve_reexport_target(
        target_path: &Path,
        target_symbol: &str,
        reexports: &ReexportLookup,
    ) -> SymbolLocation {
        let mut resolved = (target_path.to_path_buf(), target_symbol.to_string());
        let mut visited = HashSet::new();

        while visited.insert(resolved.clone()) {
            let Some(next) = reexports.get(&resolved) else {
                break;
            };
            resolved = next.clone();
        }

        resolved
    }

    fn is_non_call_keyword(name: &str) -> bool {
        matches!(
            name,
            "if" | "for"
                | "while"
                | "match"
                | "loop"
                | "fn"
                | "function"
                | "return"
                | "let"
                | "const"
                | "var"
                | "pub"
                | "export"
                | "import"
                | "require"
                | "class"
                | "struct"
                | "impl"
                | "enum"
        )
    }

    fn extract_simple_call_names(line: &str) -> Vec<String> {
        static SIMPLE_CALL_RE: OnceLock<Regex> = OnceLock::new();
        let regex = SIMPLE_CALL_RE.get_or_init(|| {
            Regex::new(r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\(")
                .expect("simple call regex must compile")
        });

        regex
            .captures_iter(line)
            .filter_map(|captures| {
                let name_match = captures.name("name")?;
                let preceding = line[..name_match.start()].chars().last();
                if matches!(preceding, Some(':') | Some('.')) {
                    return None;
                }

                let name = name_match.as_str();
                if Self::is_non_call_keyword(name) {
                    None
                } else {
                    Some(name.to_string())
                }
            })
            .collect()
    }

    fn extract_rust_qualified_calls(line: &str) -> Vec<(String, String)> {
        static QUALIFIED_RUST_CALL_RE: OnceLock<Regex> = OnceLock::new();
        let regex = QUALIFIED_RUST_CALL_RE.get_or_init(|| {
            Regex::new(r"(?P<module>[A-Za-z_][A-Za-z0-9_]*)::(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\(")
                .expect("rust qualified call regex must compile")
        });

        regex
            .captures_iter(line)
            .filter_map(|captures| {
                Some((
                    captures.name("module")?.as_str().to_string(),
                    captures.name("name")?.as_str().to_string(),
                ))
            })
            .collect()
    }

    fn extract_js_qualified_calls(line: &str) -> Vec<(String, String)> {
        static QUALIFIED_JS_CALL_RE: OnceLock<Regex> = OnceLock::new();
        let regex = QUALIFIED_JS_CALL_RE.get_or_init(|| {
            Regex::new(r"(?P<module>[A-Za-z_][A-Za-z0-9_]*)\.(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\(")
                .expect("js qualified call regex must compile")
        });

        regex
            .captures_iter(line)
            .filter_map(|captures| {
                Some((
                    captures.name("module")?.as_str().to_string(),
                    captures.name("name")?.as_str().to_string(),
                ))
            })
            .collect()
    }

    fn resolve_rust_call_targets(
        current_file: &Path,
        content: &str,
        known_paths: &HashSet<PathBuf>,
    ) -> Vec<ResolvedCallTarget> {
        let (symbol_bindings, module_bindings) =
            Self::resolve_rust_import_bindings(current_file, content, known_paths);
        let symbol_bindings: HashMap<_, _> = symbol_bindings
            .into_iter()
            .map(|binding| (binding.alias, (binding.target_path, binding.target_symbol)))
            .collect();
        let module_bindings: HashMap<_, _> = module_bindings
            .into_iter()
            .map(|binding| (binding.alias, binding.target_path))
            .collect();
        let mut targets = Vec::new();

        for (index, line) in content.lines().enumerate() {
            let line_number = index + 1;

            for (module_alias, symbol_name) in Self::extract_rust_qualified_calls(line) {
                if let Some(target_path) = module_bindings.get(&module_alias) {
                    targets.push(ResolvedCallTarget {
                        line_number,
                        target_path: target_path.clone(),
                        target_symbol: symbol_name,
                    });
                }
            }

            for symbol_name in Self::extract_simple_call_names(line) {
                if let Some((target_path, target_symbol)) = symbol_bindings.get(&symbol_name) {
                    targets.push(ResolvedCallTarget {
                        line_number,
                        target_path: target_path.clone(),
                        target_symbol: target_symbol.clone(),
                    });
                }
            }
        }

        targets
    }

    fn resolve_js_call_targets(
        current_file: &Path,
        content: &str,
        known_paths: &HashSet<PathBuf>,
    ) -> Vec<ResolvedCallTarget> {
        let (symbol_bindings, module_bindings) =
            Self::resolve_js_import_bindings(current_file, content, known_paths);
        let symbol_bindings: HashMap<_, _> = symbol_bindings
            .into_iter()
            .map(|binding| (binding.alias, (binding.target_path, binding.target_symbol)))
            .collect();
        let module_bindings: HashMap<_, _> = module_bindings
            .into_iter()
            .map(|binding| (binding.alias, binding.target_path))
            .collect();
        let mut targets = Vec::new();

        for (index, line) in content.lines().enumerate() {
            let line_number = index + 1;

            for (module_alias, symbol_name) in Self::extract_js_qualified_calls(line) {
                if let Some(target_path) = module_bindings.get(&module_alias) {
                    targets.push(ResolvedCallTarget {
                        line_number,
                        target_path: target_path.clone(),
                        target_symbol: symbol_name,
                    });
                }
            }

            for symbol_name in Self::extract_simple_call_names(line) {
                if let Some((target_path, target_symbol)) = symbol_bindings.get(&symbol_name) {
                    targets.push(ResolvedCallTarget {
                        line_number,
                        target_path: target_path.clone(),
                        target_symbol: target_symbol.clone(),
                    });
                }
            }
        }

        targets
    }

    fn build_cross_file_call_relationships(
        &mut self,
        analysis: &AnalysisResult,
        file_sources: &HashMap<PathBuf, String>,
        known_paths: &HashSet<PathBuf>,
    ) -> Result<()> {
        let symbol_lookup = self.build_symbol_node_lookup();
        let reexports = Self::build_symbol_reexport_lookup(analysis, file_sources, known_paths);

        for file in &analysis.files {
            let Some(content) = file_sources.get(&file.path) else {
                continue;
            };

            let targets = match file.language.as_str() {
                "Rust" => Self::resolve_rust_call_targets(&file.path, content, known_paths),
                "JavaScript" | "TypeScript" => {
                    Self::resolve_js_call_targets(&file.path, content, known_paths)
                }
                _ => Vec::new(),
            };

            for target in targets {
                let Some(caller) = Self::find_enclosing_callable_symbol(file, target.line_number)
                else {
                    continue;
                };
                let source_id = Self::symbol_node_id(&file.path, caller);
                let (resolved_target_path, resolved_target_symbol) = Self::resolve_reexport_target(
                    &target.target_path,
                    &target.target_symbol,
                    &reexports,
                );
                let Some(target_id) = symbol_lookup
                    .get(&(resolved_target_path.clone(), resolved_target_symbol.clone()))
                else {
                    continue;
                };
                if source_id == *target_id {
                    continue;
                }

                self.add_unique_edge(Self::create_graph_edge(
                    &source_id,
                    target_id,
                    RelationshipType::Calls,
                    0.9,
                    Some(&format!(
                        "{}:{}",
                        resolved_target_path.display(),
                        resolved_target_symbol
                    )),
                ));
            }
        }

        Ok(())
    }

    /// Build relationships within a file
    fn build_file_relationships(&mut self, file: &FileInfo) -> Result<()> {
        let file_symbols: Vec<_> = file.symbols.iter().collect();

        // Create relationships between symbols in the same file
        for (i, symbol1) in file_symbols.iter().enumerate() {
            let node1_id = format!(
                "{}:{}:{}",
                file.path.display(),
                symbol1.name,
                symbol1.start_line
            );
            let mut edges_for_node1 = Vec::new();

            for symbol2 in file_symbols.iter().skip(i + 1) {
                let node2_id = format!(
                    "{}:{}:{}",
                    file.path.display(),
                    symbol2.name,
                    symbol2.start_line
                );

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
                self.edges
                    .entry(node1_id)
                    .or_default()
                    .extend(edges_for_node1);
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
        let degree_diff =
            (node1.properties.in_degree as f64 - node2.properties.in_degree as f64).abs();
        let degree_similarity = 1.0 - (degree_diff / 10.0).min(1.0);
        similarity += degree_similarity * 0.1;

        // Tag similarity
        let common_tags = node1
            .properties
            .tags
            .iter()
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
            self.index
                .by_type
                .entry(node.node_type.clone())
                .or_default()
                .insert(node_id.to_string());

            // Index by file
            self.index
                .by_file
                .entry(node.file_path.to_path_buf())
                .or_default()
                .insert(node_id.to_string());

            // Index by name
            self.index
                .by_name
                .entry(node.name.to_string())
                .or_default()
                .insert(node_id.to_string());
        }
    }
}

/// Graph statistics for analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
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

/// Serializable snapshot of the semantic graph for CLI and agent consumers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SemanticGraphSnapshot {
    /// All graph nodes in stable order
    pub nodes: Vec<GraphNode>,
    /// All graph edges in stable order
    pub edges: Vec<GraphEdge>,
    /// Summary statistics for the graph
    pub statistics: GraphStatistics,
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
    use crate::Symbol;
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

        // Should have created nodes for the file module, function, and class
        assert_eq!(graph.nodes.len(), 3);

        let module_nodes: Vec<_> = graph
            .nodes
            .values()
            .filter(|n| n.node_type == NodeType::Module)
            .collect();
        assert_eq!(module_nodes.len(), 1);
        assert_eq!(module_nodes[0].name, "test");

        // Check that nodes were created correctly
        let function_nodes: Vec<_> = graph
            .nodes
            .values()
            .filter(|n| n.node_type == NodeType::Function)
            .collect();
        assert_eq!(function_nodes.len(), 1);
        assert_eq!(function_nodes[0].name, "test_function");

        let class_nodes: Vec<_> = graph
            .nodes
            .values()
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
        assert_eq!(module_result.nodes.len(), 1);
        assert_eq!(module_result.nodes[0].name, "test");
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

        assert_eq!(stats.total_nodes, 3);
        assert!(stats.total_edges > 0); // Should have some relationships
        assert_eq!(
            stats.node_type_distribution.get(&NodeType::Function),
            Some(&1)
        );
        assert_eq!(stats.node_type_distribution.get(&NodeType::Class), Some(&1));
        assert_eq!(stats.node_type_distribution.get(&NodeType::Module), Some(&1));
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
