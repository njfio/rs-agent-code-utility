use rust_tree_sitter::{
    SemanticGraphQuery, NodeType, RelationshipType, QueryConfig,
    AnalysisResult, FileInfo
};
use std::path::PathBuf;
use tempfile::TempDir;
use std::fs;
use std::collections::HashMap;

fn create_test_analysis_result() -> Result<AnalysisResult, Box<dyn std::error::Error>> {
    let temp_dir = TempDir::new()?;
    
    // Create test files
    let rust_file = temp_dir.path().join("test.rs");
    fs::write(&rust_file, r#"
struct User {
    name: String,
    age: u32,
}

impl User {
    fn new(name: String, age: u32) -> Self {
        User { name, age }
    }
    
    fn get_name(&self) -> &str {
        &self.name
    }
}

fn create_user() -> User {
    User::new("Alice".to_string(), 30)
}

const MAX_AGE: u32 = 120;
"#)?;

    let python_file = temp_dir.path().join("test.py");
    fs::write(&python_file, r#"
class User:
    def __init__(self, name, age):
        self.name = name
        self.age = age
    
    def get_name(self):
        return self.name

def create_user():
    return User("Bob", 25)

MAX_AGE = 120
"#)?;

    // Create analysis result with mock symbols
    let mut result = AnalysisResult {
        root_path: temp_dir.path().to_path_buf(),
        total_files: 2,
        parsed_files: 2,
        error_files: 0,
        total_lines: 50,
        languages: {
            let mut map = HashMap::new();
            map.insert("Rust".to_string(), 1);
            map.insert("Python".to_string(), 1);
            map
        },
        files: Vec::new(),
        config: rust_tree_sitter::AnalysisConfig::default(),
    };

    // Add Rust file symbols
    result.files.push(FileInfo {
        path: PathBuf::from("test.rs"),
        language: "Rust".to_string(),
        size: 500,
        lines: 25,
        parsed_successfully: true,
        parse_errors: Vec::new(),
        symbols: vec![
            rust_tree_sitter::Symbol {
                name: "User".to_string(),
                kind: "struct".to_string(),
                start_line: 2,
                end_line: 5,
                start_column: 1,
                end_column: 1,
                visibility: "public".to_string(),
                documentation: None,
            },
            rust_tree_sitter::Symbol {
                name: "new".to_string(),
                kind: "function".to_string(),
                start_line: 7,
                end_line: 9,
                start_column: 5,
                end_column: 5,
                visibility: "public".to_string(),
                documentation: None,
            },
            rust_tree_sitter::Symbol {
                name: "get_name".to_string(),
                kind: "function".to_string(),
                start_line: 11,
                end_line: 13,
                start_column: 5,
                end_column: 5,
                visibility: "public".to_string(),
                documentation: None,
            },
            rust_tree_sitter::Symbol {
                name: "create_user".to_string(),
                kind: "function".to_string(),
                start_line: 16,
                end_line: 18,
                start_column: 1,
                end_column: 1,
                visibility: "public".to_string(),
                documentation: None,
            },
            rust_tree_sitter::Symbol {
                name: "MAX_AGE".to_string(),
                kind: "constant".to_string(),
                start_line: 20,
                end_line: 20,
                start_column: 1,
                end_column: 1,
                visibility: "public".to_string(),
                documentation: None,
            },
        ],
        security_vulnerabilities: Vec::new(),
    });

    // Add Python file symbols
    result.files.push(FileInfo {
        path: PathBuf::from("test.py"),
        language: "Python".to_string(),
        size: 400,
        lines: 25,
        parsed_successfully: true,
        parse_errors: Vec::new(),
        symbols: vec![
            rust_tree_sitter::Symbol {
                name: "User".to_string(),
                kind: "class".to_string(),
                start_line: 2,
                end_line: 8,
                start_column: 1,
                end_column: 1,
                visibility: "public".to_string(),
                documentation: None,
            },
            rust_tree_sitter::Symbol {
                name: "__init__".to_string(),
                kind: "function".to_string(),
                start_line: 3,
                end_line: 5,
                start_column: 5,
                end_column: 5,
                visibility: "public".to_string(),
                documentation: None,
            },
            rust_tree_sitter::Symbol {
                name: "get_name".to_string(),
                kind: "function".to_string(),
                start_line: 7,
                end_line: 8,
                start_column: 5,
                end_column: 5,
                visibility: "public".to_string(),
                documentation: None,
            },
            rust_tree_sitter::Symbol {
                name: "create_user".to_string(),
                kind: "function".to_string(),
                start_line: 10,
                end_line: 11,
                start_column: 1,
                end_column: 1,
                visibility: "public".to_string(),
                documentation: None,
            },
            rust_tree_sitter::Symbol {
                name: "MAX_AGE".to_string(),
                kind: "constant".to_string(),
                start_line: 13,
                end_line: 13,
                start_column: 1,
                end_column: 1,
                visibility: "public".to_string(),
                documentation: None,
            },
        ],
        security_vulnerabilities: Vec::new(),
    });

    Ok(result)
}

#[test]
fn test_semantic_graph_creation() -> Result<(), Box<dyn std::error::Error>> {
    let analysis = create_test_analysis_result()?;
    let mut graph = SemanticGraphQuery::new();
    
    graph.build_from_analysis(&analysis)?;
    
    let stats = graph.get_statistics();
    assert!(stats.total_nodes > 0, "Graph should have nodes");
    // Graph should have edges (non-negative count)
    
    // Check that we have different node types
    assert!(stats.node_type_distribution.contains_key(&NodeType::Struct), "Should have struct nodes");
    assert!(stats.node_type_distribution.contains_key(&NodeType::Function), "Should have function nodes");
    assert!(stats.node_type_distribution.contains_key(&NodeType::Constant), "Should have constant nodes");
    
    Ok(())
}

#[test]
fn test_find_by_type() -> Result<(), Box<dyn std::error::Error>> {
    let analysis = create_test_analysis_result()?;
    let mut graph = SemanticGraphQuery::new();
    graph.build_from_analysis(&analysis)?;
    
    let config = QueryConfig::default();
    
    // Find all functions
    let function_result = graph.find_by_type(NodeType::Function, &config);
    assert!(function_result.nodes.len() > 0, "Should find function nodes");
    
    for node in &function_result.nodes {
        assert_eq!(node.node_type, NodeType::Function, "All nodes should be functions");
    }
    
    // Find all constants
    let constant_result = graph.find_by_type(NodeType::Constant, &config);
    assert!(constant_result.nodes.len() > 0, "Should find constant nodes");
    
    for node in &constant_result.nodes {
        assert_eq!(node.node_type, NodeType::Constant, "All nodes should be constants");
    }
    
    Ok(())
}

#[test]
fn test_find_by_name() -> Result<(), Box<dyn std::error::Error>> {
    let analysis = create_test_analysis_result()?;
    let mut graph = SemanticGraphQuery::new();
    graph.build_from_analysis(&analysis)?;
    
    let config = QueryConfig::default();
    
    // Find nodes with "User" in the name
    let user_result = graph.find_by_name("User", &config);
    assert!(user_result.nodes.len() > 0, "Should find User nodes");
    
    for node in &user_result.nodes {
        assert!(node.name.contains("User"), "Node name should contain 'User'");
    }
    
    // Find nodes with "get_name" in the name
    let get_name_result = graph.find_by_name("get_name", &config);
    assert!(get_name_result.nodes.len() > 0, "Should find get_name nodes");
    
    for node in &get_name_result.nodes {
        assert!(node.name.contains("get_name"), "Node name should contain 'get_name'");
    }
    
    Ok(())
}

#[test]
fn test_traverse_relationships() -> Result<(), Box<dyn std::error::Error>> {
    let analysis = create_test_analysis_result()?;
    let mut graph = SemanticGraphQuery::new();
    graph.build_from_analysis(&analysis)?;
    
    let config = QueryConfig {
        max_depth: 3,
        max_results: 50,
        ..QueryConfig::default()
    };
    
    // Get a starting node
    let all_nodes = graph.find_by_type(NodeType::Function, &config);
    if let Some(start_node) = all_nodes.nodes.first() {
        let traversal_result = graph.traverse_relationships(
            &start_node.id,
            &[RelationshipType::DependsOn],
            &config,
        );
        
        assert!(traversal_result.metadata.nodes_examined > 0, "Should examine nodes during traversal");
        // Execution time should be tracked
    }
    
    Ok(())
}

#[test]
fn test_find_similar() -> Result<(), Box<dyn std::error::Error>> {
    let analysis = create_test_analysis_result()?;
    let mut graph = SemanticGraphQuery::new();
    graph.build_from_analysis(&analysis)?;
    
    let config = QueryConfig {
        similarity_threshold: 0.1, // Lower threshold to find more similarities
        max_results: 10,
        ..QueryConfig::default()
    };
    
    // Get a target node
    let all_nodes = graph.find_by_name("get_name", &config);
    if let Some(target_node) = all_nodes.nodes.first() {
        let similar_result = graph.find_similar(&target_node.id, &config);
        
        // Should find at least some similar nodes (the other get_name function)
        assert!(similar_result.metadata.nodes_examined > 0, "Should examine nodes for similarity");
        // Execution time should be tracked
        
        // Verify that similar nodes are actually similar
        for node in &similar_result.nodes {
            assert_ne!(node.id, target_node.id, "Similar nodes should not include the target node itself");
        }
    }
    
    Ok(())
}

#[test]
fn test_query_metadata() -> Result<(), Box<dyn std::error::Error>> {
    let analysis = create_test_analysis_result()?;
    let mut graph = SemanticGraphQuery::new();
    graph.build_from_analysis(&analysis)?;
    
    let config = QueryConfig::default();
    
    let result = graph.find_by_type(NodeType::Function, &config);
    
    // Verify metadata is populated
    assert!(result.metadata.nodes_examined > 0, "Should track nodes examined");
    // Execution time should be tracked
    assert!(!result.metadata.truncated || result.nodes.len() == config.max_results, 
            "Truncated flag should be consistent with results");
    
    Ok(())
}

#[test]
fn test_analyzer_semantic_graph_integration() -> Result<(), Box<dyn std::error::Error>> {
    use rust_tree_sitter::CodebaseAnalyzer;

    let temp_dir = TempDir::new()?;

    // Create test files
    let rust_file = temp_dir.path().join("test.rs");
    fs::write(&rust_file, r#"
/// User struct for managing user data
pub struct User {
    pub name: String,
    pub age: u32,
}

impl User {
    /// Create a new user
    pub fn new(name: String, age: u32) -> Self {
        User { name, age }
    }

    /// Get the user's name
    pub fn get_name(&self) -> &str {
        &self.name
    }
}

/// Create a default user
pub fn create_user() -> User {
    User::new("Alice".to_string(), 30)
}
"#)?;

    let js_file = temp_dir.path().join("test.js");
    fs::write(&js_file, r#"
/**
 * User class for managing user data
 */
class User {
    constructor(name, age) {
        this.name = name;
        this.age = age;
    }

    /**
     * Get the user's name
     */
    getName() {
        return this.name;
    }
}

/**
 * Create a default user
 */
function createUser() {
    return new User("Bob", 25);
}
"#)?;

    // Create analyzer with semantic graph enabled
    let mut analyzer = CodebaseAnalyzer::new()?;
    analyzer.enable_semantic_graph();

    assert!(analyzer.is_semantic_graph_enabled(), "Semantic graph should be enabled");

    // Analyze the directory
    let result = analyzer.analyze_directory(temp_dir.path())?;

    // Verify analysis results
    assert_eq!(result.total_files, 2);
    assert_eq!(result.parsed_files, 2);
    assert!(result.languages.contains_key("Rust"));
    assert!(result.languages.contains_key("JavaScript"));

    // Verify semantic graph was built
    let graph = analyzer.semantic_graph().expect("Semantic graph should be available");
    let stats = graph.get_statistics();

    assert!(stats.total_nodes > 0, "Graph should have nodes");
    assert!(stats.node_type_distribution.len() > 0, "Graph should have different node types");

    // Test graph queries
    let config = rust_tree_sitter::QueryConfig::default();

    // Find all functions
    let function_result = graph.find_by_type(rust_tree_sitter::NodeType::Function, &config);
    assert!(function_result.nodes.len() > 0, "Should find function nodes");

    // Find nodes by name
    let user_result = graph.find_by_name("User", &config);
    assert!(user_result.nodes.len() > 0, "Should find User nodes");

    // Test relationship traversal
    if let Some(start_node) = function_result.nodes.first() {
        let traversal_result = graph.traverse_relationships(
            &start_node.id,
            &[rust_tree_sitter::RelationshipType::DependsOn],
            &config,
        );
        assert!(traversal_result.metadata.nodes_examined > 0, "Should examine nodes during traversal");
    }

    // Test similarity search
    if let Some(target_node) = user_result.nodes.first() {
        let similar_result = graph.find_similar(&target_node.id, &config);
        assert!(similar_result.metadata.nodes_examined > 0, "Should examine nodes for similarity");
    }

    // Test disabling semantic graph
    analyzer.disable_semantic_graph();
    assert!(!analyzer.is_semantic_graph_enabled(), "Semantic graph should be disabled");
    assert!(analyzer.semantic_graph().is_none(), "Semantic graph should be None");

    Ok(())
}

#[test]
fn test_graph_statistics() -> Result<(), Box<dyn std::error::Error>> {
    let analysis = create_test_analysis_result()?;
    let mut graph = SemanticGraphQuery::new();
    graph.build_from_analysis(&analysis)?;
    
    let stats = graph.get_statistics();
    
    // Verify statistics make sense
    assert!(stats.total_nodes > 0, "Should have nodes");
    // Edges should have non-negative count
    
    // Verify type distribution
    let total_types: usize = stats.node_type_distribution.values().sum();
    assert_eq!(total_types, stats.total_nodes, "Type distribution should sum to total nodes");
    
    // Should have multiple node types
    assert!(stats.node_type_distribution.len() > 1, "Should have multiple node types");
    
    Ok(())
}
