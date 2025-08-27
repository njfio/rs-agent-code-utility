use crate::{SyntaxTree, Result};
use std::collections::HashMap;
use tree_sitter::Node;

/// Represents a taint source (where untrusted data enters the system)
#[derive(Debug, Clone, PartialEq)]
pub struct TaintSource {
    /// Source identifier
    pub id: String,
    /// Variable or parameter name
    pub name: String,
    /// Source type (user input, file, network, etc.)
    pub source_type: TaintSourceType,
    /// Location in source code
    pub location: TaintLocation,
    /// Confidence level of taint detection
    pub confidence: f64,
}

/// Types of taint sources
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TaintSourceType {
    /// User input (HTTP parameters, form data, etc.)
    UserInput,
    /// File input
    FileInput,
    /// Network input
    NetworkInput,
    /// Environment variables
    Environment,
    /// Command line arguments
    CommandLine,
    /// Database query results
    Database,
    /// External API responses
    ExternalApi,
}

/// Represents a taint sink (where tainted data could cause vulnerabilities)
#[derive(Debug, Clone, PartialEq)]
pub struct TaintSink {
    /// Sink identifier
    pub id: String,
    /// Function or operation name
    pub name: String,
    /// Sink type (SQL query, command execution, etc.)
    pub sink_type: TaintSinkType,
    /// Location in source code
    pub location: TaintLocation,
    /// Vulnerability type if tainted data reaches this sink
    pub vulnerability_type: VulnerabilityType,
}

/// Types of taint sinks
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TaintSinkType {
    /// SQL query execution
    SqlQuery,
    /// Command execution
    CommandExecution,
    /// File operations
    FileOperation,
    /// HTML output (XSS)
    HtmlOutput,
    /// HTTP headers
    HttpHeader,
    /// Logging operations
    Logging,
    /// Serialization
    Serialization,
}

/// Vulnerability types that can result from taint flow
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum VulnerabilityType {
    SqlInjection,
    CommandInjection,
    CrossSiteScripting,
    PathTraversal,
    HeaderInjection,
    LogInjection,
    DeserializationAttack,
}

/// Location information for taint analysis
#[derive(Debug, Clone, PartialEq)]
pub struct TaintLocation {
    pub file: String,
    pub line: usize,
    pub column: usize,
    pub function: Option<String>,
}

/// Represents a data flow path from source to sink
#[derive(Debug, Clone)]
pub struct TaintFlow {
    /// Source of the taint
    pub source: TaintSource,
    /// Sink where taint ends up
    pub sink: TaintSink,
    /// Path through the code (variable assignments, function calls, etc.)
    pub path: Vec<TaintStep>,
    /// Confidence level of the flow
    pub confidence: f64,
    /// Whether the flow is sanitized
    pub is_sanitized: bool,
    /// Sanitization methods applied
    pub sanitizers: Vec<String>,
}

/// A step in the taint flow path
#[derive(Debug, Clone)]
pub struct TaintStep {
    /// Type of step
    pub step_type: TaintStepType,
    /// Variable or function name
    pub name: String,
    /// Location of the step
    pub location: TaintLocation,
    /// Whether this step sanitizes the data
    pub is_sanitizer: bool,
    /// Sanitization method if applicable
    pub sanitizer_method: Option<String>,
}

/// Types of taint flow steps
#[derive(Debug, Clone, PartialEq)]
pub enum TaintStepType {
    /// Variable assignment
    Assignment,
    /// Function call
    FunctionCall,
    /// Function parameter
    Parameter,
    /// Return value
    Return,
    /// Array/object access
    Access,
    /// String concatenation
    Concatenation,
    /// Type conversion
    Conversion,
}

/// Taint analysis engine with enhanced inter-procedural analysis
pub struct TaintAnalyzer {
    language: String,
    /// Known taint sources for the language
    sources: HashMap<String, TaintSourceType>,
    /// Known taint sinks for the language
    sinks: HashMap<String, (TaintSinkType, VulnerabilityType)>,
    /// Known sanitization functions
    sanitizers: HashMap<String, Vec<VulnerabilityType>>,
    /// Variable assignments and aliasing tracking
    variable_assignments: HashMap<String, Vec<VariableAssignment>>,
    /// Function definitions and their parameters
    function_definitions: HashMap<String, FunctionDefinition>,
    /// Call graph for inter-procedural analysis
    call_graph: HashMap<String, Vec<FunctionCall>>,
}

/// Represents a variable assignment for tracking data flow
#[derive(Debug, Clone)]
pub struct VariableAssignment {
    /// Variable being assigned to
    pub target: String,
    /// Source of the assignment (variable, function call, literal, etc.)
    pub source: AssignmentSource,
    /// Location of the assignment
    pub location: TaintLocation,
    /// Whether this assignment propagates taint
    pub propagates_taint: bool,
}

/// Source of a variable assignment
#[derive(Debug, Clone)]
pub enum AssignmentSource {
    /// Assignment from another variable
    Variable(String),
    /// Assignment from function call
    FunctionCall(String, Vec<String>), // function name, arguments
    /// Assignment from literal value
    Literal(String),
    /// Assignment from concatenation
    Concatenation(Vec<String>),
    /// Assignment from array/object access
    Access(String, String), // object, index/key
}

/// Function definition information for inter-procedural analysis
#[derive(Debug, Clone)]
pub struct FunctionDefinition {
    /// Function name
    pub name: String,
    /// Parameter names in order
    pub parameters: Vec<String>,
    /// Return variable (if any)
    pub return_variable: Option<String>,
    /// Location of function definition
    pub location: TaintLocation,
    /// Whether function can propagate taint from parameters to return
    pub can_propagate_taint: bool,
}

/// Function call information for call graph construction
#[derive(Debug, Clone)]
pub struct FunctionCall {
    /// Called function name
    pub function_name: String,
    /// Arguments passed to the function
    pub arguments: Vec<String>,
    /// Variable receiving return value (if any)
    pub return_target: Option<String>,
    /// Location of the call
    pub location: TaintLocation,
}

impl TaintAnalyzer {
    /// Create a new taint analyzer for the specified language
    pub fn new(language: &str) -> Self {
        let mut analyzer = Self {
            language: language.to_string(),
            sources: HashMap::new(),
            sinks: HashMap::new(),
            sanitizers: HashMap::new(),
            variable_assignments: HashMap::new(),
            function_definitions: HashMap::new(),
            call_graph: HashMap::new(),
        };

        analyzer.initialize_language_rules();
        analyzer
    }
    
    /// Initialize language-specific taint sources, sinks, and sanitizers
    fn initialize_language_rules(&mut self) {
        match self.language.as_str() {
            "rust" => self.initialize_rust_rules(),
            "javascript" | "typescript" => self.initialize_javascript_rules(),
            "python" => self.initialize_python_rules(),
            "c" | "cpp" | "c++" => self.initialize_c_rules(),
            "go" => self.initialize_go_rules(),
            _ => self.initialize_generic_rules(),
        }
    }
    
    /// Initialize Rust-specific taint rules
    fn initialize_rust_rules(&mut self) {
        // Taint sources
        self.sources.insert("std::env::args".to_string(), TaintSourceType::CommandLine);
        self.sources.insert("std::env::var".to_string(), TaintSourceType::Environment);
        self.sources.insert("std::fs::read_to_string".to_string(), TaintSourceType::FileInput);
        self.sources.insert("reqwest::get".to_string(), TaintSourceType::NetworkInput);
        self.sources.insert("actix_web::HttpRequest".to_string(), TaintSourceType::UserInput);
        
        // Taint sinks
        self.sinks.insert("sqlx::query".to_string(), (TaintSinkType::SqlQuery, VulnerabilityType::SqlInjection));
        self.sinks.insert("diesel::sql_query".to_string(), (TaintSinkType::SqlQuery, VulnerabilityType::SqlInjection));
        self.sinks.insert("std::process::Command".to_string(), (TaintSinkType::CommandExecution, VulnerabilityType::CommandInjection));
        self.sinks.insert("std::fs::write".to_string(), (TaintSinkType::FileOperation, VulnerabilityType::PathTraversal));
        
        // Sanitizers
        self.sanitizers.insert("html_escape::encode_text".to_string(), vec![VulnerabilityType::CrossSiteScripting]);
        self.sanitizers.insert("regex::escape".to_string(), vec![VulnerabilityType::SqlInjection]);
        self.sanitizers.insert("shell_escape::escape".to_string(), vec![VulnerabilityType::CommandInjection]);
    }
    
    /// Initialize JavaScript/TypeScript-specific taint rules
    fn initialize_javascript_rules(&mut self) {
        // Taint sources
        self.sources.insert("process.argv".to_string(), TaintSourceType::CommandLine);
        self.sources.insert("process.env".to_string(), TaintSourceType::Environment);
        self.sources.insert("fs.readFileSync".to_string(), TaintSourceType::FileInput);
        self.sources.insert("fetch".to_string(), TaintSourceType::NetworkInput);
        self.sources.insert("req.query".to_string(), TaintSourceType::UserInput);
        self.sources.insert("req.body".to_string(), TaintSourceType::UserInput);
        self.sources.insert("req.params".to_string(), TaintSourceType::UserInput);
        
        // Taint sinks
        self.sinks.insert("mysql.query".to_string(), (TaintSinkType::SqlQuery, VulnerabilityType::SqlInjection));
        self.sinks.insert("pg.query".to_string(), (TaintSinkType::SqlQuery, VulnerabilityType::SqlInjection));
        self.sinks.insert("child_process.exec".to_string(), (TaintSinkType::CommandExecution, VulnerabilityType::CommandInjection));
        self.sinks.insert("eval".to_string(), (TaintSinkType::CommandExecution, VulnerabilityType::CommandInjection));
        self.sinks.insert("document.write".to_string(), (TaintSinkType::HtmlOutput, VulnerabilityType::CrossSiteScripting));
        self.sinks.insert("innerHTML".to_string(), (TaintSinkType::HtmlOutput, VulnerabilityType::CrossSiteScripting));
        
        // Sanitizers
        self.sanitizers.insert("escape".to_string(), vec![VulnerabilityType::CrossSiteScripting]);
        self.sanitizers.insert("validator.escape".to_string(), vec![VulnerabilityType::CrossSiteScripting]);
        self.sanitizers.insert("mysql.escape".to_string(), vec![VulnerabilityType::SqlInjection]);
        self.sanitizers.insert("shell-escape".to_string(), vec![VulnerabilityType::CommandInjection]);
    }
    
    /// Initialize Python-specific taint rules
    fn initialize_python_rules(&mut self) {
        // Taint sources
        self.sources.insert("sys.argv".to_string(), TaintSourceType::CommandLine);
        self.sources.insert("os.environ".to_string(), TaintSourceType::Environment);
        self.sources.insert("open".to_string(), TaintSourceType::FileInput);
        self.sources.insert("requests.get".to_string(), TaintSourceType::NetworkInput);
        self.sources.insert("request.args".to_string(), TaintSourceType::UserInput);
        self.sources.insert("request.form".to_string(), TaintSourceType::UserInput);
        
        // Taint sinks
        self.sinks.insert("cursor.execute".to_string(), (TaintSinkType::SqlQuery, VulnerabilityType::SqlInjection));
        self.sinks.insert("os.system".to_string(), (TaintSinkType::CommandExecution, VulnerabilityType::CommandInjection));
        self.sinks.insert("subprocess.call".to_string(), (TaintSinkType::CommandExecution, VulnerabilityType::CommandInjection));
        self.sinks.insert("eval".to_string(), (TaintSinkType::CommandExecution, VulnerabilityType::CommandInjection));
        
        // Sanitizers
        self.sanitizers.insert("html.escape".to_string(), vec![VulnerabilityType::CrossSiteScripting]);
        self.sanitizers.insert("pymysql.escape_string".to_string(), vec![VulnerabilityType::SqlInjection]);
        self.sanitizers.insert("shlex.quote".to_string(), vec![VulnerabilityType::CommandInjection]);
    }
    
    /// Initialize C/C++-specific taint rules
    fn initialize_c_rules(&mut self) {
        // Taint sources
        self.sources.insert("argv".to_string(), TaintSourceType::CommandLine);
        self.sources.insert("getenv".to_string(), TaintSourceType::Environment);
        self.sources.insert("fgets".to_string(), TaintSourceType::FileInput);
        self.sources.insert("scanf".to_string(), TaintSourceType::UserInput);
        
        // Taint sinks
        self.sinks.insert("mysql_query".to_string(), (TaintSinkType::SqlQuery, VulnerabilityType::SqlInjection));
        self.sinks.insert("system".to_string(), (TaintSinkType::CommandExecution, VulnerabilityType::CommandInjection));
        self.sinks.insert("exec".to_string(), (TaintSinkType::CommandExecution, VulnerabilityType::CommandInjection));
        self.sinks.insert("printf".to_string(), (TaintSinkType::HtmlOutput, VulnerabilityType::CrossSiteScripting));
        
        // Sanitizers
        self.sanitizers.insert("mysql_real_escape_string".to_string(), vec![VulnerabilityType::SqlInjection]);
    }
    
    /// Initialize Go-specific taint rules
    fn initialize_go_rules(&mut self) {
        // Taint sources
        self.sources.insert("os.Args".to_string(), TaintSourceType::CommandLine);
        self.sources.insert("os.Getenv".to_string(), TaintSourceType::Environment);
        self.sources.insert("ioutil.ReadFile".to_string(), TaintSourceType::FileInput);
        self.sources.insert("http.Get".to_string(), TaintSourceType::NetworkInput);
        
        // Taint sinks
        self.sinks.insert("db.Query".to_string(), (TaintSinkType::SqlQuery, VulnerabilityType::SqlInjection));
        self.sinks.insert("exec.Command".to_string(), (TaintSinkType::CommandExecution, VulnerabilityType::CommandInjection));
        self.sinks.insert("fmt.Fprintf".to_string(), (TaintSinkType::HtmlOutput, VulnerabilityType::CrossSiteScripting));
        
        // Sanitizers
        self.sanitizers.insert("html.EscapeString".to_string(), vec![VulnerabilityType::CrossSiteScripting]);
        self.sanitizers.insert("url.QueryEscape".to_string(), vec![VulnerabilityType::SqlInjection]);
    }
    
    /// Initialize generic taint rules for unknown languages
    fn initialize_generic_rules(&mut self) {
        // Generic patterns that might apply to multiple languages
        self.sources.insert("input".to_string(), TaintSourceType::UserInput);
        self.sources.insert("read".to_string(), TaintSourceType::FileInput);
        self.sources.insert("get".to_string(), TaintSourceType::NetworkInput);
        
        self.sinks.insert("query".to_string(), (TaintSinkType::SqlQuery, VulnerabilityType::SqlInjection));
        self.sinks.insert("exec".to_string(), (TaintSinkType::CommandExecution, VulnerabilityType::CommandInjection));
        self.sinks.insert("write".to_string(), (TaintSinkType::HtmlOutput, VulnerabilityType::CrossSiteScripting));
    }
    
    /// Perform enhanced taint analysis on a syntax tree with inter-procedural analysis
    pub fn analyze(&mut self, tree: &SyntaxTree) -> Result<Vec<TaintFlow>> {
        let mut flows = Vec::new();

        // Phase 1: Build program structure (functions, assignments, call graph)
        self.build_program_structure(tree)?;

        // Phase 2: Find all taint sources in the code
        let sources = self.find_taint_sources(tree)?;

        // Phase 3: Find all taint sinks in the code
        let sinks = self.find_taint_sinks(tree)?;

        // Phase 4: Perform enhanced data flow analysis
        for source in &sources {
            let source_flows = self.trace_enhanced_taint_flows(tree, source, &sinks)?;
            flows.extend(source_flows);
        }

        Ok(flows)
    }

    /// Build program structure for inter-procedural analysis
    fn build_program_structure(&mut self, tree: &SyntaxTree) -> Result<()> {
        // Clear previous analysis data
        self.variable_assignments.clear();
        self.function_definitions.clear();
        self.call_graph.clear();

        // Traverse AST to build structure
        self.traverse_for_structure(tree.inner().root_node(), None)?;

        Ok(())
    }

    /// Traverse AST to build program structure (functions, assignments, calls)
    fn traverse_for_structure(&mut self, node: Node, current_function: Option<&str>) -> Result<()> {
        let _node_kind = node.kind();

        // Check for function definitions
        if self.is_function_definition(node) {
            if let Some(func_def) = self.extract_function_definition(node)? {
                self.function_definitions.insert(func_def.name.clone(), func_def.clone());

                // Traverse function body with this function as context
                let mut cursor = node.walk();
                if cursor.goto_first_child() {
                    loop {
                        self.traverse_for_structure(cursor.node(), Some(&func_def.name))?;
                        if !cursor.goto_next_sibling() {
                            break;
                        }
                    }
                }
                return Ok(());
            }
        }

        // Check for variable assignments
        if self.is_assignment(node) {
            if let Some(assignment) = self.extract_assignment(node, current_function)? {
                let func_key = current_function.unwrap_or("global").to_string();
                self.variable_assignments.entry(func_key).or_insert_with(Vec::new).push(assignment);
            }
        }

        // Check for function calls
        if self.is_function_call(node.kind()) {
            if let Some(call) = self.extract_function_call(node, current_function)? {
                let func_key = current_function.unwrap_or("global").to_string();
                self.call_graph.entry(func_key).or_insert_with(Vec::new).push(call);
            }
        }

        // Traverse children
        let mut cursor = node.walk();
        if cursor.goto_first_child() {
            loop {
                self.traverse_for_structure(cursor.node(), current_function)?;
                if !cursor.goto_next_sibling() {
                    break;
                }
            }
        }

        Ok(())
    }

    /// Extract function definition information from AST node
    fn extract_function_definition(&self, node: Node) -> Result<Option<FunctionDefinition>> {
        let function_name = self.extract_function_name(node);
        if function_name.is_none() {
            return Ok(None);
        }

        let name = function_name.unwrap();
        let parameters = self.extract_function_parameters(node);

        Ok(Some(FunctionDefinition {
            name: name.clone(),
            parameters,
            return_variable: None, // Would need more sophisticated analysis
            location: TaintLocation {
                file: "current_file".to_string(),
                line: node.start_position().row + 1,
                column: node.start_position().column,
                function: Some(name),
            },
            can_propagate_taint: true, // Conservative assumption
        }))
    }

    /// Extract function parameters from function definition node
    fn extract_function_parameters(&self, node: Node) -> Vec<String> {
        let mut parameters = Vec::new();
        let mut cursor = node.walk();

        // Look for parameter list
        if cursor.goto_first_child() {
            loop {
                let child = cursor.node();
                if self.is_parameter_list(child.kind()) {
                    parameters.extend(self.extract_parameter_names(child));
                    break;
                }
                if !cursor.goto_next_sibling() {
                    break;
                }
            }
        }

        parameters
    }

    /// Extract parameter names from parameter list node
    fn extract_parameter_names(&self, node: Node) -> Vec<String> {
        let mut names = Vec::new();
        let mut cursor = node.walk();

        if cursor.goto_first_child() {
            loop {
                let child = cursor.node();
                if child.kind() == "identifier" {
                    if let Ok(name) = child.utf8_text(b"") {
                        names.push(name.to_string());
                    }
                }
                if !cursor.goto_next_sibling() {
                    break;
                }
            }
        }

        names
    }

    /// Check if node represents an assignment
    fn is_assignment(&self, node: Node) -> bool {
        let node_kind = node.kind();
        match self.language.as_str() {
            "rust" => matches!(node_kind, "assignment_expression" | "let_declaration"),
            "javascript" | "typescript" => matches!(node_kind, "assignment_expression" | "variable_declarator"),
            "python" => matches!(node_kind, "assignment"),
            "c" | "cpp" | "c++" => matches!(node_kind, "assignment_expression" | "init_declarator"),
            "go" => matches!(node_kind, "assignment_statement" | "var_declaration"),
            _ => node_kind.contains("assignment") || node_kind.contains("declaration"),
        }
    }

    /// Extract assignment information from AST node
    fn extract_assignment(&self, node: Node, current_function: Option<&str>) -> Result<Option<VariableAssignment>> {
        let (target, source) = self.extract_assignment_parts(node)?;
        if target.is_none() || source.is_none() {
            return Ok(None);
        }

        let source_value = source.unwrap();
        let propagates_taint = self.assignment_propagates_taint(&source_value);

        Ok(Some(VariableAssignment {
            target: target.unwrap(),
            source: source_value,
            location: TaintLocation {
                file: "current_file".to_string(),
                line: node.start_position().row + 1,
                column: node.start_position().column,
                function: current_function.map(|s| s.to_string()),
            },
            propagates_taint,
        }))
    }

    /// Extract target and source from assignment node
    fn extract_assignment_parts(&self, node: Node) -> Result<(Option<String>, Option<AssignmentSource>)> {
        let mut cursor = node.walk();
        let mut target = None;
        let mut source = None;

        if cursor.goto_first_child() {
            // First child is usually the target
            let target_node = cursor.node();
            if target_node.kind() == "identifier" {
                if let Ok(name) = target_node.utf8_text(b"") {
                    target = Some(name.to_string());
                }
            }

            // Look for assignment operator and source
            while cursor.goto_next_sibling() {
                let child = cursor.node();
                if self.is_assignment_operator(child.kind()) {
                    if cursor.goto_next_sibling() {
                        source = self.extract_assignment_source(cursor.node());
                        break;
                    }
                }
            }
        }

        Ok((target, source))
    }

    /// Extract assignment source from AST node
    fn extract_assignment_source(&self, node: Node) -> Option<AssignmentSource> {
        let node_kind = node.kind();

        if node_kind == "identifier" {
            if let Ok(name) = node.utf8_text(b"") {
                return Some(AssignmentSource::Variable(name.to_string()));
            }
        } else if self.is_function_call(node_kind) {
            if let Some(func_name) = self.extract_function_call_name(node) {
                let args = self.extract_function_arguments(node);
                return Some(AssignmentSource::FunctionCall(func_name, args));
            }
        } else if self.is_string_literal(node_kind) || self.is_number_literal(node_kind) {
            if let Ok(value) = node.utf8_text(b"") {
                return Some(AssignmentSource::Literal(value.to_string()));
            }
        } else if self.is_concatenation(node) {
            let parts = self.extract_concatenation_parts(node);
            return Some(AssignmentSource::Concatenation(parts));
        }

        None
    }

    /// Find all taint sources in the syntax tree
    fn find_taint_sources(&self, tree: &SyntaxTree) -> Result<Vec<TaintSource>> {
        let mut sources = Vec::new();
        self.traverse_for_sources(tree.inner().root_node(), &mut sources, None)?;
        Ok(sources)
    }
    
    /// Find all taint sinks in the syntax tree
    fn find_taint_sinks(&self, tree: &SyntaxTree) -> Result<Vec<TaintSink>> {
        let mut sinks = Vec::new();
        self.traverse_for_sinks(tree.inner().root_node(), &mut sinks, None)?;
        Ok(sinks)
    }
    
    /// Recursively traverse AST to find taint sources
    fn traverse_for_sources(&self, node: Node, sources: &mut Vec<TaintSource>, current_function: Option<&str>) -> Result<()> {
        // Check if this node represents a taint source
        if let Some(source) = self.identify_taint_source(node, current_function)? {
            sources.push(source);
        }
        
        // Update current function context
        let function_name = if self.is_function_definition(node) {
            self.extract_function_name(node)
        } else {
            current_function.map(|s| s.to_string())
        };
        
        // Traverse children
        let mut cursor = node.walk();
        if cursor.goto_first_child() {
            loop {
                self.traverse_for_sources(cursor.node(), sources, function_name.as_deref())?;
                if !cursor.goto_next_sibling() {
                    break;
                }
            }
        }
        
        Ok(())
    }
    
    /// Recursively traverse AST to find taint sinks
    fn traverse_for_sinks(&self, node: Node, sinks: &mut Vec<TaintSink>, current_function: Option<&str>) -> Result<()> {
        // Check if this node represents a taint sink
        if let Some(sink) = self.identify_taint_sink(node, current_function)? {
            sinks.push(sink);
        }
        
        // Update current function context
        let function_name = if self.is_function_definition(node) {
            self.extract_function_name(node)
        } else {
            current_function.map(|s| s.to_string())
        };
        
        // Traverse children
        let mut cursor = node.walk();
        if cursor.goto_first_child() {
            loop {
                self.traverse_for_sinks(cursor.node(), sinks, function_name.as_deref())?;
                if !cursor.goto_next_sibling() {
                    break;
                }
            }
        }
        
        Ok(())
    }
    
    /// Identify if a node represents a taint source
    fn identify_taint_source(&self, node: Node, current_function: Option<&str>) -> Result<Option<TaintSource>> {
        let node_kind = node.kind();
        
        // Check for function calls that are taint sources
        if self.is_function_call(node_kind) {
            if let Some(function_name) = self.extract_function_call_name(node) {
                if let Some(source_type) = self.sources.get(&function_name) {
                    return Ok(Some(TaintSource {
                        id: format!("source_{}_{}", node.start_position().row, node.start_position().column),
                        name: function_name,
                        source_type: source_type.clone(),
                        location: TaintLocation {
                            file: "current_file".to_string(), // Would be passed in real implementation
                            line: node.start_position().row + 1,
                            column: node.start_position().column,
                            function: current_function.map(|s| s.to_string()),
                        },
                        confidence: 0.9,
                    }));
                }
            }
        }
        
        // Check for variable access that might be tainted
        if self.is_identifier(node_kind) {
            let identifier = node.utf8_text(b"").unwrap_or("");
            if self.is_likely_user_input_variable(identifier) {
                return Ok(Some(TaintSource {
                    id: format!("var_{}_{}", node.start_position().row, node.start_position().column),
                    name: identifier.to_string(),
                    source_type: TaintSourceType::UserInput,
                    location: TaintLocation {
                        file: "current_file".to_string(),
                        line: node.start_position().row + 1,
                        column: node.start_position().column,
                        function: current_function.map(|s| s.to_string()),
                    },
                    confidence: 0.6,
                }));
            }
        }
        
        Ok(None)
    }
    
    /// Identify if a node represents a taint sink
    fn identify_taint_sink(&self, node: Node, current_function: Option<&str>) -> Result<Option<TaintSink>> {
        let node_kind = node.kind();
        
        // Check for function calls that are taint sinks
        if self.is_function_call(node_kind) {
            if let Some(function_name) = self.extract_function_call_name(node) {
                if let Some((sink_type, vuln_type)) = self.sinks.get(&function_name) {
                    return Ok(Some(TaintSink {
                        id: format!("sink_{}_{}", node.start_position().row, node.start_position().column),
                        name: function_name,
                        sink_type: sink_type.clone(),
                        location: TaintLocation {
                            file: "current_file".to_string(),
                            line: node.start_position().row + 1,
                            column: node.start_position().column,
                            function: current_function.map(|s| s.to_string()),
                        },
                        vulnerability_type: vuln_type.clone(),
                    }));
                }
            }
        }
        
        Ok(None)
    }
    
    /// Check if node kind represents a function call
    fn is_function_call(&self, node_kind: &str) -> bool {
        match self.language.as_str() {
            "rust" => matches!(node_kind, "call_expression"),
            "javascript" | "typescript" => matches!(node_kind, "call_expression"),
            "python" => matches!(node_kind, "call"),
            "c" | "cpp" | "c++" => matches!(node_kind, "call_expression"),
            "go" => matches!(node_kind, "call_expression"),
            _ => node_kind.contains("call"),
        }
    }
    
    /// Check if node kind represents an identifier
    fn is_identifier(&self, node_kind: &str) -> bool {
        node_kind == "identifier"
    }
    
    /// Check if node represents a function definition
    fn is_function_definition(&self, node: Node) -> bool {
        let node_kind = node.kind();
        match self.language.as_str() {
            "rust" => matches!(node_kind, "function_item"),
            "javascript" | "typescript" => matches!(node_kind, "function_declaration" | "function_expression"),
            "python" => matches!(node_kind, "function_definition"),
            "c" | "cpp" | "c++" => matches!(node_kind, "function_definition"),
            "go" => matches!(node_kind, "function_declaration"),
            _ => node_kind.contains("function"),
        }
    }
    
    /// Extract function name from function call node
    fn extract_function_call_name(&self, node: Node) -> Option<String> {
        // This is a simplified implementation
        // In practice, would need to handle method calls, qualified names, etc.
        let mut cursor = node.walk();
        if cursor.goto_first_child() {
            let function_node = cursor.node();
            if let Ok(name) = function_node.utf8_text(b"") {
                return Some(name.to_string());
            }
        }
        None
    }
    
    /// Extract function name from function definition node
    fn extract_function_name(&self, node: Node) -> Option<String> {
        // Simplified implementation
        let mut cursor = node.walk();
        if cursor.goto_first_child() {
            loop {
                let child = cursor.node();
                if child.kind() == "identifier" {
                    if let Ok(name) = child.utf8_text(b"") {
                        return Some(name.to_string());
                    }
                }
                if !cursor.goto_next_sibling() {
                    break;
                }
            }
        }
        None
    }
    
    /// Check if variable name suggests user input
    fn is_likely_user_input_variable(&self, name: &str) -> bool {
        let name_lower = name.to_lowercase();
        let user_input_patterns = [
            "input", "request", "req", "params", "query", "body", "form",
            "user", "client", "external", "untrusted", "raw"
        ];
        
        user_input_patterns.iter().any(|&pattern| name_lower.contains(pattern))
    }
    
    /// Enhanced taint flow tracing with inter-procedural analysis
    fn trace_enhanced_taint_flows(&self, _tree: &SyntaxTree, source: &TaintSource, sinks: &[TaintSink]) -> Result<Vec<TaintFlow>> {
        let mut flows = Vec::new();

        for sink in sinks {
            if let Some(flow) = self.find_data_flow_path(source, sink)? {
                flows.push(flow);
            }
        }

        Ok(flows)
    }

    /// Find data flow path from source to sink using enhanced analysis
    fn find_data_flow_path(&self, source: &TaintSource, sink: &TaintSink) -> Result<Option<TaintFlow>> {
        // Start with the source variable/function
        let mut tainted_variables = std::collections::HashSet::new();
        tainted_variables.insert(source.name.clone());

        // Build path through variable assignments and function calls
        let path = self.build_taint_path(source, sink, &mut tainted_variables)?;

        if path.is_empty() && !self.has_potential_flow(source, sink) {
            return Ok(None);
        }

        // Calculate confidence based on path quality
        let confidence = self.calculate_path_confidence(&path, source, sink);

        // Check for sanitization along the path
        let (is_sanitized, sanitizers) = self.check_path_sanitization(&path, &sink.vulnerability_type);

        Ok(Some(TaintFlow {
            source: source.clone(),
            sink: sink.clone(),
            path,
            confidence,
            is_sanitized,
            sanitizers,
        }))
    }

    /// Build taint propagation path through assignments and function calls
    fn build_taint_path(&self, source: &TaintSource, sink: &TaintSink, tainted_variables: &mut std::collections::HashSet<String>) -> Result<Vec<TaintStep>> {
        let mut path = Vec::new();
        let source_function = source.location.function.as_deref().unwrap_or("global");
        let sink_function = sink.location.function.as_deref().unwrap_or("global");

        // Trace within source function
        if let Some(assignments) = self.variable_assignments.get(source_function) {
            for assignment in assignments {
                if self.assignment_propagates_to_tainted(&assignment, tainted_variables) {
                    tainted_variables.insert(assignment.target.clone());

                    let step = TaintStep {
                        step_type: TaintStepType::Assignment,
                        name: assignment.target.clone(),
                        location: assignment.location.clone(),
                        is_sanitizer: self.is_sanitizer_assignment(&assignment),
                        sanitizer_method: self.get_sanitizer_method(&assignment),
                    };
                    path.push(step);
                }
            }
        }

        // Handle inter-procedural flows
        if source_function != sink_function {
            if let Some(inter_path) = self.trace_inter_procedural_flow(source_function, sink_function, tainted_variables)? {
                path.extend(inter_path);
            }
        }

        // Trace within sink function if different from source
        if source_function != sink_function {
            if let Some(assignments) = self.variable_assignments.get(sink_function) {
                for assignment in assignments {
                    if self.assignment_propagates_to_tainted(&assignment, tainted_variables) {
                        tainted_variables.insert(assignment.target.clone());

                        let step = TaintStep {
                            step_type: TaintStepType::Assignment,
                            name: assignment.target.clone(),
                            location: assignment.location.clone(),
                            is_sanitizer: self.is_sanitizer_assignment(&assignment),
                            sanitizer_method: self.get_sanitizer_method(&assignment),
                        };
                        path.push(step);
                    }
                }
            }
        }

        Ok(path)
    }

    /// Trace taint flow between functions (inter-procedural analysis)
    fn trace_inter_procedural_flow(&self, source_func: &str, sink_func: &str, tainted_variables: &mut std::collections::HashSet<String>) -> Result<Option<Vec<TaintStep>>> {
        let mut path = Vec::new();

        // Look for function calls from source function
        if let Some(calls) = self.call_graph.get(source_func) {
            for call in calls {
                // Check if any tainted variables are passed as arguments
                for (i, arg) in call.arguments.iter().enumerate() {
                    if tainted_variables.contains(arg) {
                        // Check if called function can reach sink function
                        if self.can_reach_function(&call.function_name, sink_func) {
                            // Add function call step
                            path.push(TaintStep {
                                step_type: TaintStepType::FunctionCall,
                                name: call.function_name.clone(),
                                location: call.location.clone(),
                                is_sanitizer: self.is_sanitizer_function(&call.function_name),
                                sanitizer_method: if self.is_sanitizer_function(&call.function_name) {
                                    Some(call.function_name.clone())
                                } else {
                                    None
                                },
                            });

                            // Mark function parameters as tainted
                            if let Some(func_def) = self.function_definitions.get(&call.function_name) {
                                if i < func_def.parameters.len() {
                                    tainted_variables.insert(func_def.parameters[i].clone());
                                }
                            }

                            return Ok(Some(path));
                        }
                    }
                }
            }
        }

        Ok(None)
    }

    /// Check if one function can reach another through call graph
    fn can_reach_function(&self, from: &str, to: &str) -> bool {
        if from == to {
            return true;
        }

        // Simple reachability check (could be enhanced with proper graph traversal)
        if let Some(calls) = self.call_graph.get(from) {
            for call in calls {
                if call.function_name == to {
                    return true;
                }
                // Could add recursive check here for deeper analysis
            }
        }

        false
    }

    /// Trace taint flows from a source to potential sinks (legacy method for compatibility)
    #[allow(dead_code)]
    fn trace_taint_flows(&self, _tree: &SyntaxTree, source: &TaintSource, sinks: &[TaintSink]) -> Result<Vec<TaintFlow>> {
        let mut flows = Vec::new();

        // This is a simplified implementation
        // In practice, would need sophisticated data flow analysis
        for sink in sinks {
            // Check if source and sink are in the same function or have data flow connection
            if self.has_potential_flow(source, sink) {
                let flow = TaintFlow {
                    source: source.clone(),
                    sink: sink.clone(),
                    path: vec![], // Would be populated with actual data flow analysis
                    confidence: 0.7,
                    is_sanitized: false,
                    sanitizers: vec![],
                };
                flows.push(flow);
            }
        }

        Ok(flows)
    }
    
    /// Check if there's a potential flow between source and sink
    fn has_potential_flow(&self, source: &TaintSource, sink: &TaintSink) -> bool {
        // Simplified heuristic - same function or close proximity
        source.location.function == sink.location.function ||
        (source.location.line as i32 - sink.location.line as i32).abs() < 50
    }

    /// Helper methods for enhanced analysis

    /// Check if assignment propagates taint to any tainted variables
    fn assignment_propagates_to_tainted(&self, assignment: &VariableAssignment, tainted_vars: &std::collections::HashSet<String>) -> bool {
        match &assignment.source {
            AssignmentSource::Variable(var) => tainted_vars.contains(var),
            AssignmentSource::FunctionCall(func, args) => {
                // Check if any arguments are tainted or if function is a taint source
                args.iter().any(|arg| tainted_vars.contains(arg)) ||
                self.sources.contains_key(func)
            },
            AssignmentSource::Concatenation(parts) => {
                parts.iter().any(|part| tainted_vars.contains(part))
            },
            AssignmentSource::Access(obj, _) => tainted_vars.contains(obj),
            AssignmentSource::Literal(_) => false,
        }
    }

    /// Check if assignment source propagates taint
    fn assignment_propagates_taint(&self, source: &AssignmentSource) -> bool {
        match source {
            AssignmentSource::Variable(_) => true,
            AssignmentSource::FunctionCall(func, _) => self.sources.contains_key(func),
            AssignmentSource::Concatenation(_) => true,
            AssignmentSource::Access(_, _) => true,
            AssignmentSource::Literal(_) => false,
        }
    }

    /// Check if assignment involves a sanitizer
    fn is_sanitizer_assignment(&self, assignment: &VariableAssignment) -> bool {
        match &assignment.source {
            AssignmentSource::FunctionCall(func, _) => self.sanitizers.contains_key(func),
            _ => false,
        }
    }

    /// Get sanitizer method name if assignment is sanitization
    fn get_sanitizer_method(&self, assignment: &VariableAssignment) -> Option<String> {
        match &assignment.source {
            AssignmentSource::FunctionCall(func, _) if self.sanitizers.contains_key(func) => {
                Some(func.clone())
            },
            _ => None,
        }
    }

    /// Check if function is a sanitizer
    fn is_sanitizer_function(&self, func_name: &str) -> bool {
        self.sanitizers.contains_key(func_name)
    }

    /// Calculate confidence based on path quality
    fn calculate_path_confidence(&self, path: &[TaintStep], source: &TaintSource, _sink: &TaintSink) -> f64 {
        let mut confidence = source.confidence;

        // Reduce confidence for longer paths
        confidence *= 0.95_f64.powi(path.len() as i32);

        // Reduce confidence if path goes through multiple functions
        let function_changes = path.iter()
            .filter(|step| step.step_type == TaintStepType::FunctionCall)
            .count();
        confidence *= 0.9_f64.powi(function_changes as i32);

        // Increase confidence for direct assignments
        let direct_assignments = path.iter()
            .filter(|step| step.step_type == TaintStepType::Assignment)
            .count();
        confidence *= 1.0 + (direct_assignments as f64 * 0.1);

        // Ensure confidence stays within bounds
        confidence.max(0.1).min(1.0)
    }

    /// Check for sanitization along the path
    fn check_path_sanitization(&self, path: &[TaintStep], vuln_type: &VulnerabilityType) -> (bool, Vec<String>) {
        let mut sanitizers = Vec::new();
        let mut is_sanitized = false;

        for step in path {
            if step.is_sanitizer {
                if let Some(method) = &step.sanitizer_method {
                    if let Some(sanitizer_vulns) = self.sanitizers.get(method) {
                        if sanitizer_vulns.contains(vuln_type) {
                            sanitizers.push(method.clone());
                            is_sanitized = true;
                        }
                    }
                }
            }
        }

        (is_sanitized, sanitizers)
    }

    /// Additional helper methods for AST analysis

    /// Check if node kind represents a parameter list
    fn is_parameter_list(&self, node_kind: &str) -> bool {
        match self.language.as_str() {
            "rust" => matches!(node_kind, "parameters"),
            "javascript" | "typescript" => matches!(node_kind, "formal_parameters"),
            "python" => matches!(node_kind, "parameters"),
            "c" | "cpp" | "c++" => matches!(node_kind, "parameter_list"),
            "go" => matches!(node_kind, "parameter_list"),
            _ => node_kind.contains("parameter"),
        }
    }

    /// Check if node kind represents an assignment operator
    fn is_assignment_operator(&self, node_kind: &str) -> bool {
        matches!(node_kind, "=" | ":=" | "+=" | "-=" | "*=" | "/=" | "assignment_operator")
    }

    /// Check if node kind represents a string literal
    fn is_string_literal(&self, node_kind: &str) -> bool {
        node_kind.contains("string") && node_kind.contains("literal")
    }

    /// Check if node kind represents a number literal
    fn is_number_literal(&self, node_kind: &str) -> bool {
        matches!(node_kind, "number" | "integer" | "float" | "decimal") ||
        (node_kind.contains("number") && node_kind.contains("literal"))
    }

    /// Check if node represents concatenation
    fn is_concatenation(&self, node: Node) -> bool {
        let node_kind = node.kind();
        match self.language.as_str() {
            "rust" => node_kind == "binary_expression", // Would need to check operator
            "javascript" | "typescript" => node_kind == "binary_expression",
            "python" => node_kind == "binary_operator",
            "c" | "cpp" | "c++" => node_kind == "binary_expression",
            "go" => node_kind == "binary_expression",
            _ => node_kind.contains("binary") || node_kind.contains("concat"),
        }
    }

    /// Extract function arguments from function call node
    fn extract_function_arguments(&self, node: Node) -> Vec<String> {
        let mut args = Vec::new();
        let mut cursor = node.walk();

        if cursor.goto_first_child() {
            // Skip function name, look for arguments
            while cursor.goto_next_sibling() {
                let child = cursor.node();
                if self.is_argument_list(child.kind()) {
                    args.extend(self.extract_argument_names(child));
                    break;
                }
            }
        }

        args
    }

    /// Check if node kind represents an argument list
    fn is_argument_list(&self, node_kind: &str) -> bool {
        match self.language.as_str() {
            "rust" => matches!(node_kind, "arguments"),
            "javascript" | "typescript" => matches!(node_kind, "arguments"),
            "python" => matches!(node_kind, "argument_list"),
            "c" | "cpp" | "c++" => matches!(node_kind, "argument_list"),
            "go" => matches!(node_kind, "argument_list"),
            _ => node_kind.contains("argument"),
        }
    }

    /// Extract argument names from argument list
    fn extract_argument_names(&self, node: Node) -> Vec<String> {
        let mut names = Vec::new();
        let mut cursor = node.walk();

        if cursor.goto_first_child() {
            loop {
                let child = cursor.node();
                if child.kind() == "identifier" {
                    if let Ok(name) = child.utf8_text(b"") {
                        names.push(name.to_string());
                    }
                }
                if !cursor.goto_next_sibling() {
                    break;
                }
            }
        }

        names
    }

    /// Extract concatenation parts
    fn extract_concatenation_parts(&self, node: Node) -> Vec<String> {
        let mut parts = Vec::new();
        let mut cursor = node.walk();

        if cursor.goto_first_child() {
            loop {
                let child = cursor.node();
                if child.kind() == "identifier" {
                    if let Ok(name) = child.utf8_text(b"") {
                        parts.push(name.to_string());
                    }
                }
                if !cursor.goto_next_sibling() {
                    break;
                }
            }
        }

        parts
    }

    /// Extract function call information for call graph
    fn extract_function_call(&self, node: Node, current_function: Option<&str>) -> Result<Option<FunctionCall>> {
        let function_name = self.extract_function_call_name(node);
        if function_name.is_none() {
            return Ok(None);
        }

        let name = function_name.unwrap();
        let arguments = self.extract_function_arguments(node);

        Ok(Some(FunctionCall {
            function_name: name,
            arguments,
            return_target: None, // Would need more analysis to determine
            location: TaintLocation {
                file: "current_file".to_string(),
                line: node.start_position().row + 1,
                column: node.start_position().column,
                function: current_function.map(|s| s.to_string()),
            },
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_taint_analyzer_creation() {
        let analyzer = TaintAnalyzer::new("rust");
        assert_eq!(analyzer.language, "rust");
        assert!(!analyzer.sources.is_empty());
        assert!(!analyzer.sinks.is_empty());
        assert!(analyzer.variable_assignments.is_empty());
        assert!(analyzer.function_definitions.is_empty());
        assert!(analyzer.call_graph.is_empty());
    }

    #[test]
    fn test_javascript_taint_sources() {
        let analyzer = TaintAnalyzer::new("javascript");
        assert!(analyzer.sources.contains_key("req.query"));
        assert!(analyzer.sinks.contains_key("mysql.query"));
    }

    #[test]
    fn test_python_taint_analysis() {
        let analyzer = TaintAnalyzer::new("python");
        assert!(analyzer.sources.contains_key("request.args"));
        assert!(analyzer.sinks.contains_key("cursor.execute"));
    }

    #[test]
    fn test_assignment_source_types() {
        let var_source = AssignmentSource::Variable("user_input".to_string());
        let func_source = AssignmentSource::FunctionCall("get_input".to_string(), vec!["param1".to_string()]);
        let literal_source = AssignmentSource::Literal("constant".to_string());
        let concat_source = AssignmentSource::Concatenation(vec!["part1".to_string(), "part2".to_string()]);

        match var_source {
            AssignmentSource::Variable(name) => assert_eq!(name, "user_input"),
            _ => panic!("Expected Variable source"),
        }

        match func_source {
            AssignmentSource::FunctionCall(name, args) => {
                assert_eq!(name, "get_input");
                assert_eq!(args.len(), 1);
            },
            _ => panic!("Expected FunctionCall source"),
        }

        match literal_source {
            AssignmentSource::Literal(value) => assert_eq!(value, "constant"),
            _ => panic!("Expected Literal source"),
        }

        match concat_source {
            AssignmentSource::Concatenation(parts) => assert_eq!(parts.len(), 2),
            _ => panic!("Expected Concatenation source"),
        }
    }

    #[test]
    fn test_function_definition_creation() {
        let func_def = FunctionDefinition {
            name: "test_function".to_string(),
            parameters: vec!["param1".to_string(), "param2".to_string()],
            return_variable: Some("result".to_string()),
            location: TaintLocation {
                file: "test.rs".to_string(),
                line: 10,
                column: 5,
                function: Some("test_function".to_string()),
            },
            can_propagate_taint: true,
        };

        assert_eq!(func_def.name, "test_function");
        assert_eq!(func_def.parameters.len(), 2);
        assert_eq!(func_def.parameters[0], "param1");
        assert!(func_def.can_propagate_taint);
    }

    #[test]
    fn test_taint_step_types() {
        let assignment_step = TaintStep {
            step_type: TaintStepType::Assignment,
            name: "variable".to_string(),
            location: TaintLocation {
                file: "test.rs".to_string(),
                line: 5,
                column: 10,
                function: Some("main".to_string()),
            },
            is_sanitizer: false,
            sanitizer_method: None,
        };

        assert_eq!(assignment_step.step_type, TaintStepType::Assignment);
        assert!(!assignment_step.is_sanitizer);

        let function_call_step = TaintStep {
            step_type: TaintStepType::FunctionCall,
            name: "sanitize".to_string(),
            location: TaintLocation {
                file: "test.rs".to_string(),
                line: 8,
                column: 15,
                function: Some("main".to_string()),
            },
            is_sanitizer: true,
            sanitizer_method: Some("html_escape".to_string()),
        };

        assert_eq!(function_call_step.step_type, TaintStepType::FunctionCall);
        assert!(function_call_step.is_sanitizer);
        assert_eq!(function_call_step.sanitizer_method.unwrap(), "html_escape");
    }

    #[test]
    fn test_assignment_propagation_logic() {
        let analyzer = TaintAnalyzer::new("rust");

        // Test variable assignment propagation
        let var_source = AssignmentSource::Variable("tainted_var".to_string());
        assert!(analyzer.assignment_propagates_taint(&var_source));

        // Test literal assignment (should not propagate)
        let literal_source = AssignmentSource::Literal("safe_string".to_string());
        assert!(!analyzer.assignment_propagates_taint(&literal_source));

        // Test function call from taint source
        let source_func = AssignmentSource::FunctionCall("std::env::args".to_string(), vec![]);
        assert!(analyzer.assignment_propagates_taint(&source_func));

        // Test function call from non-source
        let safe_func = AssignmentSource::FunctionCall("safe_function".to_string(), vec![]);
        assert!(!analyzer.assignment_propagates_taint(&safe_func));
    }

    #[test]
    fn test_sanitizer_detection() {
        let analyzer = TaintAnalyzer::new("rust");

        // Test sanitizer function detection
        assert!(analyzer.is_sanitizer_function("html_escape::encode_text"));
        assert!(!analyzer.is_sanitizer_function("regular_function"));

        // Test sanitizer assignment
        let sanitizer_assignment = VariableAssignment {
            target: "clean_data".to_string(),
            source: AssignmentSource::FunctionCall("html_escape::encode_text".to_string(), vec!["dirty_data".to_string()]),
            location: TaintLocation {
                file: "test.rs".to_string(),
                line: 10,
                column: 5,
                function: Some("main".to_string()),
            },
            propagates_taint: false,
        };

        assert!(analyzer.is_sanitizer_assignment(&sanitizer_assignment));
        assert_eq!(analyzer.get_sanitizer_method(&sanitizer_assignment).unwrap(), "html_escape::encode_text");
    }
}
