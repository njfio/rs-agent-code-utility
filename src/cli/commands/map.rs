//! Map command implementation

use std::path::PathBuf;
use crate::cli::error::{CliResult, validate_path};
use crate::{CodebaseAnalyzer, code_map::{build_call_graph, build_module_graph}};
use serde_json;

pub fn execute(
    path: &PathBuf,
    map_type: &str,
    format: &str,
    _max_depth: usize,
    _show_sizes: bool,
    _show_symbols: bool,
    _languages: Option<&String>,
    _collapse_empty: bool,
    _depth: &str,
) -> CliResult<()> {
    validate_path(path)?;

    // Analyze the codebase
    let mut analyzer = CodebaseAnalyzer::new()
        .map_err(|e| format!("Failed to create analyzer: {}", e))?;
    let result = analyzer.analyze_directory(path)
        .map_err(|e| crate::cli::error::CliError::Analysis(e.to_string()))?;

    match (map_type, format) {
        ("tree", "json") => {
            // Generate a simple tree structure
            let tree_map = generate_tree_map(&result);
            let json = serde_json::to_string_pretty(&tree_map)
                .map_err(|e| crate::cli::error::CliError::SerializationError(e.to_string()))?;
            println!("{}", json);
        }
        ("symbol", "json") | ("symbols", "json") => {
            // Generate symbol map (accept both "symbol" and "symbols")
            let symbol_map = generate_symbol_map(&result);
            let json = serde_json::to_string_pretty(&symbol_map)
                .map_err(|e| crate::cli::error::CliError::SerializationError(e.to_string()))?;
            println!("{}", json);
        }
        ("call", "dot") => {
            // Generate call graph in DOT format
            let call_graph = build_call_graph(&result);
            println!("{}", call_graph.to_dot());
        }
        ("module", "dot") => {
            // Generate module graph in DOT format
            let module_graph = build_module_graph(&result);
            println!("{}", module_graph.to_dot());
        }
        _ => {
            return Err(crate::cli::error::CliError::InvalidArgs(
                format!("Unsupported map type '{}' with format '{}'", map_type, format)
            ));
        }
    }

    Ok(())
}

fn generate_tree_map(result: &crate::AnalysisResult) -> serde_json::Value {
    use serde_json::{json, Map, Value};

    let mut tree = Map::new();
    tree.insert("root".to_string(), json!(result.root_path.display().to_string()));
    tree.insert("total_files".to_string(), json!(result.total_files));
    tree.insert("parsed_files".to_string(), json!(result.parsed_files));
    tree.insert("error_files".to_string(), json!(result.error_files));
    tree.insert("total_lines".to_string(), json!(result.total_lines));

    let mut files = Vec::new();
    for file in &result.files {
        files.push(json!({
            "path": file.path.display().to_string(),
            "language": file.language,
            "size": file.size,
            "lines": file.lines,
            "parsed_successfully": file.parsed_successfully,
            "symbol_count": file.symbols.len()
        }));
    }
    tree.insert("files".to_string(), json!(files));

    Value::Object(tree)
}

fn generate_symbol_map(result: &crate::AnalysisResult) -> serde_json::Value {
    use serde_json::{json, Map, Value};

    let mut symbol_map = Map::new();
    symbol_map.insert("root".to_string(), json!(result.root_path.display().to_string()));

    let mut files = Vec::new();
    for file in &result.files {
        let mut symbols = Vec::new();
        for symbol in &file.symbols {
            symbols.push(json!({
                "name": symbol.name,
                "kind": symbol.kind,
                "start_line": symbol.start_line,
                "end_line": symbol.end_line,
                "start_column": symbol.start_column,
                "end_column": symbol.end_column,
                "visibility": symbol.visibility,
                "documentation": symbol.documentation
            }));
        }

        files.push(json!({
            "path": file.path.display().to_string(),
            "language": file.language,
            "symbols": symbols
        }));
    }
    symbol_map.insert("files".to_string(), json!(files));

    Value::Object(symbol_map)
}
