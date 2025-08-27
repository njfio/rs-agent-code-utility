use rust_tree_sitter::{CodebaseAnalyzer, build_call_graph, build_module_graph};
use std::env;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let target = env::args().nth(1).unwrap_or_else(|| ".".to_string());
    let mut analyzer = CodebaseAnalyzer::new()?;
    let result = analyzer.analyze_directory(&target)?;

    let call_graph = build_call_graph(&result);
    println!("Call Graph (Mermaid):\n{}", call_graph.to_mermaid());

    let module_graph = build_module_graph(&result);
    println!("Module Graph (DOT):\n{}", module_graph.to_dot());
    Ok(())
}
