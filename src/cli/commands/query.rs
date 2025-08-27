//! Query command implementation

use std::path::PathBuf;
use crate::cli::error::{CliResult, validate_path, validate_language};
use crate::cli::utils::create_progress_bar;

#[derive(Debug, Clone)]
struct QueryResult {
    file_path: PathBuf,
    start_line: usize,
    end_line: usize,
    match_text: String,
    context_lines: Vec<String>,
}

pub fn execute(
    path: &PathBuf,
    pattern: &str,
    language: &str,
    prefilter: Option<&String>,
    context: usize,
    format: &str,
) -> CliResult<()> {
    validate_path(path)?;
    validate_language(language)?;
    
    let pb = create_progress_bar("Running query...");

    use crate::analyzer::CodebaseAnalyzer;
    use crate::parser::Parser;
    use crate::languages::Language;

    // Initialize analyzer
    let mut analyzer = CodebaseAnalyzer::new()?;

    // Analyze the target path
    let analysis_result = if path.is_file() {
        analyzer.analyze_file(path)?
    } else {
        analyzer.analyze_directory(path)?
    };

    // Parse the query language
    let query_language: Language = language.parse()
        .map_err(|_| crate::cli::error::CliError::InvalidLanguage(language.to_string()))?;

    let parser = Parser::new(query_language)?;

    // Execute the query on each file
    let mut total_matches = 0;
    let mut results = Vec::new();

    for file in &analysis_result.files {
        if file.language != language {
            continue;
        }

        // Read file content
        let file_path = analysis_result.root_path.join(&file.path);
        let content = std::fs::read_to_string(&file_path)
            .map_err(|e| crate::cli::error::CliError::IoError(e))?;

        // Optional prefilter: skip files that don't contain the substring
        if let Some(sub) = prefilter {
            if !content.contains(sub) {
                continue;
            }
        }

        // Parse the file
        let tree = parser.parse(&content, None)?;

        // Find nodes matching the pattern
        let matches = tree.find_nodes_by_kind(pattern);

        if !matches.is_empty() {
            for node in &matches {
                let start_line = node.start_position().row + 1;
                let end_line = node.end_position().row + 1;
                let node_text = &content[node.start_byte()..node.end_byte()];

                // Extract context lines
                let lines: Vec<&str> = content.lines().collect();
                let context_start = start_line.saturating_sub(context + 1);
                let context_end = (end_line + context).min(lines.len());

                results.push(QueryResult {
                    file_path: file.path.clone(),
                    start_line,
                    end_line,
                    match_text: node_text.to_string(),
                    context_lines: lines[context_start..context_end].iter().map(|s| s.to_string()).collect(),
                });
            }
            total_matches += matches.len();
        }
    }

    pb.finish_with_message("Query complete!");

    // Output results in requested format
    match format {
        "json" => output_json(&results)?,
        "table" => output_table(&results),
        _ => output_default(&results, context),
    }

    println!("\n🔍 Query Summary:");
    println!("   Pattern: '{}'", pattern);
    println!("   Language: {}", language);
    println!("   Files searched: {}", analysis_result.files.len());
    println!("   Total matches: {}", total_matches);
    
    Ok(())
}

fn output_json(results: &[QueryResult]) -> CliResult<()> {
    use serde_json::json;

    let json_results: Vec<_> = results.iter().map(|r| {
        json!({
            "file": r.file_path.display().to_string(),
            "start_line": r.start_line,
            "end_line": r.end_line,
            "match": r.match_text,
            "context": r.context_lines
        })
    }).collect();

    println!("{}", serde_json::to_string_pretty(&json_results)
        .map_err(|e| crate::cli::error::CliError::SerializationError(e.to_string()))?);

    Ok(())
}

fn output_table(results: &[QueryResult]) {
    use tabled::{Table, Tabled};

    #[derive(Tabled)]
    struct TableRow {
        #[tabled(rename = "File")]
        file: String,
        #[tabled(rename = "Lines")]
        lines: String,
        #[tabled(rename = "Match")]
        match_text: String,
    }

    let rows: Vec<TableRow> = results.iter().map(|r| {
        TableRow {
            file: r.file_path.display().to_string(),
            lines: format!("{}-{}", r.start_line, r.end_line),
            match_text: r.match_text.lines().next().unwrap_or("").trim().to_string(),
        }
    }).collect();

    if !rows.is_empty() {
        println!("{}", Table::new(rows));
    }
}

fn output_default(results: &[QueryResult], context: usize) {
    for result in results {
        println!("\n📁 File: {}", result.file_path.display());
        println!("   Lines {}-{}", result.start_line, result.end_line);

        if context > 0 {
            println!("   Context:");
            for (i, line) in result.context_lines.iter().enumerate() {
                let line_num = result.start_line.saturating_sub(context) + i;
                let marker = if line_num >= result.start_line && line_num <= result.end_line {
                    ">>>"
                } else {
                    "   "
                };
                println!("   {} {:4}: {}", marker, line_num, line);
            }
        } else {
            println!("   Match: {}", result.match_text.lines().next().unwrap_or("").trim());
        }
    }
}
