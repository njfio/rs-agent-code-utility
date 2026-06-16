//! Query command implementation
#![allow(clippy::too_many_arguments)]

use crate::cli::error::{validate_language, validate_path, CliResult};
use crate::cli::utils::create_progress_bar;
use std::path::PathBuf;

#[derive(Debug, Clone)]
struct QueryResult {
    file_path: PathBuf,
    start_line: usize,
    end_line: usize,
    match_text: String,
    context_lines: Vec<String>,
}

/// Returns true if `name` appears in `haystack` as a whole identifier token,
/// i.e. not surrounded by other identifier characters. This distinguishes a
/// usage of `foo` from an unrelated `foobar` or `do_foo`.
fn matches_name(haystack: &str, name: &str) -> bool {
    if name.is_empty() {
        return true;
    }
    let is_ident = |b: u8| b == b'_' || b.is_ascii_alphanumeric();
    let bytes = haystack.as_bytes();
    for (start, m) in haystack.match_indices(name) {
        let end = start + m.len();
        let before_ok = start == 0 || !is_ident(bytes[start - 1]);
        let after_ok = end >= bytes.len() || !is_ident(bytes[end]);
        if before_ok && after_ok {
            return true;
        }
    }
    false
}

pub fn execute(
    path: &PathBuf,
    pattern: &str,
    language: &str,
    name: Option<&String>,
    text: Option<&String>,
    prefilter: Option<&String>,
    context: usize,
    format: &str,
) -> CliResult<()> {
    validate_path(path)?;
    validate_language(language)?;

    let pb = create_progress_bar("Running query...");

    use crate::analyzer::CodebaseAnalyzer;
    use crate::languages::Language;
    use crate::parser::Parser;

    // Initialize analyzer
    let mut analyzer = CodebaseAnalyzer::new()?;

    // Analyze the target path
    let analysis_result = if path.is_file() {
        analyzer.analyze_file(path)?
    } else {
        analyzer.analyze_directory(path)?
    };

    // Parse the query language
    let query_language: Language = language
        .parse()
        .map_err(|_| crate::cli::error::CliError::InvalidLanguage(language.to_string()))?;

    let parser = Parser::new(query_language)?;

    // Execute the query on each file
    let mut total_matches = 0;
    let mut results = Vec::new();

    for file in &analysis_result.files {
        // FileInfo.language is the canonical name (e.g. "Rust"); the CLI value
        // is whatever the user typed (e.g. "rust"). Compare case-insensitively.
        if !file.language.eq_ignore_ascii_case(language) {
            continue;
        }

        // Read file content
        let file_path = analysis_result.root_path.join(&file.path);
        let content =
            std::fs::read_to_string(&file_path).map_err(crate::cli::error::CliError::IoError)?;

        // Optional prefilter: skip files that don't contain the substring
        if let Some(sub) = prefilter {
            if !content.contains(sub) {
                continue;
            }
        }

        // Parse the file
        let tree = parser.parse(&content, None)?;

        // The pattern may be a comma-separated list of node kinds, e.g.
        // "identifier,field_identifier,scoped_identifier" to catch a symbol in
        // every syntactic role at once. Collect across all kinds, then dedup by
        // byte span so overlapping kinds don't double-count.
        let mut matches = Vec::new();
        for kind in pattern.split(',').map(str::trim).filter(|k| !k.is_empty()) {
            matches.extend(tree.find_nodes_by_kind(kind));
        }
        matches.sort_by_key(|n| (n.start_byte(), n.end_byte()));
        matches.dedup_by_key(|n| (n.start_byte(), n.end_byte()));

        for node in &matches {
            let node_text = &content[node.start_byte()..node.end_byte()];

            // Apply optional name/text predicates. The kind pattern selects the
            // shape (call_expression, identifier, string_literal, ...); these
            // narrow it to a specific symbol or phrase.
            if let Some(name) = name {
                if !matches_name(node_text, name) {
                    continue;
                }
            }
            if let Some(text) = text {
                if !node_text.to_lowercase().contains(&text.to_lowercase()) {
                    continue;
                }
            }

            let start_line = node.start_position().row + 1;
            let end_line = node.end_position().row + 1;

            // Extract context lines
            let lines: Vec<&str> = content.lines().collect();
            let context_start = start_line.saturating_sub(context + 1);
            let context_end = (end_line + context).min(lines.len());

            results.push(QueryResult {
                file_path: file.path.clone(),
                start_line,
                end_line,
                match_text: node_text.to_string(),
                context_lines: lines[context_start..context_end]
                    .iter()
                    .map(|s| s.to_string())
                    .collect(),
            });
            total_matches += 1;
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
    if let Some(name) = name {
        println!("   Name filter: '{}'", name);
    }
    if let Some(text) = text {
        println!("   Text filter: '{}'", text);
    }
    println!("   Language: {}", language);
    println!("   Files searched: {}", analysis_result.files.len());
    println!("   Total matches: {}", total_matches);

    Ok(())
}

fn output_json(results: &[QueryResult]) -> CliResult<()> {
    use serde_json::json;

    let json_results: Vec<_> = results
        .iter()
        .map(|r| {
            json!({
                "file": r.file_path.display().to_string(),
                "start_line": r.start_line,
                "end_line": r.end_line,
                "match": r.match_text,
                "context": r.context_lines
            })
        })
        .collect();

    println!(
        "{}",
        serde_json::to_string_pretty(&json_results)
            .map_err(|e| crate::cli::error::CliError::SerializationError(e.to_string()))?
    );

    Ok(())
}

fn output_table(results: &[QueryResult]) {
    let rows: Vec<Vec<String>> = results
        .iter()
        .map(|r| {
            vec![
                r.file_path.display().to_string(),
                format!("{}-{}", r.start_line, r.end_line),
                r.match_text.lines().next().unwrap_or("").trim().to_string(),
            ]
        })
        .collect();

    if !rows.is_empty() {
        println!(
            "{}",
            crate::cli::output::render_text_table(&["File", "Lines", "Match"], &rows)
        );
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
            println!(
                "   Match: {}",
                result.match_text.lines().next().unwrap_or("").trim()
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::matches_name;

    #[test]
    fn whole_word_identifier_matches() {
        assert!(matches_name("foo", "foo"));
        assert!(matches_name("foo(bar)", "foo")); // call site
        assert!(matches_name("let x = foo + 1;", "foo")); // usage
        assert!(matches_name("self.foo()", "foo")); // method-ish
    }

    #[test]
    fn substring_of_larger_identifier_does_not_match() {
        assert!(!matches_name("foobar", "foo"));
        assert!(!matches_name("do_foo", "foo"));
        assert!(!matches_name("foo_bar", "foo"));
    }

    #[test]
    fn empty_name_matches_anything() {
        assert!(matches_name("anything", ""));
    }

    #[test]
    fn handles_non_ascii_boundaries() {
        // A multibyte char adjacent to the token must not panic and counts as a boundary.
        assert!(matches_name("café foo", "foo"));
        assert!(matches_name("foo→bar", "foo"));
    }
}
