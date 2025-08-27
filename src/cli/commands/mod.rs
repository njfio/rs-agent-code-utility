//! CLI command implementations
//!
//! This module contains the implementation of all CLI commands with proper separation of concerns.

pub mod analyze;
pub mod security;
pub mod refactor;
pub mod dependencies;
pub mod query;
pub mod stats;
pub mod find;
pub mod symbols;
pub mod languages;
pub mod interactive;
pub mod insights;
pub mod map;
pub mod explain;
pub mod watch;
pub mod wiki;


use super::{Commands, Execute};
use super::error::{CliError, CliResult};

impl Execute for Commands {
    type Error = CliError;

    fn execute(&self) -> CliResult<()> {
        match self {
            Commands::Analyze {
                path, format, max_size, max_depth, depth, include_hidden,
                exclude_dirs, include_exts, output, detailed, threads, enable_security, print_schema, schema_version
            } => {
                if *print_schema {
                    // Currently only v1 is supported
                    match schema_version.as_str() {
                        "1" | "v1" => {
                            println!("{}", crate::cli::schemas::ANALYZE_SCHEMA_V1);
                            return Ok(());
                        }
                        other => {
                            return Err(CliError::InvalidArgs(format!("Unsupported schema version: {}", other)));
                        }
                    }
                }
                analyze::execute(
                    path, format, *max_size, *max_depth, depth, *include_hidden,
                    exclude_dirs.as_ref(), include_exts.as_ref(), output.as_ref(), *detailed, *threads, *enable_security
                )
            }
            Commands::Query { path, pattern, language, prefilter, context, format } => {
                query::execute(path, pattern, language, prefilter.as_ref(), *context, format)
            }
            Commands::Stats { path, top } => {
                stats::execute(path, *top)
            }
            Commands::Find { path, name, symbol_type, language, public_only } => {
                find::execute(path, name.as_ref(), symbol_type.as_ref(), language.as_ref(), *public_only)
            }
            Commands::Symbols { path, format, print_schema, schema_version } => {
                if *print_schema {
                    match schema_version.as_str() {
                        "1" | "v1" => {
                            println!("{}", crate::cli::schemas::SYMBOLS_SCHEMA_V1);
                            return Ok(());
                        }
                        other => return Err(CliError::InvalidArgs(format!("Unsupported schema version: {}", other))),
                    }
                }
                symbols::execute(path, format)
            }
            Commands::Languages => {
                languages::execute()
            }
            Commands::Interactive { path } => {
                interactive::execute(path)
            }
            Commands::Insights { path, focus, format } => {
                insights::execute(path, focus, format)
            }
            Commands::Map {
                path, map_type, format, max_depth, show_sizes, show_symbols,
                languages, collapse_empty, depth
            } => {
                map::execute(
                    path, map_type, format, *max_depth, *show_sizes, *show_symbols,
                    languages.as_ref(), *collapse_empty, depth
                )
            }
            Commands::Explain { path, file, symbol, format, detailed, learning } => {
                explain::execute(path, file.as_ref(), symbol.as_ref(), format, *detailed, *learning)
            }
            Commands::Security {
                path, format, min_severity, output, summary_only, compliance, depth, print_schema, schema_version, enable_security
            } => {
                if *print_schema {
                    match schema_version.as_str() {
                        "1" | "v1" => {
                            println!("{}", crate::cli::schemas::SECURITY_SCHEMA_V1);
                            return Ok(());
                        }
                        other => return Err(CliError::InvalidArgs(format!("Unsupported schema version: {}", other))),
                    }
                }
                security::execute(
                    path, format, min_severity, output.as_ref(), *summary_only, *compliance, depth, *enable_security
                )
            }
            Commands::Refactor {
                path, category, format, quick_wins, major_only, min_priority, output
            } => {
                refactor::execute(
                    path, category.as_ref(), format, *quick_wins, *major_only, min_priority, output.as_ref()
                )
            }
            Commands::Dependencies {
                path, format, include_dev, vulnerabilities, licenses, outdated, graph, output
            } => {
                dependencies::execute(
                    path, format, *include_dev, *vulnerabilities, *licenses, *outdated, *graph, output.as_ref()
                )
            }
            Commands::Watch { path, interval, max_iterations, depth } => {
                watch::execute(path, *interval, *max_iterations, depth)
            }
            Commands::Wiki { path, output, include_api, include_examples, depth, ai, ai_mock, ai_config } => {
                wiki::execute(
                    path,
                    output.as_ref(),
                    *include_api,
                    *include_examples,
                    depth,
                    *ai,
                    *ai_mock,
                    ai_config.as_ref(),
                    *ai, // enhanced_ai (same as ai for now)
                    *ai, // function_enhancement (same as ai for now)
                    *ai, // security_insights (same as ai for now)
                    *ai, // refactoring_hints (same as ai for now)
                    false // diagram_annotations (disabled by default)
                )
            }
        }
    }
}
