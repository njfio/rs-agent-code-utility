//! Dependencies command implementation
//! 
//! Provides comprehensive dependency analysis with security scanning and license compliance.

use std::path::PathBuf;
use colored::*;
use crate::{CodebaseAnalyzer, DependencyAnalyzer};
use crate::cli::error::{CliError, CliResult, validate_path, validate_format};
use crate::cli::utils::{create_progress_bar, create_analysis_config, validate_output_path, print_success};
use crate::cli::output::OutputFormat;

/// Execute the dependencies command
pub fn execute(
    path: &PathBuf,
    format: &str,
    include_dev: bool,
    vulnerabilities: bool,
    licenses: bool,
    outdated: bool,
    graph: bool,
    output: Option<&PathBuf>,
) -> CliResult<()> {
    // Validate inputs
    validate_path(path)?;
    validate_format(format, &["table", "json", "markdown"])?;
    
    if let Some(output_path) = output {
        validate_output_path(output_path)?;
    }
    
    // Create progress bar
    let pb = create_progress_bar("Analyzing dependencies...");
    
    // Configure analyzer
    let config = create_analysis_config(1024, 20, "full", false, None, None, None, false)?;
    let mut analyzer = CodebaseAnalyzer::with_config(config)
        .map_err(|e| CliError::Dependencies(e.to_string()))?;
    
    // Run analysis first
    pb.set_message("Analyzing codebase...");
    let analysis_result = analyzer.analyze_directory(path)
        .map_err(|e| CliError::Dependencies(e.to_string()))?;
    
    // Run dependency analysis
    pb.set_message("Analyzing dependencies...");
    let mut dep_config = crate::DependencyConfig::default();
    dep_config.include_dev_dependencies = include_dev;
    dep_config.vulnerability_scanning = vulnerabilities;
    dep_config.license_compliance = licenses;
    dep_config.outdated_detection = outdated;
    dep_config.graph_analysis = graph;

    let dependency_analyzer = DependencyAnalyzer::with_config(dep_config);
    let dependency_result = dependency_analyzer.analyze(&analysis_result)
        .map_err(|e| CliError::Dependencies(e.to_string()))?;
    
    pb.finish_with_message("Dependency analysis complete!");
    
    // Display results based on format
    let output_format = OutputFormat::from_str(format)
        .map_err(|e| CliError::UnsupportedFormat(e))?;
    
    match output_format {
        OutputFormat::Json => {
            let json = serde_json::to_string_pretty(&dependency_result)?;
            if let Some(output_path) = output {
                std::fs::write(output_path, &json)?;
                print_success(&format!("Dependency report saved to {}", output_path.display()));
            } else {
                println!("{}", json);
            }
        }
        OutputFormat::Markdown => {
            print_dependencies_markdown(&dependency_result, vulnerabilities, licenses, outdated, graph);
            if let Some(output_path) = output {
                let markdown = render_dependencies_markdown(&dependency_result, vulnerabilities, licenses, outdated, graph);
                std::fs::write(output_path, markdown)?;
                print_success(&format!("Dependency report saved to {}", output_path.display()));
            }
        }
        OutputFormat::Table | _ => {
            print_dependencies_table(&dependency_result, vulnerabilities, licenses, outdated, graph);
            if let Some(output_path) = output {
                let json = serde_json::to_string_pretty(&dependency_result)?;
                std::fs::write(output_path, json)?;
                print_success(&format!("Dependency report saved to {}", output_path.display()));
            }
        }
    }

    // Optional SBOM emission if path ends with .sbom.json
    if let Some(output_path) = output {
        if let Some(file) = output_path.file_name().and_then(|n| n.to_str()) {
            if file.ends_with(".sbom.json") {
                let sbom = crate::cli::sbom::to_cyclonedx(&dependency_result);
                std::fs::write(output_path, sbom)?;
                print_success(&format!("SBOM saved to {}", output_path.display()));
            }
        }
    }
    
    Ok(())
}

fn print_dependencies_table(
    dependency_result: &crate::DependencyAnalysisResult,
    show_vulnerabilities: bool,
    show_licenses: bool,
    show_outdated: bool,
    show_graph: bool,
) {
    println!("\n{}", "🔍 DEPENDENCY ANALYSIS".bright_blue().bold());
    println!("{}", "=".repeat(60).bright_blue());

    println!("\n{}", "📊 SUMMARY".bright_cyan().bold());
    println!("Total Dependencies: {}", dependency_result.total_dependencies.to_string().bright_white());
    println!("Direct Dependencies: {}", dependency_result.direct_dependencies.to_string().bright_green());
    println!("Transitive Dependencies: {}", dependency_result.transitive_dependencies.to_string().bright_yellow());

    if !dependency_result.package_managers.is_empty() {
        println!("\n{}", "📦 PACKAGE MANAGERS".bright_cyan().bold());
        for pm in &dependency_result.package_managers {
            println!("  {} - {} dependencies",
                pm.manager.to_string().bright_blue(),
                dependency_result.dependencies_by_manager.get(&pm.manager).unwrap_or(&0).to_string().bright_white()
            );
        }
    }

    if show_vulnerabilities && !dependency_result.vulnerabilities.is_empty() {
        println!("\n{}", "🚨 VULNERABILITIES".bright_red().bold());
        for vuln in &dependency_result.vulnerabilities {
            println!("  {} - {} ({})",
                vuln.dependency.bright_white(),
                vuln.title.bright_red(),
                vuln.severity.to_string().bright_yellow()
            );
        }
    }

    if show_licenses && !dependency_result.license_analysis.compliance_issues.is_empty() {
        println!("\n{}", "⚖️ LICENSE ISSUES".bright_yellow().bold());
        for issue in &dependency_result.license_analysis.compliance_issues {
            println!("  {} - {} license issue",
                issue.dependency.bright_white(),
                issue.issue_type.to_string().bright_yellow()
            );
        }
    }

    if show_outdated && !dependency_result.outdated_dependencies.is_empty() {
        println!("\n{}", "📅 OUTDATED DEPENDENCIES".bright_yellow().bold());
        for outdated in &dependency_result.outdated_dependencies {
            println!("  {} {} → {} ({})",
                outdated.name.bright_white(),
                outdated.current_version.bright_red(),
                outdated.latest_version.bright_green(),
                outdated.urgency.to_string().bright_yellow()
            );
        }
    }

    if show_graph {
        println!("\n{}", "🕸️ DEPENDENCY GRAPH".bright_cyan().bold());
        println!("  Nodes: {}", dependency_result.graph_analysis.total_nodes.to_string().bright_white());
        println!("  Max Depth: {}", dependency_result.graph_analysis.max_depth.to_string().bright_white());
        println!("  Circular Dependencies: {}", dependency_result.graph_analysis.circular_dependencies.len().to_string().bright_red());
    }

    if !dependency_result.security_recommendations.is_empty() {
        println!("\n{}", "💡 SECURITY RECOMMENDATIONS".bright_green().bold());
        for (i, rec) in dependency_result.security_recommendations.iter().enumerate() {
            println!("{}. {} (Priority: {})",
                format!("{}", i + 1).bright_cyan(),
                rec.recommendation.bright_white(),
                rec.priority.to_string().bright_yellow()
            );
        }
    }
}

fn print_dependencies_markdown(
    dependency_result: &crate::DependencyAnalysisResult,
    show_vulnerabilities: bool,
    show_licenses: bool,
    show_outdated: bool,
    show_graph: bool,
) {
    println!("# 🔍 Dependency Analysis Report\n");

    println!("## 📊 Summary\n");
    println!("- **Total Dependencies**: {}", dependency_result.total_dependencies);
    println!("- **Direct Dependencies**: {}", dependency_result.direct_dependencies);
    println!("- **Transitive Dependencies**: {}", dependency_result.transitive_dependencies);

    if !dependency_result.package_managers.is_empty() {
        println!("\n## 📦 Package Managers\n");
        for pm in &dependency_result.package_managers {
            println!("- **{}**: {} dependencies",
                pm.manager,
                dependency_result.dependencies_by_manager.get(&pm.manager).unwrap_or(&0)
            );
        }
    }

    if show_vulnerabilities && !dependency_result.vulnerabilities.is_empty() {
        println!("\n## 🚨 Security Vulnerabilities\n");
        for vuln in &dependency_result.vulnerabilities {
            println!("### {}\n", vuln.title);
            println!("- **Dependency**: {}", vuln.dependency);
            println!("- **Severity**: {}", vuln.severity);
            println!("- **Description**: {}\n", vuln.description);
        }
    }

    if show_licenses && !dependency_result.license_analysis.compliance_issues.is_empty() {
        println!("\n## ⚖️ License Compliance Issues\n");
        for issue in &dependency_result.license_analysis.compliance_issues {
            println!("- **{}**: {} license issue - {}",
                issue.dependency,
                issue.issue_type.to_string(),
                issue.description
            );
        }
    }

    if show_outdated && !dependency_result.outdated_dependencies.is_empty() {
        println!("\n## 📅 Outdated Dependencies\n");
        for outdated in &dependency_result.outdated_dependencies {
            println!("- **{}**: {} → {} ({})",
                outdated.name,
                outdated.current_version,
                outdated.latest_version,
                outdated.urgency.to_string()
            );
        }
    }

    if show_graph {
        println!("\n## 🕸️ Dependency Graph Analysis\n");
        println!("- **Total Nodes**: {}", dependency_result.graph_analysis.total_nodes);
        println!("- **Maximum Depth**: {}", dependency_result.graph_analysis.max_depth);
        println!("- **Circular Dependencies**: {}", dependency_result.graph_analysis.circular_dependencies.len());
    }
}

fn render_dependencies_markdown(
    dependency_result: &crate::DependencyAnalysisResult,
    show_vulnerabilities: bool,
    show_licenses: bool,
    show_outdated: bool,
    show_graph: bool,
) -> String {
    use std::fmt::Write;
    let mut out = String::new();
    
    writeln!(out, "# 🔍 Dependency Analysis Report\n").unwrap();
    writeln!(out, "## 📊 Summary\n").unwrap();
    writeln!(out, "- **Total Dependencies**: {}", dependency_result.total_dependencies).unwrap();
    writeln!(out, "- **Direct Dependencies**: {}", dependency_result.direct_dependencies).unwrap();
    writeln!(out, "- **Transitive Dependencies**: {}", dependency_result.transitive_dependencies).unwrap();

    if !dependency_result.package_managers.is_empty() {
        writeln!(out, "\n## 📦 Package Managers\n").unwrap();
        for pm in &dependency_result.package_managers {
            writeln!(out, "- **{}**: {} dependencies",
                pm.manager,
                dependency_result.dependencies_by_manager.get(&pm.manager).unwrap_or(&0)
            ).unwrap();
        }
    }

    if show_vulnerabilities && !dependency_result.vulnerabilities.is_empty() {
        writeln!(out, "\n## 🚨 Security Vulnerabilities\n").unwrap();
        for vuln in &dependency_result.vulnerabilities {
            writeln!(out, "### {}\n", vuln.title).unwrap();
            writeln!(out, "- **Dependency**: {}", vuln.dependency).unwrap();
            writeln!(out, "- **Severity**: {}", vuln.severity).unwrap();
            writeln!(out, "- **Description**: {}\n", vuln.description).unwrap();
        }
    }

    if show_licenses && !dependency_result.license_analysis.compliance_issues.is_empty() {
        writeln!(out, "\n## ⚖️ License Compliance Issues\n").unwrap();
        for issue in &dependency_result.license_analysis.compliance_issues {
            writeln!(out, "- **{}**: {} license issue - {}",
                issue.dependency,
                issue.issue_type.to_string(),
                issue.description
            ).unwrap();
        }
    }

    if show_outdated && !dependency_result.outdated_dependencies.is_empty() {
        writeln!(out, "\n## 📅 Outdated Dependencies\n").unwrap();
        for outdated in &dependency_result.outdated_dependencies {
            writeln!(out, "- **{}**: {} → {} ({})",
                outdated.name,
                outdated.current_version,
                outdated.latest_version,
                outdated.urgency.to_string()
            ).unwrap();
        }
    }

    if show_graph {
        writeln!(out, "\n## 🕸️ Dependency Graph Analysis\n").unwrap();
        writeln!(out, "- **Total Nodes**: {}", dependency_result.graph_analysis.total_nodes).unwrap();
        writeln!(out, "- **Maximum Depth**: {}", dependency_result.graph_analysis.max_depth).unwrap();
        writeln!(out, "- **Circular Dependencies**: {}", dependency_result.graph_analysis.circular_dependencies.len()).unwrap();
    }
    
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    
    #[test]
    fn test_dependencies_command_validation() {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path().to_path_buf();
        
        let result = execute(
            &path,
            "table",
            false,
            false,
            false,
            false,
            false,
            None,
        );
        assert!(result.is_ok());
    }
}
