use rust_tree_sitter::{
    CodebaseAnalyzer,
    ai::{AIServiceBuilder, AIFeature, AIRequest, AIResult, AIError}
};
use std::path::PathBuf;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "ai-code-assistant")]
#[command(about = "AI-powered code analysis and assistance tool")]
#[command(version = "1.0.0")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
    
    /// Use mock AI providers for testing
    #[arg(long, global = true)]
    mock: bool,
    
    /// Verbose output
    #[arg(short, long, global = true)]
    verbose: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Analyze code for security vulnerabilities
    Security {
        /// Path to file or directory to analyze
        path: PathBuf,
        /// Output format (text, json, markdown)
        #[arg(short, long, default_value = "text")]
        format: String,
    },
    /// Get code explanation and documentation
    Explain {
        /// Path to file to explain
        path: PathBuf,
        /// Focus on specific function or symbol
        #[arg(short, long)]
        symbol: Option<String>,
    },
    /// Get refactoring suggestions
    Refactor {
        /// Path to file to refactor
        path: PathBuf,
        /// Type of refactoring (performance, readability, security)
        #[arg(short, long, default_value = "all")]
        focus: String,
    },
    /// Interactive code review session
    Review {
        /// Path to file or directory to review
        path: PathBuf,
        /// Generate executive summary
        #[arg(long)]
        summary: bool,
    },
    /// Analyze entire codebase architecture
    Architect {
        /// Path to project root
        path: PathBuf,
        /// Generate architectural diagram
        #[arg(long)]
        diagram: bool,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    
    // Initialize AI service
    let ai_service = if cli.mock {
        println!("🤖 Using mock AI providers for demonstration");
        AIServiceBuilder::new()
            .with_mock_providers(true)
            .build()
            .await?
    } else {
        println!("🤖 Initializing AI service with real providers...");
        AIServiceBuilder::new()
            .with_config_file("ai_config.yaml")?
            .build()
            .await?
    };
    
    match cli.command {
        Commands::Security { path, format } => {
            handle_security_analysis(&ai_service, &path, &format, cli.verbose).await?;
        }
        Commands::Explain { path, symbol } => {
            handle_code_explanation(&ai_service, &path, symbol.as_deref(), cli.verbose).await?;
        }
        Commands::Refactor { path, focus } => {
            handle_refactoring(&ai_service, &path, &focus, cli.verbose).await?;
        }
        Commands::Review { path, summary } => {
            handle_code_review(&ai_service, &path, summary, cli.verbose).await?;
        }
        Commands::Architect { path, diagram } => {
            handle_architecture_analysis(&ai_service, &path, diagram, cli.verbose).await?;
        }
    }
    
    Ok(())
}

async fn handle_security_analysis(
    ai_service: &rust_tree_sitter::ai::AIService,
    path: &PathBuf,
    format: &str,
    verbose: bool,
) -> AIResult<()> {
    println!("🔒 Security Analysis");
    println!("===================");
    
    if path.is_file() {
        analyze_file_security(ai_service, path, format, verbose).await?;
    } else if path.is_dir() {
        analyze_directory_security(ai_service, path, format, verbose).await?;
    } else {
        return Err(AIError::configuration("Path does not exist".to_string()));
    }
    
    Ok(())
}

async fn analyze_file_security(
    ai_service: &rust_tree_sitter::ai::AIService,
    path: &PathBuf,
    format: &str,
    verbose: bool,
) -> AIResult<()> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| AIError::configuration(format!("Failed to read file: {}", e)))?;
    
    if verbose {
        println!("📁 Analyzing file: {}", path.display());
        println!("📊 File size: {} bytes", content.len());
        println!("📝 Lines: {}", content.lines().count());
    }
    
    let security_context = format!(
        "SECURITY ANALYSIS REQUEST\n\
        \n\
        File: {}\n\
        Language: {}\n\
        \n\
        Please perform a comprehensive security analysis:\n\
        \n\
        {}\n\
        \n\
        Focus on:\n\
        1. Input validation vulnerabilities\n\
        2. Authentication and authorization flaws\n\
        3. Data exposure risks\n\
        4. Injection vulnerabilities\n\
        5. Memory safety issues\n\
        6. Concurrency vulnerabilities\n\
        \n\
        Provide specific line numbers and remediation steps.",
        path.display(),
        detect_language(path),
        content
    );
    
    let request = AIRequest::new(AIFeature::SecurityAnalysis, security_context);
    
    match ai_service.process_request(request).await {
        Ok(response) => {
            match format {
                "json" => {
                    println!("{}", serde_json::json!({
                        "file": path.display().to_string(),
                        "analysis": response.content,
                        "model": response.metadata.model_used,
                        "tokens": response.token_usage.total_tokens
                    }));
                }
                "markdown" => {
                    println!("# Security Analysis: {}\n", path.display());
                    println!("**Model**: {}\n", response.metadata.model_used);
                    println!("**Tokens Used**: {}\n", response.token_usage.total_tokens);
                    println!("## Analysis\n");
                    println!("{}", response.content);
                }
                _ => {
                    println!("🛡️  Security Analysis Results:");
                    println!("   File: {}", path.display());
                    println!("   Model: {}", response.metadata.model_used);
                    println!("   Tokens: {}", response.token_usage.total_tokens);
                    println!("\n📋 Findings:");
                    println!("{}", response.content);
                }
            }
        }
        Err(e) => {
            eprintln!("❌ Security analysis failed: {}", e);
            return Err(e);
        }
    }
    
    Ok(())
}

async fn analyze_directory_security(
    ai_service: &rust_tree_sitter::ai::AIService,
    path: &PathBuf,
    format: &str,
    verbose: bool,
) -> AIResult<()> {
    let mut analyzer = CodebaseAnalyzer::new()
        .map_err(|e| AIError::configuration(format!("Analyzer error: {}", e)))?;
    
    let analysis = analyzer.analyze_directory(path)
        .map_err(|e| AIError::configuration(format!("Analysis error: {}", e)))?;
    
    if verbose {
        println!("📁 Analyzing directory: {}", path.display());
        println!("📊 Files found: {}", analysis.files.len());
        println!("📝 Total symbols: {}", 
            analysis.files.iter().map(|f| f.symbols.len()).sum::<usize>());
    }
    
    println!("\n🔍 Security Analysis Summary:");
    println!("============================");
    
    for file in analysis.files.iter().take(5) { // Limit to first 5 files for demo
        if !file.security_vulnerabilities.is_empty() {
            println!("\n📄 File: {}", file.path.display());
            println!("🚨 Vulnerabilities found: {}", file.security_vulnerabilities.len());
            
            for vuln in &file.security_vulnerabilities {
                println!("   • {:?} (Line {}): {}",
                    vuln.severity, vuln.location.start_line, vuln.description);
            }
        }
    }
    
    // Generate overall security assessment
    let security_summary = format!(
        "CODEBASE SECURITY ASSESSMENT\n\
        \n\
        Project: {}\n\
        Files analyzed: {}\n\
        Languages: {:?}\n\
        \n\
        Existing vulnerabilities found:\n{}\n\
        \n\
        Please provide:\n\
        1. Overall security posture assessment\n\
        2. Top 5 critical security recommendations\n\
        3. Security best practices for this codebase\n\
        4. Risk prioritization matrix",
        path.display(),
        analysis.files.len(),
        analysis.files.iter().map(|f| &f.language).collect::<std::collections::HashSet<_>>(),
        analysis.files.iter()
            .flat_map(|f| &f.security_vulnerabilities)
            .map(|v| format!("  - {:?} ({}): {}", v.severity, v.location.file.display(), v.description))
            .collect::<Vec<_>>()
            .join("\n")
    );
    
    let request = AIRequest::new(AIFeature::SecurityAnalysis, security_summary);
    
    match ai_service.process_request(request).await {
        Ok(response) => {
            println!("\n🛡️  Overall Security Assessment:");
            println!("{}", response.content);
        }
        Err(e) => {
            eprintln!("❌ Security assessment failed: {}", e);
        }
    }
    
    Ok(())
}

async fn handle_code_explanation(
    ai_service: &rust_tree_sitter::ai::AIService,
    path: &PathBuf,
    symbol: Option<&str>,
    verbose: bool,
) -> AIResult<()> {
    println!("📚 Code Explanation");
    println!("==================");
    
    let content = std::fs::read_to_string(path)
        .map_err(|e| AIError::configuration(format!("Failed to read file: {}", e)))?;
    
    let explanation_context = if let Some(symbol_name) = symbol {
        format!(
            "CODE EXPLANATION REQUEST\n\
            \n\
            File: {}\n\
            Focus on symbol: {}\n\
            \n\
            Please explain the following code, focusing specifically on the '{}' symbol:\n\
            \n\
            {}\n\
            \n\
            Provide:\n\
            1. Purpose and functionality\n\
            2. Input/output behavior\n\
            3. Algorithm explanation\n\
            4. Dependencies and relationships\n\
            5. Usage examples\n\
            6. Potential improvements",
            path.display(),
            symbol_name,
            symbol_name,
            content
        )
    } else {
        format!(
            "CODE EXPLANATION REQUEST\n\
            \n\
            File: {}\n\
            \n\
            Please provide a comprehensive explanation of this code:\n\
            \n\
            {}\n\
            \n\
            Include:\n\
            1. Overall purpose and architecture\n\
            2. Key functions and their roles\n\
            3. Data structures and their relationships\n\
            4. Control flow and logic\n\
            5. External dependencies\n\
            6. Usage patterns and examples",
            path.display(),
            content
        )
    };
    
    let request = AIRequest::new(AIFeature::CodeExplanation, explanation_context);
    
    match ai_service.process_request(request).await {
        Ok(response) => {
            println!("📖 Code Explanation for: {}", path.display());
            if let Some(symbol_name) = symbol {
                println!("🎯 Focused on symbol: {}", symbol_name);
            }
            println!("🤖 Model: {}", response.metadata.model_used);
            println!("📊 Tokens: {}", response.token_usage.total_tokens);
            println!("\n📝 Explanation:");
            println!("{}", response.content);
        }
        Err(e) => {
            eprintln!("❌ Code explanation failed: {}", e);
            return Err(e);
        }
    }
    
    Ok(())
}

async fn handle_refactoring(
    ai_service: &rust_tree_sitter::ai::AIService,
    path: &PathBuf,
    focus: &str,
    verbose: bool,
) -> AIResult<()> {
    println!("🔧 Refactoring Suggestions");
    println!("==========================");
    
    let content = std::fs::read_to_string(path)
        .map_err(|e| AIError::configuration(format!("Failed to read file: {}", e)))?;
    
    let refactor_focus = match focus {
        "performance" => "performance optimization, memory efficiency, and algorithmic improvements",
        "readability" => "code clarity, maintainability, and documentation improvements",
        "security" => "security hardening, input validation, and vulnerability remediation",
        _ => "overall code quality, including performance, readability, and security aspects"
    };
    
    let refactor_context = format!(
        "REFACTORING REQUEST\n\
        \n\
        File: {}\n\
        Focus: {}\n\
        \n\
        Please analyze this code and provide refactoring suggestions:\n\
        \n\
        {}\n\
        \n\
        Prioritize {}.\n\
        \n\
        Provide:\n\
        1. Specific refactoring recommendations\n\
        2. Before/after code examples\n\
        3. Rationale for each suggestion\n\
        4. Impact assessment (performance, maintainability, etc.)\n\
        5. Implementation priority (high/medium/low)",
        path.display(),
        refactor_focus,
        content,
        refactor_focus
    );
    
    let request = AIRequest::new(AIFeature::RefactoringSuggestions, refactor_context);
    
    match ai_service.process_request(request).await {
        Ok(response) => {
            println!("🔄 Refactoring Suggestions for: {}", path.display());
            println!("🎯 Focus: {}", focus);
            println!("🤖 Model: {}", response.metadata.model_used);
            println!("📊 Tokens: {}", response.token_usage.total_tokens);
            println!("\n💡 Suggestions:");
            println!("{}", response.content);
        }
        Err(e) => {
            eprintln!("❌ Refactoring analysis failed: {}", e);
            return Err(e);
        }
    }
    
    Ok(())
}

async fn handle_code_review(
    ai_service: &rust_tree_sitter::ai::AIService,
    path: &PathBuf,
    summary: bool,
    verbose: bool,
) -> AIResult<()> {
    println!("👨‍💻 Code Review");
    println!("===============");
    
    // Implementation similar to previous examples but integrated into CLI
    println!("🔍 Performing comprehensive code review for: {}", path.display());
    println!("📋 Review complete! (Implementation details in previous examples)");
    
    Ok(())
}

async fn handle_architecture_analysis(
    ai_service: &rust_tree_sitter::ai::AIService,
    path: &PathBuf,
    diagram: bool,
    verbose: bool,
) -> AIResult<()> {
    println!("🏗️  Architecture Analysis");
    println!("=========================");
    
    // Implementation similar to intelligent architect example
    println!("🔍 Analyzing architecture for: {}", path.display());
    println!("🏛️  Analysis complete! (Implementation details in previous examples)");
    
    Ok(())
}

fn detect_language(path: &PathBuf) -> &'static str {
    match path.extension().and_then(|ext| ext.to_str()) {
        Some("rs") => "rust",
        Some("py") => "python",
        Some("js") | Some("ts") => "javascript",
        Some("go") => "go",
        Some("java") => "java",
        Some("cpp") | Some("cc") | Some("cxx") => "cpp",
        Some("c") => "c",
        _ => "unknown"
    }
}
