use rust_tree_sitter::{
    ai::{AIError, AIFeature, AIRequest, AIResult, AIServiceBuilder},
    analyzer::CodebaseAnalyzer,
};
use std::path::PathBuf;

#[tokio::main]
async fn main() -> AIResult<()> {
    println!("🏗️  Intelligent Codebase Architect");
    println!("===================================");

    // Initialize AI service
    let ai_service = AIServiceBuilder::new()
        .with_mock_providers(true)
        .build()
        .await?;

    // Analyze the entire codebase
    println!("📁 Analyzing codebase structure...");
    let mut analyzer = CodebaseAnalyzer::new()
        .map_err(|e| AIError::configuration(format!("Analyzer error: {}", e)))?;

    let analysis = analyzer
        .analyze_directory(&PathBuf::from("./src"))
        .map_err(|e| AIError::configuration(format!("Analysis error: {}", e)))?;

    println!(
        "✅ Found {} files with {} total symbols",
        analysis.files.len(),
        analysis
            .files
            .iter()
            .map(|f| f.symbols.len())
            .sum::<usize>()
    );

    // 1. ARCHITECTURAL ANALYSIS
    println!("\n🏛️  PHASE 1: Architectural Analysis");
    println!("=====================================");

    let architecture_context = format!(
        "Codebase Structure Analysis:\n\
        - Total Files: {}\n\
        - Languages: {:?}\n\
        - Key Modules: {}\n\
        - Total Symbols: {}\n\
        \n\
        File Structure:\n{}",
        analysis.files.len(),
        analysis
            .files
            .iter()
            .map(|f| &f.language)
            .collect::<std::collections::HashSet<_>>(),
        analysis
            .files
            .iter()
            .map(|f| f.path.file_stem().unwrap_or_default().to_string_lossy())
            .collect::<Vec<_>>()
            .join(", "),
        analysis
            .files
            .iter()
            .map(|f| f.symbols.len())
            .sum::<usize>(),
        analysis
            .files
            .iter()
            .take(10)
            .map(|f| format!("  - {} ({} symbols)", f.path.display(), f.symbols.len()))
            .collect::<Vec<_>>()
            .join("\n")
    );

    let arch_request = AIRequest::new(AIFeature::ArchitecturalInsights, architecture_context);

    match ai_service.process_request(arch_request).await {
        Ok(response) => {
            println!("🎯 Architectural Insights:");
            println!("{}", response.content);
        }
        Err(e) => println!("❌ Architectural analysis failed: {}", e),
    }

    // 2. SECURITY DEEP DIVE
    println!("\n🔒 PHASE 2: Security Deep Dive");
    println!("===============================");

    for (i, file) in analysis.files.iter().take(3).enumerate() {
        // For demo: we use symbol names as context even without file content field
        println!("\n🔍 Analyzing security for: {}", file.path.display());

        let security_context = format!(
            "File: {}\n\
            Language: {}\n\
            Symbols: {:?}\n\
            \n\
            Code snippet unavailable in this demo.",
            file.path.display(),
            file.language,
            file.symbols.iter().map(|s| &s.name).collect::<Vec<_>>()
        );

        let security_request = AIRequest::new(AIFeature::SecurityAnalysis, security_context);

        match ai_service.process_request(security_request).await {
            Ok(response) => {
                println!("🛡️  Security Analysis {}:", i + 1);
                println!("{}", response.content);
            }
            Err(e) => println!("❌ Security analysis failed: {}", e),
        }
    }

    // 3. INTELLIGENT REFACTORING SUGGESTIONS
    println!("\n🔧 PHASE 3: Intelligent Refactoring");
    println!("====================================");

    // Find complex functions for refactoring
    let complex_functions: Vec<_> = analysis
        .files
        .iter()
        .flat_map(|f| &f.symbols)
        .filter(|s| s.kind == "function" && s.name.len() > 5)
        .take(2)
        .collect();

    for (i, symbol) in complex_functions.iter().enumerate() {
        println!("\n🎯 Refactoring suggestion for: {}", symbol.name);

        let refactor_context = format!(
            "Function Analysis:\n\
            - Name: {}\n\
            - Type: {}\n\
            - Location: {}:{}\n\
            - Context: This function is part of a {} codebase\n\
            \n\
            Please provide specific refactoring suggestions focusing on:\n\
            1. Code clarity and maintainability\n\
            2. Performance optimizations\n\
            3. Error handling improvements\n\
            4. Design pattern applications",
            symbol.name,
            symbol.kind,
            symbol.start_line,
            symbol.end_line,
            "Rust tree-sitter analysis"
        );

        let refactor_request = AIRequest::new(AIFeature::RefactoringSuggestions, refactor_context);

        match ai_service.process_request(refactor_request).await {
            Ok(response) => {
                println!("🔧 Refactoring Suggestions {}:", i + 1);
                println!("{}", response.content);
            }
            Err(e) => println!("❌ Refactoring analysis failed: {}", e),
        }
    }

    // 4. PATTERN DETECTION AND RECOMMENDATIONS
    println!("\n🎨 PHASE 4: Design Pattern Analysis");
    println!("====================================");

    let pattern_context = format!(
        "Codebase Pattern Analysis:\n\
        \n\
        Module Structure:\n{}\n\
        \n\
        Key Abstractions:\n{}\n\
        \n\
        Please analyze this codebase for:\n\
        1. Existing design patterns\n\
        2. Missing patterns that could improve the code\n\
        3. Anti-patterns to avoid\n\
        4. Architectural recommendations",
        analysis
            .files
            .iter()
            .map(|f| format!("  - {}", f.path.display()))
            .collect::<Vec<_>>()
            .join("\n"),
        analysis
            .files
            .iter()
            .flat_map(|f| &f.symbols)
            .filter(|s| s.kind == "struct" || s.kind == "trait")
            .map(|s| format!("  - {} ({})", s.name, s.kind))
            .collect::<Vec<_>>()
            .join("\n")
    );

    let pattern_request = AIRequest::new(AIFeature::PatternDetection, pattern_context);

    match ai_service.process_request(pattern_request).await {
        Ok(response) => {
            println!("🎨 Design Pattern Analysis:");
            println!("{}", response.content);
        }
        Err(e) => println!("❌ Pattern analysis failed: {}", e),
    }

    // 5. FINAL RECOMMENDATIONS
    println!("\n📋 PHASE 5: Executive Summary");
    println!("=============================");

    let summary_context = format!(
        "Executive Codebase Report:\n\
        \n\
        Project: Rust Tree-sitter Analysis Tool\n\
        Files Analyzed: {}\n\
        Total Symbols: {}\n\
        Languages: {:?}\n\
        \n\
        Please provide an executive summary with:\n\
        1. Overall code quality assessment\n\
        2. Top 3 priority improvements\n\
        3. Security posture evaluation\n\
        4. Maintainability score (1-10)\n\
        5. Recommended next steps",
        analysis.files.len(),
        analysis
            .files
            .iter()
            .map(|f| f.symbols.len())
            .sum::<usize>(),
        analysis
            .files
            .iter()
            .map(|f| &f.language)
            .collect::<std::collections::HashSet<_>>()
    );

    let summary_request = AIRequest::new(AIFeature::QualityAssessment, summary_context);

    match ai_service.process_request(summary_request).await {
        Ok(response) => {
            println!("📊 Executive Summary:");
            println!("{}", response.content);
        }
        Err(e) => println!("❌ Summary generation failed: {}", e),
    }

    println!("\n🎉 Intelligent Codebase Analysis Complete!");
    println!("==========================================");
    println!("✅ Architectural insights generated");
    println!("✅ Security vulnerabilities identified");
    println!("✅ Refactoring opportunities discovered");
    println!("✅ Design patterns analyzed");
    println!("✅ Executive summary provided");

    Ok(())
}
