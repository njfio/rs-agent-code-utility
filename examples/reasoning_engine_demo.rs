use rust_tree_sitter::{
    AutomatedReasoningEngine, ReasoningConfig, CodebaseAnalyzer
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🧠 Automated Reasoning Engine Demo");
    println!("==================================");

    // Create a reasoning engine with custom configuration
    let config = ReasoningConfig {
        enable_deductive: true,
        enable_inductive: true,
        enable_abductive: false,
        enable_constraints: true,
        enable_theorem_proving: false,
        max_reasoning_time_ms: 10000,
        confidence_threshold: 0.7,
    };

    let mut reasoning_engine = AutomatedReasoningEngine::with_config(config);
    
    println!("✅ Created reasoning engine with configuration:");
    println!("   - Deductive reasoning: enabled");
    println!("   - Inductive reasoning: enabled");
    println!("   - Constraint solving: enabled");
    println!("   - Confidence threshold: 0.7");
    println!();

    // Analyze a sample codebase (using current directory as example)
    let mut analyzer = CodebaseAnalyzer::new()?;
    let current_dir = std::env::current_dir()?;
    
    println!("📁 Analyzing codebase at: {}", current_dir.display());
    
    // For demo purposes, let's analyze just the src directory if it exists
    let src_dir = current_dir.join("src");
    let analysis_result = if src_dir.exists() {
        analyzer.analyze_directory(&src_dir)?
    } else {
        // Fallback to current directory
        analyzer.analyze_directory(&current_dir)?
    };

    println!("📊 Analysis completed:");
    println!("   - Total files: {}", analysis_result.total_files);
    println!("   - Parsed files: {}", analysis_result.parsed_files);
    println!("   - Total lines: {}", analysis_result.total_lines);
    println!("   - Languages: {:?}", analysis_result.languages.keys().collect::<Vec<_>>());
    println!();

    // Run automated reasoning on the analysis results
    println!("🔍 Running automated reasoning...");
    let reasoning_result = reasoning_engine.analyze_code(&analysis_result)?;

    println!("✨ Reasoning completed in {} ms", reasoning_result.metrics.total_time_ms);
    println!();

    // Display reasoning results
    println!("📈 Reasoning Metrics:");
    println!("   - Facts processed: {}", reasoning_result.metrics.facts_processed);
    println!("   - Rules applied: {}", reasoning_result.metrics.rules_applied);
    println!("   - Constraints solved: {}", reasoning_result.metrics.constraints_solved);
    println!("   - Theorems attempted: {}", reasoning_result.metrics.theorems_attempted);
    println!();

    // Show extracted facts
    println!("🔬 Knowledge Base Facts (showing first 10):");
    let facts = reasoning_engine.knowledge_base().facts();
    for (i, fact) in facts.iter().take(10).enumerate() {
        println!("   {}. {} (confidence: {:.2})", 
                 i + 1, fact.predicate, fact.confidence);
    }
    if facts.len() > 10 {
        println!("   ... and {} more facts", facts.len() - 10);
    }
    println!();

    // Show derived facts
    if !reasoning_result.derived_facts.is_empty() {
        println!("🧮 Derived Facts:");
        for (i, fact) in reasoning_result.derived_facts.iter().take(5).enumerate() {
            println!("   {}. {} (confidence: {:.2})", 
                     i + 1, fact.predicate, fact.confidence);
        }
        if reasoning_result.derived_facts.len() > 5 {
            println!("   ... and {} more derived facts", reasoning_result.derived_facts.len() - 5);
        }
        println!();
    }

    // Show insights
    if !reasoning_result.insights.is_empty() {
        println!("💡 Reasoning Insights:");
        for (i, insight) in reasoning_result.insights.iter().take(3).enumerate() {
            println!("   {}. {} (confidence: {:.2})", 
                     i + 1, insight.description, insight.confidence);
            println!("      Evidence: {}", insight.evidence.join(", "));
        }
        if reasoning_result.insights.len() > 3 {
            println!("   ... and {} more insights", reasoning_result.insights.len() - 3);
        }
        println!();
    }

    // Show constraint solutions
    if !reasoning_result.constraint_solutions.is_empty() {
        println!("⚖️  Constraint Solutions:");
        for (var, value) in reasoning_result.constraint_solutions.iter().take(5) {
            println!("   {} = {:?}", var, value);
        }
        if reasoning_result.constraint_solutions.len() > 5 {
            println!("   ... and {} more solutions", reasoning_result.constraint_solutions.len() - 5);
        }
        println!();
    }

    // Show rules in knowledge base
    let rules = reasoning_engine.knowledge_base().rules();
    if !rules.is_empty() {
        println!("📋 Knowledge Base Rules:");
        for (i, rule) in rules.iter().take(3).enumerate() {
            println!("   {}. {} (type: {:?}, priority: {})", 
                     i + 1, rule.name, rule.rule_type, rule.priority);
        }
        if rules.len() > 3 {
            println!("   ... and {} more rules", rules.len() - 3);
        }
        println!();
    }

    println!("🎉 Reasoning engine demo completed successfully!");
    println!();
    println!("The automated reasoning engine has:");
    println!("✓ Extracted facts from code analysis");
    println!("✓ Applied logical rules for inference");
    println!("✓ Solved constraints where applicable");
    println!("✓ Generated insights about the codebase");
    println!();
    println!("This demonstrates the foundation for advanced AI-powered");
    println!("code analysis and automated reasoning capabilities.");

    Ok(())
}
