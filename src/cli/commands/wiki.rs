use std::path::PathBuf;
use crate::cli::error::{CliError, CliResult};
use crate::wiki::{WikiConfig, WikiGenerator};

pub fn execute(
    path: &PathBuf,
    output: Option<&PathBuf>,
    include_api: bool,
    include_examples: bool,
    _depth: &str,
    ai: bool,
    ai_mock: bool,
    ai_config: Option<&PathBuf>,
    enhanced_ai: bool,
    function_enhancement: bool,
    security_insights: bool,
    refactoring_hints: bool,
    diagram_annotations: bool,
) -> CliResult<()> {
    let out_dir = output.cloned().unwrap_or_else(|| PathBuf::from("./wiki_site"));

    let mut builder = WikiConfig::builder()
        .with_site_title("Project Wiki")
        .with_output_dir(&out_dir)
        .include_api_docs(include_api)
        .include_examples(include_examples)
        .with_ai_enabled(ai)
        .with_ai_mock(ai_mock)
        .with_enhanced_ai(enhanced_ai)
        .with_function_enhancement(function_enhancement)
        .with_security_insights(security_insights)
        .with_refactoring_hints(refactoring_hints);

    if let Some(cfg) = ai_config { builder = builder.with_ai_config_path(cfg); }

    let cfg = builder
        .build()
        .map_err(|e| CliError::Config(format!("config: {}", e)))?;

    let gen = WikiGenerator::new(cfg);
    let res = gen
        .generate_from_path(path)
        .map_err(|e| CliError::Analysis(format!("wiki: {}", e)))?;

    println!("Generated wiki at {} (pages: {})", out_dir.display(), res.pages);

    if enhanced_ai {
        println!("Enhanced AI features enabled:");
        if function_enhancement { println!("  ✓ Function documentation enhancement"); }
        if security_insights { println!("  ✓ Security vulnerability explanations"); }
        if refactoring_hints { println!("  ✓ Refactoring suggestions"); }
        if diagram_annotations { println!("  ✓ Diagram annotations"); }
    }

    Ok(())
}
