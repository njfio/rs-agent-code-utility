use rust_tree_sitter::{AnalysisConfig, AnalysisDepth, CodebaseAnalyzer, PerformanceAnalyzer};
use serde::Serialize;
use std::env;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

const MIN_TOTAL_FILES: usize = 25;
const MIN_TOTAL_SYMBOLS: usize = 100;
const MIN_SECURITY_FINDINGS: usize = 1;
const MIN_PERFORMANCE_HOTSPOTS: usize = 1;

#[derive(Debug, Serialize)]
struct DogfoodSummary {
    schema_version: &'static str,
    analyzed_root: String,
    total_files: usize,
    parsed_files: usize,
    total_symbols: usize,
    total_security_findings: usize,
    security_findings_with_confidence: usize,
    total_performance_hotspots: usize,
    performance_score: u8,
    sample_hotspots: Vec<HotspotSummary>,
}

#[derive(Debug, Serialize)]
struct HotspotSummary {
    title: String,
    category: String,
    severity: String,
    file: String,
    start_line: usize,
}

#[test]
fn self_analysis_produces_non_empty_results() -> Result<(), Box<dyn Error>> {
    let analysis_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut analyzer = CodebaseAnalyzer::with_config(AnalysisConfig {
        depth: AnalysisDepth::Full,
        enable_security: true,
        ..AnalysisConfig::default()
    })?;

    let analysis = analyzer.analyze_directory(&analysis_root)?;
    let performance = PerformanceAnalyzer::new().analyze(&analysis)?;

    let total_symbols = analysis
        .files
        .iter()
        .map(|file| file.symbols.len())
        .sum::<usize>();
    let total_security_findings = analysis
        .files
        .iter()
        .map(|file| file.security_vulnerabilities.len())
        .sum::<usize>();
    let security_findings_with_confidence = analysis
        .files
        .iter()
        .flat_map(|file| &file.security_vulnerabilities)
        .count();

    let summary = DogfoodSummary {
        schema_version: env!("CARGO_PKG_VERSION"),
        analyzed_root: analysis_root.display().to_string(),
        total_files: analysis.total_files,
        parsed_files: analysis.parsed_files,
        total_symbols,
        total_security_findings,
        security_findings_with_confidence,
        total_performance_hotspots: performance.total_hotspots,
        performance_score: performance.performance_score,
        sample_hotspots: performance
            .hotspots
            .iter()
            .take(5)
            .map(|hotspot| HotspotSummary {
                title: hotspot.title.clone(),
                category: format!("{:?}", hotspot.category),
                severity: format!("{:?}", hotspot.severity),
                file: hotspot.location.file.clone(),
                start_line: hotspot.location.start_line,
            })
            .collect(),
    };

    write_summary(&summary)?;

    assert!(
        summary.total_files >= MIN_TOTAL_FILES,
        "expected at least {MIN_TOTAL_FILES} files, found {}",
        summary.total_files
    );
    assert!(
        summary.total_symbols >= MIN_TOTAL_SYMBOLS,
        "expected at least {MIN_TOTAL_SYMBOLS} symbols, found {}",
        summary.total_symbols
    );
    assert!(
        summary.total_security_findings >= MIN_SECURITY_FINDINGS,
        "expected at least {MIN_SECURITY_FINDINGS} security finding, found {}",
        summary.total_security_findings
    );
    assert_eq!(
        summary.security_findings_with_confidence, summary.total_security_findings,
        "expected every security finding to include confidence metadata"
    );
    assert!(
        summary.total_performance_hotspots >= MIN_PERFORMANCE_HOTSPOTS,
        "expected at least {MIN_PERFORMANCE_HOTSPOTS} performance hotspot, found {}",
        summary.total_performance_hotspots
    );

    Ok(())
}

fn write_summary(summary: &DogfoodSummary) -> Result<(), Box<dyn Error>> {
    let output_path = dogfood_output_path();
    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent)?;
    }

    fs::write(output_path, serde_json::to_string_pretty(summary)?)?;
    Ok(())
}

fn dogfood_output_path() -> PathBuf {
    if let Ok(path) = env::var("DOGFOOD_OUTPUT") {
        return PathBuf::from(path);
    }

    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join("dogfood")
        .join("self-analysis.json")
}
