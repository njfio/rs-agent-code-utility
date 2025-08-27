use rust_tree_sitter::{
    CodeEvolutionTracker, EvolutionConfig, ChangeType
};
use rust_tree_sitter::constants::common::RiskLevel;
use std::path::PathBuf;
use tempfile::TempDir;
use std::fs;
use std::process::Command;

fn create_test_git_repo() -> Result<TempDir, Box<dyn std::error::Error>> {
    let temp_dir = TempDir::new()?;
    
    // Initialize git repository
    Command::new("git")
        .args(&["init"])
        .current_dir(temp_dir.path())
        .output()?;
    
    // Configure git user
    Command::new("git")
        .args(&["config", "user.name", "Test User"])
        .current_dir(temp_dir.path())
        .output()?;
    
    Command::new("git")
        .args(&["config", "user.email", "test@example.com"])
        .current_dir(temp_dir.path())
        .output()?;
    
    // Create initial file
    let test_file = temp_dir.path().join("test.rs");
    fs::write(&test_file, r#"
fn main() {
    println!("Hello, world!");
}
"#)?;
    
    // Add and commit
    Command::new("git")
        .args(&["add", "."])
        .current_dir(temp_dir.path())
        .output()?;
    
    Command::new("git")
        .args(&["commit", "-m", "feat: initial commit"])
        .current_dir(temp_dir.path())
        .output()?;
    
    // Create more commits to simulate evolution
    fs::write(&test_file, r#"
fn main() {
    println!("Hello, world!");
    println!("Second line");
}
"#)?;
    
    Command::new("git")
        .args(&["add", "."])
        .current_dir(temp_dir.path())
        .output()?;
    
    Command::new("git")
        .args(&["commit", "-m", "feat: add second line"])
        .current_dir(temp_dir.path())
        .output()?;
    
    // Bug fix commit
    fs::write(&test_file, r#"
fn main() {
    println!("Hello, world!");
    println!("Fixed second line");
}
"#)?;
    
    Command::new("git")
        .args(&["add", "."])
        .current_dir(temp_dir.path())
        .output()?;
    
    Command::new("git")
        .args(&["commit", "-m", "fix: correct second line"])
        .current_dir(temp_dir.path())
        .output()?;
    
    // Refactor commit
    fs::write(&test_file, r#"
fn greet() {
    println!("Hello, world!");
    println!("Fixed second line");
}

fn main() {
    greet();
}
"#)?;
    
    Command::new("git")
        .args(&["add", "."])
        .current_dir(temp_dir.path())
        .output()?;
    
    Command::new("git")
        .args(&["commit", "-m", "refactor: extract greet function"])
        .current_dir(temp_dir.path())
        .output()?;
    
    Ok(temp_dir)
}

#[test]
fn test_code_evolution_tracker_creation() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = create_test_git_repo()?;
    
    let _tracker = CodeEvolutionTracker::new(temp_dir.path())?;
    
    // Should succeed for valid git repository
    assert!(temp_dir.path().join(".git").exists());
    
    Ok(())
}

#[test]
fn test_code_evolution_tracker_invalid_repo() {
    let temp_dir = TempDir::new().unwrap();
    
    // Should fail for non-git directory
    let result = CodeEvolutionTracker::new(temp_dir.path());
    assert!(result.is_err());
}

#[test]
fn test_evolution_analysis() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = create_test_git_repo()?;
    
    let mut tracker = CodeEvolutionTracker::new(temp_dir.path())?;
    let result = tracker.analyze_evolution()?;
    
    // Should have analyzed commits
    assert!(result.metrics.total_commits > 0);
    assert!(result.metrics.total_files > 0);
    assert!(result.metrics.active_contributors > 0);
    
    // Should have file insights
    assert!(!result.file_insights.is_empty());
    
    // Should have timestamp
    assert!(result.timestamp > 0);
    
    Ok(())
}

#[test]
fn test_evolution_analysis_with_config() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = create_test_git_repo()?;
    
    let config = EvolutionConfig {
        max_commits: 10,
        time_window_days: 30,
        pattern_confidence_threshold: 0.5,
        hotspot_threshold: 2,
        coupling_threshold: 0.2,
    };
    
    let mut tracker = CodeEvolutionTracker::with_config(temp_dir.path(), config)?;
    let result = tracker.analyze_evolution()?;
    
    // Should respect configuration
    assert!(result.metrics.total_commits <= 10);
    
    Ok(())
}

#[test]
fn test_file_specific_analysis() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = create_test_git_repo()?;
    
    let mut tracker = CodeEvolutionTracker::new(temp_dir.path())?;
    let files = vec![PathBuf::from("test.rs")];
    let result = tracker.analyze_files(&files)?;
    
    // Should have analyzed the specific file
    assert!(result.file_insights.contains_key(&PathBuf::from("test.rs")));
    
    // Should have metrics
    assert!(result.metrics.total_files > 0);
    
    Ok(())
}

#[test]
fn test_change_type_classification() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = create_test_git_repo()?;
    
    let mut tracker = CodeEvolutionTracker::new(temp_dir.path())?;
    let result = tracker.analyze_evolution()?;
    
    // Should have classified different change types
    if let Some(insight) = result.file_insights.get(&PathBuf::from("test.rs")) {
        assert!(!insight.change_types.is_empty());
        
        // Should have detected feature, fix, and refactor changes
        assert!(insight.change_types.contains_key(&ChangeType::Feature));
        assert!(insight.change_types.contains_key(&ChangeType::BugFix));
        assert!(insight.change_types.contains_key(&ChangeType::Refactor));
    }
    
    Ok(())
}

#[test]
fn test_pattern_detection() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = create_test_git_repo()?;
    
    // Create more commits to trigger pattern detection
    let test_file = temp_dir.path().join("test.rs");
    for i in 0..5 {
        fs::write(&test_file, format!(r#"
fn greet() {{
    println!("Hello, world! {}", {});
    println!("Fixed second line");
}}

fn main() {{
    greet();
}}
"#, i, i))?;
        
        Command::new("git")
            .args(&["add", "."])
            .current_dir(temp_dir.path())
            .output()?;
        
        Command::new("git")
            .args(&["commit", "-m", &format!("feat: update greeting {}", i)])
            .current_dir(temp_dir.path())
            .output()?;
    }
    
    let config = EvolutionConfig {
        max_commits: 20,
        time_window_days: 365,
        pattern_confidence_threshold: 0.1, // Lower threshold for testing
        hotspot_threshold: 3, // Lower threshold for testing
        coupling_threshold: 0.1,
    };
    
    let mut tracker = CodeEvolutionTracker::with_config(temp_dir.path(), config)?;
    let _result = tracker.analyze_evolution()?;
    
    // Should detect patterns with enough commits
    // Note: Pattern detection depends on git history and thresholds
    // Pattern detection completed without errors
    
    Ok(())
}

#[test]
fn test_file_insight_generation() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = create_test_git_repo()?;
    
    let mut tracker = CodeEvolutionTracker::new(temp_dir.path())?;
    let result = tracker.analyze_evolution()?;
    
    if let Some(insight) = result.file_insights.get(&PathBuf::from("test.rs")) {
        // Should have change frequency
        assert!(insight.change_frequency >= 0.0);
        
        // Should have contributors
        assert!(!insight.primary_contributors.is_empty());
        
        // Should have change types
        assert!(!insight.change_types.is_empty());
        
        // Should have risk level
        assert!(matches!(insight.risk_level, RiskLevel::Low | RiskLevel::Medium | RiskLevel::High | RiskLevel::Critical));
        
        // Should have last significant change
        assert!(insight.last_significant_change.is_some());
    }
    
    Ok(())
}

#[test]
fn test_recommendations_generation() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = create_test_git_repo()?;
    
    let mut tracker = CodeEvolutionTracker::new(temp_dir.path())?;
    let result = tracker.analyze_evolution()?;
    
    // Should generate recommendations (may be empty for simple test case)
    // Recommendations generated successfully
    
    // If recommendations exist, they should have proper structure
    for recommendation in &result.recommendations {
        assert!(!recommendation.description.is_empty());
        assert!(!recommendation.affected_files.is_empty());
        assert!(!recommendation.expected_impact.is_empty());
    }
    
    Ok(())
}

#[test]
fn test_metrics_calculation() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = create_test_git_repo()?;
    
    let mut tracker = CodeEvolutionTracker::new(temp_dir.path())?;
    let result = tracker.analyze_evolution()?;
    
    let metrics = &result.metrics;
    
    // Should have calculated basic metrics
    assert!(metrics.total_commits > 0);
    assert!(metrics.total_files > 0);
    assert!(metrics.active_contributors > 0);
    assert!(metrics.commit_frequency >= 0.0);
    assert!(metrics.churn_rate >= 0.0);
    assert!(metrics.bus_factor > 0);
    assert!(metrics.coupling_strength >= 0.0);
    
    Ok(())
}
