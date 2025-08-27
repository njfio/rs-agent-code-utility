//! Code Evolution Tracking System
//! 
//! This module provides comprehensive tracking of code changes, patterns,
//! and evolution metrics for software development analysis.

use crate::Result;
use crate::constants::common::RiskLevel;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(feature = "serde")]
use serde::{Serialize, Deserialize};

/// Code evolution tracking system
#[derive(Debug, Clone)]
pub struct CodeEvolutionTracker {
    /// Repository root path
    repo_path: PathBuf,
    /// Tracked file changes
    file_changes: HashMap<PathBuf, Vec<FileChange>>,
    /// Code change patterns
    patterns: Vec<ChangePattern>,
    /// Evolution metrics
    metrics: EvolutionMetrics,
    /// Configuration
    config: EvolutionConfig,
}

/// A single file change record
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct FileChange {
    /// Commit hash
    pub commit_hash: String,
    /// Author information
    pub author: String,
    /// Timestamp of change
    pub timestamp: u64,
    /// Change type
    pub change_type: ChangeType,
    /// Lines added
    pub lines_added: usize,
    /// Lines removed
    pub lines_removed: usize,
    /// Commit message
    pub message: String,
    /// Files modified in same commit
    pub related_files: Vec<PathBuf>,
}

/// Type of code change
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum ChangeType {
    /// New feature addition
    Feature,
    /// Bug fix
    BugFix,
    /// Refactoring
    Refactor,
    /// Documentation update
    Documentation,
    /// Test addition/modification
    Test,
    /// Configuration change
    Config,
    /// Performance improvement
    Performance,
    /// Security fix
    Security,
    /// Other/unknown
    Other,
}

/// Detected change pattern
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ChangePattern {
    /// Pattern type
    pub pattern_type: PatternType,
    /// Pattern description
    pub description: String,
    /// Confidence score (0.0 to 1.0)
    pub confidence: f64,
    /// Files involved
    pub files: Vec<PathBuf>,
    /// Time period
    pub time_range: (u64, u64),
    /// Frequency of occurrence
    pub frequency: usize,
}

/// Types of evolution patterns
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum PatternType {
    /// Files frequently changed together
    CoupledChanges,
    /// Code churn hotspots
    Hotspot,
    /// Knowledge concentration (single author)
    KnowledgeSilo,
    /// Architectural boundary violations
    BoundaryViolation,
    /// Technical debt accumulation
    TechnicalDebt,
    /// Refactoring opportunity
    RefactoringOpportunity,
    /// Test coverage gap
    TestGap,
    /// Performance degradation
    PerformanceDrift,
}

/// Evolution metrics and statistics
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct EvolutionMetrics {
    /// Total commits analyzed
    pub total_commits: usize,
    /// Total files tracked
    pub total_files: usize,
    /// Active contributors
    pub active_contributors: usize,
    /// Average commit frequency (commits per day)
    pub commit_frequency: f64,
    /// Code churn rate (lines changed per commit)
    pub churn_rate: f64,
    /// Bus factor (minimum contributors for 50% of code)
    pub bus_factor: usize,
    /// Change coupling strength
    pub coupling_strength: f64,
    /// Technical debt trend
    pub debt_trend: TrendDirection,
    /// Test coverage trend
    pub coverage_trend: TrendDirection,
}

/// Trend direction indicator
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum TrendDirection {
    Improving,
    Stable,
    Degrading,
    Unknown,
}

/// Configuration for evolution tracking
#[derive(Debug, Clone)]
pub struct EvolutionConfig {
    /// Maximum number of commits to analyze
    pub max_commits: usize,
    /// Time window for analysis (days)
    pub time_window_days: usize,
    /// Minimum confidence threshold for patterns
    pub pattern_confidence_threshold: f64,
    /// Hotspot threshold (minimum changes to be considered hotspot)
    pub hotspot_threshold: usize,
    /// Coupling threshold (minimum co-change frequency)
    pub coupling_threshold: f64,
}

impl Default for EvolutionConfig {
    fn default() -> Self {
        Self {
            max_commits: 1000,
            time_window_days: 90,
            pattern_confidence_threshold: crate::constants::code_evolution::DEFAULT_PATTERN_CONFIDENCE_THRESHOLD,
            hotspot_threshold: 10,
            coupling_threshold: 0.3,
        }
    }
}

/// Result of evolution analysis
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct EvolutionAnalysisResult {
    /// Evolution metrics
    pub metrics: EvolutionMetrics,
    /// Detected patterns
    pub patterns: Vec<ChangePattern>,
    /// File-level insights
    pub file_insights: HashMap<PathBuf, FileInsight>,
    /// Recommendations
    pub recommendations: Vec<EvolutionRecommendation>,
    /// Analysis timestamp
    pub timestamp: u64,
}

/// Insights for a specific file
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct FileInsight {
    /// Change frequency
    pub change_frequency: f64,
    /// Primary contributors
    pub primary_contributors: Vec<String>,
    /// Change types distribution
    pub change_types: HashMap<ChangeType, usize>,
    /// Coupling with other files
    pub coupled_files: Vec<(PathBuf, f64)>,
    /// Risk assessment
    pub risk_level: RiskLevel,
    /// Last significant change
    pub last_significant_change: Option<FileChange>,
}

// RiskLevel is now imported from crate::constants::common

/// Evolution-based recommendation
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct EvolutionRecommendation {
    /// Recommendation type
    pub recommendation_type: RecommendationType,
    /// Description
    pub description: String,
    /// Priority level
    pub priority: Priority,
    /// Affected files
    pub affected_files: Vec<PathBuf>,
    /// Estimated effort
    pub effort_estimate: EffortLevel,
    /// Expected impact
    pub expected_impact: String,
}

/// Types of recommendations
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum RecommendationType {
    Refactor,
    AddTests,
    ReduceCoupling,
    DocumentCode,
    PerformanceOptimization,
    SecurityReview,
    ArchitecturalReview,
    KnowledgeSharing,
}

// Use common Priority from constants module
pub use crate::constants::common::Priority;

// Use common EffortLevel from constants module
pub use crate::constants::common::EffortLevel;

impl CodeEvolutionTracker {
    /// Create a new code evolution tracker
    pub fn new<P: AsRef<Path>>(repo_path: P) -> Result<Self> {
        let repo_path = repo_path.as_ref().to_path_buf();
        
        // Verify this is a git repository
        if !repo_path.join(".git").exists() {
            return Err(crate::Error::invalid_input_error(
                "path",
                "git repository",
                "non-git directory"
            ));
        }

        Ok(Self {
            repo_path,
            file_changes: HashMap::new(),
            patterns: Vec::new(),
            metrics: EvolutionMetrics::default(),
            config: EvolutionConfig::default(),
        })
    }

    /// Create tracker with custom configuration
    pub fn with_config<P: AsRef<Path>>(repo_path: P, config: EvolutionConfig) -> Result<Self> {
        let mut tracker = Self::new(repo_path)?;
        tracker.config = config;
        Ok(tracker)
    }

    /// Helper function to create file change without excessive cloning
    fn create_file_change(
        commit_hash: &str,
        author: &str,
        timestamp: u64,
        message: &str,
        change_type: ChangeType,
        lines_added: usize,
        lines_removed: usize,
        related_files: &[PathBuf],
    ) -> FileChange {
        FileChange {
            commit_hash: commit_hash.to_string(),
            author: author.to_string(),
            timestamp,
            change_type,
            lines_added,
            lines_removed,
            message: message.to_string(),
            related_files: related_files.to_vec(),
        }
    }

    /// Analyze code evolution from git history
    pub fn analyze_evolution(&mut self) -> Result<EvolutionAnalysisResult> {
        // Extract git history
        self.extract_git_history()?;
        
        // Detect patterns
        self.detect_patterns()?;
        
        // Calculate metrics
        self.calculate_metrics()?;
        
        // Generate insights
        let file_insights = self.generate_file_insights()?;
        
        // Generate recommendations
        let recommendations = self.generate_recommendations(&file_insights)?;

        Ok(EvolutionAnalysisResult {
            metrics: self.metrics.clone(),
            patterns: self.patterns.clone(),
            file_insights,
            recommendations,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        })
    }

    /// Analyze evolution for specific files
    pub fn analyze_files(&mut self, files: &[PathBuf]) -> Result<EvolutionAnalysisResult> {
        // Extract history for specific files
        self.extract_file_history(files)?;

        // Detect patterns for these files
        self.detect_file_patterns(files)?;

        // Calculate metrics
        self.calculate_metrics()?;

        // Generate insights for specific files
        let file_insights = self.generate_specific_file_insights(files)?;

        // Generate targeted recommendations
        let recommendations = self.generate_targeted_recommendations(files, &file_insights)?;

        Ok(EvolutionAnalysisResult {
            metrics: self.metrics.clone(),
            patterns: self.patterns.clone(),
            file_insights,
            recommendations,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        })
    }

    // Private implementation methods

    /// Extract git history for all files
    fn extract_git_history(&mut self) -> Result<()> {
        let output = Command::new("git")
            .args(&[
                "log",
                "--pretty=format:%H|%an|%at|%s",
                "--numstat",
                &format!("--max-count={}", self.config.max_commits),
                &format!("--since={} days ago", self.config.time_window_days),
            ])
            .current_dir(&self.repo_path)
            .output()
            .map_err(|e| crate::Error::internal_error("git", format!("Failed to run git log: {}", e)))?;

        if !output.status.success() {
            return Err(crate::Error::internal_error(
                "git",
                "Git log command failed"
            ));
        }

        let log_output = String::from_utf8_lossy(&output.stdout);
        self.parse_git_log(&log_output)?;

        Ok(())
    }

    /// Extract git history for specific files
    fn extract_file_history(&mut self, files: &[PathBuf]) -> Result<()> {
        for file in files {
            let output = Command::new("git")
                .args(&[
                    "log",
                    "--pretty=format:%H|%an|%at|%s",
                    "--numstat",
                    &format!("--max-count={}", self.config.max_commits),
                    &format!("--since={} days ago", self.config.time_window_days),
                    "--",
                    &file.to_string_lossy(),
                ])
                .current_dir(&self.repo_path)
                .output()
                .map_err(|e| crate::Error::internal_error("git", format!("Failed to run git log: {}", e)))?;

            if output.status.success() {
                let log_output = String::from_utf8_lossy(&output.stdout);
                self.parse_git_log(&log_output)?;
            }
        }

        Ok(())
    }

    /// Parse git log output
    fn parse_git_log(&mut self, log_output: &str) -> Result<()> {
        let lines: Vec<&str> = log_output.lines().collect();
        let mut i = 0;

        while i < lines.len() {
            if let Some(commit_info) = self.parse_commit_line(lines[i]) {
                let mut related_files = Vec::new();
                i += 1;

                // Parse numstat lines
                while i < lines.len() && !lines[i].contains('|') {
                    if let Some((file_path, added, removed)) = self.parse_numstat_line(lines[i]) {
                        let change = Self::create_file_change(
                            &commit_info.0,
                            &commit_info.1,
                            commit_info.2,
                            &commit_info.3,
                            self.classify_change_type(&commit_info.3),
                            added,
                            removed,
                            &related_files,
                        );

                        self.file_changes
                            .entry(file_path.clone())
                            .or_insert_with(Vec::new)
                            .push(change);

                        related_files.push(file_path);
                    }
                    i += 1;
                }

                // Update related files for all changes in this commit
                for file_path in &related_files {
                    if let Some(changes) = self.file_changes.get_mut(file_path) {
                        if let Some(last_change) = changes.last_mut() {
                            if last_change.commit_hash == commit_info.0 {
                                last_change.related_files = related_files.clone();
                            }
                        }
                    }
                }
            } else {
                i += 1;
            }
        }

        Ok(())
    }

    /// Parse a commit line
    fn parse_commit_line(&self, line: &str) -> Option<(String, String, u64, String)> {
        let parts: Vec<&str> = line.split('|').collect();
        if parts.len() >= 4 {
            let hash = parts[0].to_string();
            let author = parts[1].to_string();
            let timestamp = parts[2].parse().unwrap_or(0);
            let message = parts[3..].join("|");
            Some((hash, author, timestamp, message))
        } else {
            None
        }
    }

    /// Parse a numstat line
    fn parse_numstat_line(&self, line: &str) -> Option<(PathBuf, usize, usize)> {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 3 {
            let added = parts[0].parse().unwrap_or(0);
            let removed = parts[1].parse().unwrap_or(0);
            let file_path = PathBuf::from(parts[2]);
            Some((file_path, added, removed))
        } else {
            None
        }
    }

    /// Classify change type based on commit message
    fn classify_change_type(&self, message: &str) -> ChangeType {
        let message_lower = message.to_lowercase();

        if message_lower.contains("fix") || message_lower.contains("bug") {
            ChangeType::BugFix
        } else if message_lower.contains("feat") || message_lower.contains("feature") {
            ChangeType::Feature
        } else if message_lower.contains("refactor") || message_lower.contains("cleanup") {
            ChangeType::Refactor
        } else if message_lower.contains("test") {
            ChangeType::Test
        } else if message_lower.contains("doc") {
            ChangeType::Documentation
        } else if message_lower.contains("perf") || message_lower.contains("performance") {
            ChangeType::Performance
        } else if message_lower.contains("security") || message_lower.contains("sec") {
            ChangeType::Security
        } else if message_lower.contains("config") || message_lower.contains("conf") {
            ChangeType::Config
        } else {
            ChangeType::Other
        }
    }

    /// Detect evolution patterns
    fn detect_patterns(&mut self) -> Result<()> {
        self.patterns.clear();

        // Detect hotspots
        self.detect_hotspots()?;

        // Detect coupled changes
        self.detect_coupled_changes()?;

        // Detect knowledge silos
        self.detect_knowledge_silos()?;

        // Detect technical debt patterns
        self.detect_technical_debt_patterns()?;

        Ok(())
    }

    /// Detect file patterns for specific files
    fn detect_file_patterns(&mut self, files: &[PathBuf]) -> Result<()> {
        // Filter patterns to only include specified files
        self.patterns.retain(|pattern| {
            pattern.files.iter().any(|f| files.contains(f))
        });

        // Detect new patterns for these files
        self.detect_hotspots_for_files(files)?;
        self.detect_coupled_changes_for_files(files)?;
        self.detect_knowledge_silos_for_files(files)?;

        Ok(())
    }

    /// Detect code hotspots (frequently changed files)
    fn detect_hotspots(&mut self) -> Result<()> {
        let mut change_counts: HashMap<PathBuf, usize> = HashMap::new();

        for (file_path, changes) in &self.file_changes {
            change_counts.insert(file_path.to_path_buf(), changes.len());
        }

        for (file_path, count) in change_counts {
            if count >= self.config.hotspot_threshold {
                let time_range = self.get_time_range_for_file(&file_path)?;
                let pattern = ChangePattern {
                    pattern_type: PatternType::Hotspot,
                    description: format!("File {} changed {} times", file_path.display(), count),
                    confidence: (count as f64 / self.config.max_commits as f64).min(1.0),
                    files: vec![file_path],
                    time_range,
                    frequency: count,
                };

                if pattern.confidence >= self.config.pattern_confidence_threshold {
                    self.patterns.push(pattern);
                }
            }
        }

        Ok(())
    }

    /// Detect hotspots for specific files
    fn detect_hotspots_for_files(&mut self, files: &[PathBuf]) -> Result<()> {
        for file_path in files {
            if let Some(changes) = self.file_changes.get(file_path) {
                let count = changes.len();
                if count >= self.config.hotspot_threshold {
                    let pattern = ChangePattern {
                        pattern_type: PatternType::Hotspot,
                        description: format!("File {} changed {} times", file_path.display(), count),
                        confidence: (count as f64 / self.config.max_commits as f64).min(1.0),
                        files: vec![file_path.clone()],
                        time_range: self.get_time_range_for_file(file_path)?,
                        frequency: count,
                    };

                    if pattern.confidence >= self.config.pattern_confidence_threshold {
                        self.patterns.push(pattern);
                    }
                }
            }
        }

        Ok(())
    }

    /// Detect coupled changes (files that change together)
    fn detect_coupled_changes(&mut self) -> Result<()> {
        let mut coupling_matrix: HashMap<(PathBuf, PathBuf), usize> = HashMap::new();
        let mut file_change_counts: HashMap<PathBuf, usize> = HashMap::new();

        // Count co-changes
        for changes in self.file_changes.values() {
            for change in changes {
                file_change_counts.insert(change.related_files[0].clone(),
                    file_change_counts.get(&change.related_files[0]).unwrap_or(&0) + 1);

                for i in 0..change.related_files.len() {
                    for j in (i + 1)..change.related_files.len() {
                        let file1 = &change.related_files[i];
                        let file2 = &change.related_files[j];
                        let key = if file1 < file2 { (file1.clone(), file2.clone()) }
                                 else { (file2.clone(), file1.clone()) };

                        *coupling_matrix.entry(key).or_insert(0) += 1;
                    }
                }
            }
        }

        // Calculate coupling strength and create patterns
        for ((file1, file2), co_changes) in coupling_matrix {
            let file1_changes = file_change_counts.get(&file1).unwrap_or(&1);
            let file2_changes = file_change_counts.get(&file2).unwrap_or(&1);
            let coupling_strength = co_changes as f64 / (*file1_changes.min(file2_changes) as f64);

            if coupling_strength >= self.config.coupling_threshold {
                let time_range = self.calculate_time_range_for_files(&[file1.clone(), file2.clone()])?;
                let pattern = ChangePattern {
                    pattern_type: PatternType::CoupledChanges,
                    description: format!("Files {} and {} frequently change together",
                                       file1.display(), file2.display()),
                    confidence: coupling_strength,
                    files: vec![file1, file2],
                    time_range,
                    frequency: co_changes,
                };

                if pattern.confidence >= self.config.pattern_confidence_threshold {
                    self.patterns.push(pattern);
                }
            }
        }

        Ok(())
    }

    /// Detect coupled changes for specific files
    fn detect_coupled_changes_for_files(&mut self, files: &[PathBuf]) -> Result<()> {
        // Similar to detect_coupled_changes but filtered to specific files
        let mut coupling_matrix: HashMap<(PathBuf, PathBuf), usize> = HashMap::new();
        let mut file_change_counts: HashMap<PathBuf, usize> = HashMap::new();

        for file_path in files {
            if let Some(changes) = self.file_changes.get(file_path) {
                for change in changes {
                    file_change_counts.insert(file_path.clone(),
                        file_change_counts.get(file_path).unwrap_or(&0) + 1);

                    for related_file in &change.related_files {
                        if files.contains(related_file) && related_file != file_path {
                            let key = if file_path < related_file {
                                (file_path.clone(), related_file.clone())
                            } else {
                                (related_file.clone(), file_path.clone())
                            };

                            *coupling_matrix.entry(key).or_insert(0) += 1;
                        }
                    }
                }
            }
        }

        // Calculate coupling strength and create patterns
        for ((file1, file2), co_changes) in coupling_matrix {
            let file1_changes = file_change_counts.get(&file1).unwrap_or(&1);
            let file2_changes = file_change_counts.get(&file2).unwrap_or(&1);
            let coupling_strength = co_changes as f64 / (*file1_changes.min(file2_changes) as f64);

            if coupling_strength >= self.config.coupling_threshold {
                let time_range = self.calculate_time_range_for_files(&[file1.clone(), file2.clone()])?;
                let pattern = ChangePattern {
                    pattern_type: PatternType::CoupledChanges,
                    description: format!("Files {} and {} frequently change together",
                                       file1.display(), file2.display()),
                    confidence: coupling_strength,
                    files: vec![file1, file2],
                    time_range,
                    frequency: co_changes,
                };

                if pattern.confidence >= self.config.pattern_confidence_threshold {
                    self.patterns.push(pattern);
                }
            }
        }

        Ok(())
    }

    /// Detect knowledge silos (files modified by single authors)
    fn detect_knowledge_silos(&mut self) -> Result<()> {
        for (file_path, changes) in &self.file_changes {
            let mut authors: HashSet<String> = HashSet::new();
            for change in changes {
                authors.insert(change.author.clone());
            }

            if authors.len() == 1 && changes.len() >= 3 {
                let pattern = ChangePattern {
                    pattern_type: PatternType::KnowledgeSilo,
                    description: format!("File {} only modified by single author", file_path.display()),
                    confidence: 0.8,
                    files: vec![file_path.clone()],
                    time_range: self.get_time_range_for_file(file_path)?,
                    frequency: changes.len(),
                };

                if pattern.confidence >= self.config.pattern_confidence_threshold {
                    self.patterns.push(pattern);
                }
            }
        }

        Ok(())
    }

    /// Detect knowledge silos for specific files
    fn detect_knowledge_silos_for_files(&mut self, files: &[PathBuf]) -> Result<()> {
        for file_path in files {
            if let Some(changes) = self.file_changes.get(file_path) {
                let mut authors: HashSet<String> = HashSet::new();
                for change in changes {
                    authors.insert(change.author.clone());
                }

                if authors.len() == 1 && changes.len() >= 3 {
                    let pattern = ChangePattern {
                        pattern_type: PatternType::KnowledgeSilo,
                        description: format!("File {} only modified by single author", file_path.display()),
                        confidence: 0.8,
                        files: vec![file_path.clone()],
                        time_range: self.get_time_range_for_file(file_path)?,
                        frequency: changes.len(),
                    };

                    if pattern.confidence >= self.config.pattern_confidence_threshold {
                        self.patterns.push(pattern);
                    }
                }
            }
        }

        Ok(())
    }

    /// Detect technical debt patterns
    fn detect_technical_debt_patterns(&mut self) -> Result<()> {
        for (file_path, changes) in &self.file_changes {
            let mut refactor_count = 0;
            let mut bug_fix_count = 0;

            for change in changes {
                match change.change_type {
                    ChangeType::Refactor => refactor_count += 1,
                    ChangeType::BugFix => bug_fix_count += 1,
                    _ => {}
                }
            }

            let total_changes = changes.len();
            if total_changes >= 5 {
                let debt_ratio = (refactor_count + bug_fix_count) as f64 / total_changes as f64;

                if debt_ratio > 0.6 {
                    let pattern = ChangePattern {
                        pattern_type: PatternType::TechnicalDebt,
                        description: format!("File {} shows high technical debt ({}% maintenance changes)",
                                           file_path.display(), (debt_ratio * 100.0) as u32),
                        confidence: debt_ratio,
                        files: vec![file_path.clone()],
                        time_range: self.get_time_range_for_file(file_path)?,
                        frequency: refactor_count + bug_fix_count,
                    };

                    if pattern.confidence >= self.config.pattern_confidence_threshold {
                        self.patterns.push(pattern);
                    }
                }
            }
        }

        Ok(())
    }

    /// Calculate evolution metrics
    fn calculate_metrics(&mut self) -> Result<()> {
        let total_commits = self.count_unique_commits();
        let total_files = self.file_changes.len();
        let active_contributors = self.count_active_contributors();
        let commit_frequency = self.calculate_commit_frequency();
        let churn_rate = self.calculate_churn_rate();
        let bus_factor = self.calculate_bus_factor();
        let coupling_strength = self.calculate_average_coupling_strength();
        let debt_trend = self.calculate_debt_trend();
        let coverage_trend = self.calculate_coverage_trend();

        self.metrics = EvolutionMetrics {
            total_commits,
            total_files,
            active_contributors,
            commit_frequency,
            churn_rate,
            bus_factor,
            coupling_strength,
            debt_trend,
            coverage_trend,
        };

        Ok(())
    }

    /// Generate file insights
    fn generate_file_insights(&self) -> Result<HashMap<PathBuf, FileInsight>> {
        let mut insights = HashMap::new();

        for (file_path, changes) in &self.file_changes {
            let insight = self.generate_file_insight(file_path, changes)?;
            insights.insert(file_path.clone(), insight);
        }

        Ok(insights)
    }

    /// Generate insights for specific files
    fn generate_specific_file_insights(&self, files: &[PathBuf]) -> Result<HashMap<PathBuf, FileInsight>> {
        let mut insights = HashMap::new();

        for file_path in files {
            if let Some(changes) = self.file_changes.get(file_path) {
                let insight = self.generate_file_insight(file_path, changes)?;
                insights.insert(file_path.clone(), insight);
            }
        }

        Ok(insights)
    }

    /// Generate insight for a single file
    fn generate_file_insight(&self, file_path: &PathBuf, changes: &[FileChange]) -> Result<FileInsight> {
        let change_frequency = changes.len() as f64 / self.config.time_window_days as f64;

        let mut contributors: HashMap<String, usize> = HashMap::new();
        let mut change_types: HashMap<ChangeType, usize> = HashMap::new();

        for change in changes {
            *contributors.entry(change.author.clone()).or_insert(0) += 1;
            *change_types.entry(change.change_type.clone()).or_insert(0) += 1;
        }

        let primary_contributors: Vec<String> = contributors
            .into_iter()
            .filter(|(_, count)| *count >= 2)
            .map(|(author, _)| author)
            .collect();

        let coupled_files = self.find_coupled_files(file_path);
        let risk_level = self.assess_risk_level(changes, &coupled_files);
        let last_significant_change = changes.last().cloned();

        Ok(FileInsight {
            change_frequency,
            primary_contributors,
            change_types,
            coupled_files,
            risk_level,
            last_significant_change,
        })
    }

    /// Generate recommendations
    fn generate_recommendations(&self, _file_insights: &HashMap<PathBuf, FileInsight>) -> Result<Vec<EvolutionRecommendation>> {
        let mut recommendations = Vec::new();

        // Generate recommendations based on patterns and insights
        for pattern in &self.patterns {
            match pattern.pattern_type {
                PatternType::Hotspot => {
                    recommendations.push(EvolutionRecommendation {
                        recommendation_type: RecommendationType::Refactor,
                        description: format!("Consider refactoring hotspot files to reduce change frequency"),
                        priority: Priority::High,
                        affected_files: pattern.files.clone(),
                        effort_estimate: EffortLevel::Hard,
                        expected_impact: "Reduced maintenance burden and improved code stability".to_string(),
                    });
                }
                PatternType::KnowledgeSilo => {
                    recommendations.push(EvolutionRecommendation {
                        recommendation_type: RecommendationType::KnowledgeSharing,
                        description: format!("Share knowledge about files with single contributors"),
                        priority: Priority::Medium,
                        affected_files: pattern.files.clone(),
                        effort_estimate: EffortLevel::Medium,
                        expected_impact: "Reduced bus factor risk and improved team collaboration".to_string(),
                    });
                }
                PatternType::TechnicalDebt => {
                    recommendations.push(EvolutionRecommendation {
                        recommendation_type: RecommendationType::Refactor,
                        description: format!("Address technical debt in frequently maintained files"),
                        priority: Priority::High,
                        affected_files: pattern.files.clone(),
                        effort_estimate: EffortLevel::VeryHard,
                        expected_impact: "Reduced bug frequency and maintenance costs".to_string(),
                    });
                }
                _ => {}
            }
        }

        Ok(recommendations)
    }

    /// Generate targeted recommendations for specific files
    fn generate_targeted_recommendations(&self, files: &[PathBuf], file_insights: &HashMap<PathBuf, FileInsight>) -> Result<Vec<EvolutionRecommendation>> {
        let mut recommendations = Vec::new();

        for file_path in files {
            if let Some(insight) = file_insights.get(file_path) {
                match insight.risk_level {
                    RiskLevel::High | RiskLevel::Critical => {
                        recommendations.push(EvolutionRecommendation {
                            recommendation_type: RecommendationType::Refactor,
                            description: format!("High-risk file {} needs attention", file_path.display()),
                            priority: Priority::High,
                            affected_files: vec![file_path.clone()],
                            effort_estimate: EffortLevel::Hard,
                            expected_impact: "Reduced risk and improved maintainability".to_string(),
                        });
                    }
                    _ => {}
                }
            }
        }

        Ok(recommendations)
    }

    // Helper methods

    fn get_time_range_for_file(&self, file_path: &PathBuf) -> Result<(u64, u64)> {
        if let Some(changes) = self.file_changes.get(file_path) {
            if !changes.is_empty() {
                let min_time = changes.iter().map(|c| c.timestamp).min().unwrap_or(0);
                let max_time = changes.iter().map(|c| c.timestamp).max().unwrap_or(0);
                return Ok((min_time, max_time));
            }
        }
        Ok((0, 0))
    }

    fn calculate_time_range_for_files(&self, files: &[PathBuf]) -> Result<(u64, u64)> {
        let mut min_time = u64::MAX;
        let mut max_time = 0u64;
        let mut found_changes = false;

        for file_path in files {
            if let Some(changes) = self.file_changes.get(file_path) {
                for change in changes {
                    found_changes = true;
                    min_time = min_time.min(change.timestamp);
                    max_time = max_time.max(change.timestamp);
                }
            }
        }

        if found_changes {
            Ok((min_time, max_time))
        } else {
            Ok((0, 0))
        }
    }

    fn count_unique_commits(&self) -> usize {
        let mut commits: HashSet<String> = HashSet::new();
        for changes in self.file_changes.values() {
            for change in changes {
                commits.insert(change.commit_hash.clone());
            }
        }
        commits.len()
    }

    fn count_active_contributors(&self) -> usize {
        let mut contributors: HashSet<String> = HashSet::new();
        for changes in self.file_changes.values() {
            for change in changes {
                contributors.insert(change.author.clone());
            }
        }
        contributors.len()
    }

    fn calculate_commit_frequency(&self) -> f64 {
        let total_commits = self.count_unique_commits();
        total_commits as f64 / self.config.time_window_days as f64
    }

    fn calculate_churn_rate(&self) -> f64 {
        let mut total_lines_changed = 0;
        let mut total_commits = 0;

        for changes in self.file_changes.values() {
            for change in changes {
                total_lines_changed += change.lines_added + change.lines_removed;
                total_commits += 1;
            }
        }

        if total_commits > 0 {
            total_lines_changed as f64 / total_commits as f64
        } else {
            0.0
        }
    }

    fn calculate_bus_factor(&self) -> usize {
        // Simplified bus factor calculation
        let contributors = self.count_active_contributors();
        (contributors / 2).max(1)
    }

    fn calculate_average_coupling_strength(&self) -> f64 {
        let coupling_patterns: Vec<_> = self.patterns.iter()
            .filter(|p| p.pattern_type == PatternType::CoupledChanges)
            .collect();

        if coupling_patterns.is_empty() {
            0.0
        } else {
            let total_confidence: f64 = coupling_patterns.iter().map(|p| p.confidence).sum();
            total_confidence / coupling_patterns.len() as f64
        }
    }

    fn calculate_debt_trend(&self) -> TrendDirection {
        // Simplified trend calculation
        let debt_patterns = self.patterns.iter()
            .filter(|p| p.pattern_type == PatternType::TechnicalDebt)
            .count();

        if debt_patterns > 3 {
            TrendDirection::Degrading
        } else if debt_patterns > 1 {
            TrendDirection::Stable
        } else {
            TrendDirection::Improving
        }
    }

    fn calculate_coverage_trend(&self) -> TrendDirection {
        // Simplified coverage trend
        let test_changes: usize = self.file_changes.values()
            .flat_map(|changes| changes.iter())
            .filter(|change| change.change_type == ChangeType::Test)
            .count();

        let total_changes: usize = self.file_changes.values()
            .map(|changes| changes.len())
            .sum();

        if total_changes > 0 {
            let test_ratio = test_changes as f64 / total_changes as f64;
            if test_ratio > 0.2 {
                TrendDirection::Improving
            } else if test_ratio > 0.1 {
                TrendDirection::Stable
            } else {
                TrendDirection::Degrading
            }
        } else {
            TrendDirection::Unknown
        }
    }

    fn find_coupled_files(&self, file_path: &PathBuf) -> Vec<(PathBuf, f64)> {
        self.patterns.iter()
            .filter(|p| p.pattern_type == PatternType::CoupledChanges && p.files.contains(file_path))
            .flat_map(|p| p.files.iter())
            .filter(|f| *f != file_path)
            .map(|f| (f.clone(), 0.5)) // Simplified coupling strength
            .collect()
    }

    fn assess_risk_level(&self, changes: &[FileChange], coupled_files: &[(PathBuf, f64)]) -> RiskLevel {
        let change_count = changes.len();
        let coupling_count = coupled_files.len();

        if change_count > 20 || coupling_count > 5 {
            RiskLevel::Critical
        } else if change_count > 10 || coupling_count > 3 {
            RiskLevel::High
        } else if change_count > 5 || coupling_count > 1 {
            RiskLevel::Medium
        } else {
            RiskLevel::Low
        }
    }
}

impl Default for EvolutionMetrics {
    fn default() -> Self {
        Self {
            total_commits: 0,
            total_files: 0,
            active_contributors: 0,
            commit_frequency: 0.0,
            churn_rate: 0.0,
            bus_factor: 1,
            coupling_strength: 0.0,
            debt_trend: TrendDirection::Unknown,
            coverage_trend: TrendDirection::Unknown,
        }
    }
}
