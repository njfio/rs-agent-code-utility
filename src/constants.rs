//! Constants used throughout the rust-treesitter library
//!
//! This module contains all magic numbers and configuration constants
//! used across the codebase, providing clear documentation for their purpose.

use serde::{Serialize, Deserialize};

/// Common enums used across modules for consistency
pub mod common {
    use super::*;

    /// Standard priority levels used across all modules
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
    pub enum Priority {
        Low,
        Medium,
        High,
        Critical,
    }

    /// Standard severity levels used across all modules
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
    pub enum Severity {
        Info,
        Low,
        Medium,
        High,
        Critical,
    }

    /// Standard effort levels for implementation estimation
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
    pub enum EffortLevel {
        Trivial,    // < 30 minutes
        Easy,       // < 2 hours
        Medium,     // < 1 day
        Hard,       // < 1 week
        VeryHard,   // > 1 week
    }

    /// Standard risk levels for assessment
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
    pub enum RiskLevel {
        Low,
        Medium,
        High,
        Critical,
    }

    impl std::fmt::Display for Priority {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                Priority::Low => write!(f, "Low"),
                Priority::Medium => write!(f, "Medium"),
                Priority::High => write!(f, "High"),
                Priority::Critical => write!(f, "Critical"),
            }
        }
    }

    impl std::fmt::Display for Severity {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                Severity::Info => write!(f, "Info"),
                Severity::Low => write!(f, "Low"),
                Severity::Medium => write!(f, "Medium"),
                Severity::High => write!(f, "High"),
                Severity::Critical => write!(f, "Critical"),
            }
        }
    }

    impl std::fmt::Display for EffortLevel {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                EffortLevel::Trivial => write!(f, "Trivial"),
                EffortLevel::Easy => write!(f, "Easy"),
                EffortLevel::Medium => write!(f, "Medium"),
                EffortLevel::Hard => write!(f, "Hard"),
                EffortLevel::VeryHard => write!(f, "Very Hard"),
            }
        }
    }

    impl std::fmt::Display for RiskLevel {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                RiskLevel::Low => write!(f, "Low"),
                RiskLevel::Medium => write!(f, "Medium"),
                RiskLevel::High => write!(f, "High"),
                RiskLevel::Critical => write!(f, "Critical"),
            }
        }
    }
}

/// Security analysis constants
pub mod security {
    /// Default minimum confidence threshold for security findings (0.0-1.0)
    pub const DEFAULT_MIN_CONFIDENCE: f64 = 0.7;
    
    /// Maximum security score (0-100)
    pub const MAX_SECURITY_SCORE: u8 = 100;
    
    /// Perfect security score when no issues found
    pub const PERFECT_SECURITY_SCORE: u8 = 100;
    
    /// Base security score before deductions
    pub const BASE_SECURITY_SCORE: u8 = 100;
    
    /// Divisor for coverage percentage calculation
    pub const COVERAGE_CALCULATION_DIVISOR: f64 = 10.0;
    
    /// High secrets compliance score threshold
    pub const HIGH_SECRETS_COMPLIANCE: u8 = 100;
    
    /// Medium secrets compliance score
    pub const MEDIUM_SECRETS_COMPLIANCE: u8 = 80;
    
    /// Effort estimation for different severity levels
    pub const HIGH_SEVERITY_EFFORT: f64 = 3.0;
    pub const MEDIUM_SEVERITY_EFFORT: f64 = 1.5;
    pub const LOW_SEVERITY_EFFORT: f64 = 0.5;

    /// Entropy-based secret detection confidence multiplier
    pub const ENTROPY_CONFIDENCE_MULTIPLIER: f64 = 0.7;
}

/// Intent mapping and traceability constants
pub mod intent_mapping {
    /// Default confidence threshold for automatic mapping (0.0-1.0)
    pub const DEFAULT_CONFIDENCE_THRESHOLD: f64 = 0.7;
    
    /// Maximum mapping distance threshold (0.0-1.0)
    pub const DEFAULT_MAX_MAPPING_DISTANCE: f64 = 0.8;
    
    /// Auto-validation threshold for high-confidence mappings (0.0-1.0)
    pub const DEFAULT_AUTO_VALIDATION_THRESHOLD: f64 = 0.9;
    
    /// Default values for initialization
    pub const DEFAULT_COVERAGE: f64 = 0.0;
    pub const DEFAULT_COMPLEXITY: f64 = 1.0;
    pub const DEFAULT_MAINTAINABILITY: f64 = 0.8;
    pub const DEFAULT_PERFORMANCE: f64 = 0.8;
    pub const DEFAULT_SECURITY: f64 = 0.8;
    
    /// Validation scoring weights
    pub const VALIDATION_CONFIDENCE_WEIGHT: f64 = 0.4;
    pub const VALIDATION_REQUIREMENT_WEIGHT: f64 = 0.2;
    pub const VALIDATION_IMPLEMENTATION_WEIGHT: f64 = 0.2;
    pub const VALIDATION_QUALITY_WEIGHT: f64 = 0.2;
    
    /// Validation thresholds
    pub const VALIDATION_VALID_THRESHOLD: f64 = 0.8;
    pub const VALIDATION_REVIEW_THRESHOLD: f64 = 0.5;
    pub const QUALITY_COVERAGE_THRESHOLD: f64 = 0.7;
    pub const COVERAGE_THRESHOLD: f64 = 0.8;
    
    /// Pattern matching weights
    pub const USER_STORY_API_WEIGHT: f64 = 0.3;
    pub const FUNCTIONAL_FUNCTION_WEIGHT: f64 = 0.4;
    pub const TECHNICAL_MODULE_WEIGHT: f64 = 0.3;
    pub const SECURITY_WEIGHT: f64 = 0.2;
    pub const KEYWORD_SIMILARITY_WEIGHT: f64 = 0.7;
}

/// Performance analysis constants
pub mod performance {
    /// Maximum performance score (0-100)
    pub const MAX_PERFORMANCE_SCORE: u8 = 100;
    
    /// Base performance score before deductions
    pub const BASE_PERFORMANCE_SCORE: f64 = 100.0;
    
    /// Function length threshold for high severity
    pub const FUNCTION_LENGTH_HIGH_THRESHOLD: usize = 100;
    
    /// Large codebase threshold (number of files)
    pub const LARGE_CODEBASE_THRESHOLD: usize = 100;
    
    /// Lines per complexity unit for size calculation
    pub const LINES_PER_COMPLEXITY_UNIT: f64 = 100.0;
    
    /// Maximum impact scores
    pub const MAX_CPU_IMPACT: f64 = 100.0;
    pub const MAX_OVERALL_IMPACT: f64 = 100.0;
    
    /// Impact calculation multipliers
    pub const COMPLEXITY_CPU_MULTIPLIER: f64 = 5.0;
    pub const COMPLEXITY_OVERALL_MULTIPLIER: f64 = 4.0;
}

/// Test coverage constants
pub mod test_coverage {
    /// Maximum test coverage score (0-100)
    pub const MAX_COVERAGE_SCORE: f64 = 100.0;
    
    /// Perfect coverage when no functions to test
    pub const PERFECT_COVERAGE_SCORE: f64 = 100.0;
    
    /// Percentage multiplier for coverage calculations
    pub const PERCENTAGE_MULTIPLIER: f64 = 100.0;
}

/// Refactoring constants
pub mod refactoring {
    /// Large file threshold (lines of code)
    pub const LARGE_FILE_THRESHOLD: usize = 500;

    /// Base refactoring score
    pub const BASE_REFACTORING_SCORE: u8 = 100;

    /// Default minimum confidence for refactoring suggestions
    pub const DEFAULT_MIN_CONFIDENCE: f64 = 0.7;

    /// High confidence threshold for pattern recommendations
    pub const HIGH_CONFIDENCE_THRESHOLD: f64 = 0.75;
}

/// Code evolution analysis constants
pub mod code_evolution {
    /// Default pattern confidence threshold for evolution analysis
    pub const DEFAULT_PATTERN_CONFIDENCE_THRESHOLD: f64 = 0.7;
}

/// File size and processing constants
pub mod file_processing {
    /// Default maximum file size (1MB in bytes)
    pub const DEFAULT_MAX_FILE_SIZE: usize = 1024 * 1024;
    
    /// Kilobyte size
    pub const KILOBYTE: usize = 1024;
    
    /// Megabyte size
    pub const MEGABYTE: usize = 1024 * 1024;
}

/// Scoring and percentage constants
pub mod scoring {
    /// Minimum score value
    pub const MIN_SCORE: f64 = 0.0;
    
    /// Maximum score value
    pub const MAX_SCORE: f64 = 100.0;
    
    /// Perfect score
    pub const PERFECT_SCORE: f64 = 100.0;
    
    /// Percentage conversion factor
    pub const PERCENTAGE_FACTOR: f64 = 100.0;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_security_constants() {
        assert!(security::DEFAULT_MIN_CONFIDENCE > 0.0);
        assert!(security::DEFAULT_MIN_CONFIDENCE <= 1.0);
        assert_eq!(security::MAX_SECURITY_SCORE, 100);
        assert_eq!(security::PERFECT_SECURITY_SCORE, 100);
        assert_eq!(security::BASE_SECURITY_SCORE, 100);
        assert!(security::COVERAGE_CALCULATION_DIVISOR > 0.0);
        assert_eq!(security::HIGH_SECRETS_COMPLIANCE, 100);
        assert_eq!(security::MEDIUM_SECRETS_COMPLIANCE, 80);
        assert!(security::HIGH_SEVERITY_EFFORT > security::MEDIUM_SEVERITY_EFFORT);
        assert!(security::MEDIUM_SEVERITY_EFFORT > security::LOW_SEVERITY_EFFORT);
    }

    #[test]
    fn test_intent_mapping_constants() {
        assert!(intent_mapping::DEFAULT_CONFIDENCE_THRESHOLD > 0.0);
        assert!(intent_mapping::DEFAULT_CONFIDENCE_THRESHOLD <= 1.0);
        assert!(intent_mapping::DEFAULT_AUTO_VALIDATION_THRESHOLD > intent_mapping::DEFAULT_CONFIDENCE_THRESHOLD);
        assert!(intent_mapping::DEFAULT_MAX_MAPPING_DISTANCE > intent_mapping::DEFAULT_CONFIDENCE_THRESHOLD);

        // Test validation weights sum to 1.0
        let total_weight = intent_mapping::VALIDATION_CONFIDENCE_WEIGHT +
                          intent_mapping::VALIDATION_REQUIREMENT_WEIGHT +
                          intent_mapping::VALIDATION_IMPLEMENTATION_WEIGHT +
                          intent_mapping::VALIDATION_QUALITY_WEIGHT;
        assert!((total_weight - 1.0).abs() < 0.001);

        // Test thresholds are in logical order
        assert!(intent_mapping::VALIDATION_VALID_THRESHOLD > intent_mapping::VALIDATION_REVIEW_THRESHOLD);
        assert!(intent_mapping::COVERAGE_THRESHOLD > intent_mapping::QUALITY_COVERAGE_THRESHOLD);

        // Test default values are reasonable
        assert_eq!(intent_mapping::DEFAULT_COVERAGE, 0.0);
        assert_eq!(intent_mapping::DEFAULT_COMPLEXITY, 1.0);
        assert!(intent_mapping::DEFAULT_MAINTAINABILITY > 0.0);
        assert!(intent_mapping::DEFAULT_PERFORMANCE > 0.0);
        assert!(intent_mapping::DEFAULT_SECURITY > 0.0);
    }

    #[test]
    fn test_performance_constants() {
        assert_eq!(performance::MAX_PERFORMANCE_SCORE, 100);
        assert!(performance::FUNCTION_LENGTH_HIGH_THRESHOLD > 0);
        assert!(performance::LARGE_CODEBASE_THRESHOLD > 0);
        assert!(performance::LINES_PER_COMPLEXITY_UNIT > 0.0);
        assert_eq!(performance::BASE_PERFORMANCE_SCORE, 100.0);
        assert!(performance::COMPLEXITY_CPU_MULTIPLIER > 0.0);
        assert!(performance::COMPLEXITY_OVERALL_MULTIPLIER > 0.0);
        assert_eq!(performance::MAX_CPU_IMPACT, 100.0);
        assert_eq!(performance::MAX_OVERALL_IMPACT, 100.0);
    }

    #[test]
    fn test_test_coverage_constants() {
        assert_eq!(test_coverage::MAX_COVERAGE_SCORE, 100.0);
        assert_eq!(test_coverage::PERFECT_COVERAGE_SCORE, 100.0);
        assert_eq!(test_coverage::PERCENTAGE_MULTIPLIER, 100.0);
    }

    #[test]
    fn test_refactoring_constants() {
        assert!(refactoring::LARGE_FILE_THRESHOLD > 0);
        assert_eq!(refactoring::BASE_REFACTORING_SCORE, 100);
    }

    #[test]
    fn test_file_processing_constants() {
        assert_eq!(file_processing::DEFAULT_MAX_FILE_SIZE, 1024 * 1024);
        assert_eq!(file_processing::MEGABYTE, 1024 * 1024);
        assert_eq!(file_processing::KILOBYTE, 1024);
        assert!(file_processing::MEGABYTE > file_processing::KILOBYTE);
    }

    #[test]
    fn test_scoring_constants() {
        assert_eq!(scoring::MIN_SCORE, 0.0);
        assert_eq!(scoring::MAX_SCORE, 100.0);
        assert_eq!(scoring::PERFECT_SCORE, 100.0);
        assert_eq!(scoring::PERCENTAGE_FACTOR, 100.0);
        assert!(scoring::MAX_SCORE > scoring::MIN_SCORE);
    }

    #[test]
    fn test_constants_consistency() {
        // Ensure security and performance max scores are consistent
        assert_eq!(security::MAX_SECURITY_SCORE as f64, performance::MAX_PERFORMANCE_SCORE as f64);
        assert_eq!(security::MAX_SECURITY_SCORE as f64, scoring::MAX_SCORE);

        // Ensure percentage factors are consistent
        assert_eq!(test_coverage::PERCENTAGE_MULTIPLIER, scoring::PERCENTAGE_FACTOR);

        // Ensure perfect scores are consistent
        assert_eq!(security::PERFECT_SECURITY_SCORE as f64, scoring::PERFECT_SCORE);
        assert_eq!(test_coverage::PERFECT_COVERAGE_SCORE, scoring::PERFECT_SCORE);
    }

    #[test]
    fn test_constants_ranges() {
        // Test that confidence thresholds are in valid range [0.0, 1.0]
        assert!(security::DEFAULT_MIN_CONFIDENCE >= 0.0 && security::DEFAULT_MIN_CONFIDENCE <= 1.0);
        assert!(intent_mapping::DEFAULT_CONFIDENCE_THRESHOLD >= 0.0 && intent_mapping::DEFAULT_CONFIDENCE_THRESHOLD <= 1.0);
        assert!(intent_mapping::DEFAULT_MAX_MAPPING_DISTANCE >= 0.0 && intent_mapping::DEFAULT_MAX_MAPPING_DISTANCE <= 1.0);
        assert!(intent_mapping::DEFAULT_AUTO_VALIDATION_THRESHOLD >= 0.0 && intent_mapping::DEFAULT_AUTO_VALIDATION_THRESHOLD <= 1.0);

        // Test that validation weights are in valid range [0.0, 1.0]
        assert!(intent_mapping::VALIDATION_CONFIDENCE_WEIGHT >= 0.0 && intent_mapping::VALIDATION_CONFIDENCE_WEIGHT <= 1.0);
        assert!(intent_mapping::VALIDATION_REQUIREMENT_WEIGHT >= 0.0 && intent_mapping::VALIDATION_REQUIREMENT_WEIGHT <= 1.0);
        assert!(intent_mapping::VALIDATION_IMPLEMENTATION_WEIGHT >= 0.0 && intent_mapping::VALIDATION_IMPLEMENTATION_WEIGHT <= 1.0);
        assert!(intent_mapping::VALIDATION_QUALITY_WEIGHT >= 0.0 && intent_mapping::VALIDATION_QUALITY_WEIGHT <= 1.0);

        // Test that pattern matching weights are reasonable
        assert!(intent_mapping::USER_STORY_API_WEIGHT >= 0.0 && intent_mapping::USER_STORY_API_WEIGHT <= 1.0);
        assert!(intent_mapping::FUNCTIONAL_FUNCTION_WEIGHT >= 0.0 && intent_mapping::FUNCTIONAL_FUNCTION_WEIGHT <= 1.0);
        assert!(intent_mapping::TECHNICAL_MODULE_WEIGHT >= 0.0 && intent_mapping::TECHNICAL_MODULE_WEIGHT <= 1.0);
        assert!(intent_mapping::SECURITY_WEIGHT >= 0.0 && intent_mapping::SECURITY_WEIGHT <= 1.0);
        assert!(intent_mapping::KEYWORD_SIMILARITY_WEIGHT >= 0.0 && intent_mapping::KEYWORD_SIMILARITY_WEIGHT <= 1.0);
    }
}
