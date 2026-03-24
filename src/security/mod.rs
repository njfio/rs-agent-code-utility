//! Real security analysis implementation
//!
//! This module provides production-grade security analysis with real
//! vulnerability database integration, secrets detection, and OWASP compliance.

#[cfg(feature = "net")]
pub mod ai_false_positive_filter;
pub mod ast_analyzer;
pub mod deterministic_filter;
pub mod heuristic_filter;
pub mod owasp_detector;
pub mod pipeline;
pub mod rust_analyzer;
#[cfg(any(feature = "net", feature = "db"))]
pub mod vulnerability_correlation;

pub mod accuracy_metrics;
pub mod dashboard;
#[cfg(any(feature = "net", feature = "db"))]
pub mod secrets_detector;
#[cfg(any(feature = "net", feature = "db"))]
pub mod vulnerability_db;

#[cfg(feature = "net")]
pub use ai_false_positive_filter::*;
pub use ast_analyzer::{
    AstSecurityAnalyzer, LanguageSpecificAnalyzer, SecurityFinding, SecurityFindingType,
    SecuritySeverity,
};
pub use deterministic_filter::*;
pub use heuristic_filter::*;
pub use owasp_detector::*;
pub use pipeline::{ConfidenceSource, ScoredFinding, SecurityPipeline, SecurityPipelineConfig};
pub use rust_analyzer::RustAnalyzer;
#[cfg(any(feature = "net", feature = "db"))]
pub use vulnerability_correlation::*;

#[cfg(any(feature = "net", feature = "db"))]
pub use secrets_detector::*;
#[cfg(any(feature = "net", feature = "db"))]
pub use vulnerability_db::*;
