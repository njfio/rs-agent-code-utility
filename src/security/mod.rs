//! Real security analysis implementation
//!
//! This module provides production-grade security analysis with real
//! vulnerability database integration, secrets detection, and OWASP compliance.

pub mod ai_false_positive_filter;
pub mod ast_analyzer;
pub mod ml_filter;
pub mod owasp_detector;
pub mod rust_analyzer;
pub mod vulnerability_correlation;

pub mod accuracy_metrics;
pub mod dashboard;
#[cfg(any(feature = "net", feature = "db"))]
pub mod secrets_detector;
#[cfg(any(feature = "net", feature = "db"))]
pub mod vulnerability_db;

pub use ai_false_positive_filter::*;
pub use ast_analyzer::{
    AstSecurityAnalyzer, LanguageSpecificAnalyzer, SecurityFinding, SecurityFindingType,
    SecuritySeverity,
};
pub use ml_filter::*;
pub use owasp_detector::*;
pub use rust_analyzer::RustAnalyzer;
pub use vulnerability_correlation::*;

#[cfg(any(feature = "net", feature = "db"))]
pub use secrets_detector::*;
#[cfg(any(feature = "net", feature = "db"))]
pub use vulnerability_db::*;
