//! Real security analysis implementation
//!
//! This module provides production-grade security analysis with real
//! vulnerability database integration, secrets detection, and OWASP compliance.

pub mod ast_analyzer;
pub mod ml_filter;
pub mod owasp_detector;
pub mod rust_analyzer;

#[cfg(any(feature = "net", feature = "db"))]
pub mod secrets_detector;
#[cfg(any(feature = "net", feature = "db"))]
pub mod vulnerability_db;

pub use ast_analyzer::*;
pub use ml_filter::*;
pub use owasp_detector::*;
pub use rust_analyzer::*;

#[cfg(any(feature = "net", feature = "db"))]
pub use secrets_detector::*;
#[cfg(any(feature = "net", feature = "db"))]
pub use vulnerability_db::*;
