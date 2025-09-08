//! Real security analysis implementation
//!
//! This module provides production-grade security analysis with real
//! vulnerability database integration, secrets detection, and OWASP compliance.

pub mod owasp_detector;
#[cfg(any(feature = "net", feature = "db"))]
pub mod secrets_detector;
#[cfg(any(feature = "net", feature = "db"))]
pub mod vulnerability_db;

pub use owasp_detector::*;
#[cfg(any(feature = "net", feature = "db"))]
pub use secrets_detector::*;
#[cfg(any(feature = "net", feature = "db"))]
pub use vulnerability_db::*;
