//! Real security analysis implementation
//! 
//! This module provides production-grade security analysis with real
//! vulnerability database integration, secrets detection, and OWASP compliance.

#[cfg(any(feature = "net", feature = "db"))]
pub mod vulnerability_db;
#[cfg(any(feature = "net", feature = "db"))]
pub mod secrets_detector;
pub mod owasp_detector;

#[cfg(any(feature = "net", feature = "db"))]
pub use vulnerability_db::*;
#[cfg(any(feature = "net", feature = "db"))]
pub use secrets_detector::*;
pub use owasp_detector::*;
