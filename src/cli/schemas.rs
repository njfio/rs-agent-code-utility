//! CLI-exposed JSON Schemas for outputs

/// JSON Schema for `analyze` command, version 1
pub const ANALYZE_SCHEMA_V1: &str = include_str!("../../docs/schemas/analyze.v1.json");
/// JSON Schema for `symbols` command, version 1
pub const SYMBOLS_SCHEMA_V1: &str = include_str!("../../docs/schemas/symbols.v1.json");
/// JSON Schema for `security` command, version 1
pub const SECURITY_SCHEMA_V1: &str = include_str!("../../docs/schemas/security.v1.json");
