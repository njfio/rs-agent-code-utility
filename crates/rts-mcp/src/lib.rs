//! `rts-mcp` library surface.
//!
//! Re-exports the transport modules (`socket`, `daemon_client`) so the
//! sibling `rts` human-facing CLI binary (added in the v0.5.5+ human-CLI
//! plan) can reuse the same daemon-discovery + auto-spawn + JSON-RPC
//! plumbing without duplicating ~150 LOC.
//!
//! The MCP server itself (`server.rs`, `RtsServer`) is binary-internal —
//! it depends on the rmcp macro-generated tool router and is not part of
//! the public API.

pub mod cli;
pub mod daemon_client;
pub mod socket;
pub mod telemetry;
