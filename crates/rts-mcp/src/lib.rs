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
//!
//! ## Feature flags
//!
//! - `default` — none. The stable build links zero HTTP and gates no
//!   experimental surface.
//! - `telemetry` — compiles the opt-in anonymous-telemetry HTTP client
//!   (`dep:ureq`) plus the `rts telemetry flush` send path. Off by default.
//! - `experimental` — gates unstable MCP tools / `rts` CLI subcommands
//!   behind `#[cfg(feature = "experimental")]` until they're promoted to
//!   the frozen surface in a release. Off by default; empty today.

pub mod cli;
pub mod connection;
pub mod daemon_client;
pub mod socket;
pub mod telemetry;
