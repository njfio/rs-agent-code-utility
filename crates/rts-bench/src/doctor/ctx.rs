//! Doctor's runtime context. Carries everything sections need to know
//! about the user's environment (workspace path, home directory,
//! TTY/color state, daemon stats snapshot) so each section function
//! can stay a small, pure-ish read-and-emit-rows operation.

use std::io::IsTerminal;
use std::path::{Path, PathBuf};

use anyhow::Result;
use serde_json::Value as JsonValue;

use super::DoctorArgs;

/// Doctor's runtime context. Built once at `run()` entry; threaded
/// through each section. The `daemon_stats` field is populated by
/// `daemon_section::run` and read by `workspace_section::run`.
#[derive(Debug)]
#[allow(dead_code)] // color_enabled / socket_path read by future sections + U9 wiring.
pub struct Ctx {
    /// `$PWD` (or `--workspace <path>`) canonicalized when possible.
    /// `None` when neither resolves to an existing directory.
    pub workspace_path: Option<PathBuf>,
    /// User's home directory. Used by per-host detectors to look up
    /// `~/.cursor/mcp.json`, `~/.continue/config.yaml`, etc.
    pub home: Option<PathBuf>,
    /// Doctor's own binary version, from `CARGO_PKG_VERSION`.
    pub doctor_version: &'static str,
    /// Should the human renderer emit ANSI? `true` iff stdout is a TTY
    /// AND `--no-color` is unset AND `NO_COLOR` env var is unset.
    pub color_enabled: bool,
    /// Populated by `daemon_section::run`: the raw `Daemon.Stats v2`
    /// response body (or the v1 fallback shape) once the section
    /// completes a successful round-trip. `None` when the daemon was
    /// unreachable. Read by `workspace_section::run`.
    pub daemon_stats: Option<JsonValue>,
    /// Resolved per-workspace socket path, computed from
    /// `workspace_path`. Lets `daemon_section` and `workspace_section`
    /// share one path computation; the `mcp_section` and `nudge_hook`
    /// don't need it.
    pub socket_path: Option<PathBuf>,
}

impl Ctx {
    /// Build a fresh `Ctx` from clap-parsed `DoctorArgs`. Resolves
    /// the workspace path (or falls back to `$PWD`); resolves the
    /// home dir; computes color-enable state. Never fails on
    /// "workspace doesn't exist" — that's a row, not an init error.
    pub fn build(args: &DoctorArgs) -> Result<Self> {
        let workspace_arg = args.workspace.clone().or_else(|| std::env::current_dir().ok());
        let workspace_path = workspace_arg.map(|p| p.canonicalize().unwrap_or(p));

        let home = dirs::home_dir();

        // ANSI gating: respect both `--no-color` and NO_COLOR env var,
        // and require stdout to be a TTY.
        let color_enabled = !args.no_color
            && std::env::var_os("NO_COLOR").is_none()
            && std::io::stdout().is_terminal();

        // Socket path follows the rts-daemon convention:
        // `<state_dir>/rts/ws-<16hex>.sock` keyed off the workspace
        // fingerprint. We can compute the fingerprint client-side
        // because it's blake3(dev_id || inode || canonical_path) per
        // protocol-v0 §5.2. For doctor v1 we punt on this — the
        // daemon_section can probe known socket locations directly
        // since the daemon writes a `default.sock` fallback too.
        let socket_path = None;

        Ok(Self {
            workspace_path,
            home,
            doctor_version: env!("CARGO_PKG_VERSION"),
            color_enabled,
            daemon_stats: None,
            socket_path,
        })
    }

    /// Helper: workspace path as a string ref (for messages).
    #[allow(dead_code)] // consumed by U9 fix-snippet renderers.
    pub fn workspace_str(&self) -> &str {
        self.workspace_path
            .as_deref()
            .and_then(Path::to_str)
            .unwrap_or("<no workspace>")
    }
}
