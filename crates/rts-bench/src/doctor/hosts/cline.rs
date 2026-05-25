//! Cline MCP-registration detector. Soft-detect via the VS Code
//! extension's global-storage directory; the path varies by OS.
//!
//! - Linux:   `~/.config/Code/User/globalStorage/saoudrizwan.claude-dev/`
//! - macOS:   `~/Library/Application Support/Code/User/globalStorage/saoudrizwan.claude-dev/`
//! - Windows: `%APPDATA%/Code/User/globalStorage/saoudrizwan.claude-dev/`
//!
//! Inside that directory Cline historically stores a JSON file named
//! `cline_mcp_settings.json` (or, in older builds, `mcp_settings.json`).
//! We probe both and emit a `[?]` info row when nothing is found.

use std::path::{Path, PathBuf};

use super::{DetectionClass, HostDetector, HostFinding, RegistrationDetail};
use crate::doctor::ctx::Ctx;
use crate::doctor::hosts::claude_code::binary_resolves;
use crate::doctor::report::{FixClass, FixSnippet, Row};

pub struct Cline;

impl HostDetector for Cline {
    fn host_name(&self) -> &'static str {
        "cline"
    }
    fn detection_class(&self) -> DetectionClass {
        DetectionClass::Soft
    }
    fn detect(&self, ctx: &Ctx) -> HostFinding {
        // Production path: read the live env once at the trait
        // entry, then thread the resolved value down through the
        // dependency-free helper(s). Tests bypass via the
        // explicit-override entry below.
        let xdg = std::env::var_os("XDG_CONFIG_HOME").map(std::path::PathBuf::from);
        detect_impl(ctx, ctx.home.as_deref(), xdg.as_deref())
    }
}

pub(crate) fn detect_impl(
    _ctx: &Ctx,
    home: Option<&Path>,
    xdg_config_home: Option<&Path>,
) -> HostFinding {
    let mut finding = HostFinding {
        host_name: "cline",
        detection_class: DetectionClass::Soft,
        rows: Vec::new(),
        rts_registered: None,
        skipped_reason: None,
    };

    let Some(h) = home else {
        finding.rows.push(Row::info(
            "cline:detect",
            "no home directory; cannot soft-detect Cline",
        ));
        finding.skipped_reason = Some("no home directory".to_string());
        return finding;
    };

    let bases = candidate_global_storage_dirs(h, xdg_config_home);
    let mut any_dir_found = false;
    let mut any_file_found = false;

    for base in &bases {
        if !base.exists() {
            continue;
        }
        any_dir_found = true;
        for candidate_name in [
            // Current Cline (saoudrizwan.claude-dev v3.x+) stores MCP
            // settings under `settings/cline_mcp_settings.json`.
            "settings/cline_mcp_settings.json",
            // Older builds shipped the file at the directory root.
            "cline_mcp_settings.json",
            // Legacy / pre-rebrand builds used the bare filename.
            // Including it here avoids false-negative soft-detects
            // on long-tenured installs — flagged by Codex review on
            // PR #109.
            "mcp_settings.json",
        ] {
            let path = base.join(candidate_name);
            if !path.exists() {
                continue;
            }
            any_file_found = true;
            handle_settings_file(&mut finding, &path);
        }
    }

    if !any_dir_found {
        finding.rows.push(Row::info(
            "cline:detect",
            "no Cline VS Code extension storage directory found (soft-detect)",
        ));
        finding.skipped_reason = Some("not installed".to_string());
        return finding;
    }
    if !any_file_found {
        finding.rows.push(Row::info(
            "cline:settings",
            "Cline extension storage found but no MCP settings file present",
        ));
    }

    finding
}

fn handle_settings_file(finding: &mut HostFinding, path: &Path) {
    let label = "cline:vs_code_extension";
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            finding.rows.push(Row::warn(
                label,
                if e.kind() == std::io::ErrorKind::PermissionDenied {
                    format!("permission denied reading {}", path.display())
                } else {
                    format!("read error on {}: {}", path.display(), e)
                },
            ));
            return;
        }
    };
    let value: serde_json::Value = match serde_json::from_slice(&bytes) {
        Ok(v) => v,
        Err(e) => {
            finding.rows.push(
                Row::warn(label, format!("could not parse {}: {}", path.display(), e)).with_fix(
                    FixSnippet::new(
                        FixClass::FixConfigSyntax,
                        format!("$EDITOR {}", path.display()),
                    )
                    .with_description("fix JSON syntax in Cline settings"),
                ),
            );
            return;
        }
    };
    let entry = value.get("mcpServers").and_then(|m| m.get("rts"));
    let Some(entry) = entry else {
        finding.rows.push(Row::info(
            label,
            format!("rts not registered in {}", path.display()),
        ));
        return;
    };
    let cmd = entry
        .get("command")
        .and_then(|c| c.as_str())
        .map(str::to_string);
    match cmd {
        Some(c) if binary_resolves(&c) => {
            finding.rows.push(Row::ok(
                label,
                format!("rts registered ({}) in {}", c, path.display()),
            ));
            if finding.rts_registered.is_none() {
                finding.rts_registered = Some(RegistrationDetail {
                    scope: "vs_code_extension".to_string(),
                    binary_path: Some(PathBuf::from(c)),
                    config_path: path.to_path_buf(),
                });
            }
        }
        Some(c) => {
            finding.rows.push(
                Row::fail(
                    label,
                    format!(
                        "rts registered in {} but binary {} not found",
                        path.display(),
                        c
                    ),
                )
                .with_fix(
                    FixSnippet::new(
                        FixClass::FixMcpBinaryPath,
                        format!("$EDITOR {}", path.display()),
                    )
                    .with_description("point Cline's rts entry at an existing binary"),
                ),
            );
        }
        None => {
            finding.rows.push(Row::warn(
                label,
                format!("rts entry in {} has no `command`", path.display()),
            ));
        }
    }
}

/// Return the OS-specific list of VS Code `globalStorage/saoudrizwan.claude-dev`
/// directories to probe. Multiple entries are returned for OSes where
/// VS Code Insiders / VSCodium ship parallel install trees.
///
/// `xdg_config_home` is the resolved value of the `XDG_CONFIG_HOME`
/// env var (Linux only). The production caller reads the env once at
/// `detect_impl` entry and passes it down; tests pass `None` (or a
/// synthetic path) so they don't have to mutate the process-wide env
/// — `std::env::set_var` is `unsafe` under Rust 2024 and forbidden by
/// the workspace's `unsafe_code = "deny"` lint.
fn candidate_global_storage_dirs(
    home: &Path,
    #[cfg_attr(not(target_os = "linux"), allow(unused_variables))] xdg_config_home: Option<&Path>,
) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let ext = "saoudrizwan.claude-dev";

    #[cfg(target_os = "macos")]
    {
        let base = home.join("Library").join("Application Support");
        for product in ["Code", "Code - Insiders", "VSCodium"] {
            out.push(
                base.join(product)
                    .join("User")
                    .join("globalStorage")
                    .join(ext),
            );
        }
    }
    #[cfg(target_os = "linux")]
    {
        // Honor the passed-in XDG_CONFIG_HOME if set + absolute;
        // otherwise default to `~/.config`.
        let xdg = xdg_config_home
            .map(PathBuf::from)
            .filter(|p| p.is_absolute())
            .unwrap_or_else(|| home.join(".config"));
        for product in ["Code", "Code - Insiders", "VSCodium"] {
            out.push(
                xdg.join(product)
                    .join("User")
                    .join("globalStorage")
                    .join(ext),
            );
        }
    }
    #[cfg(target_os = "windows")]
    {
        if let Some(appdata) = std::env::var_os("APPDATA").map(PathBuf::from) {
            for product in ["Code", "Code - Insiders", "VSCodium"] {
                out.push(
                    appdata
                        .join(product)
                        .join("User")
                        .join("globalStorage")
                        .join(ext),
                );
            }
        } else {
            // Fallback: walk under the typical %USERPROFILE%/AppData/Roaming.
            let fallback = home.join("AppData").join("Roaming");
            for product in ["Code", "Code - Insiders", "VSCodium"] {
                out.push(
                    fallback
                        .join(product)
                        .join("User")
                        .join("globalStorage")
                        .join(ext),
                );
            }
        }
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        // Unknown OS: best-effort under ~/.config — better than nothing.
        out.push(
            home.join(".config")
                .join("Code")
                .join("User")
                .join("globalStorage")
                .join(ext),
        );
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::doctor::report::RowKind;
    use crate::doctor::{DoctorArgs, DoctorOutput};
    use std::fs;
    use tempfile::tempdir;

    fn mk_ctx() -> Ctx {
        Ctx::build(&DoctorArgs {
            output: DoctorOutput::Json,
            no_color: true,
            workspace: None,
        })
        .unwrap()
    }

    #[test]
    fn absent_extension_dir_yields_info_and_skipped() {
        let home = tempdir().unwrap();
        // Pass `None` for the XDG override so the test stays
        // hermetic regardless of the runner's real `XDG_CONFIG_HOME`.
        let f = detect_impl(&mk_ctx(), Some(home.path()), None);
        assert!(f.skipped_reason.is_some());
        assert!(f.rows.iter().any(|r| r.kind == RowKind::Info));
    }

    /// Build a synthetic Cline-extension dir for the current OS and
    /// drop a settings file in it. Mirrors what
    /// `candidate_global_storage_dirs(home, None)` would return.
    fn write_synth_settings(home: &Path, contents: &str) -> PathBuf {
        let dirs = candidate_global_storage_dirs(home, None);
        let base = dirs.into_iter().next().expect("at least one candidate");
        let settings = base.join("settings");
        fs::create_dir_all(&settings).unwrap();
        let path = settings.join("cline_mcp_settings.json");
        fs::write(&path, contents).unwrap();
        path
    }

    #[test]
    fn registered_with_resolving_binary_is_ok() {
        let home = tempdir().unwrap();
        let bin = home.path().join("rts-mcp");
        fs::write(&bin, "#!/bin/sh\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&bin, fs::Permissions::from_mode(0o755)).unwrap();
        }
        // No env mutation needed: pass `None` so the function
        // defaults to `<home>/.config` on Linux (matches what
        // `write_synth_settings` writes to).
        write_synth_settings(
            home.path(),
            &format!(
                r#"{{ "mcpServers": {{ "rts": {{ "command": "{}" }} }} }}"#,
                bin.display()
            ),
        );
        let f = detect_impl(&mk_ctx(), Some(home.path()), None);
        assert!(
            f.rows.iter().any(|r| r.kind == RowKind::Ok),
            "rows: {:?}",
            f.rows
        );
    }

    #[test]
    fn missing_binary_is_fail() {
        let home = tempdir().unwrap();
        write_synth_settings(
            home.path(),
            r#"{ "mcpServers": { "rts": { "command": "/nope/rts-mcp" } } }"#,
        );
        let f = detect_impl(&mk_ctx(), Some(home.path()), None);
        let row = f
            .rows
            .iter()
            .find(|r| r.label == "cline:vs_code_extension")
            .expect("vs_code_extension row");
        assert_eq!(row.kind, RowKind::Fail);
        assert_eq!(row.fix.as_ref().unwrap().class, FixClass::FixMcpBinaryPath);
    }
}
