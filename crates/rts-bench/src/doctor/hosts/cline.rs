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
        detect_impl(ctx, ctx.home.as_deref())
    }
}

pub(crate) fn detect_impl(_ctx: &Ctx, home: Option<&Path>) -> HostFinding {
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

    let bases = candidate_global_storage_dirs(h);
    let mut any_dir_found = false;
    let mut any_file_found = false;

    for base in &bases {
        if !base.exists() {
            continue;
        }
        any_dir_found = true;
        for candidate_name in ["settings/cline_mcp_settings.json", "cline_mcp_settings.json"] {
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
                Row::warn(label, format!("could not parse {}: {}", path.display(), e))
                    .with_fix(
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
    let entry = value
        .get("mcpServers")
        .and_then(|m| m.get("rts"));
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
fn candidate_global_storage_dirs(home: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let ext = "saoudrizwan.claude-dev";

    #[cfg(target_os = "macos")]
    {
        let base = home.join("Library").join("Application Support");
        for product in ["Code", "Code - Insiders", "VSCodium"] {
            out.push(base.join(product).join("User").join("globalStorage").join(ext));
        }
    }
    #[cfg(target_os = "linux")]
    {
        // Honor XDG_CONFIG_HOME if set; otherwise default to ~/.config.
        let xdg = std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .filter(|p| p.is_absolute())
            .unwrap_or_else(|| home.join(".config"));
        for product in ["Code", "Code - Insiders", "VSCodium"] {
            out.push(xdg.join(product).join("User").join("globalStorage").join(ext));
        }
    }
    #[cfg(target_os = "windows")]
    {
        if let Some(appdata) = std::env::var_os("APPDATA").map(PathBuf::from) {
            for product in ["Code", "Code - Insiders", "VSCodium"] {
                out.push(appdata.join(product).join("User").join("globalStorage").join(ext));
            }
        } else {
            // Fallback: walk under the typical %USERPROFILE%/AppData/Roaming.
            let fallback = home.join("AppData").join("Roaming");
            for product in ["Code", "Code - Insiders", "VSCodium"] {
                out.push(fallback.join(product).join("User").join("globalStorage").join(ext));
            }
        }
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        // Unknown OS: best-effort under ~/.config — better than nothing.
        out.push(home.join(".config").join("Code").join("User").join("globalStorage").join(ext));
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
        let f = detect_impl(&mk_ctx(), Some(home.path()));
        assert!(f.skipped_reason.is_some());
        assert!(f.rows.iter().any(|r| r.kind == RowKind::Info));
    }

    /// Build a synthetic Cline-extension dir for the current OS and
    /// drop a settings file in it.
    fn write_synth_settings(home: &Path, contents: &str) -> PathBuf {
        let dirs = candidate_global_storage_dirs(home);
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
        // For Linux the XDG_CONFIG_HOME may divert candidate_global_storage_dirs
        // away from `home`; override it locally for test determinism.
        #[cfg(target_os = "linux")]
        let _guard = {
            // We just unset to make the function fall back to ~/.config.
            let prev = std::env::var_os("XDG_CONFIG_HOME");
            std::env::remove_var("XDG_CONFIG_HOME");
            scopeguard_restore(prev)
        };
        write_synth_settings(
            home.path(),
            &format!(
                r#"{{ "mcpServers": {{ "rts": {{ "command": "{}" }} }} }}"#,
                bin.display()
            ),
        );
        let f = detect_impl(&mk_ctx(), Some(home.path()));
        assert!(
            f.rows.iter().any(|r| r.kind == RowKind::Ok),
            "rows: {:?}",
            f.rows
        );
    }

    #[test]
    fn missing_binary_is_fail() {
        let home = tempdir().unwrap();
        #[cfg(target_os = "linux")]
        let _guard = {
            let prev = std::env::var_os("XDG_CONFIG_HOME");
            std::env::remove_var("XDG_CONFIG_HOME");
            scopeguard_restore(prev)
        };
        write_synth_settings(
            home.path(),
            r#"{ "mcpServers": { "rts": { "command": "/nope/rts-mcp" } } }"#,
        );
        let f = detect_impl(&mk_ctx(), Some(home.path()));
        let row = f
            .rows
            .iter()
            .find(|r| r.label == "cline:vs_code_extension")
            .expect("vs_code_extension row");
        assert_eq!(row.kind, RowKind::Fail);
        assert_eq!(row.fix.as_ref().unwrap().class, FixClass::FixMcpBinaryPath);
    }

    // -- tiny RAII helper used only on Linux to restore XDG_CONFIG_HOME.
    #[cfg(target_os = "linux")]
    fn scopeguard_restore(prev: Option<std::ffi::OsString>) -> impl Drop {
        struct R(Option<std::ffi::OsString>);
        impl Drop for R {
            fn drop(&mut self) {
                if let Some(v) = self.0.take() {
                    std::env::set_var("XDG_CONFIG_HOME", v);
                }
            }
        }
        R(prev)
    }
}
