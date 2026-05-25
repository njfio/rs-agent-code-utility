//! Aider MCP-registration detector. Soft-detect at
//! `~/.config/aider/mcp.json`, `<workspace>/.aider/mcp.json`, or
//! `~/.aider.conf.yml`.
//!
//! Aider's MCP support is still alpha and the canonical wire-up uses
//! the JSON `mcpServers` block; the YAML `.aider.conf.yml` is
//! Aider's general config file (no formal MCP slot yet). We probe all
//! three and emit a `[?]` info row when none are present.

use std::path::{Path, PathBuf};

use super::{DetectionClass, HostDetector, HostFinding, RegistrationDetail};
use crate::doctor::ctx::Ctx;
use crate::doctor::hosts::claude_code::binary_resolves;
use crate::doctor::report::{FixClass, FixSnippet, Row};

pub struct Aider;

impl HostDetector for Aider {
    fn host_name(&self) -> &'static str {
        "aider"
    }
    fn detection_class(&self) -> DetectionClass {
        DetectionClass::Soft
    }
    fn detect(&self, ctx: &Ctx) -> HostFinding {
        detect_impl(ctx, ctx.home.as_deref(), ctx.workspace_path.as_deref())
    }
}

pub(crate) fn detect_impl(
    _ctx: &Ctx,
    home: Option<&Path>,
    workspace: Option<&Path>,
) -> HostFinding {
    let mut finding = HostFinding {
        host_name: "aider",
        detection_class: DetectionClass::Soft,
        rows: Vec::new(),
        rts_registered: None,
        skipped_reason: None,
    };

    let mut candidates: Vec<(&'static str, PathBuf, ConfigKind)> = Vec::new();
    if let Some(h) = home {
        candidates.push((
            "user_scope",
            h.join(".config").join("aider").join("mcp.json"),
            ConfigKind::Json,
        ));
    }
    if let Some(ws) = workspace {
        candidates.push((
            "project_scope",
            ws.join(".aider").join("mcp.json"),
            ConfigKind::Json,
        ));
    }
    if let Some(h) = home {
        // The general aider conf — only relevant if/when Aider adds a
        // proper MCP block. For now we just acknowledge its presence as
        // an info row.
        candidates.push((
            "aider_conf",
            h.join(".aider.conf.yml"),
            ConfigKind::AiderConfYaml,
        ));
    }

    let mut any_seen = false;
    for (scope, path, kind) in candidates {
        if !path.exists() {
            continue;
        }
        any_seen = true;
        let label = format!("aider:{}", scope);

        match kind {
            ConfigKind::Json => match read_and_parse_json(&path) {
                Ok(v) => {
                    let entry = v.get("mcpServers").and_then(|m| m.get("rts"));
                    if let Some(entry) = entry {
                        let cmd = entry
                            .get("command")
                            .and_then(|c| c.as_str())
                            .map(str::to_string);
                        match cmd {
                            Some(c) if binary_resolves(&c) => {
                                finding.rows.push(Row::ok(
                                    label.clone(),
                                    format!("rts registered ({}) in {}", c, path.display()),
                                ));
                                if finding.rts_registered.is_none() {
                                    finding.rts_registered = Some(RegistrationDetail {
                                        scope: scope.to_string(),
                                        binary_path: Some(PathBuf::from(c)),
                                        config_path: path.clone(),
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
                                            format!(
                                                "$EDITOR {}  # update mcpServers.rts.command",
                                                path.display()
                                            ),
                                        )
                                        .with_description(
                                            "point Aider's rts entry at an existing binary",
                                        ),
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
                    } else {
                        finding.rows.push(Row::info(
                            label,
                            format!("rts not registered in {}", path.display()),
                        ));
                    }
                }
                Err(msg) => {
                    finding.rows.push(
                        Row::warn(
                            label,
                            format!("could not parse {}: {}", path.display(), msg),
                        )
                        .with_fix(
                            FixSnippet::new(
                                FixClass::FixConfigSyntax,
                                format!("$EDITOR {}", path.display()),
                            )
                            .with_description("fix JSON syntax in Aider mcp.json"),
                        ),
                    );
                }
            },
            ConfigKind::AiderConfYaml => {
                // ~/.aider.conf.yml exists. No formal MCP slot yet —
                // emit an info row so the user knows we noticed.
                finding.rows.push(Row::info(
                    label,
                    format!(
                        "{} present; Aider's MCP support is alpha — see docs/install.md",
                        path.display()
                    ),
                ));
            }
        }
    }

    if !any_seen {
        // Soft-detect: emit a `[?]` rather than a skipped_reason so the
        // operator sees that we tried but found nothing.
        finding.rows.push(Row::info(
            "aider:detect",
            "no Aider MCP config found (soft-detect)",
        ));
        finding.skipped_reason = Some("not installed".to_string());
    }

    finding
}

enum ConfigKind {
    Json,
    AiderConfYaml,
}

fn read_and_parse_json(path: &Path) -> Result<serde_json::Value, String> {
    let bytes = std::fs::read(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::PermissionDenied {
            format!("permission denied reading {}", path.display())
        } else {
            format!("read error: {e}")
        }
    })?;
    serde_json::from_slice(&bytes).map_err(|e| e.to_string())
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
    fn absent_emits_info_soft_detect() {
        let home = tempdir().unwrap();
        let ws = tempdir().unwrap();
        let f = detect_impl(&mk_ctx(), Some(home.path()), Some(ws.path()));
        // Soft-detect: rows non-empty with a `[?]`, skipped_reason set.
        assert!(f.rows.iter().any(|r| r.kind == RowKind::Info));
        assert!(f.skipped_reason.is_some());
    }

    #[test]
    fn registered_json_is_ok() {
        let home = tempdir().unwrap();
        let ws = tempdir().unwrap();
        let bin = home.path().join("rts-mcp");
        fs::write(&bin, "#!/bin/sh\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&bin, fs::Permissions::from_mode(0o755)).unwrap();
        }
        let cfg = home.path().join(".config").join("aider").join("mcp.json");
        fs::create_dir_all(cfg.parent().unwrap()).unwrap();
        fs::write(
            &cfg,
            format!(
                r#"{{ "mcpServers": {{ "rts": {{ "command": "{}" }} }} }}"#,
                bin.display()
            ),
        )
        .unwrap();
        let f = detect_impl(&mk_ctx(), Some(home.path()), Some(ws.path()));
        assert!(f.rows.iter().any(|r| r.kind == RowKind::Ok));
        assert!(f.rts_registered.is_some());
        assert!(f.skipped_reason.is_none());
    }

    #[test]
    fn missing_binary_is_fail() {
        let home = tempdir().unwrap();
        let ws = tempdir().unwrap();
        let cfg = home.path().join(".config").join("aider").join("mcp.json");
        fs::create_dir_all(cfg.parent().unwrap()).unwrap();
        fs::write(
            &cfg,
            r#"{ "mcpServers": { "rts": { "command": "/nope/rts-mcp" } } }"#,
        )
        .unwrap();
        let f = detect_impl(&mk_ctx(), Some(home.path()), Some(ws.path()));
        let row = f
            .rows
            .iter()
            .find(|r| r.label == "aider:user_scope")
            .expect("user_scope row");
        assert_eq!(row.kind, RowKind::Fail);
        assert_eq!(row.fix.as_ref().unwrap().class, FixClass::FixMcpBinaryPath);
    }
}
