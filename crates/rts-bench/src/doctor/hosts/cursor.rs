//! Cursor MCP-registration detector. Hard-detect at `~/.cursor/mcp.json`
//! (per `docs/install.md`).

use std::path::{Path, PathBuf};

use super::{DetectionClass, HostDetector, HostFinding, RegistrationDetail};
use crate::doctor::ctx::Ctx;
use crate::doctor::hosts::claude_code::binary_resolves;
use crate::doctor::report::{FixClass, FixSnippet, Row};

pub struct Cursor;

impl HostDetector for Cursor {
    fn host_name(&self) -> &'static str {
        "cursor"
    }
    fn detection_class(&self) -> DetectionClass {
        DetectionClass::Hard
    }
    fn detect(&self, ctx: &Ctx) -> HostFinding {
        detect_impl(ctx, ctx.home.as_deref())
    }
}

pub(crate) fn detect_impl(_ctx: &Ctx, home: Option<&Path>) -> HostFinding {
    let Some(h) = home else {
        return HostFinding::skipped("cursor", DetectionClass::Hard, "no home directory");
    };
    let path = h.join(".cursor").join("mcp.json");
    if !path.exists() {
        return HostFinding::skipped("cursor", DetectionClass::Hard, "not installed");
    }

    let mut finding = HostFinding {
        host_name: "cursor",
        detection_class: DetectionClass::Hard,
        rows: Vec::new(),
        rts_registered: None,
        skipped_reason: None,
    };

    let bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) => {
            finding.rows.push(Row::warn(
                "cursor:user_scope",
                if e.kind() == std::io::ErrorKind::PermissionDenied {
                    format!("permission denied reading {}", path.display())
                } else {
                    format!("read error on {}: {}", path.display(), e)
                },
            ));
            return finding;
        }
    };
    let value: serde_json::Value = match serde_json::from_slice(&bytes) {
        Ok(v) => v,
        Err(e) => {
            finding.rows.push(
                Row::warn(
                    "cursor:user_scope",
                    format!("could not parse {}: {}", path.display(), e),
                )
                .with_fix(
                    FixSnippet::new(
                        FixClass::FixConfigSyntax,
                        format!("$EDITOR {}", path.display()),
                    )
                    .with_description("fix JSON syntax in Cursor's mcp.json"),
                ),
            );
            return finding;
        }
    };

    let entry = value
        .get("mcpServers")
        .and_then(|v| v.get("rts"))
        .cloned();
    let Some(entry) = entry else {
        finding.rows.push(Row::info(
            "cursor:user_scope",
            format!("rts not registered in {}", path.display()),
        ));
        return finding;
    };
    let command = entry
        .get("command")
        .and_then(|v| v.as_str())
        .map(str::to_string);

    if let Some(cmd) = command.as_deref() {
        if binary_resolves(cmd) {
            finding.rows.push(Row::ok(
                "cursor:user_scope",
                format!("rts registered ({}) in {}", cmd, path.display()),
            ));
            finding.rts_registered = Some(RegistrationDetail {
                scope: "user_scope".to_string(),
                binary_path: Some(PathBuf::from(cmd)),
                config_path: path.clone(),
            });
        } else {
            finding.rows.push(
                Row::fail(
                    "cursor:user_scope",
                    format!(
                        "rts registered in {} but binary {} not found",
                        path.display(),
                        cmd
                    ),
                )
                .with_fix(
                    FixSnippet::new(
                        FixClass::FixMcpBinaryPath,
                        format!("$EDITOR {}  # update mcpServers.rts.command", path.display()),
                    )
                    .with_description("point Cursor's rts entry at an existing binary"),
                ),
            );
            // Still record the registration so the orchestrator sees it.
            finding.rts_registered = Some(RegistrationDetail {
                scope: "user_scope".to_string(),
                binary_path: Some(PathBuf::from(cmd)),
                config_path: path.clone(),
            });
        }
    } else {
        finding.rows.push(Row::warn(
            "cursor:user_scope",
            format!("rts entry in {} has no `command`", path.display()),
        ));
    }

    finding
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
    fn absent_config_is_skipped() {
        let home = tempdir().unwrap();
        let f = detect_impl(&mk_ctx(), Some(home.path()));
        assert!(f.skipped_reason.is_some());
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
        let cfg = home.path().join(".cursor").join("mcp.json");
        fs::create_dir_all(cfg.parent().unwrap()).unwrap();
        fs::write(
            &cfg,
            format!(
                r#"{{ "mcpServers": {{ "rts": {{ "command": "{}" }} }} }}"#,
                bin.display()
            ),
        )
        .unwrap();
        let f = detect_impl(&mk_ctx(), Some(home.path()));
        assert!(f.rows.iter().any(|r| r.kind == RowKind::Ok));
        assert!(f.rts_registered.is_some());
    }

    #[test]
    fn missing_binary_is_fail_with_fix_class() {
        let home = tempdir().unwrap();
        let cfg = home.path().join(".cursor").join("mcp.json");
        fs::create_dir_all(cfg.parent().unwrap()).unwrap();
        fs::write(
            &cfg,
            r#"{ "mcpServers": { "rts": { "command": "/nope/rts-mcp" } } }"#,
        )
        .unwrap();
        let f = detect_impl(&mk_ctx(), Some(home.path()));
        let row = f
            .rows
            .iter()
            .find(|r| r.label == "cursor:user_scope")
            .expect("user_scope row");
        assert_eq!(row.kind, RowKind::Fail);
        assert_eq!(row.fix.as_ref().unwrap().class, FixClass::FixMcpBinaryPath);
    }

    #[test]
    fn malformed_json_warns_not_fails() {
        let home = tempdir().unwrap();
        let cfg = home.path().join(".cursor").join("mcp.json");
        fs::create_dir_all(cfg.parent().unwrap()).unwrap();
        fs::write(&cfg, "not json").unwrap();
        let f = detect_impl(&mk_ctx(), Some(home.path()));
        let row = f
            .rows
            .iter()
            .find(|r| r.label == "cursor:user_scope")
            .expect("user_scope row");
        assert_eq!(row.kind, RowKind::Warn);
    }
}
