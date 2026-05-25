//! Continue MCP-registration detector. Hard-detect at
//! `~/.continue/config.yaml` or `<workspace>/.continue/config.yaml`
//! (YAML, per `docs/install.md`).
//!
//! Continue's `mcpServers` is a YAML *list* of objects (with a `name`
//! field), not a map keyed by server name — this is the schema documented
//! in `docs/install.md:137-144`.

use std::path::{Path, PathBuf};

use serde_yaml::Value as YamlValue;

use super::{DetectionClass, HostDetector, HostFinding, RegistrationDetail};
use crate::doctor::ctx::Ctx;
use crate::doctor::hosts::claude_code::binary_resolves;
use crate::doctor::report::{FixClass, FixSnippet, Row};

pub struct Continue;

impl HostDetector for Continue {
    fn host_name(&self) -> &'static str {
        "continue"
    }
    fn detection_class(&self) -> DetectionClass {
        DetectionClass::Hard
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
        host_name: "continue",
        detection_class: DetectionClass::Hard,
        rows: Vec::new(),
        rts_registered: None,
        skipped_reason: None,
    };

    // Order: workspace override first, then user-global. Both are valid;
    // we surface a row per scope so users can see which file declared it.
    let mut candidates: Vec<(&'static str, PathBuf)> = Vec::new();
    if let Some(ws) = workspace {
        candidates.push(("project_scope", ws.join(".continue").join("config.yaml")));
    }
    if let Some(h) = home {
        candidates.push(("user_scope", h.join(".continue").join("config.yaml")));
    }

    let mut any_seen = false;
    for (scope, path) in candidates {
        if !path.exists() {
            continue;
        }
        any_seen = true;
        let label = format!("continue:{}", scope);
        match read_and_parse_yaml(&path) {
            Ok(v) => match find_rts_entry(&v) {
                Some(cmd) => {
                    let resolves = cmd.as_deref().map(binary_resolves).unwrap_or(false);
                    if let Some(c) = cmd.as_deref() {
                        if resolves {
                            finding.rows.push(Row::ok(
                                label.clone(),
                                format!("rts registered ({}) in {}", c, path.display()),
                            ));
                        } else {
                            finding.rows.push(
                                Row::fail(
                                    label.clone(),
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
                                            "$EDITOR {}  # update mcpServers[].command",
                                            path.display()
                                        ),
                                    )
                                    .with_description(
                                        "point Continue's rts entry at an existing binary",
                                    ),
                                ),
                            );
                        }
                        if finding.rts_registered.is_none() {
                            finding.rts_registered = Some(RegistrationDetail {
                                scope: scope.to_string(),
                                binary_path: Some(PathBuf::from(c)),
                                config_path: path.clone(),
                            });
                        }
                    } else {
                        finding.rows.push(Row::warn(
                            label,
                            format!("rts entry in {} has no `command`", path.display()),
                        ));
                    }
                }
                None => {
                    finding.rows.push(Row::info(
                        label,
                        format!("rts not registered in {}", path.display()),
                    ));
                }
            },
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
                        .with_description("fix YAML syntax in Continue config"),
                    ),
                );
            }
        }
    }

    if !any_seen {
        return HostFinding::skipped(
            "continue",
            DetectionClass::Hard,
            "not installed (no ~/.continue/config.yaml found)",
        );
    }
    finding
}

fn read_and_parse_yaml(path: &Path) -> Result<YamlValue, String> {
    let bytes = std::fs::read(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::PermissionDenied {
            format!("permission denied reading {}", path.display())
        } else {
            format!("read error: {e}")
        }
    })?;
    serde_yaml::from_slice(&bytes).map_err(|e| e.to_string())
}

/// Extract the `command` for an mcpServer named `rts`. Continue's
/// schema lists `mcpServers` as a sequence of `{name, command, args}`
/// maps; older docs sometimes show a map keyed by name. We tolerate both.
fn find_rts_entry(root: &YamlValue) -> Option<Option<String>> {
    let mcp = root.get("mcpServers")?;
    if let Some(seq) = mcp.as_sequence() {
        for item in seq {
            let name = item.get("name").and_then(YamlValue::as_str);
            if name == Some("rts") {
                let cmd = item
                    .get("command")
                    .and_then(YamlValue::as_str)
                    .map(str::to_string);
                return Some(cmd);
            }
        }
        return None;
    }
    if let Some(map) = mcp.as_mapping() {
        // Map-style fallback: `mcpServers: { rts: { command: ... } }`.
        let key = YamlValue::String("rts".to_string());
        if let Some(entry) = map.get(&key) {
            let cmd = entry
                .get("command")
                .and_then(YamlValue::as_str)
                .map(str::to_string);
            return Some(cmd);
        }
    }
    None
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

    fn write_config(dir: &Path, contents: &str) -> PathBuf {
        let cfg = dir.join(".continue").join("config.yaml");
        fs::create_dir_all(cfg.parent().unwrap()).unwrap();
        fs::write(&cfg, contents).unwrap();
        cfg
    }

    #[test]
    fn absent_config_is_skipped() {
        let home = tempdir().unwrap();
        let ws = tempdir().unwrap();
        let f = detect_impl(&mk_ctx(), Some(home.path()), Some(ws.path()));
        assert!(f.skipped_reason.is_some());
    }

    #[test]
    fn registered_sequence_form_is_ok() {
        let home = tempdir().unwrap();
        let ws = tempdir().unwrap();
        let bin = home.path().join("rts-mcp");
        fs::write(&bin, "#!/bin/sh\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&bin, fs::Permissions::from_mode(0o755)).unwrap();
        }
        write_config(
            home.path(),
            &format!(
                "mcpServers:\n  - name: rts\n    command: {}\n    args:\n      - --workspace\n      - .\n",
                bin.display()
            ),
        );
        let f = detect_impl(&mk_ctx(), Some(home.path()), Some(ws.path()));
        assert!(f.rows.iter().any(|r| r.kind == RowKind::Ok));
        assert!(f.rts_registered.is_some());
    }

    #[test]
    fn missing_binary_is_fail() {
        let home = tempdir().unwrap();
        let ws = tempdir().unwrap();
        write_config(
            home.path(),
            "mcpServers:\n  - name: rts\n    command: /nope/rts-mcp\n",
        );
        let f = detect_impl(&mk_ctx(), Some(home.path()), Some(ws.path()));
        let row = f
            .rows
            .iter()
            .find(|r| r.label == "continue:user_scope")
            .expect("user_scope row");
        assert_eq!(row.kind, RowKind::Fail);
        assert_eq!(row.fix.as_ref().unwrap().class, FixClass::FixMcpBinaryPath);
    }

    #[test]
    fn malformed_yaml_warns() {
        let home = tempdir().unwrap();
        let ws = tempdir().unwrap();
        write_config(home.path(), "mcpServers: [unclosed");
        let f = detect_impl(&mk_ctx(), Some(home.path()), Some(ws.path()));
        let row = f
            .rows
            .iter()
            .find(|r| r.label == "continue:user_scope")
            .expect("user_scope row");
        assert_eq!(row.kind, RowKind::Warn);
    }
}
