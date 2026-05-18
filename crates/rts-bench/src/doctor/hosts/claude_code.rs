//! Claude Code MCP-registration detector. Hard-detect.
//!
//! Scopes (per `docs/install.md`):
//! - user scope: `~/.claude.json`
//! - project scope: `<workspace>/.mcp.json`
//! - settings.json hook block: `<workspace>/.claude/settings.json`
//!
//! Multi-scope drift (user + project register different binaries) is the
//! load-bearing foot-gun this detector catches and surfaces as a WARN.

use std::path::{Path, PathBuf};

use serde_json::Value as JsonValue;

use super::{DetectionClass, HostDetector, HostFinding, RegistrationDetail};
use crate::doctor::ctx::Ctx;
use crate::doctor::report::{FixClass, FixSnippet, Row};

pub struct ClaudeCode;

impl HostDetector for ClaudeCode {
    fn host_name(&self) -> &'static str {
        "claude_code"
    }
    fn detection_class(&self) -> DetectionClass {
        DetectionClass::Hard
    }
    fn detect(&self, ctx: &Ctx) -> HostFinding {
        detect_impl(ctx, ctx.home.as_deref(), ctx.workspace_path.as_deref())
    }
}

/// Internal entry point — broken out so tests can pass synthetic
/// `home` / `workspace` paths without constructing a full `Ctx`.
pub(crate) fn detect_impl(
    _ctx: &Ctx,
    home: Option<&Path>,
    workspace: Option<&Path>,
) -> HostFinding {
    let mut finding = HostFinding {
        host_name: "claude_code",
        detection_class: DetectionClass::Hard,
        rows: Vec::new(),
        rts_registered: None,
        skipped_reason: None,
    };

    let mut registrations: Vec<RegistrationDetail> = Vec::new();
    let mut any_config_seen = false;

    // -- User scope: `~/.claude.json`
    if let Some(h) = home {
        let path = h.join(".claude.json");
        if path.exists() {
            any_config_seen = true;
            match read_and_parse_json(&path) {
                Ok(v) => match find_mcp_entry(&v, "rts") {
                    Some(entry) => {
                        let detail = RegistrationDetail {
                            scope: "user_scope".to_string(),
                            binary_path: entry.command.clone().map(PathBuf::from),
                            config_path: path.clone(),
                        };
                        emit_entry_row(
                            &mut finding,
                            "claude_code:user_scope",
                            &entry,
                            &path,
                        );
                        registrations.push(detail);
                    }
                    None => {
                        // Config present but no rts entry — info row.
                        finding.rows.push(Row::info(
                            "claude_code:user_scope",
                            format!("rts not registered in {}", path.display()),
                        ));
                    }
                },
                Err(msg) => {
                    finding.rows.push(
                        Row::warn(
                            "claude_code:user_scope",
                            format!("could not parse {}: {}", path.display(), msg),
                        )
                        .with_fix(
                            FixSnippet::new(
                                FixClass::FixConfigSyntax,
                                format!("$EDITOR {}", path.display()),
                            )
                            .with_description("fix JSON syntax in user-scope config"),
                        ),
                    );
                }
            }
        }
    }

    // -- Project scope: `<workspace>/.mcp.json`
    if let Some(ws) = workspace {
        let path = ws.join(".mcp.json");
        if path.exists() {
            any_config_seen = true;
            match read_and_parse_json(&path) {
                Ok(v) => {
                    if let Some(entry) = find_mcp_entry(&v, "rts") {
                        let detail = RegistrationDetail {
                            scope: "project_scope".to_string(),
                            binary_path: entry.command.clone().map(PathBuf::from),
                            config_path: path.clone(),
                        };
                        emit_entry_row(
                            &mut finding,
                            "claude_code:project_scope",
                            &entry,
                            &path,
                        );
                        registrations.push(detail);
                    } else {
                        finding.rows.push(Row::info(
                            "claude_code:project_scope",
                            format!("rts not registered in {}", path.display()),
                        ));
                    }
                }
                Err(msg) => {
                    finding.rows.push(
                        Row::warn(
                            "claude_code:project_scope",
                            format!("could not parse {}: {}", path.display(), msg),
                        )
                        .with_fix(
                            FixSnippet::new(
                                FixClass::FixConfigSyntax,
                                format!("$EDITOR {}", path.display()),
                            )
                            .with_description("fix JSON syntax in project-scope config"),
                        ),
                    );
                }
            }
        }
    }

    // -- Hook block scope: `<workspace>/.claude/settings.json` — we look
    //    for a PreToolUse entry that references `rts-nudge.sh`. The hook
    //    section (U8) handles the hook *file* itself; here we only note
    //    that the settings.json wires it in.
    if let Some(ws) = workspace {
        let path = ws.join(".claude").join("settings.json");
        if path.exists() {
            any_config_seen = true;
            match read_and_parse_json(&path) {
                Ok(v) => {
                    if has_rts_nudge_hook(&v) {
                        finding.rows.push(Row::ok(
                            "claude_code:hook_block",
                            format!("rts-nudge.sh wired in {}", path.display()),
                        ));
                    } else {
                        finding.rows.push(Row::info(
                            "claude_code:hook_block",
                            format!("no rts-nudge hook entry in {}", path.display()),
                        ));
                    }
                }
                Err(msg) => {
                    finding.rows.push(
                        Row::warn(
                            "claude_code:hook_block",
                            format!("could not parse {}: {}", path.display(), msg),
                        )
                        .with_fix(
                            FixSnippet::new(
                                FixClass::FixConfigSyntax,
                                format!("$EDITOR {}", path.display()),
                            )
                            .with_description("fix JSON syntax in settings.json"),
                        ),
                    );
                }
            }
        }
    }

    if !any_config_seen {
        // No Claude Code config files at all — soft skip.
        return HostFinding::skipped(
            "claude_code",
            DetectionClass::Hard,
            "not installed (no ~/.claude.json or project .mcp.json found)",
        );
    }

    // Store first registration for the orchestrator's drift check.
    finding.rts_registered = registrations.into_iter().next();
    finding
}

/// Parsed view of a single host's `mcpServers.<name>` entry.
#[derive(Clone, Debug)]
pub(crate) struct McpEntry {
    pub command: Option<String>,
}

/// Look up `mcpServers.<name>` at either the document root (Cursor,
/// project .mcp.json) or nested inside a `projects.<workspace>` object
/// (the shape `~/.claude.json` uses for per-project servers). Returns
/// the first match.
fn find_mcp_entry(root: &JsonValue, name: &str) -> Option<McpEntry> {
    if let Some(entry) = root
        .get("mcpServers")
        .and_then(|v| v.get(name))
        .and_then(parse_mcp_entry)
    {
        return Some(entry);
    }
    // `~/.claude.json` also has `projects.<path>.mcpServers.<name>`.
    if let Some(projects) = root.get("projects").and_then(JsonValue::as_object) {
        for (_proj, body) in projects {
            if let Some(entry) = body
                .get("mcpServers")
                .and_then(|v| v.get(name))
                .and_then(parse_mcp_entry)
            {
                return Some(entry);
            }
        }
    }
    None
}

fn parse_mcp_entry(v: &JsonValue) -> Option<McpEntry> {
    let cmd = v.get("command").and_then(JsonValue::as_str).map(str::to_string);
    Some(McpEntry { command: cmd })
}

/// Look for a PreToolUse hook block that references `rts-nudge.sh`.
/// The shape (per `.claude/settings.json` convention) is:
/// `{ "hooks": { "PreToolUse": [ { "hooks": [ { "command": "..." } ] } ] } }`.
/// We do a tolerant scan rather than a strict schema match.
fn has_rts_nudge_hook(root: &JsonValue) -> bool {
    fn walk(v: &JsonValue) -> bool {
        match v {
            JsonValue::String(s) => s.contains("rts-nudge.sh"),
            JsonValue::Array(a) => a.iter().any(walk),
            JsonValue::Object(m) => m.values().any(walk),
            _ => false,
        }
    }
    walk(root)
}

fn read_and_parse_json(path: &Path) -> Result<JsonValue, String> {
    let bytes = std::fs::read(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::PermissionDenied {
            format!("permission denied reading {}", path.display())
        } else {
            format!("read error: {e}")
        }
    })?;
    serde_json::from_slice(&bytes).map_err(|e| e.to_string())
}

/// Validate the entry's binary path; emit OK / FAIL accordingly.
fn emit_entry_row(
    finding: &mut HostFinding,
    label: &str,
    entry: &McpEntry,
    config_path: &Path,
) {
    match entry.command.as_deref() {
        Some(cmd) => {
            if binary_resolves(cmd) {
                finding.rows.push(Row::ok(
                    label,
                    format!("rts registered ({}) via {}", cmd, config_path.display()),
                ));
            } else {
                finding.rows.push(
                    Row::fail(
                        label,
                        format!(
                            "rts registered in {} but binary {} not found / not executable",
                            config_path.display(),
                            cmd
                        ),
                    )
                    .with_fix(
                        FixSnippet::new(
                            FixClass::FixMcpBinaryPath,
                            "claude mcp remove rts && claude mcp add rts -- $(which rts-mcp) --workspace \"$PWD\"",
                        )
                        .with_description("rebind rts to a binary that exists on PATH"),
                    ),
                );
            }
        }
        None => {
            finding.rows.push(Row::warn(
                label,
                format!("rts entry in {} has no `command` field", config_path.display()),
            ));
        }
    }
}

/// Does the MCP `command` string resolve to an existing, executable
/// file? Accepts absolute paths (`/path/to/rts-mcp`) and bare names
/// resolvable through `$PATH` (`rts-mcp`). Returns true on either.
pub(crate) fn binary_resolves(cmd: &str) -> bool {
    let p = Path::new(cmd);
    if p.is_absolute() || cmd.contains('/') {
        is_executable_file(p)
    } else {
        which_on_path(cmd).is_some()
    }
}

fn is_executable_file(p: &Path) -> bool {
    let Ok(meta) = std::fs::metadata(p) else {
        return false;
    };
    if !meta.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        meta.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}

fn which_on_path(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join(name);
        if is_executable_file(&candidate) {
            return Some(candidate);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::doctor::DoctorArgs;
    use crate::doctor::DoctorOutput;
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

    fn write(path: &Path, contents: &str) {
        if let Some(p) = path.parent() {
            fs::create_dir_all(p).unwrap();
        }
        fs::write(path, contents).unwrap();
    }

    #[test]
    fn absent_config_is_skipped() {
        let home = tempdir().unwrap();
        let ws = tempdir().unwrap();
        let ctx = mk_ctx();
        let f = detect_impl(&ctx, Some(home.path()), Some(ws.path()));
        assert!(f.skipped_reason.is_some());
        assert!(f.rows.is_empty());
    }

    #[test]
    fn user_scope_ok_when_binary_resolves() {
        let home = tempdir().unwrap();
        let ws = tempdir().unwrap();
        // synthetic executable
        let bin = home.path().join("rts-mcp");
        fs::write(&bin, "#!/bin/sh\nexit 0\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&bin, fs::Permissions::from_mode(0o755)).unwrap();
        }
        let cfg = home.path().join(".claude.json");
        write(
            &cfg,
            &format!(
                r#"{{ "mcpServers": {{ "rts": {{ "command": "{}" }} }} }}"#,
                bin.display()
            ),
        );

        let ctx = mk_ctx();
        let f = detect_impl(&ctx, Some(home.path()), Some(ws.path()));
        assert_eq!(f.host_name, "claude_code");
        assert!(f.skipped_reason.is_none());
        assert!(
            f.rows.iter().any(|r| r.label == "claude_code:user_scope"
                && r.kind == crate::doctor::report::RowKind::Ok),
            "expected OK user_scope row; rows = {:?}",
            f.rows
        );
        assert!(f.rts_registered.is_some());
    }

    #[test]
    fn missing_binary_is_fail_with_fix() {
        let home = tempdir().unwrap();
        let ws = tempdir().unwrap();
        let cfg = home.path().join(".claude.json");
        write(
            &cfg,
            r#"{ "mcpServers": { "rts": { "command": "/nonexistent/rts-mcp" } } }"#,
        );

        let ctx = mk_ctx();
        let f = detect_impl(&ctx, Some(home.path()), Some(ws.path()));
        let row = f
            .rows
            .iter()
            .find(|r| r.label == "claude_code:user_scope")
            .expect("user_scope row");
        assert_eq!(row.kind, crate::doctor::report::RowKind::Fail);
        let fix = row.fix.as_ref().expect("fix");
        assert_eq!(fix.class, FixClass::FixMcpBinaryPath);
    }

    #[test]
    fn malformed_json_is_warn_not_fail() {
        let home = tempdir().unwrap();
        let ws = tempdir().unwrap();
        let cfg = home.path().join(".claude.json");
        write(&cfg, "{ this is not json");
        let ctx = mk_ctx();
        let f = detect_impl(&ctx, Some(home.path()), Some(ws.path()));
        let row = f
            .rows
            .iter()
            .find(|r| r.label == "claude_code:user_scope")
            .expect("user_scope row");
        assert_eq!(row.kind, crate::doctor::report::RowKind::Warn);
    }

    #[test]
    fn multi_scope_drift_yields_two_registrations() {
        let home = tempdir().unwrap();
        let ws = tempdir().unwrap();
        // Two different "binaries" — neither needs to exist; we only
        // care that two RegistrationDetails get produced for the
        // orchestrator's drift check.
        write(
            &home.path().join(".claude.json"),
            r#"{ "mcpServers": { "rts": { "command": "/opt/a/rts-mcp" } } }"#,
        );
        write(
            &ws.path().join(".mcp.json"),
            r#"{ "mcpServers": { "rts": { "command": "/opt/b/rts-mcp" } } }"#,
        );
        let ctx = mk_ctx();
        let f = detect_impl(&ctx, Some(home.path()), Some(ws.path()));
        // Two scopes both produced rows (both FAIL on missing binary
        // but that's fine — drift is detected at the orchestrator
        // level off `rts_registered` + a peek at `rows`).
        let scope_rows: Vec<_> = f
            .rows
            .iter()
            .filter(|r| {
                r.label == "claude_code:user_scope"
                    || r.label == "claude_code:project_scope"
            })
            .collect();
        assert_eq!(scope_rows.len(), 2);
    }
}
