//! `hook` section — `.claude/hooks/rts-nudge.sh` presence,
//! executability, version-marker match.
//!
//! Four observable states (in worsening-to-best order of "looks like a
//! drift"):
//!
//!   1. No workspace → single `[?]` info row; we can't check anything.
//!   2. Hook file absent → `[WARN]` + install-fix snippet.
//!   3. Hook present but not executable → `[WARN]` + `chmod +x` fix.
//!   4. Hook present + executable but version marker missing or
//!      mismatched against `ctx.doctor_version` → `[WARN]` + update fix.
//!   5. Hook present + executable + version marker matches → `[OK]`.
//!
//! The version marker is a single line near the top of the hook file
//! shaped `# version: <semver>`. Adding the marker to the hook itself
//! is part of U8 — see `.claude/hooks/rts-nudge.sh`. The marker is a
//! soft-drift signal: when the hook bundled with the user's workspace
//! diverges from the version doctor was compiled against, we don't
//! know whether the drift matters, only that the maintainer may want
//! to refresh the hook.

use std::fs;
use std::path::{Path, PathBuf};

use super::ctx::Ctx;
use super::report::{FixClass, FixSnippet, Row, SectionReport};

/// Relative path inside the workspace where the PreToolUse nudge hook
/// lives. Kept as a constant so the test helpers and the runtime check
/// can never drift.
const HOOK_REL_PATH: &str = ".claude/hooks/rts-nudge.sh";

pub fn run(ctx: &Ctx) -> SectionReport {
    let mut s = SectionReport::new("hook");

    let workspace = match ctx.workspace_path.as_deref() {
        Some(p) => p,
        None => {
            s.push(Row::info(
                "hook:no_workspace",
                "no workspace; cannot check hook",
            ));
            return s;
        }
    };

    let hook_path: PathBuf = workspace.join(HOOK_REL_PATH);
    check_hook(&hook_path, ctx.doctor_version, &mut s);
    s
}

/// Inspect `hook_path` and push one row reflecting the highest-
/// severity observation. Extracted from `run` so tests can drive it
/// against synthetic temp dirs without constructing a full `Ctx`.
fn check_hook(hook_path: &Path, doctor_version: &str, s: &mut SectionReport) {
    let meta = match fs::metadata(hook_path) {
        Ok(m) => m,
        Err(_) => {
            // Absent (or unreadable — same remediation either way).
            s.push(
                Row::warn(
                    "hook:absent",
                    "PreToolUse nudge hook not installed",
                )
                .with_fix(
                    FixSnippet::new(
                        FixClass::UpdateHook,
                        format!(
                            "mkdir -p .claude/hooks && curl -fsSL \
https://raw.githubusercontent.com/yourusername/rust_tree_sitter/main/.claude/hooks/rts-nudge.sh \
-o {rel} && chmod +x {rel}",
                            rel = HOOK_REL_PATH
                        ),
                    )
                    .with_description(
                        "install the bundled PreToolUse nudge hook (also \
register it in .claude/settings.json — see docs/install.md)",
                    ),
                ),
            );
            return;
        }
    };

    if !is_executable(&meta) {
        s.push(
            Row::warn(
                "hook:not_executable",
                "hook not executable; chmod +x required",
            )
            .with_fix(
                FixSnippet::new(
                    FixClass::MakeHookExecutable,
                    format!("chmod +x {}", hook_path.display()),
                ),
            ),
        );
        return;
    }

    // Present + executable: read the file and look for the version marker.
    let contents = match fs::read_to_string(hook_path) {
        Ok(c) => c,
        Err(_) => {
            // Unreadable on a path that fs::metadata said exists — treat
            // as a soft "no marker" rather than escalating to FAIL. The
            // operator can re-install with the same UpdateHook fix.
            s.push(
                Row::warn(
                    "hook:unreadable",
                    "hook present but unreadable; consider re-installing",
                )
                .with_fix(update_hook_fix(hook_path)),
            );
            return;
        }
    };

    match parse_version_marker(&contents) {
        None => {
            s.push(
                Row::warn(
                    "hook:no_version_marker",
                    "hook present but no version marker; consider updating",
                )
                .with_fix(update_hook_fix(hook_path)),
            );
        }
        Some(hook_version) if hook_version == doctor_version => {
            s.push(Row::ok(
                "hook:current",
                format!(
                    "hook installed and current (v{ver})",
                    ver = hook_version
                ),
            ));
        }
        Some(hook_version) => {
            s.push(
                Row::warn(
                    "hook:version_mismatch",
                    format!(
                        "hook is v{old}, doctor is v{new}; consider updating",
                        old = hook_version,
                        new = doctor_version,
                    ),
                )
                .with_fix(update_hook_fix(hook_path)),
            );
        }
    }
}

/// Standard "refresh the hook from the upstream copy" fix snippet,
/// reused across the no-marker / mismatch / unreadable paths.
fn update_hook_fix(hook_path: &Path) -> FixSnippet {
    FixSnippet::new(
        FixClass::UpdateHook,
        format!(
            "curl -fsSL \
https://raw.githubusercontent.com/yourusername/rust_tree_sitter/main/.claude/hooks/rts-nudge.sh \
-o {path} && chmod +x {path}",
            path = hook_path.display()
        ),
    )
    .with_description("refresh the PreToolUse nudge hook to the bundled version")
}

/// Unix executable bit on owner. The hook is a bash script the user
/// owns; we don't need to walk group/other or care about ACLs.
#[cfg(unix)]
fn is_executable(meta: &fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;
    meta.permissions().mode() & 0o111 != 0
}

#[cfg(not(unix))]
fn is_executable(_meta: &fs::Metadata) -> bool {
    // On non-unix targets we don't enforce the executable bit (Windows
    // doesn't have a meaningful one for shell scripts). Treat as
    // executable so we fall through to the version-marker check.
    true
}

/// Scan `contents` for a `# version: <semver>` line. The marker may be
/// preceded by any whitespace; trailing whitespace is trimmed. We only
/// look at the first 50 lines — the marker lives near the top and
/// scanning further is wasted work on large hook files.
fn parse_version_marker(contents: &str) -> Option<String> {
    for line in contents.lines().take(50) {
        let trimmed = line.trim_start();
        if let Some(rest) = trimmed.strip_prefix("# version:") {
            let ver = rest.trim();
            if !ver.is_empty() {
                return Some(ver.to_string());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    use tempfile::TempDir;

    use super::super::ctx::Ctx;
    use super::super::report::RowKind;
    use super::super::DoctorArgs;
    use super::super::DoctorOutput;

    /// Construct a `Ctx` rooted at `workspace`. We can't go through
    /// `Ctx::build` because it canonicalizes via `current_dir()` and
    /// our tests need a deterministic synthetic root.
    fn ctx_with_workspace(workspace: Option<PathBuf>) -> Ctx {
        Ctx {
            workspace_path: workspace,
            home: None,
            doctor_version: env!("CARGO_PKG_VERSION"),
            color_enabled: false,
            daemon_stats: None,
            socket_path: None,
        }
    }

    /// Write `body` to `<workspace>/.claude/hooks/rts-nudge.sh`,
    /// creating parent dirs. `executable` toggles the owner-x bit.
    fn write_hook(workspace: &Path, body: &str, executable: bool) -> PathBuf {
        let hook = workspace.join(HOOK_REL_PATH);
        fs::create_dir_all(hook.parent().unwrap()).unwrap();
        fs::write(&hook, body).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = if executable { 0o755 } else { 0o644 };
            fs::set_permissions(&hook, fs::Permissions::from_mode(mode)).unwrap();
        }
        let _ = executable;
        hook
    }

    fn first_row(s: &SectionReport) -> &Row {
        s.rows.first().expect("section must have at least one row")
    }

    #[test]
    fn hook_absent_warns_and_provides_install_fix() {
        let tmp = TempDir::new().unwrap();
        let ctx = ctx_with_workspace(Some(tmp.path().to_path_buf()));

        let s = run(&ctx);
        let row = first_row(&s);
        assert_eq!(row.kind, RowKind::Warn);
        assert_eq!(row.label, "hook:absent");
        assert!(
            row.message.contains("not installed"),
            "message was: {}",
            row.message
        );
        let fix = row.fix.as_ref().expect("absent hook must include a fix");
        assert_eq!(fix.class, FixClass::UpdateHook);
        assert!(
            fix.command.contains("rts-nudge.sh"),
            "fix command should reference the hook path: {}",
            fix.command
        );
    }

    #[cfg(unix)]
    #[test]
    fn hook_present_non_executable_warns_chmod() {
        let tmp = TempDir::new().unwrap();
        write_hook(
            tmp.path(),
            "#!/usr/bin/env bash\n# version: 0.5.5\necho hi\n",
            false,
        );
        let ctx = ctx_with_workspace(Some(tmp.path().to_path_buf()));

        let s = run(&ctx);
        let row = first_row(&s);
        assert_eq!(row.kind, RowKind::Warn);
        assert_eq!(row.label, "hook:not_executable");
        let fix = row.fix.as_ref().expect("non-exec hook must include a fix");
        assert_eq!(fix.class, FixClass::MakeHookExecutable);
        assert!(
            fix.command.starts_with("chmod +x "),
            "fix command should be a chmod: {}",
            fix.command
        );
    }

    #[test]
    fn hook_present_executable_no_version_marker_warns() {
        let tmp = TempDir::new().unwrap();
        // Body intentionally omits the marker.
        write_hook(
            tmp.path(),
            "#!/usr/bin/env bash\n# rts-nudge.sh — no marker here\nexit 0\n",
            true,
        );
        let ctx = ctx_with_workspace(Some(tmp.path().to_path_buf()));

        let s = run(&ctx);
        let row = first_row(&s);
        assert_eq!(row.kind, RowKind::Warn);
        assert_eq!(row.label, "hook:no_version_marker");
        let fix = row.fix.as_ref().expect("no-marker hook must include a fix");
        assert_eq!(fix.class, FixClass::UpdateHook);
    }

    #[test]
    fn hook_present_executable_version_matches_ok() {
        let tmp = TempDir::new().unwrap();
        let body = format!(
            "#!/usr/bin/env bash\n# version: {ver}\nexit 0\n",
            ver = env!("CARGO_PKG_VERSION")
        );
        write_hook(tmp.path(), &body, true);
        let ctx = ctx_with_workspace(Some(tmp.path().to_path_buf()));

        let s = run(&ctx);
        let row = first_row(&s);
        assert_eq!(row.kind, RowKind::Ok);
        assert_eq!(row.label, "hook:current");
        assert!(row.fix.is_none(), "OK row must not carry a fix");
        assert!(
            row.message.contains(env!("CARGO_PKG_VERSION")),
            "message should mention the current version: {}",
            row.message
        );
    }

    #[test]
    fn hook_present_executable_version_mismatch_warns_update() {
        let tmp = TempDir::new().unwrap();
        write_hook(
            tmp.path(),
            "#!/usr/bin/env bash\n# version: 0.0.1-ancient\nexit 0\n",
            true,
        );
        let ctx = ctx_with_workspace(Some(tmp.path().to_path_buf()));

        let s = run(&ctx);
        let row = first_row(&s);
        assert_eq!(row.kind, RowKind::Warn);
        assert_eq!(row.label, "hook:version_mismatch");
        assert!(
            row.message.contains("0.0.1-ancient")
                && row.message.contains(env!("CARGO_PKG_VERSION")),
            "mismatch message should name both versions: {}",
            row.message
        );
        let fix = row.fix.as_ref().expect("mismatch must include a fix");
        assert_eq!(fix.class, FixClass::UpdateHook);
    }

    #[test]
    fn hook_no_workspace_returns_info_row() {
        let ctx = ctx_with_workspace(None);
        let s = run(&ctx);
        let row = first_row(&s);
        assert_eq!(row.kind, RowKind::Info);
        assert_eq!(row.label, "hook:no_workspace");
        assert!(row.fix.is_none(), "info row must not carry a fix");
    }

    #[test]
    fn parse_version_marker_finds_top_of_file() {
        let body = "#!/usr/bin/env bash\n# version: 1.2.3\n# more comments\n";
        assert_eq!(parse_version_marker(body).as_deref(), Some("1.2.3"));
    }

    #[test]
    fn parse_version_marker_ignores_trailing_whitespace() {
        let body = "#!/usr/bin/env bash\n# version: 1.2.3   \n";
        assert_eq!(parse_version_marker(body).as_deref(), Some("1.2.3"));
    }

    #[test]
    fn parse_version_marker_returns_none_when_missing() {
        let body = "#!/usr/bin/env bash\necho hi\n";
        assert!(parse_version_marker(body).is_none());
    }

    /// Belt-and-suspenders: the marker we shipped in the workspace
    /// hook file must match the rts-bench crate version, otherwise
    /// `doctor` against this very repo would emit a `version_mismatch`
    /// row out of the box. This protects against forgetting to bump
    /// the hook marker when bumping the workspace version.
    #[test]
    fn workspace_hook_marker_matches_crate_version() {
        // CARGO_MANIFEST_DIR points at crates/rts-bench. The hook lives
        // at <workspace_root>/.claude/hooks/rts-nudge.sh.
        let workspace_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(|p| p.parent())
            .map(|p| p.to_path_buf());
        let Some(workspace_root) = workspace_root else {
            // Out-of-tree build (e.g. published crate); skip.
            return;
        };
        let hook = workspace_root.join(HOOK_REL_PATH);
        let Ok(body) = fs::read_to_string(&hook) else {
            // Hook not present in this build context; skip rather than
            // fail (this test is a guardrail for the repo, not the crate).
            return;
        };
        let marker = parse_version_marker(&body)
            .expect("workspace hook must carry a `# version:` marker");
        assert_eq!(
            marker,
            env!("CARGO_PKG_VERSION"),
            "hook marker drifted from crate version; bump .claude/hooks/rts-nudge.sh"
        );
    }

    // Keep DoctorArgs / DoctorOutput referenced so a future refactor
    // that drops them from the public surface trips this section's
    // tests, not some far-away callsite.
    #[allow(dead_code)]
    fn _link_check(_a: DoctorArgs, _o: DoctorOutput) {}
}
