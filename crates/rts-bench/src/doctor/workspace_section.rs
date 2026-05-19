//! `workspace_index` section — per-workspace index health: pinned-path
//! match against `$PWD`, cold-walk completion, index generation, file
//! count. U6.
//!
//! Reads `ctx.daemon_stats` populated by `daemon_section`. This is the
//! "consumer" side of the daemon round-trip: U5 fetches the bytes; U6
//! interprets them into checklist rows. Decoupling the two lets the
//! workspace_section be tested with synthetic `serde_json::json!({...})`
//! fixtures without standing up a daemon.
//!
//! Row taxonomy (see plan §U6):
//!
//! - No workspace at $PWD → `[WARN] no rts workspace at $PWD`, skip rest.
//! - `ctx.daemon_stats` is None → `[WARN] no daemon stats available`,
//!   skip rest. This happens when the daemon was unreachable; U5's
//!   `[WARN] daemon not running` row already explains why.
//! - `pinned_workspace_path` ≠ canonicalize($PWD) → `[FAIL]` +
//!   `FixClass::MoveWorkspace`.
//! - `cold_walk_completed_at_ms` is null → `[WARN] indexing in progress`.
//! - Everything healthy → `[OK] index generation N, M files`.

use std::path::Path;

use serde_json::Value as JsonValue;

use super::ctx::Ctx;
use super::report::{FixClass, FixSnippet, Row, SectionReport};

pub fn run(ctx: &Ctx) -> SectionReport {
    let mut s = SectionReport::new("workspace_index");

    // 1. No workspace at $PWD → single WARN row, skip inner checks.
    let workspace_path = match ctx.workspace_path.as_deref() {
        Some(p) => p,
        None => {
            s.push(Row::warn(
                "workspace_index:no_workspace",
                "no rts workspace at $PWD — index checks skipped",
            ));
            return s;
        }
    };

    // 2. Daemon unreachable (or section didn't populate stats) →
    //    single WARN row. The reason was already explained by U5's
    //    `daemon` section, so we keep the message terse here.
    let stats = match ctx.daemon_stats.as_ref() {
        Some(v) => v,
        None => {
            s.push(Row::warn(
                "workspace_index:no_daemon_stats",
                "daemon unreachable — see daemon section for details",
            ));
            return s;
        }
    };

    classify(stats, workspace_path, &mut s);
    s
}

/// Decode `stats` (the `result` object from `Daemon.Stats v2` or the
/// `Workspace.Status` fallback) into rows. Split out for unit-testing
/// against synthetic JSON fixtures without going through `Ctx::build`.
fn classify(stats: &JsonValue, workspace_path: &Path, s: &mut SectionReport) {
    // Pinned-path mismatch is the most consequential failure mode —
    // doctor is reporting against a workspace the daemon doesn't
    // believe it's serving. Check it first so even if we can't read
    // other fields we still flag this.
    let pinned = stats
        .get("pinned_workspace_path")
        .and_then(JsonValue::as_str);

    let canonical_pwd = workspace_path
        .canonicalize()
        .unwrap_or_else(|_| workspace_path.to_path_buf());
    let canonical_pwd_str = canonical_pwd.to_string_lossy().into_owned();

    if let Some(pinned_str) = pinned {
        // Compare as canonicalized paths. The daemon already
        // canonicalizes when computing `pinned_workspace_path`, so we
        // canonicalize the doctor side to match. macOS's `/var` →
        // `/private/var` resolution is handled by both sides doing the
        // same canonicalize() call.
        if pinned_str != canonical_pwd_str {
            s.push(
                Row::fail(
                    "workspace_index:pinned_path_mismatch",
                    format!("daemon pinned to {pinned_str}, doctor running in {canonical_pwd_str}"),
                )
                .with_fix(
                    FixSnippet::new(
                        FixClass::MoveWorkspace,
                        format!(
                            "rts-daemon --workspace {} &",
                            shell_escape(&canonical_pwd_str)
                        ),
                    )
                    .with_description(
                        "restart rts-daemon pinned to this workspace, or cd to the pinned path",
                    ),
                ),
            );
            // Continue with the other fields — they're still informative.
        }
    } else {
        // No pinned_workspace_path → either we got a v1 Daemon.Stats
        // response or a Workspace.Status response (which doesn't carry
        // pinned_workspace_path either). Either way, surface a WARN
        // so the user knows we couldn't verify path agreement.
        s.push(Row::warn(
            "workspace_index:pinned_path_unknown",
            "pinned workspace path not reported (pre-daemon_stats_v2 daemon)",
        ));
    }

    // Cold-walk completion. `cold_walk_completed_at_ms` is `null`
    // until the writer's ColdWalkComplete commit lands. A null value
    // means "still indexing"; an absent field means "daemon doesn't
    // expose it" (pre-v2). Treat both as WARN with slightly
    // different messages.
    let cold_walk = stats.get("cold_walk_completed_at_ms");
    let in_progress = match cold_walk {
        None => false, // field absent — covered by pinned_path_unknown above
        Some(v) if v.is_null() => true,
        Some(_) => false,
    };
    if in_progress {
        s.push(Row::warn(
            "workspace_index:indexing",
            "indexing in progress — cold walk not yet complete",
        ));
    }

    // index_generation + file count. v2 carries `index_generation`;
    // Workspace.Status carries it too. Either source is fine.
    let index_gen = stats.get("index_generation").and_then(JsonValue::as_u64);
    let file_count = stats
        .get("file_count")
        .or_else(|| stats.get("files_indexed"))
        .and_then(JsonValue::as_u64);

    let pinned_matches = pinned.map(|p| p == canonical_pwd_str).unwrap_or(false);
    let any_fail = s
        .rows
        .iter()
        .any(|r| matches!(r.kind, super::report::RowKind::Fail));

    if pinned_matches && !in_progress && !any_fail {
        // Happy-path OK row.
        let gen_str = index_gen
            .map(|n| n.to_string())
            .unwrap_or_else(|| "?".to_string());
        let count_str = file_count
            .map(|n| format!("{n} files"))
            .unwrap_or_else(|| "file count unknown".to_string());
        s.push(Row::ok(
            "workspace_index:healthy",
            format!("index generation {gen_str}, {count_str}"),
        ));
    } else if !any_fail && index_gen.is_some() && !in_progress {
        // No FAILs (e.g. pinned_path_unknown is just a WARN) but we
        // still have an index_generation — surface it as an OK
        // informational row so the user sees the index count even
        // when we couldn't verify pinned-path agreement.
        let gen_str = index_gen.unwrap();
        let count_str = file_count
            .map(|n| format!("{n} files"))
            .unwrap_or_else(|| "file count unknown".to_string());
        s.push(Row::ok(
            "workspace_index:generation",
            format!("index generation {gen_str}, {count_str}"),
        ));
    }
}

/// Single-quote a shell argument the same way `printf %q` would. Used
/// for the fix-snippet command so workspaces with spaces in the path
/// don't produce a broken paste-and-run line.
fn shell_escape(s: &str) -> String {
    if s.chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '_' | '-' | '.' | '+' | ':'))
    {
        return s.to_string();
    }
    // Wrap in single quotes; embedded single quotes become `'\''`.
    let mut out = String::with_capacity(s.len() + 2);
    out.push('\'');
    for c in s.chars() {
        if c == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(c);
        }
    }
    out.push('\'');
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::doctor::report::RowKind;
    use serde_json::json;

    fn ctx_with(stats: Option<JsonValue>, workspace: Option<std::path::PathBuf>) -> Ctx {
        Ctx {
            workspace_path: workspace,
            home: None,
            doctor_version: "0.0.0-test",
            color_enabled: false,
            daemon_stats: stats,
            socket_path: None,
        }
    }

    #[test]
    fn workspace_section_warns_when_no_workspace_path() {
        let ctx = ctx_with(None, None);
        let r = run(&ctx);
        assert_eq!(r.rows.len(), 1);
        assert_eq!(r.rows[0].kind, RowKind::Warn);
        assert!(r.rows[0].message.contains("no rts workspace"));
    }

    #[test]
    fn workspace_section_warns_when_daemon_stats_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = ctx_with(None, Some(tmp.path().to_path_buf()));
        let r = run(&ctx);
        assert_eq!(r.rows.len(), 1);
        assert_eq!(r.rows[0].kind, RowKind::Warn);
        assert!(r.rows[0].message.contains("daemon unreachable"));
    }

    #[test]
    fn workspace_section_ok_when_pinned_path_matches() {
        let tmp = tempfile::tempdir().unwrap();
        let ws = tmp.path().canonicalize().unwrap();
        let pinned = ws.to_string_lossy().into_owned();
        let stats = json!({
            "uptime_ms": 1000,
            "version": "0.6.0",
            "pinned_workspace_path": pinned,
            "workspace_id": "deadbeef".repeat(4),
            "index_generation": 7,
            "cold_walk_completed_at_ms": 1234567890u64,
            "file_count": 42,
        });
        let ctx = ctx_with(Some(stats), Some(ws));
        let r = run(&ctx);
        // No FAIL rows; at least one OK row with the index generation.
        assert!(
            !r.rows.iter().any(|row| row.kind == RowKind::Fail),
            "got rows: {:?}",
            r.rows
        );
        let ok = r
            .rows
            .iter()
            .find(|row| row.kind == RowKind::Ok)
            .expect("OK row");
        assert!(ok.message.contains("generation 7"));
        assert!(ok.message.contains("42 files"));
    }

    #[test]
    fn workspace_section_fails_when_pinned_path_mismatches() {
        let tmp = tempfile::tempdir().unwrap();
        let ws = tmp.path().canonicalize().unwrap();
        let stats = json!({
            "pinned_workspace_path": "/some/other/workspace",
            "workspace_id": "deadbeef".repeat(4),
            "index_generation": 3,
            "cold_walk_completed_at_ms": 999u64,
        });
        let ctx = ctx_with(Some(stats), Some(ws.clone()));
        let r = run(&ctx);
        let fail = r
            .rows
            .iter()
            .find(|row| row.kind == RowKind::Fail)
            .expect("FAIL row for pinned-path mismatch");
        assert_eq!(fail.label, "workspace_index:pinned_path_mismatch");
        assert!(fail.message.contains("/some/other/workspace"));
        let fix = fail.fix.as_ref().expect("FAIL row carries a fix");
        assert_eq!(fix.class, FixClass::MoveWorkspace);
        assert!(fix.command.contains("rts-daemon --workspace"));
    }

    #[test]
    fn workspace_section_warns_when_cold_walk_in_progress() {
        let tmp = tempfile::tempdir().unwrap();
        let ws = tmp.path().canonicalize().unwrap();
        let pinned = ws.to_string_lossy().into_owned();
        let stats = json!({
            "pinned_workspace_path": pinned,
            "index_generation": 1,
            "cold_walk_completed_at_ms": JsonValue::Null,
        });
        let ctx = ctx_with(Some(stats), Some(ws));
        let r = run(&ctx);
        let warn = r
            .rows
            .iter()
            .find(|row| row.label == "workspace_index:indexing")
            .expect("WARN row for in-progress cold walk");
        assert_eq!(warn.kind, RowKind::Warn);
        assert!(warn.message.contains("indexing in progress"));
    }

    #[test]
    fn workspace_section_warns_when_pinned_path_field_absent() {
        // Pre-v2 daemon: Workspace.Status fallback gives us
        // index_generation but no pinned_workspace_path.
        let tmp = tempfile::tempdir().unwrap();
        let ws = tmp.path().canonicalize().unwrap();
        let stats = json!({
            "index_generation": 2,
            "file_count": 11,
        });
        let ctx = ctx_with(Some(stats), Some(ws));
        let r = run(&ctx);
        let warn = r
            .rows
            .iter()
            .find(|row| row.label == "workspace_index:pinned_path_unknown")
            .expect("WARN row for missing pinned_workspace_path");
        assert_eq!(warn.kind, RowKind::Warn);
        // Even without a pinned-path check, we still surface the
        // generation so the user sees the index data.
        let ok = r
            .rows
            .iter()
            .find(|row| row.label == "workspace_index:generation")
            .expect("OK generation row");
        assert!(ok.message.contains("generation 2"));
        assert!(ok.message.contains("11 files"));
    }

    #[test]
    fn shell_escape_quotes_paths_with_spaces() {
        assert_eq!(shell_escape("/Users/n/foo"), "/Users/n/foo");
        assert_eq!(shell_escape("/Users/n/with space"), "'/Users/n/with space'");
        assert_eq!(shell_escape("/path/with'quote"), "'/path/with'\\''quote'");
    }
}
