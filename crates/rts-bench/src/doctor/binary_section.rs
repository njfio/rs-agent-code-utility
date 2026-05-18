//! `binary` section — doctor's own version, rts-daemon / rts-mcp
//! presence on PATH, symlink resolution, and version-drift detection.
//!
//! Implementation notes:
//! - PATH lookup is a manual walk over `std::env::var_os("PATH")`. We
//!   deliberately avoid the `which` crate (no new dep) and we never
//!   shell out to `realpath -m` / `readlink -f` because their flag
//!   semantics differ between BSD/macOS and GNU/Linux (cf. #106).
//! - Symlink resolution uses `std::fs::canonicalize`, which is the
//!   portable Rust equivalent.
//! - `--version` invocation uses `std::process::Command::new(bin)`;
//!   stdout is parsed leniently (we look for a `v?<semver-ish>` token
//!   anywhere on the first non-empty line).

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;

use super::ctx::Ctx;
use super::report::{FixClass, FixSnippet, Row, SectionReport};

/// Binaries this section probes for. Order matters — it's the row
/// emission order.
const PROBED_BINARIES: &[&str] = &["rts-daemon", "rts-mcp"];

pub fn run(ctx: &Ctx) -> SectionReport {
    let mut s = SectionReport::new("binary");

    // Row 1 — doctor's own version. Always present, always OK.
    s.push(Row::ok(
        "binary:doctor_version",
        format!("rts-bench doctor v{}", ctx.doctor_version),
    ));

    // Rows 2..N — per-binary discovery. Each binary either resolves to
    // a path (OK row + optional drift WARN) or doesn't (FAIL row with
    // install fix snippet).
    let path_var = std::env::var_os("PATH");
    let mut drift_rows: Vec<Row> = Vec::new();

    for bin in PROBED_BINARIES {
        let label = bin_label(bin);
        match find_on_path(bin, path_var.as_deref()) {
            Some(found) => {
                let resolved = canonicalize_or(&found);
                let version = probe_version(&found);
                let msg = match &version {
                    Some(v) => format!("{} at {} (v{})", bin, resolved.display(), v),
                    None => format!("{} at {}", bin, resolved.display()),
                };
                s.push(Row::ok(label, msg));

                // Drift check: if we got a version and it doesn't match
                // doctor's, emit a peer WARN row. No fix snippet — the
                // recovery is contextual (rebuild vs reinstall vs pin).
                if let Some(v) = version {
                    if !versions_match(&v, ctx.doctor_version) {
                        drift_rows.push(Row::warn(
                            "binary:version_drift",
                            format!(
                                "version drift: doctor=v{}, {}=v{}",
                                ctx.doctor_version, bin, v
                            ),
                        ));
                    }
                }
            }
            None => {
                s.push(
                    Row::fail(label, format!("{} not found on $PATH", bin))
                        .with_fix(install_fix(bin)),
                );
            }
        }
    }

    for r in drift_rows {
        s.push(r);
    }

    s
}

/// Stable row label for a binary name. We can't use `format!` in a
/// const context, so this small helper keeps the labels predictable
/// and snake_cased.
fn bin_label(bin: &str) -> String {
    format!("binary:{}", bin.replace('-', "_"))
}

/// Walk `$PATH` manually and return the first entry that contains an
/// executable file named `bin`. Returns `None` when `$PATH` is unset
/// or empty, or when no entry contains an executable match.
///
/// "Executable" on Unix means at least one of the user/group/other
/// execute bits is set on a regular file. We deliberately do not
/// check ownership or ACLs — doctor's job is to mirror what the
/// shell would actually find.
fn find_on_path(bin: &str, path_var: Option<&std::ffi::OsStr>) -> Option<PathBuf> {
    let path_var = path_var?;
    for dir in std::env::split_paths(path_var) {
        if dir.as_os_str().is_empty() {
            continue;
        }
        let candidate = dir.join(bin);
        if is_executable_file(&candidate) {
            return Some(candidate);
        }
    }
    None
}

/// True iff `path` is a regular file with at least one execute bit.
#[cfg(unix)]
fn is_executable_file(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    let Ok(meta) = std::fs::metadata(path) else {
        return false;
    };
    if !meta.is_file() {
        return false;
    }
    meta.permissions().mode() & 0o111 != 0
}

#[cfg(not(unix))]
fn is_executable_file(path: &Path) -> bool {
    // On non-Unix, fall back to "is a file". rts doesn't ship
    // Windows tarballs today, so this branch exists only to keep
    // the crate building if someone tries `cargo check --target …`.
    std::fs::metadata(path).map(|m| m.is_file()).unwrap_or(false)
}

/// Resolve symlinks via `std::fs::canonicalize`. Falls back to the
/// original path on any error — canonicalize fails on broken
/// symlinks and on paths the user can't stat through, neither of
/// which should block the row.
fn canonicalize_or(path: &Path) -> PathBuf {
    std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

/// Invoke `<bin> --version` and extract a semver-ish token. Returns
/// `None` when the subprocess fails, exits non-zero, or its output
/// doesn't contain a recognizable version.
///
/// Output format we accept (very lenient — both crates' `--version`
/// emit a single line like `rts-daemon 0.5.4` today):
///   `<name> [v]?<digits>.<digits>.<digits>[-suffix]`
///
/// We strip a leading `v` if present so the returned string is
/// directly comparable to `ctx.doctor_version`.
fn probe_version(bin: &Path) -> Option<String> {
    let output = Command::new(bin).arg("--version").output().ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_version_token(&stdout)
}

/// Extract the first semver-shaped token from a `--version` blob.
/// Pure function; tested in isolation below.
fn parse_version_token(s: &str) -> Option<String> {
    for line in s.lines() {
        for token in line.split_whitespace() {
            let trimmed = token.trim_start_matches('v');
            if looks_like_semver(trimmed) {
                return Some(trimmed.to_string());
            }
        }
    }
    None
}

/// "Does this look like `MAJOR.MINOR.PATCH[-extras]`?" Pragmatic
/// check — we just need to discriminate version tokens from the
/// surrounding `rts-daemon` / `rts-mcp` name tokens. Not a full
/// semver parser.
fn looks_like_semver(s: &str) -> bool {
    let core = s.split('-').next().unwrap_or(s);
    let mut parts = core.split('.');
    let (a, b, c) = (parts.next(), parts.next(), parts.next());
    if parts.next().is_some() {
        return false;
    }
    match (a, b, c) {
        (Some(a), Some(b), Some(c)) => {
            !a.is_empty()
                && !b.is_empty()
                && !c.is_empty()
                && a.bytes().all(|x| x.is_ascii_digit())
                && b.bytes().all(|x| x.is_ascii_digit())
                && c.bytes().all(|x| x.is_ascii_digit())
        }
        _ => false,
    }
}

/// Equality on the core `MAJOR.MINOR.PATCH` triple. Pre-release
/// suffixes (`-rc1`, `-dev`) are ignored — we only care about
/// drift at the release level. Both inputs may carry a leading `v`.
fn versions_match(a: &str, b: &str) -> bool {
    fn core(s: &str) -> &str {
        s.trim_start_matches('v').split('-').next().unwrap_or(s)
    }
    core(a) == core(b)
}

/// Fix snippet for a missing binary. We prefer the prebuilt-tarball
/// install pattern from README.md because it works on a clean machine
/// without a Rust toolchain; we add a `cargo install` fallback in the
/// description for source-build environments.
fn install_fix(bin: &str) -> FixSnippet {
    // Concise one-liner: source the binaries from the matching release
    // tarball. Users on the source build can read the description for
    // the `cargo install --path …` alternative.
    let command = format!(
        "curl -fsSL https://github.com/njfio/rs-agent-code-utility/releases/latest/download/install.sh | sh   # or: see docs/install.md"
    );
    FixSnippet::new(FixClass::InstallBinary, command).with_description(format!(
        "{} is missing from $PATH. Install from a release tarball (see docs/install.md) or run `cargo install --path crates/{}` from a source checkout.",
        bin, bin
    ))
}

// `OsString` is referenced via `std::env::var_os` (Option<OsString>)
// — keep the import explicit so this file documents its own surface.
#[allow(dead_code)]
fn _osstring_marker(_: OsString) {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::doctor::DoctorArgs;
    use crate::doctor::DoctorOutput;
    use crate::doctor::report::RowKind;

    fn ctx_for_tests() -> Ctx {
        Ctx::build(&DoctorArgs {
            output: DoctorOutput::Json,
            no_color: true,
            workspace: None,
        })
        .expect("Ctx::build should not fail in tests")
    }

    #[test]
    fn section_name_is_binary() {
        let ctx = ctx_for_tests();
        let report = run(&ctx);
        assert_eq!(report.name, "binary");
    }

    #[test]
    fn doctor_version_row_is_present_and_ok() {
        let ctx = ctx_for_tests();
        let report = run(&ctx);
        let row = report
            .rows
            .iter()
            .find(|r| r.label == "binary:doctor_version")
            .expect("doctor_version row must always be emitted");
        assert_eq!(row.kind, RowKind::Ok);
        assert!(
            row.message.contains(ctx.doctor_version),
            "doctor_version row should embed CARGO_PKG_VERSION: {:?}",
            row.message
        );
    }

    #[test]
    fn empty_path_yields_fail_rows_for_each_probed_binary() {
        // Snapshot the current PATH, then probe with an empty PATH
        // directly (no env mutation needed — `find_on_path` accepts a
        // PATH override). This avoids the Rust 2024 `unsafe` env
        // dance and keeps the test thread-safe.
        let empty: std::ffi::OsString = std::ffi::OsString::new();
        for bin in PROBED_BINARIES {
            assert!(
                find_on_path(bin, Some(&empty)).is_none(),
                "empty PATH should never resolve {}",
                bin
            );
        }
    }

    #[test]
    fn find_on_path_resolves_existing_binary_in_tmpdir() {
        // Build a tempdir with a single executable file and prove the
        // walker finds it. This is a self-contained sanity check for
        // the executable-bit gating.
        let dir = tempfile::tempdir().expect("tempdir");
        let bin_path = dir.path().join("rts-doctor-test-stub");
        std::fs::write(&bin_path, b"#!/bin/sh\necho stub 0.0.0\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&bin_path).unwrap().permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&bin_path, perms).unwrap();
        }

        let path_var: std::ffi::OsString = dir.path().as_os_str().to_owned();
        let found = find_on_path("rts-doctor-test-stub", Some(&path_var));
        assert_eq!(found.as_deref(), Some(bin_path.as_path()));
    }

    #[test]
    fn find_on_path_skips_non_executable_files() {
        let dir = tempfile::tempdir().expect("tempdir");
        let bin_path = dir.path().join("not-executable");
        std::fs::write(&bin_path, b"plain file\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&bin_path).unwrap().permissions();
            perms.set_mode(0o644);
            std::fs::set_permissions(&bin_path, perms).unwrap();
        }

        let path_var: std::ffi::OsString = dir.path().as_os_str().to_owned();
        assert!(
            find_on_path("not-executable", Some(&path_var)).is_none(),
            "find_on_path should skip non-executable regular files"
        );
    }

    #[test]
    fn parse_version_token_extracts_semver_from_typical_output() {
        assert_eq!(
            parse_version_token("rts-daemon 0.5.4\n").as_deref(),
            Some("0.5.4")
        );
        assert_eq!(
            parse_version_token("rts-mcp v1.2.3-rc1\n").as_deref(),
            Some("1.2.3-rc1")
        );
    }

    #[test]
    fn parse_version_token_returns_none_when_no_semver_present() {
        assert!(parse_version_token("hello world\n").is_none());
        assert!(parse_version_token("").is_none());
    }

    #[test]
    fn looks_like_semver_filters_name_tokens() {
        assert!(looks_like_semver("0.5.4"));
        assert!(looks_like_semver("1.2.3-rc1"));
        assert!(!looks_like_semver("rts-daemon"));
        assert!(!looks_like_semver("0.5"));
        assert!(!looks_like_semver("0.5.4.5"));
    }

    #[test]
    fn versions_match_ignores_pre_release_and_leading_v() {
        assert!(versions_match("0.5.4", "0.5.4"));
        assert!(versions_match("v0.5.4", "0.5.4"));
        assert!(versions_match("0.5.4-rc1", "0.5.4-dev"));
        assert!(!versions_match("0.5.4", "0.5.5"));
        assert!(!versions_match("0.6.0", "0.5.5"));
    }

    #[test]
    fn missing_binaries_produce_fail_rows_with_install_fix() {
        // We can't reliably remove rts-daemon from the real PATH inside
        // a test (it's not safe to mutate PATH from a unit test in
        // parallel), but we *can* exercise the install_fix codepath
        // directly and validate the snippet shape.
        let fix = install_fix("rts-daemon");
        assert_eq!(fix.class, FixClass::InstallBinary);
        assert!(
            !fix.command.is_empty(),
            "install fix command must be non-empty"
        );
        assert!(
            fix.description
                .as_deref()
                .is_some_and(|d| d.contains("rts-daemon")),
            "fix description should name the missing binary"
        );
    }

    #[test]
    fn section_does_not_panic_with_real_environment() {
        // Smoke: regardless of whether rts-daemon/rts-mcp are on $PATH
        // in the test harness, `run` must produce a well-formed
        // SectionReport with at least the doctor_version row.
        let ctx = ctx_for_tests();
        let report = run(&ctx);
        assert!(report.rows.len() >= 1 + PROBED_BINARIES.len());
        assert!(
            report
                .rows
                .iter()
                .any(|r| r.label == "binary:doctor_version")
        );
        for bin in PROBED_BINARIES {
            let label = bin_label(bin);
            assert!(
                report.rows.iter().any(|r| r.label == label),
                "per-binary row should be emitted for {}",
                bin
            );
        }
    }
}
