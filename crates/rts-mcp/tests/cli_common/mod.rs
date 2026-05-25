//! Shared helpers for the `rts` CLI integration tests.
//!
//! Every test spins up an isolated XDG runtime/state/home tempdir and
//! lets `rts` auto-spawn the daemon (so the autobootstrap path is
//! exercised on every run). Tests are intentionally Rust 2024 friendly
//! — we thread env values per-`Command` instead of mutating the
//! process-global env (Rust 2024 marks set_var unsafe).

#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::process::{Output, Stdio};

use tokio::process::Command;

pub fn rts_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rts"))
}

pub fn sibling(name: &str) -> PathBuf {
    rts_bin()
        .parent()
        .expect("CARGO_BIN_EXE_rts has parent")
        .join(name)
}

pub fn rts_daemon_bin() -> PathBuf {
    sibling("rts-daemon")
}

/// A complete test environment: workspace + isolated XDG dirs. Drops
/// the tempdirs (and their daemon sockets) on test end.
pub struct TestEnv {
    pub workspace: tempfile::TempDir,
    pub runtime: tempfile::TempDir,
    pub state: tempfile::TempDir,
    pub home: tempfile::TempDir,
}

impl TestEnv {
    pub fn new() -> Self {
        let env = Self {
            workspace: tempfile::tempdir().expect("workspace tempdir"),
            runtime: tempfile::tempdir().expect("runtime tempdir"),
            state: tempfile::tempdir().expect("state tempdir"),
            home: tempfile::tempdir().expect("home tempdir"),
        };
        // XDG_RUNTIME_DIR must be 0700 per the daemon's security
        // policy — without this, the daemon refuses to bind.
        use std::os::unix::fs::PermissionsExt;
        let _ =
            std::fs::set_permissions(env.runtime.path(), std::fs::Permissions::from_mode(0o700));
        env
    }

    pub fn workspace_path(&self) -> &Path {
        self.workspace.path()
    }

    /// Build a `Command` for `rts` with the test env wired up. Does
    /// NOT mutate process-global env.
    pub fn rts(&self) -> Command {
        let mut cmd = Command::new(rts_bin());
        cmd.env_clear();
        // Preserve PATH so tokio + dynamic linker still work, but
        // nothing else from the host env.
        if let Some(path) = std::env::var_os("PATH") {
            cmd.env("PATH", path);
        }
        cmd.env("XDG_RUNTIME_DIR", self.runtime.path())
            .env("XDG_STATE_HOME", self.state.path())
            .env("HOME", self.home.path())
            .env("RTS_DAEMON_BIN", rts_daemon_bin())
            // Idle the daemon long enough that all our test RPCs land
            // before it shuts down. 60s is more than enough.
            .env("RTS_IDLE_SHUTDOWN_SECS", "60")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        cmd
    }

    /// Run an `rts` invocation, return the captured output.
    pub async fn run(&self, args: &[&str]) -> Output {
        let mut cmd = self.rts();
        cmd.args(args).arg("--workspace").arg(self.workspace.path());
        cmd.output().await.expect("spawn rts")
    }

    /// Run an `rts` invocation with an extra env var set.
    pub async fn run_with_env(&self, args: &[&str], k: &str, v: &str) -> Output {
        let mut cmd = self.rts();
        cmd.args(args)
            .arg("--workspace")
            .arg(self.workspace.path())
            .env(k, v);
        cmd.output().await.expect("spawn rts")
    }

    /// Run `rts` with NO `--workspace` arg (so it must walk up from
    /// the tempdir's cwd) — used by the workspace-error test.
    pub async fn run_in_dir(&self, dir: &Path, args: &[&str]) -> Output {
        let mut cmd = self.rts();
        cmd.args(args).current_dir(dir);
        cmd.output().await.expect("spawn rts")
    }
}

/// Seed a minimal Rust workspace with predictable symbol names. Most
/// CLI tests share this fixture: `make_widget`, `make_circle`,
/// `format_widget` in `hub.rs`, callers in `callers.rs`.
pub fn seed_minimal_rust_workspace(root: &Path) {
    std::fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"fixture\"\nversion = \"0.0.0\"\nedition = \"2021\"\n",
    )
    .unwrap();
    std::fs::write(
        root.join("hub.rs"),
        "pub fn make_widget(id: u32) -> u32 { id + 1 }\n\
         pub fn make_circle(r: u32) -> u32 { r * 2 }\n\
         pub fn format_widget(w: u32) -> String {\n    \
             // TODO: prettier formatting\n    \
             format!(\"w#{w}\")\n}\n",
    )
    .unwrap();
    std::fs::write(
        root.join("callers.rs"),
        "use crate::hub::make_widget;\n\
         pub fn caller_a() { let _ = make_widget(1); }\n\
         pub fn caller_b() { let _ = make_widget(2); }\n",
    )
    .unwrap();
}

/// Convert an Output's stdout/stderr to (stdout, stderr, status_code).
/// Surfaces both streams in the panic message when callers fail an
/// assertion — without this, debugging a CI failure is painful.
pub fn parts(out: &Output) -> (String, String, i32) {
    (
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
        out.status.code().unwrap_or(-1),
    )
}
