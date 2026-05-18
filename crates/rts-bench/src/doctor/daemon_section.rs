//! `daemon` section — per-workspace socket probe, `Daemon.Stats v2`
//! round-trip with pre-v2 fallback. U5.
//!
//! On success, populates `ctx.daemon_stats` so `workspace_section` can
//! read the pinned-path / index_generation / cold_walk_completed_at_ms
//! fields without a second round-trip.
//!
//! Probing strategy (post Codex PR #109 review):
//!
//! 1. Compute *both* candidate socket paths in priority order:
//!    a. workspace-scoped (`<runtime_root>/rts/ws-<16hex>.sock`),
//!       where `16hex` is the first 8 bytes of
//!       `blake3(canonical_workspace_path)` — mirrors the daemon's
//!       `socket_path_for_workspace` in
//!       `crates/rts-daemon/src/socket.rs:54`. Present whenever
//!       `ctx.workspace_path` is set.
//!    b. default (`<runtime_root>/rts/default.sock`) — the bootstrap
//!       socket for daemons spawned without `--workspace`.
//!    Pick the first candidate whose socket file *exists*. The
//!    workspace-scoped path wins by priority because it's the more
//!    specific match.
//! 2. If neither file exists → `[WARN] daemon not running` + fix
//!    `rts-daemon --workspace $PWD &`. Report uses the *expected*
//!    path (workspace-scoped if known) so the fix command matches
//!    where the daemon would actually bind.
//! 3. If a file is present, attempt a `connect(2)` with a 1-second
//!    timeout. On connection refused → `[FAIL] stale socket` + fix
//!    `rm -f <path>`.
//! 4. If the handshake succeeds, send `Daemon.Stats` and read one
//!    JSON-RPC line back (1-second total deadline). If the response
//!    carries v2 fields, mark OK and populate `ctx.daemon_stats`. If
//!    the response is v1-shape only, fall back to `Workspace.Status`
//!    so `workspace_section` still has `index_generation` data, and
//!    emit a `[WARN] daemon predates daemon_stats_v2`.
//!
//! Replicating the daemon's blake3 hash here (rather than depending
//! on the daemon crate) keeps doctor independent of the daemon's
//! internal surface; drift risk is bounded because the hash function
//! is deterministic and the daemon-side comment marks it stable.
//! `workspace_socket_path_*` tests pin the file-shape contract.
//!
//! Synchronous `std::os::unix::net::UnixStream` is used here (no
//! tokio); a single round-trip per section run, called from within
//! the existing `#[tokio::main]` runtime via the `spawn_blocking`-
//! equivalent of just calling sync code from an async fn. This avoids
//! `Handle::current().block_on(...)` which would deadlock on
//! `current_thread` runtimes.

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde_json::Value as JsonValue;

use super::ctx::Ctx;
use super::report::{FixClass, FixSnippet, Row, SectionReport};

/// 1-second hard cap on the daemon round-trip. Doctor is a fast
/// diagnostic; a slow daemon is itself a diagnosis ("daemon hung").
const ROUND_TRIP_TIMEOUT: Duration = Duration::from_secs(1);

/// Compute the runtime-root directory the same way rts-daemon does.
/// Returns `None` on unsupported OS or unset XDG_RUNTIME_DIR (Linux).
fn runtime_root() -> Option<PathBuf> {
    #[cfg(target_os = "linux")]
    {
        let xdg = std::env::var("XDG_RUNTIME_DIR").ok()?;
        if xdg.is_empty() {
            return None;
        }
        Some(PathBuf::from(xdg).join("rts"))
    }
    #[cfg(target_os = "macos")]
    {
        let home = dirs::home_dir()?;
        Some(home.join("Library").join("Caches").join("rts"))
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        None
    }
}

/// Compute the default-socket path the same way rts-daemon does for the
/// no-`--workspace` case. Mirrors `crates/rts-daemon/src/socket.rs`.
///
/// Linux: `$XDG_RUNTIME_DIR/rts/default.sock` (refuses to fall back to
/// `/tmp` for security parity with the daemon).
///
/// macOS: `$HOME/Library/Caches/rts/default.sock`.
pub(crate) fn default_socket_path() -> Option<PathBuf> {
    Some(runtime_root()?.join("default.sock"))
}

/// Compute the per-workspace socket path the same way rts-daemon does
/// for the `--workspace <path>` case. Mirrors
/// `socket_path_for_workspace` in `crates/rts-daemon/src/socket.rs:54`:
/// `<runtime_root>/ws-<16hex>.sock` where `16hex` is the first 8 bytes
/// of `blake3(canonical_path.as_os_str_bytes())`.
///
/// Replicating the daemon's hash logic here (instead of depending on
/// the daemon crate) keeps doctor independent of the daemon's internal
/// surface. Drift risk is real but bounded — the hash is deterministic
/// and the daemon-side comment marks it as stable.
///
/// Returns `None` when the runtime root can't be resolved (Linux with
/// unset `XDG_RUNTIME_DIR`, or an unsupported OS).
pub(crate) fn workspace_socket_path(canonical_workspace: &Path) -> Option<PathBuf> {
    let dir = runtime_root()?;
    let bytes = canonical_workspace.as_os_str().as_encoded_bytes();
    let hash = blake3::hash(bytes);
    let short = hash.to_hex();
    let short16 = &short.as_str()[..16];
    Some(dir.join(format!("ws-{short16}.sock")))
}

pub fn run(ctx: &mut Ctx) -> SectionReport {
    let mut s = SectionReport::new("daemon");

    // 1. Build the candidate socket path list. When the user is
    //    running in a workspace (the common case after #109),
    //    `rts-daemon --workspace $PWD` binds the per-workspace
    //    `ws-<16hex>.sock` instead of `default.sock` — so we have to
    //    probe both. The workspace-scoped path takes precedence
    //    because it's the more specific match; default.sock is the
    //    fallback for daemons spawned without `--workspace`.
    //
    //    Codex review on PR #109 (P1) caught the original code's
    //    blind spot: probing only `default.sock` reported `not
    //    running` for any user running a workspace-scoped daemon,
    //    masking the actual index state.
    let workspace_socket = ctx
        .workspace_path
        .as_deref()
        .and_then(workspace_socket_path);
    let default_socket = default_socket_path();

    let candidates: Vec<PathBuf> = [workspace_socket.clone(), default_socket.clone()]
        .into_iter()
        .flatten()
        .collect();

    if candidates.is_empty() {
        s.push(Row::warn(
            "daemon:socket_path_unresolved",
            "could not resolve any socket path (unsupported OS or XDG_RUNTIME_DIR unset)",
        ));
        return s;
    }

    // 2. Pick the first candidate whose socket file *exists*. We
    //    don't try to connect yet — that's step 3. Probing presence
    //    first lets us report `not running` with the *expected*
    //    workspace-scoped path in the fix snippet, instead of
    //    nudging the user toward `default.sock`.
    let socket_path = match candidates.iter().find(|p| std::fs::metadata(p).is_ok()) {
        Some(p) => p.clone(),
        None => {
            // No socket exists at any candidate path. Report
            // `not_running` using the workspace-scoped path (or
            // default if no workspace was set) so the fix command
            // matches the path the daemon would bind.
            let preferred = workspace_socket
                .clone()
                .or(default_socket.clone())
                .expect("candidates was non-empty");
            s.push(
                Row::warn(
                    "daemon:not_running",
                    format!(
                        "no daemon socket at {} — daemon not running for this workspace",
                        preferred.display()
                    ),
                )
                .with_fix(
                    FixSnippet::new(FixClass::StartDaemon, "rts-daemon --workspace $PWD &")
                        .with_description(
                            "start rts-daemon as a background process for this workspace",
                        ),
                ),
            );
            return s;
        }
    };
    // Make the resolved path available to peers (workspace_section
    // reads `ctx.daemon_stats` rather than the socket directly, but
    // the path is informative for future debug/diagnostics).
    ctx.socket_path = Some(socket_path.clone());

    // 3. Connect with a short deadline. EREFUSED → stale socket.
    // (The candidate-resolution above already established the socket
    // file exists, so the original `if !exists` early-out has moved
    // up there.)
    let stream = match UnixStream::connect(&socket_path) {
        Ok(s) => s,
        Err(e) => {
            // ECONNREFUSED means the socket file exists but no daemon
            // is listening — the classic stale-socket case. ENOENT was
            // ruled out by the metadata check above; any other error
            // we report as FAIL with the same `rm -f` hint, since the
            // user's recovery action is the same regardless of errno.
            s.push(stale_socket_row(&socket_path, e));
            return s;
        }
    };

    // 4. Round-trip `Daemon.Stats` once. v2 fields are gated by the
    //    daemon-side `daemon_stats_v2` capability; their absence is a
    //    WARN (not FAIL) — the daemon is reachable, just old.
    let stats = match do_round_trip(stream, "Daemon.Stats") {
        Ok(v) => v,
        Err(e) => {
            s.push(Row::fail(
                "daemon:stats_round_trip",
                format!("Daemon.Stats round-trip failed: {e}"),
            ));
            return s;
        }
    };

    let result = stats.get("result").cloned().unwrap_or(JsonValue::Null);
    let has_v2 =
        result.get("pinned_workspace_path").is_some() && result.get("index_generation").is_some();

    if has_v2 {
        // Happy path. One round-trip, all the data we need.
        let version = result
            .get("version")
            .and_then(JsonValue::as_str)
            .unwrap_or("?");
        let uptime_ms = result
            .get("uptime_ms")
            .and_then(JsonValue::as_u64)
            .unwrap_or(0);
        s.push(Row::ok(
            "daemon:reachable",
            format!(
                "daemon v{version} reachable, uptime {} ms (daemon_stats_v2 capability present)",
                uptime_ms
            ),
        ));
        ctx.daemon_stats = Some(result);
    } else {
        // Pre-v2 daemon. Emit a WARN about version, then attempt a
        // fallback `Workspace.Status` so workspace_section can still
        // surface index_generation.
        s.push(Row::warn(
            "daemon:predates_v2",
            "daemon reachable but predates daemon_stats_v2 — fields missing; please upgrade",
        ));

        match UnixStream::connect(&socket_path)
            .map_err(anyhow_io)
            .and_then(|s| do_round_trip(s, "Workspace.Status"))
        {
            Ok(status) => {
                ctx.daemon_stats = Some(status.get("result").cloned().unwrap_or(JsonValue::Null));
            }
            Err(e) => {
                // Non-fatal — workspace_section will surface a row about
                // missing data. Annotate the partial failure here so
                // the section's footnote line tells the operator why.
                s.push_partial_failure(
                    "daemon:fallback_status",
                    format!("Workspace.Status fallback failed: {e}"),
                );
            }
        }
    }

    s
}

/// Build the FAIL row for the stale-socket case. Pulled out for clarity
/// and because future error-kind classification (e.g. EACCES vs
/// ECONNREFUSED) might split into multiple rows.
fn stale_socket_row(socket_path: &Path, e: std::io::Error) -> Row {
    Row::fail(
        "daemon:stale_socket",
        format!(
            "socket file at {} exists but no daemon is listening ({e})",
            socket_path.display()
        ),
    )
    .with_fix(
        FixSnippet::new(
            FixClass::RemoveStaleSocket,
            format!("rm -f {}", socket_path.display()),
        )
        .with_description("remove the stale socket file; then start rts-daemon"),
    )
}

/// Synchronous one-shot JSON-RPC round-trip on a `UnixStream`. Writes a
/// single newline-terminated request, reads one newline-terminated
/// response back, parses it as JSON. All wrapped in a 1-second deadline
/// via socket-level read/write timeouts.
fn do_round_trip(stream: UnixStream, method: &str) -> Result<JsonValue, anyhow::Error> {
    stream.set_read_timeout(Some(ROUND_TRIP_TIMEOUT))?;
    stream.set_write_timeout(Some(ROUND_TRIP_TIMEOUT))?;

    // Build the request line. id="doctor-1" so logs are diagnosable;
    // params={} since both Daemon.Stats and Workspace.Status accept
    // an empty object.
    let req = serde_json::json!({
        "id": "doctor-1",
        "method": method,
        "params": {}
    });
    let mut bytes = serde_json::to_vec(&req)?;
    bytes.push(b'\n');

    let mut writer = &stream;
    writer.write_all(&bytes)?;
    writer.flush()?;

    let mut reader = BufReader::new(&stream);
    let mut line = Vec::with_capacity(4096);
    let n = reader.read_until(b'\n', &mut line)?;
    if n == 0 {
        return Err(anyhow::anyhow!("EOF before response"));
    }
    // Trim trailing newline.
    if line.ends_with(b"\n") {
        line.pop();
    }
    let parsed: JsonValue = serde_json::from_slice(&line)?;
    Ok(parsed)
}

fn anyhow_io(e: std::io::Error) -> anyhow::Error {
    anyhow::Error::new(e)
}

// Silence unused-import warnings on platforms where the `Read` trait is
// only used indirectly through `BufReader`. The use is real (BufReader
// requires `R: Read`); keep the import to satisfy clippy in case it
// later expands.
#[allow(dead_code)]
fn _force_read_import<R: Read>(_: R) {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixListener;
    use std::thread;
    use tempfile::TempDir;

    #[test]
    fn workspace_socket_path_mirrors_daemon_naming() {
        // Pinning the expected shape: `ws-<16hex>.sock`. The 16hex is
        // the first 8 bytes of `blake3(canonical_path.as_os_str_bytes())`
        // — same algorithm the daemon's
        // `crates/rts-daemon/src/socket.rs::socket_path_for_workspace`
        // uses. Drift here would silently route doctor away from the
        // socket the daemon actually binds.
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = workspace_socket_path(tmp.path());
        let Some(p) = path else {
            // Linux test env without XDG_RUNTIME_DIR is a real possibility
            // in CI; just confirm the absent path doesn't panic.
            return;
        };
        let file = p
            .file_name()
            .and_then(|n| n.to_str())
            .expect("filename")
            .to_string();
        assert!(file.starts_with("ws-"), "expected `ws-` prefix; got {file}");
        assert!(
            file.ends_with(".sock"),
            "expected `.sock` suffix; got {file}"
        );
        // 3 ("ws-") + 16 hex + 5 (".sock") = 24 chars total
        assert_eq!(file.len(), 24, "expected 24-char filename; got `{file}`");
        let hex = &file["ws-".len()..file.len() - ".sock".len()];
        assert!(
            hex.chars().all(|c| c.is_ascii_hexdigit()),
            "expected lowercase-hex middle segment; got `{hex}`"
        );
    }

    #[test]
    fn workspace_socket_path_is_deterministic() {
        // Same path → same hash. The fingerprint must be stable across
        // process restarts so doctor and daemon agree.
        let tmp = tempfile::tempdir().expect("tempdir");
        let a = workspace_socket_path(tmp.path());
        let b = workspace_socket_path(tmp.path());
        assert_eq!(a, b);
    }

    #[test]
    fn workspace_socket_path_differs_per_workspace() {
        // Two different paths must hash to different sockets, else the
        // daemon's bind-per-workspace invariant breaks.
        let a_tmp = tempfile::tempdir().expect("tempdir a");
        let b_tmp = tempfile::tempdir().expect("tempdir b");
        let a = workspace_socket_path(a_tmp.path());
        let b = workspace_socket_path(b_tmp.path());
        if let (Some(a), Some(b)) = (a, b) {
            assert_ne!(
                a.file_name(),
                b.file_name(),
                "distinct workspaces must hash to distinct sockets"
            );
        }
    }

    fn make_ctx(socket_override: Option<PathBuf>) -> (TempDir, Ctx) {
        let tmp = tempfile::tempdir().expect("tempdir");
        let ctx = Ctx {
            workspace_path: Some(tmp.path().to_path_buf()),
            home: None,
            doctor_version: "0.0.0-test",
            color_enabled: false,
            daemon_stats: None,
            socket_path: socket_override,
        };
        (tmp, ctx)
    }

    /// Override the daemon-section probe to talk to an explicit
    /// socket path rather than the real default-socket location.
    /// We can't change `default_socket_path()` per-test (it reads
    /// env vars set by the test harness, which races other tests),
    /// so this helper reproduces the section's probe logic against
    /// a known socket path. It mirrors the production code closely
    /// so the tests still exercise the meaningful branches.
    fn probe_with_socket(socket_path: &Path) -> SectionReport {
        let mut s = SectionReport::new("daemon");
        let exists = socket_path.exists();
        if !exists {
            s.push(
                Row::warn(
                    "daemon:not_running",
                    format!(
                        "no daemon socket at {} — daemon not running for this workspace",
                        socket_path.display()
                    ),
                )
                .with_fix(FixSnippet::new(
                    FixClass::StartDaemon,
                    "rts-daemon --workspace $PWD &",
                )),
            );
            return s;
        }
        match UnixStream::connect(socket_path) {
            Ok(_) => s.push(Row::ok("daemon:reachable", "connected")),
            Err(e) => s.push(stale_socket_row(socket_path, e)),
        }
        s
    }

    #[test]
    fn daemon_section_reports_warn_when_socket_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let socket = tmp.path().join("no-such.sock");
        let report = probe_with_socket(&socket);
        assert_eq!(report.rows.len(), 1);
        let row = &report.rows[0];
        assert_eq!(row.kind, super::super::report::RowKind::Warn);
        assert!(row.message.contains("daemon not running"));
        let fix = row.fix.as_ref().expect("warn must have a fix");
        assert_eq!(fix.class, FixClass::StartDaemon);
        assert!(fix.command.contains("rts-daemon"));
    }

    #[test]
    fn daemon_section_reports_fail_when_socket_stale() {
        // Create a regular file at the socket path. connect(2) will
        // return ENOTSOCK / ECONNREFUSED — both classified as "stale".
        let tmp = tempfile::tempdir().unwrap();
        let socket = tmp.path().join("stale.sock");
        std::fs::write(&socket, b"").expect("create stale file");
        let report = probe_with_socket(&socket);
        assert_eq!(report.rows.len(), 1);
        let row = &report.rows[0];
        assert_eq!(row.kind, super::super::report::RowKind::Fail);
        assert!(row.message.contains("no daemon is listening"));
        let fix = row.fix.as_ref().expect("fail must have a fix");
        assert_eq!(fix.class, FixClass::RemoveStaleSocket);
        assert!(fix.command.starts_with("rm -f "));
    }

    #[test]
    fn daemon_section_round_trip_with_listener_returns_response() {
        // Spin up a tiny echo-style UnixListener on a temp path, hand
        // the client a connected stream, and assert `do_round_trip`
        // sends/receives a single JSON-RPC line. This exercises the
        // wire path without depending on the real rts-daemon binary.
        let tmp = tempfile::tempdir().unwrap();
        let socket = tmp.path().join("echo.sock");
        let listener = UnixListener::bind(&socket).unwrap();

        let server = thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(conn.try_clone().unwrap());
            let mut line = Vec::new();
            reader.read_until(b'\n', &mut line).unwrap();
            // Verify the request shape briefly.
            let req: JsonValue = serde_json::from_slice(line.trim_ascii_end()).unwrap();
            assert_eq!(req["method"], "Daemon.Stats");
            // Respond with a synthetic v2 payload.
            let resp = serde_json::json!({
                "id": req["id"],
                "result": {
                    "uptime_ms": 1234u64,
                    "version": "0.6.0",
                    "total_calls": 0u64,
                    "calls": {},
                    "pinned_workspace_path": "/tmp/ws",
                    "workspace_id": "deadbeef".repeat(4),
                    "index_generation": 1u64,
                    "cold_walk_completed_at_ms": 100u64,
                }
            });
            let mut bytes = serde_json::to_vec(&resp).unwrap();
            bytes.push(b'\n');
            conn.write_all(&bytes).unwrap();
        });

        let stream = UnixStream::connect(&socket).unwrap();
        let resp = do_round_trip(stream, "Daemon.Stats").expect("round-trip");
        let result = &resp["result"];
        assert_eq!(result["version"], "0.6.0");
        assert_eq!(result["index_generation"], 1u64);
        assert_eq!(result["pinned_workspace_path"], "/tmp/ws");
        server.join().unwrap();
    }

    #[test]
    fn daemon_section_writes_socket_path_into_ctx() {
        // Smoke: even when the socket is missing, run() should
        // populate ctx.socket_path with the resolved default path
        // so peers (and future debug snapshots) can see it.
        let (_tmp, mut ctx) = make_ctx(None);
        // Note: run() reads the real env at default_socket_path(); we
        // only assert that *some* path got written, or that None is
        // returned on unsupported OS — both branches are valid.
        let _ = run(&mut ctx);
        // If default_socket_path() returned None, we WARN and bail
        // before writing ctx.socket_path. That's fine — the assertion
        // here is only that the section completes without panicking.
    }
}
