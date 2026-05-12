//! Daemon lifecycle: pre-flight, lockfile, signal handling, idle shutdown.
//!
//! Enforces `docs/protocol-v0.md` §12 (auth boundary, `umask(0077)`,
//! refuse-to-run-as-root, no-coredump) and §15 (startup, stale PID rename,
//! idle shutdown).

use anyhow::{Context, anyhow};
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::signal::unix::{SignalKind, signal};
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::state::DaemonState;

/// Pre-flight: must succeed *before* binding the socket or opening redb.
///
/// 1. Refuse to run as root (protocol-v0 §12.3).
/// 2. `umask(0077)` so any incidentally-created files default to 0600
///    (protocol-v0 §12.1).
/// 3. Prevent core dumps from leaking indexed content (protocol-v0 §12.4).
pub fn preflight() -> anyhow::Result<()> {
    let euid = nix::unistd::geteuid();
    if euid.is_root() {
        return Err(anyhow!(
            "rts-daemon refuses to run as root (euid=0); start as an unprivileged user"
        ));
    }

    nix::sys::stat::umask(nix::sys::stat::Mode::from_bits_truncate(0o077));

    // No core dumps. RLIMIT_CORE=0 works on both Linux and macOS; Linux also
    // gets PR_SET_DUMPABLE=0 as belt-and-braces.
    {
        use nix::sys::resource::{Resource, setrlimit};
        if let Err(e) = setrlimit(Resource::RLIMIT_CORE, 0, 0) {
            warn!(error = %e, "could not set RLIMIT_CORE=0; continuing anyway");
        }
    }
    #[cfg(target_os = "linux")]
    if let Err(e) = set_no_dumpable_linux() {
        warn!(error = %e, "could not clear PR_SET_DUMPABLE; continuing anyway");
    }

    info!(euid = euid.as_raw(), "daemon preflight ok");
    Ok(())
}

#[cfg(target_os = "linux")]
fn set_no_dumpable_linux() -> std::io::Result<()> {
    // SAFETY: `prctl(PR_SET_DUMPABLE, 0, …)` is a pure side-effect on the
    // current process; no pointers, no aliasing, no `unsafe` invariants.
    #[allow(unsafe_code)]
    let rc = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0 as libc::c_long, 0, 0, 0) };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// Holds the daemon's PID lockfile open for the lifetime of the daemon.
/// Dropping unlocks the file (via close) and unlinks the lockfile path so a
/// fresh start doesn't trip over a stale entry. The *authoritative* lock is
/// redb's own flock on its data file; this PID file is observability +
/// stale-detection.
pub struct DaemonLock {
    _pid_file: std::fs::File,
    pid_path: PathBuf,
}

impl Drop for DaemonLock {
    fn drop(&mut self) {
        if let Err(e) = std::fs::remove_file(&self.pid_path) {
            if e.kind() != std::io::ErrorKind::NotFound {
                warn!(
                    error = %e,
                    path = %self.pid_path.display(),
                    "could not unlink PID file on shutdown"
                );
            }
        }
        // `_pid_file` drops here, closing the fd and releasing the flock.
    }
}

/// Acquire the daemon-instance lockfile next to the socket path.
///
/// - File path is `<socket_path>.pid`.
/// - Lock semantics: `O_CREAT | O_RDWR` + `flock(LOCK_EX | LOCK_NB)`.
/// - On `EWOULDBLOCK` (another live daemon), check liveness via `kill(pid, 0)`;
///   if stale, rename the file out of the way and retry once.
pub fn acquire_lock(socket_path: &Path) -> anyhow::Result<DaemonLock> {
    let pid_path = pid_path_for_socket(socket_path);

    if let Some(parent) = pid_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create parent dir {}", parent.display()))?;
        nix::sys::stat::fchmodat(
            None,
            parent,
            nix::sys::stat::Mode::from_bits_truncate(0o700),
            nix::sys::stat::FchmodatFlags::FollowSymlink,
        )
        .with_context(|| format!("chmod 0700 on {}", parent.display()))?;
    }

    for attempt in 0..2 {
        match try_lock_pid_file(&pid_path) {
            Ok(file) => {
                write_pid_to_file(&file)?;
                return Ok(DaemonLock {
                    _pid_file: file,
                    pid_path,
                });
            }
            Err(LockError::HeldByLive { pid }) => {
                return Err(anyhow!(
                    "another rts-daemon is already running for this workspace (pid={pid}); pid file: {}",
                    pid_path.display()
                ));
            }
            Err(LockError::HeldButStale { pid }) if attempt == 0 => {
                let stale_path = stale_pid_path(&pid_path);
                warn!(
                    pid = pid,
                    stale = %stale_path.display(),
                    "renaming stale PID file before retry"
                );
                std::fs::rename(&pid_path, &stale_path).with_context(|| {
                    format!(
                        "rename stale PID {} → {}",
                        pid_path.display(),
                        stale_path.display()
                    )
                })?;
                continue;
            }
            Err(LockError::HeldButStale { pid }) => {
                return Err(anyhow!(
                    "stale PID file at {} (pid={pid}) survived rename; aborting",
                    pid_path.display()
                ));
            }
            Err(LockError::Io(e)) => return Err(anyhow::Error::from(e)),
        }
    }

    Err(anyhow!("unreachable: lock loop bounded at 2 attempts"))
}

#[derive(Debug, thiserror::Error)]
enum LockError {
    #[error("PID file is held by live process (pid={pid})")]
    HeldByLive { pid: i32 },
    #[error("PID file is stale (pid={pid})")]
    HeldButStale { pid: i32 },
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

fn try_lock_pid_file(pid_path: &Path) -> Result<std::fs::File, LockError> {
    use std::os::unix::fs::OpenOptionsExt;

    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(pid_path)?;

    // SAFETY: `fd` is owned by `file`, which is held by this function and
    // returned to the caller on success. `libc::flock` is a pure syscall that
    // mutates kernel state only; no Rust invariants involved.
    let fd = file.as_raw_fd();
    #[allow(unsafe_code)]
    let rc = unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) };
    if rc == 0 {
        return Ok(file);
    }
    let io_err = std::io::Error::last_os_error();
    if matches!(io_err.raw_os_error(), Some(libc::EWOULDBLOCK)) {
        return classify_held_pid_file(pid_path, file);
    }
    Err(LockError::Io(io_err))
}

fn classify_held_pid_file(
    _pid_path: &Path,
    mut file: std::fs::File,
) -> Result<std::fs::File, LockError> {
    use std::io::Read;
    let mut buf = String::new();
    file.read_to_string(&mut buf).map_err(LockError::Io)?;
    let pid: i32 = buf
        .trim()
        .lines()
        .next()
        .and_then(|s| s.parse().ok())
        .unwrap_or(-1);
    if pid <= 0 {
        return Err(LockError::HeldButStale { pid });
    }
    match nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid), None) {
        Ok(()) => Err(LockError::HeldByLive { pid }),
        Err(nix::errno::Errno::ESRCH) => Err(LockError::HeldButStale { pid }),
        Err(e) => Err(LockError::Io(std::io::Error::from_raw_os_error(e as i32))),
    }
}

fn write_pid_to_file(file: &std::fs::File) -> anyhow::Result<()> {
    use std::io::{Seek, SeekFrom, Write};
    let pid = std::process::id();
    let start = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let line = format!("{pid}\n{start}\n");
    let mut f = file.try_clone().context("clone pid file fd for write")?;
    f.set_len(0).context("truncate pid file")?;
    f.seek(SeekFrom::Start(0)).context("seek pid file")?;
    f.write_all(line.as_bytes()).context("write pid line")?;
    f.flush().context("flush pid line")?;
    Ok(())
}

fn pid_path_for_socket(socket_path: &Path) -> PathBuf {
    let mut p = socket_path.as_os_str().to_owned();
    p.push(".pid");
    PathBuf::from(p)
}

fn stale_pid_path(pid_path: &Path) -> PathBuf {
    let now_ns = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let mut p = pid_path.as_os_str().to_owned();
    p.push(format!(".stale.{now_ns}"));
    PathBuf::from(p)
}

/// Wait for SIGTERM, SIGINT, or SIGHUP. Returns the human-readable signal name
/// that fired. SIGHUP in v0 is treated the same as SIGTERM (config reload is
/// not yet implemented; see protocol-v0 §15).
pub async fn wait_for_shutdown_signal() -> anyhow::Result<&'static str> {
    let mut term = signal(SignalKind::terminate()).context("install SIGTERM handler")?;
    let mut int = signal(SignalKind::interrupt()).context("install SIGINT handler")?;
    let mut hup = signal(SignalKind::hangup()).context("install SIGHUP handler")?;
    tokio::select! {
        _ = term.recv() => Ok("SIGTERM"),
        _ = int.recv() => Ok("SIGINT"),
        _ = hup.recv() => Ok("SIGHUP"),
    }
}

/// Polls `state.is_idle(window)` every `window/3` and cancels the shutdown
/// token when idle. Runs forever otherwise.
pub async fn idle_shutdown_timer(
    state: Arc<DaemonState>,
    window: Duration,
    cancel: CancellationToken,
) {
    let tick = (window / 3).max(Duration::from_secs(5));
    let mut interval = tokio::time::interval(tick);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            _ = cancel.cancelled() => return,
            _ = interval.tick() => {
                if state.is_idle(window) {
                    info!(window_secs = window.as_secs(), "idle timer fired; shutting down");
                    cancel.cancel();
                    return;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pid_path_appends_pid_suffix() {
        let p = pid_path_for_socket(Path::new("/tmp/rts/abc.sock"));
        assert_eq!(p, PathBuf::from("/tmp/rts/abc.sock.pid"));
    }

    #[test]
    fn stale_path_uses_nano_timestamp() {
        let p = stale_pid_path(Path::new("/tmp/x.pid"));
        assert!(p.to_string_lossy().starts_with("/tmp/x.pid.stale."));
        let suffix = p.file_name().unwrap().to_string_lossy().to_string();
        let n: &str = suffix.rsplit('.').next().unwrap();
        // Final component is a decimal ns since epoch.
        assert!(n.parse::<u128>().is_ok(), "expected decimal ns, got {n}");
    }

    #[test]
    fn lock_acquire_and_drop_cycles_cleanly() {
        let tmp = tempfile::tempdir().unwrap();
        let socket = tmp.path().join("daemon.sock");
        let lock = acquire_lock(&socket).expect("first acquire");
        let pid_path = pid_path_for_socket(&socket);
        assert!(pid_path.exists(), "pid file should be created");
        drop(lock);
        assert!(!pid_path.exists(), "pid file should be unlinked on drop");
    }

    #[test]
    fn second_acquire_blocked_by_first() {
        let tmp = tempfile::tempdir().unwrap();
        let socket = tmp.path().join("daemon.sock");
        let _first = acquire_lock(&socket).expect("first acquire");
        let result = acquire_lock(&socket);
        assert!(result.is_err(), "second acquire should fail while first held");
    }
}
