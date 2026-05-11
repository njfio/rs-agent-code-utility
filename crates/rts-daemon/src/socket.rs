//! Unix-socket server: bind with safe perms, peer-cred check, accept loop.
//!
//! Implements the auth boundary from `docs/protocol-v0.md` §12 and the
//! accept-loop concurrency notes from §9 (one task per connection;
//! per-connection in-flight cap enforced inside `serve_connection`).

use anyhow::{Context, anyhow};
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::error::{ErrorCode, ProtocolError};
use crate::methods;
use crate::protocol::{MAX_MESSAGE_BYTES, Request, Response, parse_request_line};
use crate::state::DaemonState;

/// Per-connection in-flight cap (protocol-v0 §9.4).
const PER_CONNECTION_INFLIGHT_CAP: usize = 16;

/// Fallback socket path used when no per-workspace hash is known yet —
/// for v0's bootstrap "I haven't mounted yet" state. Once a workspace is
/// mounted, future invocations would write to the per-workspace path; this
/// fallback lets us boot a daemon without one.
pub fn socket_path_for_default() -> anyhow::Result<PathBuf> {
    let dir = runtime_root()?;
    std::fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;
    nix::sys::stat::fchmodat(
        None,
        &dir,
        nix::sys::stat::Mode::from_bits_truncate(0o700),
        nix::sys::stat::FchmodatFlags::FollowSymlink,
    )
    .with_context(|| format!("chmod 0700 on {}", dir.display()))?;
    Ok(dir.join("default.sock"))
}

fn runtime_root() -> anyhow::Result<PathBuf> {
    // Linux: `${XDG_RUNTIME_DIR}/rts/`. Refuse if unset (protocol-v0 §5.3 /
    // security F2 — never fall back to /tmp).
    #[cfg(target_os = "linux")]
    {
        let xdg = std::env::var("XDG_RUNTIME_DIR").map_err(|_| {
            anyhow!(
                "XDG_RUNTIME_DIR is unset; refusing to fall back to /tmp (security)"
            )
        })?;
        if xdg.is_empty() {
            return Err(anyhow!("XDG_RUNTIME_DIR is empty"));
        }
        return Ok(PathBuf::from(xdg).join("rts"));
    }
    #[cfg(target_os = "macos")]
    {
        let home = dirs::home_dir()
            .ok_or_else(|| anyhow!("could not resolve $HOME for socket dir"))?;
        return Ok(home.join("Library").join("Caches").join("rts"));
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        Err(anyhow!("unsupported OS for v0 socket placement"))
    }
}

/// Bind a Unix socket at `path` with file mode `0600` and parent dir mode
/// `0700`. Unlinks any pre-existing socket file (the lockfile already
/// guarantees no other live daemon owns it).
pub fn bind_with_safe_perms(path: &Path) -> anyhow::Result<UnixListener> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create parent {}", parent.display()))?;
        nix::sys::stat::fchmodat(
            None,
            parent,
            nix::sys::stat::Mode::from_bits_truncate(0o700),
            nix::sys::stat::FchmodatFlags::FollowSymlink,
        )
        .with_context(|| format!("chmod 0700 on {}", parent.display()))?;
    }
    // Stale socket cleanup. The lockfile is authoritative; if we got here, no
    // live daemon owns it.
    if path.exists() {
        std::fs::remove_file(path)
            .with_context(|| format!("remove stale socket {}", path.display()))?;
    }
    let listener =
        UnixListener::bind(path).with_context(|| format!("bind {}", path.display()))?;
    nix::sys::stat::fchmodat(
        None,
        path,
        nix::sys::stat::Mode::from_bits_truncate(0o600),
        nix::sys::stat::FchmodatFlags::FollowSymlink,
    )
    .with_context(|| format!("chmod 0600 on {}", path.display()))?;
    Ok(listener)
}

/// Verify the peer of an accepted Unix-socket connection has the same uid as
/// the daemon process (protocol-v0 §12.2). Returns the peer's uid on success.
fn check_peer_credentials(stream: &tokio::net::UnixStream) -> anyhow::Result<u32> {
    let fd = stream.as_raw_fd();
    // SAFETY: `fd` is owned by `stream`, which lives for the duration of the
    // call. `BorrowedFd::borrow_raw` doesn't violate any Rust invariants on
    // its own; the only requirement is that the fd remain open for the
    // duration of the borrow, which it does.
    #[allow(unsafe_code)]
    let borrowed: std::os::fd::BorrowedFd<'_> = unsafe { std::os::fd::BorrowedFd::borrow_raw(fd) };
    #[cfg(target_os = "linux")]
    {
        let cred = nix::sys::socket::getsockopt(
            &borrowed,
            nix::sys::socket::sockopt::PeerCredentials,
        )
        .context("SO_PEERCRED getsockopt failed")?;
        let our_uid = nix::unistd::geteuid().as_raw();
        if cred.uid() != our_uid {
            return Err(anyhow!(
                "peer uid {} != daemon uid {}; refusing connection",
                cred.uid(),
                our_uid
            ));
        }
        return Ok(cred.uid());
    }
    #[cfg(target_os = "macos")]
    {
        let xucred = nix::sys::socket::getsockopt(
            &borrowed,
            nix::sys::socket::sockopt::LocalPeerCred,
        )
        .context("LOCAL_PEERCRED getsockopt failed")?;
        let our_uid = nix::unistd::geteuid().as_raw();
        let peer_uid = xucred.uid();
        if peer_uid != our_uid {
            return Err(anyhow!(
                "peer uid {} != daemon uid {}; refusing connection",
                peer_uid,
                our_uid
            ));
        }
        return Ok(peer_uid);
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = borrowed;
        Err(anyhow!("peer credential check unimplemented on this OS"))
    }
}

/// Accept loop: spawn a per-connection task for every incoming connection
/// until `cancel` fires.
pub async fn accept_loop(
    listener: UnixListener,
    state: Arc<DaemonState>,
    cancel: CancellationToken,
) -> anyhow::Result<()> {
    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                info!("accept loop cancelled");
                return Ok(());
            }
            accept = listener.accept() => {
                let (stream, _addr) = match accept {
                    Ok(a) => a,
                    Err(e) => {
                        warn!(error = %e, "accept failed");
                        continue;
                    }
                };
                let peer_uid = match check_peer_credentials(&stream) {
                    Ok(u) => u,
                    Err(e) => {
                        warn!(error = %e, "rejecting connection on peer-cred check");
                        // Drop without responding.
                        continue;
                    }
                };
                let state = state.clone();
                let cancel_child = cancel.child_token();
                tokio::spawn(async move {
                    if let Err(e) = serve_connection(stream, peer_uid, state, cancel_child).await {
                        warn!(error = %e, "connection ended with error");
                    }
                });
            }
        }
    }
}

/// Serve a single client connection. Reads newline-JSON requests, dispatches
/// to method handlers, writes newline-JSON responses.
async fn serve_connection(
    stream: tokio::net::UnixStream,
    peer_uid: u32,
    state: Arc<DaemonState>,
    cancel: CancellationToken,
) -> anyhow::Result<()> {
    state
        .active_connections
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    state.touch();
    debug!(uid = peer_uid, "connection opened");

    let (reader_half, writer_half) = stream.into_split();
    let mut reader = BufReader::new(reader_half);
    let writer = Arc::new(tokio::sync::Mutex::new(writer_half));

    let in_flight = Arc::new(tokio::sync::Semaphore::new(PER_CONNECTION_INFLIGHT_CAP));

    let mut line = Vec::with_capacity(4096);
    loop {
        line.clear();
        tokio::select! {
            _ = cancel.cancelled() => break,
            n = reader.read_until(b'\n', &mut line) => {
                let n = n.context("read_until")?;
                if n == 0 {
                    // EOF — client closed.
                    break;
                }
                // Strip trailing \n and optional \r.
                if line.ends_with(b"\n") { line.pop(); }
                if line.ends_with(b"\r") { line.pop(); }
                if line.len() > MAX_MESSAGE_BYTES {
                    write_response(&writer, Response::err(
                        "0".into(),
                        &ProtocolError::new(
                            ErrorCode::MessageTooLarge,
                            "message exceeds 16 MiB",
                        ),
                    )).await?;
                    break;
                }
                let req = match parse_request_line(&line) {
                    Ok(r) => r,
                    Err(err) => {
                        // We don't have a request id when parsing fails; use "0".
                        write_response(&writer, Response::err("0".into(), &err)).await?;
                        // INVALID_FRAME is connection-fatal per protocol-v0 §14.
                        if err.code == ErrorCode::InvalidFrame {
                            break;
                        }
                        continue;
                    }
                };
                state.touch();

                // Reserve in-flight slot; if all 16 are busy, BUSY.
                let permit = match in_flight.clone().try_acquire_owned() {
                    Ok(p) => p,
                    Err(_) => {
                        let err = ProtocolError::new(
                            ErrorCode::Busy,
                            "per-connection in-flight cap reached",
                        );
                        write_response(&writer, Response::err(req.id.clone(), &err)).await?;
                        continue;
                    }
                };
                let writer = writer.clone();
                let state = state.clone();
                tokio::spawn(async move {
                    let id = req.id.clone();
                    let resp = dispatch(req, &state).await;
                    let response = match resp {
                        Ok(value) => Response::ok(id, value),
                        Err(err) => Response::err(id, &err),
                    };
                    let _ = write_response(&writer, response).await;
                    drop(permit);
                });
            }
        }
    }

    state
        .active_connections
        .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
    state.touch();
    debug!("connection closed");
    Ok(())
}

async fn dispatch(req: Request, state: &Arc<DaemonState>) -> Result<serde_json::Value, ProtocolError> {
    methods::dispatch(&req.method, req.params, state).await
}

async fn write_response(
    writer: &Arc<tokio::sync::Mutex<tokio::net::unix::OwnedWriteHalf>>,
    resp: Response,
) -> anyhow::Result<()> {
    let line = resp.into_line().context("serialise response")?;
    let mut w = writer.lock().await;
    w.write_all(&line).await.context("write response")?;
    w.flush().await.context("flush response")?;
    Ok(())
}
