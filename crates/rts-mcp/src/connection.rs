//! Connection manager — heartbeat, reconnect-with-backoff, structured
//! disconnection state. (Plan
//! `docs/plans/2026-05-19-004-feat-mcp-server-resilience-plan.md`.)
//!
//! ## Motivation
//!
//! Pre-resilience, the rts-mcp shim opened the per-workspace UDS connection
//! once at startup and treated any transport error as fatal. When the
//! daemon's idle-shutdown timer fired or the daemon crashed, the shim would
//! sit on a dead socket; the next tool call returned `Broken pipe` and the
//! MCP host marked the server as disconnected. The reconnect-on-call path
//! added in v0.5.5 (`DaemonClient::reconnect`) covered the *next* tool call
//! after a death, but not:
//!
//! - **Concurrent tool calls during the reconnect window** — they queued on
//!   the mutex and all paid the auto-spawn deadline serially.
//! - **No proactive detection** — a disconnect went undiscovered until the
//!   next tool call; on idle sessions that could be minutes.
//! - **No structured disconnection error** — agents saw `INTERNAL_ERROR
//!   broken pipe`, which is indistinguishable from a daemon bug.
//!
//! The `ConnectionManager` here adds:
//!
//! 1. **Heartbeat loop.** A background task issues `Daemon.Ping` every
//!    `RTS_MCP_HEARTBEAT_INTERVAL_SECS` (default 10s). A failed ping demotes
//!    state to `Reconnecting`.
//! 2. **Reconnect-with-backoff.** When demoted, a background reconnect task
//!    schedules attempts at 1s, 2s, 4s, 8s, 16s, 30s, 30s, 30s
//!    (`RTS_MCP_RECONNECT_MAX_ATTEMPTS`, default 8). After the cap, state
//!    transitions to `Down` but retries continue at the 30s ceiling forever
//!    — transient outages of arbitrary length still recover.
//! 3. **Structured disconnection.** Tool calls hitting non-`Connected`
//!    state return `ConnectionError::DaemonUnavailable { retry_after_ms }`
//!    or `ConnectionError::DaemonDown`. The shim's tool-handler layer
//!    maps these to JSON-RPC error codes `-32098` / `-32097` so agents
//!    can branch on transient vs. sustained outage.
//!
//! ## Heartbeat ↔ idle-shutdown interaction
//!
//! `Daemon.Ping` resets the daemon's `last_activity` timestamp. The daemon
//! only idle-shuts down when `active_connections == 0` AND the activity
//! window has elapsed (`crates/rts-daemon/src/state.rs::is_idle`); the
//! shim's heartbeat keeps `active_connections >= 1` for the lifetime of
//! the shim process, so idle-shutdown is already gated. The heartbeat
//! additionally bumps `last_activity` so a future change that loosens the
//! connection-count gate (e.g. counting only *recent* connections) still
//! sees fresh traffic. **An MCP shim that's still attached keeps its
//! daemon alive — this is intentional.**
//!
//! ## State machine
//!
//! ```text
//!  ┌──────────────┐  heartbeat ok / call ok    ┌──────────────┐
//!  │              │ ──────────────────────────►│              │
//!  │  Connected   │                            │  Reconnecting│
//!  │              │ ◄──────────────────────────│              │
//!  └──────┬───────┘  ping/call transport err   └──────┬───────┘
//!         │                                           │
//!         │                                           │ max_attempts
//!         │                                           │ exhausted
//!         │                                           ▼
//!         │                                    ┌──────────────┐
//!         │  ceiling reconnect succeeds        │              │
//!         └─────────────────────────────◄──────│     Down     │
//!                                              │              │
//!                                              └──────────────┘
//! ```

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use serde_json::{Value, json};
use tokio::net::UnixStream;
use tokio::sync::{Mutex, RwLock};
use tokio::time::Instant;
use tracing::{debug, info, warn};

use crate::daemon_client::{DaemonClient, DaemonError};
use crate::socket;

/// JSON-RPC error code for transient daemon unavailability — the daemon
/// is in the middle of reconnect. Carries a `retry_after_ms` hint.
///
/// Numeric: matches the plan's `-32098`. Per JSON-RPC 2.0, codes in
/// the range `-32099..=-32000` are reserved for implementation-defined
/// errors; we use the high end of that range for our transport-layer
/// concerns to avoid clashing with the daemon's `-32099` `CANCELLED`
/// (which is application-level, surfaced through a different field).
pub const DAEMON_UNAVAILABLE_CODE: i32 = -32098;

/// JSON-RPC error code for sustained daemon outage — the reconnect
/// loop has exhausted its bounded attempts but continues to retry at
/// the ceiling interval. Agents seeing this code should surface to the
/// user.
pub const DAEMON_DOWN_CODE: i32 = -32097;

/// Stable string code mirroring [`DAEMON_UNAVAILABLE_CODE`]. The shim
/// returns this in the `error.code` field so agents that match on
/// strings (existing pattern across protocol-v0 §14) can branch on it.
pub const DAEMON_UNAVAILABLE_STRING: &str = "DAEMON_UNAVAILABLE";

/// Stable string code mirroring [`DAEMON_DOWN_CODE`].
pub const DAEMON_DOWN_STRING: &str = "DAEMON_DOWN";

/// Default heartbeat interval (override via `RTS_MCP_HEARTBEAT_INTERVAL_SECS`).
const DEFAULT_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(10);
/// Default per-ping timeout (override via `RTS_MCP_HEARTBEAT_TIMEOUT_SECS`).
const DEFAULT_HEARTBEAT_TIMEOUT: Duration = Duration::from_secs(3);
/// Default max reconnect attempts before transitioning to `Down`
/// (override via `RTS_MCP_RECONNECT_MAX_ATTEMPTS`).
const DEFAULT_MAX_RECONNECT_ATTEMPTS: u32 = 8;
/// Backoff ceiling (override via `RTS_MCP_RECONNECT_CEILING_SECS`).
const DEFAULT_RECONNECT_CEILING: Duration = Duration::from_secs(30);

/// Resilience knobs. All have defaults; nothing requires user setup.
#[derive(Debug, Clone)]
pub struct ResilienceConfig {
    pub heartbeat_interval: Duration,
    pub heartbeat_timeout: Duration,
    pub max_reconnect_attempts: u32,
    pub reconnect_ceiling: Duration,
}

impl Default for ResilienceConfig {
    fn default() -> Self {
        Self {
            heartbeat_interval: DEFAULT_HEARTBEAT_INTERVAL,
            heartbeat_timeout: DEFAULT_HEARTBEAT_TIMEOUT,
            max_reconnect_attempts: DEFAULT_MAX_RECONNECT_ATTEMPTS,
            reconnect_ceiling: DEFAULT_RECONNECT_CEILING,
        }
    }
}

impl ResilienceConfig {
    /// Load knobs from `RTS_MCP_HEARTBEAT_*` / `RTS_MCP_RECONNECT_*` env
    /// vars, falling back to the documented defaults on parse failure.
    /// Parse failures emit a `warn` so misconfiguration is loud.
    pub fn from_env() -> Self {
        let mut cfg = Self::default();
        if let Some(v) = env_secs("RTS_MCP_HEARTBEAT_INTERVAL_SECS") {
            cfg.heartbeat_interval = v;
        }
        if let Some(v) = env_secs("RTS_MCP_HEARTBEAT_TIMEOUT_SECS") {
            cfg.heartbeat_timeout = v;
        }
        if let Some(v) = env_u32("RTS_MCP_RECONNECT_MAX_ATTEMPTS") {
            cfg.max_reconnect_attempts = v;
        }
        if let Some(v) = env_secs("RTS_MCP_RECONNECT_CEILING_SECS") {
            cfg.reconnect_ceiling = v;
        }
        cfg
    }
}

fn env_secs(key: &str) -> Option<Duration> {
    match std::env::var(key) {
        Ok(s) => match s.parse::<u64>() {
            Ok(n) if n > 0 => Some(Duration::from_secs(n)),
            Ok(_) => {
                warn!(target: "rts_mcp::connection", "{key}=0 ignored; using default");
                None
            }
            Err(e) => {
                warn!(target: "rts_mcp::connection", "{key} parse failed ({e}); using default");
                None
            }
        },
        Err(_) => None,
    }
}

fn env_u32(key: &str) -> Option<u32> {
    match std::env::var(key) {
        Ok(s) => match s.parse::<u32>() {
            Ok(n) => Some(n),
            Err(e) => {
                warn!(target: "rts_mcp::connection", "{key} parse failed ({e}); using default");
                None
            }
        },
        Err(_) => None,
    }
}

/// Connection-manager state. Stored behind `Arc<RwLock<…>>`; heartbeat
/// takes the write lock briefly to transition, tool-call sites take the
/// read lock to inspect.
///
/// The `DaemonClient` socket itself lives in a separate `Arc<Mutex<…>>`
/// — see the module-level docs for why the plan's "socket lives inside
/// the enum" sketch was relaxed.
#[derive(Debug, Clone)]
pub enum ConnectionState {
    /// Connection live; last ping succeeded within the heartbeat
    /// window. Tool calls forward through.
    Connected {
        /// Wall-clock instant of the most recent successful ping or
        /// tool call. Exposed mostly for diagnostics.
        last_pong_at: Instant,
    },
    /// Reconnect in flight. Tool calls return `DAEMON_UNAVAILABLE`
    /// with a `retry_after_ms` derived from `next_retry_at`.
    Reconnecting {
        attempt: u32,
        next_retry_at: Instant,
        last_error: String,
    },
    /// Reconnect attempts exhausted. Tool calls return `DAEMON_DOWN`.
    /// The reconnect loop continues at the ceiling interval; recovery
    /// promotes back to `Connected` automatically.
    Down {
        first_failure_at: Instant,
        last_error: String,
    },
}

impl ConnectionState {
    fn new_connected() -> Self {
        Self::Connected {
            last_pong_at: Instant::now(),
        }
    }

    fn is_connected(&self) -> bool {
        matches!(self, ConnectionState::Connected { .. })
    }
}

/// Error surface for `ConnectionManager::call`. Two new variants
/// (`DaemonUnavailable`, `DaemonDown`) carry the structured
/// disconnection state; `Daemon` wraps the underlying
/// [`DaemonError`] for everything that landed on the socket and came
/// back with a typed error.
#[derive(Debug, Clone)]
pub enum ConnectionError {
    /// Daemon socket is down and reconnect is in progress. `retry_after_ms`
    /// is the wall-clock time until the next reconnect attempt is
    /// scheduled. Agents should retry the call after that delay.
    DaemonUnavailable {
        retry_after_ms: u64,
        attempt: u32,
        last_error: String,
    },
    /// Reconnect attempts have been exhausted; ceiling-interval retries
    /// continue but the daemon has been unreachable long enough that the
    /// agent should surface this to the user. The state can still recover
    /// — a subsequent successful retry returns the manager to `Connected`.
    DaemonDown {
        first_failure_ms_ago: u64,
        last_error: String,
    },
    /// Daemon returned a structured `error` envelope (e.g.
    /// `INDEX_NOT_READY`, `OUT_OF_ROOT`).
    Daemon(DaemonError),
}

impl ConnectionError {
    /// Stable string code suitable for the `error.code` field of an MCP
    /// `CallToolResult::error` body.
    pub fn code(&self) -> &str {
        match self {
            ConnectionError::DaemonUnavailable { .. } => DAEMON_UNAVAILABLE_STRING,
            ConnectionError::DaemonDown { .. } => DAEMON_DOWN_STRING,
            ConnectionError::Daemon(e) => &e.code,
        }
    }

    /// Human-readable message. For `DaemonUnavailable` / `DaemonDown`
    /// this is built to be unambiguously transient/sustained so the
    /// agent doesn't mistake either for "tool doesn't exist."
    pub fn message(&self) -> String {
        match self {
            ConnectionError::DaemonUnavailable {
                retry_after_ms,
                attempt,
                last_error,
            } => format!(
                "rts-daemon temporarily unavailable (reconnect attempt {attempt}); \
                 retry in {retry_after_ms}ms. Last error: {last_error}"
            ),
            ConnectionError::DaemonDown {
                first_failure_ms_ago,
                last_error,
            } => format!(
                "rts-daemon has been unreachable for {first_failure_ms_ago}ms after \
                 exhausting reconnect attempts; ceiling-interval retries continue. \
                 Last error: {last_error}"
            ),
            ConnectionError::Daemon(e) => e.message.clone(),
        }
    }

    /// Structured payload for the MCP `error.data` slot. For transient
    /// disconnects this carries `retry_after_ms` so agents can back off
    /// without parsing the message string.
    pub fn data(&self) -> Value {
        match self {
            ConnectionError::DaemonUnavailable {
                retry_after_ms,
                attempt,
                last_error,
            } => json!({
                "retry_after_ms": retry_after_ms,
                "attempt": attempt,
                "last_error": last_error,
                "transient": true,
            }),
            ConnectionError::DaemonDown {
                first_failure_ms_ago,
                last_error,
            } => json!({
                "first_failure_ms_ago": first_failure_ms_ago,
                "last_error": last_error,
                "transient": false,
            }),
            ConnectionError::Daemon(e) => e.data.clone().unwrap_or(Value::Null),
        }
    }

    /// True iff the error indicates the manager is in a non-Connected
    /// state. Used by tests and diagnostics.
    pub fn is_disconnection(&self) -> bool {
        matches!(
            self,
            ConnectionError::DaemonUnavailable { .. } | ConnectionError::DaemonDown { .. }
        )
    }
}

impl std::fmt::Display for ConnectionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}] {}", self.code(), self.message())
    }
}

impl std::error::Error for ConnectionError {}

/// Compute the reconnect delay for a given attempt count. Schedule:
/// `1s, 2s, 4s, 8s, 16s, 30s, 30s, …` (ceiling at
/// `cfg.reconnect_ceiling`). `attempt` is 1-indexed.
fn backoff_for_attempt(attempt: u32, ceiling: Duration) -> Duration {
    // 2^(attempt-1) seconds, capped at ceiling. Saturating arithmetic
    // so absurd attempt counts never panic.
    let secs = 1u64
        .checked_shl(attempt.saturating_sub(1))
        .unwrap_or(u64::MAX);
    let raw = Duration::from_secs(secs);
    if raw > ceiling { ceiling } else { raw }
}

/// Long-lived connection manager. Owns the socket (via a `DaemonClient`
/// inside an `Arc<Mutex<…>>`) and a background heartbeat / reconnect
/// task. `clone()` is cheap (`Arc` clones); the same manager is shared
/// by the MCP server's tool handlers.
#[derive(Clone)]
pub struct ConnectionManager {
    inner: Arc<Inner>,
}

struct Inner {
    /// Owning handle to the live socket. Tool calls take this mutex
    /// briefly per call. Heartbeat / reconnect tasks take it too.
    daemon: Arc<Mutex<DaemonClient>>,
    /// Connection-state metadata. Separate from `daemon` so heartbeat
    /// status reads don't serialize behind a long-running tool call.
    state: Arc<RwLock<ConnectionState>>,
    /// Path to `rts-daemon` for re-auto-spawn on reconnect.
    daemon_bin: PathBuf,
    /// Canonical workspace path — required for per-workspace socket
    /// resolution + Mount on the reconnected daemon.
    workspace: PathBuf,
    /// Heartbeat / reconnect knobs.
    config: ResilienceConfig,
    /// `true` when the background tasks have been spawned. Set in
    /// `start_background_tasks`; checked by `Drop` to skip aborting
    /// non-existent handles.
    background_started: std::sync::atomic::AtomicBool,
    /// Handles to the background tasks so `Drop` can abort them; the
    /// daemon stays up but the shim's tasks shouldn't outlive the
    /// manager.
    heartbeat_handle: Mutex<Option<tokio::task::JoinHandle<()>>>,
    reconnect_handle: Mutex<Option<tokio::task::JoinHandle<()>>>,
    /// `Workspace.Mount` sentinel — cleared on reconnect, set on first
    /// successful Mount. Mirrors `RtsServer.mounted` but lives here so
    /// the CLI can reuse the manager without re-implementing the
    /// lazy-mount handshake. v0.6 keeps Mount idempotent on the
    /// daemon, so multiple sets across reconnects are safe.
    mounted: std::sync::atomic::AtomicBool,
    /// Wakes the reconnect task when a foreground tool call observes
    /// a transport error and demotes the state. Without this, the
    /// reconnect loop would sleep through the heartbeat interval
    /// before noticing.
    reconnect_signal: tokio::sync::Notify,
}

impl ConnectionManager {
    /// Build a manager around an already-open `DaemonClient`. Spawns
    /// the background heartbeat + reconnect tasks immediately when
    /// `start_background_tasks: true`.
    ///
    /// CLI callers pass `start_background_tasks: false` to skip the
    /// heartbeat — a single-shot CLI doesn't need it and shouldn't
    /// leak a task. The reconnect path still fires synchronously on
    /// the next `call()` if needed (matching pre-resilience behavior).
    pub fn new(
        client: DaemonClient,
        daemon_bin: PathBuf,
        workspace: PathBuf,
        config: ResilienceConfig,
        start_background_tasks: bool,
    ) -> Self {
        let inner = Arc::new(Inner {
            daemon: Arc::new(Mutex::new(client)),
            state: Arc::new(RwLock::new(ConnectionState::new_connected())),
            daemon_bin,
            workspace,
            config,
            background_started: std::sync::atomic::AtomicBool::new(false),
            heartbeat_handle: Mutex::new(None),
            reconnect_handle: Mutex::new(None),
            mounted: std::sync::atomic::AtomicBool::new(false),
            reconnect_signal: tokio::sync::Notify::new(),
        });
        let mgr = Self { inner };
        if start_background_tasks {
            mgr.start_background_tasks();
        }
        mgr
    }

    /// Spawn the heartbeat and reconnect tasks. Idempotent — the second
    /// call is a no-op (the `background_started` flag gates it).
    pub fn start_background_tasks(&self) {
        if self
            .inner
            .background_started
            .swap(true, std::sync::atomic::Ordering::AcqRel)
        {
            return;
        }
        let hb = tokio::spawn(heartbeat_loop(self.inner.clone()));
        let rc = tokio::spawn(reconnect_loop(self.inner.clone()));
        // Stash the handles for abort-on-drop. We use try_lock since
        // we just allocated these and nothing else holds the mutex.
        if let Ok(mut g) = self.inner.heartbeat_handle.try_lock() {
            *g = Some(hb);
        }
        if let Ok(mut g) = self.inner.reconnect_handle.try_lock() {
            *g = Some(rc);
        }
    }

    /// Snapshot the current state. Cheap read-lock.
    pub async fn state(&self) -> ConnectionState {
        self.inner.state.read().await.clone()
    }

    /// Cheap synchronous check: are we Connected? Used by the MCP
    /// tool layer to short-circuit on `DAEMON_UNAVAILABLE`/`DAEMON_DOWN`
    /// without taking the daemon mutex.
    pub async fn is_connected(&self) -> bool {
        self.inner.state.read().await.is_connected()
    }

    /// Forward a daemon RPC, transparently handling the
    /// `Workspace.Mount` lazy handshake. Returns the JSON result on
    /// success, a structured `ConnectionError` on failure.
    ///
    /// **Behavior:**
    /// 1. If state is `Reconnecting` or `Down`, returns the matching
    ///    `ConnectionError` immediately without touching the socket
    ///    (no thundering-herd on the daemon-mutex during a known
    ///    disconnect window).
    /// 2. If state is `Connected`, acquires the daemon mutex, ensures
    ///    `Workspace.Mount` has been called (lazy), forwards the call.
    /// 3. On a transport-shaped `DaemonError`, demotes state to
    ///    `Reconnecting` and returns `DaemonUnavailable`. The
    ///    background reconnect task picks it up. The caller does NOT
    ///    retry here — pre-resilience the retry was bounded inline,
    ///    but the new design uses the manager's state machine
    ///    explicitly so concurrent callers all see consistent state.
    pub async fn call(&self, method: &str, params: Value) -> Result<Value, ConnectionError> {
        // 1. Fast-path state check. If we're not Connected, return the
        //    structured error without acquiring the daemon mutex.
        {
            let st = self.inner.state.read().await;
            match &*st {
                ConnectionState::Reconnecting {
                    attempt,
                    next_retry_at,
                    last_error,
                } => {
                    let now = Instant::now();
                    let retry_after_ms = if *next_retry_at > now {
                        (*next_retry_at - now).as_millis() as u64
                    } else {
                        0
                    };
                    return Err(ConnectionError::DaemonUnavailable {
                        retry_after_ms,
                        attempt: *attempt,
                        last_error: last_error.clone(),
                    });
                }
                ConnectionState::Down {
                    first_failure_at,
                    last_error,
                } => {
                    return Err(ConnectionError::DaemonDown {
                        first_failure_ms_ago: first_failure_at.elapsed().as_millis() as u64,
                        last_error: last_error.clone(),
                    });
                }
                ConnectionState::Connected { .. } => { /* fall through */ }
            }
        }

        // 2. Connected path. Acquire daemon, ensure Mount, forward call.
        let mut guard = self.inner.daemon.lock().await;
        if !self
            .inner
            .mounted
            .load(std::sync::atomic::Ordering::Acquire)
        {
            match guard
                .call("Workspace.Mount", json!({ "root": self.inner.workspace }))
                .await
            {
                Ok(_) => {
                    self.inner
                        .mounted
                        .store(true, std::sync::atomic::Ordering::Release);
                }
                Err(e) if e.is_disconnect() => {
                    drop(guard);
                    self.demote_to_reconnecting(format!(
                        "Workspace.Mount transport error: {}",
                        e.message
                    ))
                    .await;
                    return Err(self
                        .unavailable_now(format!("Mount failed: {}", e.message))
                        .await);
                }
                Err(e) => return Err(ConnectionError::Daemon(e)),
            }
        }

        match guard.call(method, params).await {
            Ok(v) => {
                // Successful call counts as a fresh heartbeat — bump
                // last_pong_at so we don't waste a ping on a known-live
                // socket. Take write-lock briefly.
                drop(guard);
                self.bump_pong().await;
                Ok(v)
            }
            Err(e) if e.is_disconnect() => {
                drop(guard);
                self.demote_to_reconnecting(format!("{} transport error: {}", method, e.message))
                    .await;
                Err(self
                    .unavailable_now(format!("{} failed: {}", method, e.message))
                    .await)
            }
            Err(e) => Err(ConnectionError::Daemon(e)),
        }
    }

    /// Refresh `last_pong_at` without changing the discriminant. No-op
    /// when state is non-Connected.
    async fn bump_pong(&self) {
        let mut st = self.inner.state.write().await;
        if matches!(&*st, ConnectionState::Connected { .. }) {
            *st = ConnectionState::Connected {
                last_pong_at: Instant::now(),
            };
        }
    }

    /// Foreground demote: a tool call hit a transport error. Sets the
    /// state to `Reconnecting{attempt:1, next_retry_at: now+1s}` and
    /// signals the reconnect task. Idempotent — if we're already
    /// reconnecting, leaves the attempt counter alone (the reconnect
    /// task owns it).
    async fn demote_to_reconnecting(&self, reason: String) {
        let mut st = self.inner.state.write().await;
        match &*st {
            ConnectionState::Reconnecting { .. } | ConnectionState::Down { .. } => {
                // Already non-Connected; nothing to do.
                return;
            }
            ConnectionState::Connected { .. } => {
                warn!(
                    target: "rts_mcp::connection",
                    "daemon disconnect detected; entering reconnect ({reason})"
                );
                // Clear the Mount sentinel — the next successful
                // reconnect will need a fresh Mount on the new daemon.
                self.inner
                    .mounted
                    .store(false, std::sync::atomic::Ordering::Release);
                *st = ConnectionState::Reconnecting {
                    attempt: 1,
                    next_retry_at: Instant::now() + Duration::from_secs(1),
                    last_error: reason,
                };
            }
        }
        drop(st);
        // Kick the reconnect loop awake immediately.
        self.inner.reconnect_signal.notify_one();
    }

    /// Read the current state and build a `DaemonUnavailable` error
    /// reflecting where in the reconnect schedule we are. Caller has
    /// just demoted us, so this is guaranteed to find `Reconnecting`
    /// (or, in a rare race with the reconnect task, `Down`).
    async fn unavailable_now(&self, fallback_msg: String) -> ConnectionError {
        let st = self.inner.state.read().await;
        match &*st {
            ConnectionState::Reconnecting {
                attempt,
                next_retry_at,
                last_error,
            } => {
                let now = Instant::now();
                let retry_after_ms = if *next_retry_at > now {
                    (*next_retry_at - now).as_millis() as u64
                } else {
                    0
                };
                ConnectionError::DaemonUnavailable {
                    retry_after_ms,
                    attempt: *attempt,
                    last_error: last_error.clone(),
                }
            }
            ConnectionState::Down {
                first_failure_at,
                last_error,
            } => ConnectionError::DaemonDown {
                first_failure_ms_ago: first_failure_at.elapsed().as_millis() as u64,
                last_error: last_error.clone(),
            },
            ConnectionState::Connected { .. } => {
                // Lost a race with the reconnect task. Surface the
                // original fallback message.
                ConnectionError::DaemonUnavailable {
                    retry_after_ms: 0,
                    attempt: 0,
                    last_error: fallback_msg,
                }
            }
        }
    }

    /// Test/diagnostics helper: snapshot the daemon binary path.
    #[doc(hidden)]
    pub fn daemon_bin_path(&self) -> &std::path::Path {
        &self.inner.daemon_bin
    }
}

impl std::fmt::Debug for ConnectionManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnectionManager")
            .field("workspace", &self.inner.workspace)
            .field("daemon_bin", &self.inner.daemon_bin)
            .field("config", &self.inner.config)
            .finish()
    }
}

impl Drop for Inner {
    fn drop(&mut self) {
        // Abort the background tasks if they were spawned. `try_lock`
        // because we're in `drop` and can't await. Aborting an already-
        // finished JoinHandle is a no-op.
        if let Ok(mut g) = self.heartbeat_handle.try_lock() {
            if let Some(h) = g.take() {
                h.abort();
            }
        }
        if let Ok(mut g) = self.reconnect_handle.try_lock() {
            if let Some(h) = g.take() {
                h.abort();
            }
        }
    }
}

/// Heartbeat task — runs in the background, demotes state on ping
/// failure, promotes back on ping success.
async fn heartbeat_loop(inner: Arc<Inner>) {
    let interval = inner.config.heartbeat_interval;
    let timeout = inner.config.heartbeat_timeout;
    debug!(
        target: "rts_mcp::connection",
        "heartbeat task started (interval={interval:?}, timeout={timeout:?})"
    );

    loop {
        tokio::time::sleep(interval).await;

        // Only ping when we believe we're Connected. While reconnecting,
        // the reconnect task is in charge.
        let connected = inner.state.read().await.is_connected();
        if !connected {
            continue;
        }

        let ping_res = {
            let mut guard = inner.daemon.lock().await;
            tokio::time::timeout(timeout, guard.call("Daemon.Ping", json!({}))).await
        };
        match ping_res {
            Ok(Ok(_)) => {
                // Reset last_pong_at.
                let mut st = inner.state.write().await;
                if matches!(&*st, ConnectionState::Connected { .. }) {
                    *st = ConnectionState::new_connected();
                }
            }
            Ok(Err(e)) => {
                warn!(
                    target: "rts_mcp::connection",
                    "heartbeat ping returned error ({}); demoting",
                    e.message
                );
                demote_inner(&inner, format!("heartbeat ping error: {}", e.message)).await;
                inner.reconnect_signal.notify_one();
            }
            Err(_) => {
                warn!(
                    target: "rts_mcp::connection",
                    "heartbeat ping timed out after {timeout:?}; demoting"
                );
                demote_inner(&inner, format!("heartbeat ping timeout {timeout:?}")).await;
                inner.reconnect_signal.notify_one();
            }
        }
    }
}

/// Background reconnect task — sleeps until either the heartbeat /
/// foreground call demotes state, then steps the backoff schedule
/// until reconnect succeeds.
async fn reconnect_loop(inner: Arc<Inner>) {
    debug!(target: "rts_mcp::connection", "reconnect task started");
    loop {
        // Wait until someone signals a disconnect. The notify is
        // edge-triggered with one permit, so spurious wakes are
        // possible; we re-check state below.
        inner.reconnect_signal.notified().await;

        loop {
            // Snapshot state. If we're already Connected (e.g. heartbeat
            // raced ahead), exit the inner loop and wait for the next
            // signal.
            let (next_retry_at, attempt) = {
                let st = inner.state.read().await;
                match &*st {
                    ConnectionState::Reconnecting {
                        next_retry_at,
                        attempt,
                        ..
                    } => (*next_retry_at, *attempt),
                    ConnectionState::Down { .. } => {
                        // Sleep at ceiling and try again.
                        let ceiling = inner.config.reconnect_ceiling;
                        (
                            Instant::now() + ceiling,
                            inner.config.max_reconnect_attempts + 1,
                        )
                    }
                    ConnectionState::Connected { .. } => break,
                }
            };

            let now = Instant::now();
            if next_retry_at > now {
                tokio::time::sleep(next_retry_at - now).await;
            }

            // Attempt the reconnect.
            let attempt_res = try_reconnect(&inner).await;
            match attempt_res {
                Ok(()) => {
                    let mut st = inner.state.write().await;
                    if !matches!(&*st, ConnectionState::Connected { .. }) {
                        info!(
                            target: "rts_mcp::connection",
                            "reconnect succeeded on attempt {attempt}"
                        );
                    }
                    *st = ConnectionState::new_connected();
                    // Mount sentinel was cleared on demote; the next
                    // tool call will re-Mount the fresh daemon.
                    break;
                }
                Err(e) => {
                    let next_attempt = attempt.saturating_add(1);
                    let mut st = inner.state.write().await;
                    if next_attempt > inner.config.max_reconnect_attempts {
                        match &*st {
                            ConnectionState::Down { .. } => {
                                // Already Down; update last_error and
                                // continue retrying at ceiling.
                                *st = ConnectionState::Down {
                                    first_failure_at: match &*st {
                                        ConnectionState::Down {
                                            first_failure_at, ..
                                        } => *first_failure_at,
                                        _ => Instant::now(),
                                    },
                                    last_error: e.to_string(),
                                };
                            }
                            ConnectionState::Reconnecting { .. } => {
                                warn!(
                                    target: "rts_mcp::connection",
                                    "reconnect exhausted after {} attempts; transitioning to Down ({})",
                                    inner.config.max_reconnect_attempts,
                                    e
                                );
                                *st = ConnectionState::Down {
                                    first_failure_at: Instant::now(),
                                    last_error: e.to_string(),
                                };
                            }
                            ConnectionState::Connected { .. } => {
                                // Raced with another task that promoted
                                // us. Trust the promotion.
                                break;
                            }
                        }
                    } else {
                        let backoff =
                            backoff_for_attempt(next_attempt, inner.config.reconnect_ceiling);
                        debug!(
                            target: "rts_mcp::connection",
                            "reconnect attempt {attempt} failed ({e}); next in {backoff:?}"
                        );
                        *st = ConnectionState::Reconnecting {
                            attempt: next_attempt,
                            next_retry_at: Instant::now() + backoff,
                            last_error: e.to_string(),
                        };
                    }
                }
            }
        }
    }
}

async fn demote_inner(inner: &Inner, reason: String) {
    let mut st = inner.state.write().await;
    if let ConnectionState::Connected { .. } = &*st {
        inner
            .mounted
            .store(false, std::sync::atomic::Ordering::Release);
        *st = ConnectionState::Reconnecting {
            attempt: 1,
            next_retry_at: Instant::now() + Duration::from_secs(1),
            last_error: reason,
        };
    }
}

/// Open a fresh UDS connection (auto-spawning the daemon if needed),
/// send one `Daemon.Ping`, and on success swap it into the manager's
/// `DaemonClient`. Returns `Ok(())` on success.
async fn try_reconnect(inner: &Inner) -> Result<(), String> {
    let stream: UnixStream =
        socket::connect_with_auto_spawn(&inner.daemon_bin, Some(&inner.workspace))
            .await
            .map_err(|e| format!("auto-spawn: {e:#}"))?;
    // Swap the new stream into the existing DaemonClient by building
    // a fresh client and replacing the contents of the mutex.
    let new_client = DaemonClient::new(stream, inner.daemon_bin.clone(), inner.workspace.clone());
    // Quick `Daemon.Ping` on the new client to confirm it speaks. We
    // do this *after* the mutex swap so the ping uses the new socket
    // and any failure surfaces here, not on the next tool call.
    {
        let mut guard = inner.daemon.lock().await;
        *guard = new_client;
        guard
            .call("Daemon.Ping", json!({}))
            .await
            .map_err(|e| format!("ping after reconnect: {}", e.message))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_schedule_matches_spec() {
        let c = Duration::from_secs(30);
        assert_eq!(backoff_for_attempt(1, c), Duration::from_secs(1));
        assert_eq!(backoff_for_attempt(2, c), Duration::from_secs(2));
        assert_eq!(backoff_for_attempt(3, c), Duration::from_secs(4));
        assert_eq!(backoff_for_attempt(4, c), Duration::from_secs(8));
        assert_eq!(backoff_for_attempt(5, c), Duration::from_secs(16));
        assert_eq!(backoff_for_attempt(6, c), Duration::from_secs(30));
        assert_eq!(backoff_for_attempt(7, c), Duration::from_secs(30));
        assert_eq!(backoff_for_attempt(8, c), Duration::from_secs(30));
        // Defensive: absurd attempt counts cap at the ceiling, no panic.
        assert_eq!(backoff_for_attempt(64, c), Duration::from_secs(30));
        assert_eq!(backoff_for_attempt(u32::MAX, c), Duration::from_secs(30));
    }

    #[test]
    fn connection_error_codes_round_trip_strings() {
        let e = ConnectionError::DaemonUnavailable {
            retry_after_ms: 500,
            attempt: 2,
            last_error: "x".into(),
        };
        assert_eq!(e.code(), DAEMON_UNAVAILABLE_STRING);
        assert!(e.is_disconnection());
        let body = e.data();
        assert_eq!(body["retry_after_ms"], 500);
        assert_eq!(body["attempt"], 2);
        assert_eq!(body["transient"], true);

        let d = ConnectionError::DaemonDown {
            first_failure_ms_ago: 100_000,
            last_error: "y".into(),
        };
        assert_eq!(d.code(), DAEMON_DOWN_STRING);
        assert!(d.is_disconnection());
        let body = d.data();
        assert_eq!(body["first_failure_ms_ago"], 100_000);
        assert_eq!(body["transient"], false);
    }

    #[test]
    fn resilience_config_defaults_are_documented() {
        let cfg = ResilienceConfig::default();
        assert_eq!(cfg.heartbeat_interval, Duration::from_secs(10));
        assert_eq!(cfg.heartbeat_timeout, Duration::from_secs(3));
        assert_eq!(cfg.max_reconnect_attempts, 8);
        assert_eq!(cfg.reconnect_ceiling, Duration::from_secs(30));
    }

    // Note on env-driven config: `ResilienceConfig::from_env` reads
    // process-global env vars and Rust 2024 made `set_var`/`remove_var`
    // `unsafe`. Workspace lints deny `unsafe_code`, so we cannot mutate
    // env in unit tests. Coverage for env parsing lives in the
    // integration tests (`tests/connection_resilience.rs`), which set
    // env vars on the subprocess they spawn.
}
