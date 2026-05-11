//! Shared daemon state.
//!
//! At this phase the state is minimal — a refcount of active workspace mounts
//! and an "active connections" gauge driving the idle-shutdown timer (per
//! `docs/protocol-v0.md` §15.2).

use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Instant;

use crate::workspace::MountedWorkspace;

/// Process-wide daemon state. Cheap to `Arc`-share; everything inside is
/// interior-mutable.
#[derive(Debug)]
pub struct DaemonState {
    /// Number of currently-open client connections. The idle-shutdown timer
    /// only fires when this is 0 *and* `last_activity` is older than the
    /// configured window.
    pub active_connections: AtomicU32,
    /// Last time a connection was accepted or a workspace was mounted. Stored
    /// as a `Mutex<Instant>` rather than an atomic because `Instant` doesn't
    /// have a portable atomic representation; contention is negligible.
    pub last_activity: Mutex<Instant>,
    /// The single workspace this daemon serves. A daemon is workspace-pinned —
    /// the first `Workspace.Mount` decides; subsequent mounts on different
    /// paths return `WorkspaceVanished`. Stored as `Mutex<Option<...>>` so the
    /// accept loop and method handlers can both reach it.
    pub workspace: Mutex<Option<MountedWorkspace>>,
    /// Refcount of `Workspace.Mount` minus `Workspace.Unmount` across all
    /// currently-open connections. When this drops back to 0 with idle time
    /// elapsed, the daemon exits.
    pub mount_refcount: AtomicU32,
    /// Process start time, used only for `Daemon.Ping.uptime_ms`.
    pub started_at: Instant,
    /// Daemon-internal generation counter. Bumps on every committed index
    /// write; later phases expose this via `Workspace.Status.index_generation`.
    /// Currently always 0 (no writer yet).
    pub index_generation: AtomicU64,
}

impl DaemonState {
    pub fn new() -> Self {
        Self {
            active_connections: AtomicU32::new(0),
            last_activity: Mutex::new(Instant::now()),
            workspace: Mutex::new(None),
            mount_refcount: AtomicU32::new(0),
            started_at: Instant::now(),
            index_generation: AtomicU64::new(0),
        }
    }

    /// Bump the activity timestamp. Called on connect, on every method
    /// dispatch, and on mount/unmount.
    pub fn touch(&self) {
        if let Ok(mut last) = self.last_activity.lock() {
            *last = Instant::now();
        }
    }

    /// `(active_connections == 0) && (now - last_activity > window)`.
    pub fn is_idle(&self, window: std::time::Duration) -> bool {
        if self.active_connections.load(Ordering::Relaxed) > 0 {
            return false;
        }
        let last = match self.last_activity.lock() {
            Ok(g) => *g,
            Err(_) => return false,
        };
        last.elapsed() >= window
    }

    pub fn uptime(&self) -> std::time::Duration {
        self.started_at.elapsed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn idle_detection_respects_active_connections() {
        let state = DaemonState::new();
        // A long window with last_activity = now → not idle.
        assert!(!state.is_idle(Duration::from_secs(60)));
        state.active_connections.store(1, Ordering::Relaxed);
        // Active connection blocks idle even when the window has elapsed.
        std::thread::sleep(Duration::from_millis(10));
        assert!(!state.is_idle(Duration::from_millis(1)));
        state.active_connections.store(0, Ordering::Relaxed);
        std::thread::sleep(Duration::from_millis(10));
        assert!(state.is_idle(Duration::from_millis(1)));
    }

    #[test]
    fn touch_resets_activity_window() {
        let state = DaemonState::new();
        std::thread::sleep(Duration::from_millis(15));
        assert!(state.is_idle(Duration::from_millis(10)));
        state.touch();
        // After touch, the window starts over.
        assert!(!state.is_idle(Duration::from_millis(10)));
    }
}
