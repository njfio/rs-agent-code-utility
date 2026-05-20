//! Cooperative cancellation for in-flight requests.
//!
//! See `docs/plans/2026-05-19-001-feat-cancellable-queries-plan.md`.
//!
//! Clients attach an optional `cancel_id: String` to any request and
//! later send `Daemon.Cancel { cancel_id }` to abort it. The dispatcher
//! registers a [`CancelToken`] under that id on request entry, hands it
//! to the handler, and drops the registry entry on completion via a
//! RAII guard so panics also clean up. Handlers cooperatively poll
//! [`CancelToken::is_cancelled`] at hot-loop boundaries (per-match for
//! the structural scanner, per-file/per-match for multiline regex,
//! per-batch for the mount cold walk).
//!
//! The token is a bare `Arc<AtomicBool>` rather than
//! `tokio_util::sync::CancellationToken`: we don't need the
//! parent/child tree machinery, and a single relaxed load is the
//! cheapest possible check inside a tight loop (~1 ns).

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use tokio::sync::RwLock;

/// Cooperative cancellation flag. Cheap to clone (`Arc` bump). Cheap to
/// poll (relaxed atomic load). Single-shot: once cancelled, the flag
/// stays set for the token's lifetime.
#[derive(Clone, Debug, Default)]
pub struct CancelToken(Arc<AtomicBool>);

impl CancelToken {
    /// A fresh, un-cancelled token. Unregistered handlers receive this
    /// (cheap default) so they don't need to branch on `Option`.
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns `true` once any holder has called [`Self::cancel`].
    /// Hot-path callers should use this — one relaxed load per poll.
    #[inline]
    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::Relaxed)
    }

    /// Trip the flag. Idempotent — repeat calls are no-ops.
    pub fn cancel(&self) {
        self.0.store(true, Ordering::Relaxed);
    }
}

/// Daemon-wide registry of in-flight cancellation tokens, keyed by the
/// client-supplied `cancel_id` string. Lookups are short and bounded
/// (one map probe + an `Arc` clone or copy of `bool`) so the `RwLock`
/// is the right shape: writes (register/drop) are rare relative to
/// the cancellation poll on the hot path, which doesn't touch the
/// registry at all.
#[derive(Debug, Default)]
pub struct CancelRegistry {
    inner: RwLock<HashMap<String, CancelToken>>,
}

impl CancelRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register `token` under `cancel_id`. If the id is already in
    /// use the previous token is replaced — clients are responsible
    /// for picking unique ids; a clash means the older request's
    /// `Daemon.Cancel` would target the newer one, which is the
    /// caller's problem, not the daemon's. We do not error here so
    /// the read path stays free of bookkeeping branches.
    pub async fn register(&self, cancel_id: String, token: CancelToken) {
        let mut g = self.inner.write().await;
        g.insert(cancel_id, token);
    }

    /// Remove the entry for `cancel_id`. No-op if absent.
    pub async fn remove(&self, cancel_id: &str) {
        let mut g = self.inner.write().await;
        g.remove(cancel_id);
    }

    /// Trip the token keyed by `cancel_id`. Returns `true` if a token
    /// existed and was tripped; `false` if the id was unknown (either
    /// never registered, already completed, or already removed).
    /// Idempotent — repeat calls are no-ops.
    pub async fn cancel(&self, cancel_id: &str) -> bool {
        let g = self.inner.read().await;
        match g.get(cancel_id) {
            Some(token) => {
                token.cancel();
                true
            }
            None => false,
        }
    }

    /// Number of currently-registered tokens. Surfaced via
    /// `Daemon.Stats.cancellations.in_flight`.
    pub async fn in_flight(&self) -> usize {
        let g = self.inner.read().await;
        g.len()
    }
}

/// RAII guard that removes a token from the registry on drop. Holding
/// one ensures cleanup happens even if the handler panics — without
/// this the registry would slowly leak after every panic'd request,
/// and `cancellations.in_flight` would drift.
///
/// The drop fires a `tokio::spawn` because removal needs the async
/// lock. The spawned future captures owned data and is cheap; it runs
/// promptly once the handler future returns.
pub struct CancelGuard {
    registry: Arc<CancelRegistry>,
    cancel_id: Option<String>,
}

impl CancelGuard {
    /// Register `token` under `cancel_id` and return a guard that will
    /// unregister it on drop. The actual registration is awaited
    /// here; only cleanup runs in the drop path.
    pub async fn register(
        registry: Arc<CancelRegistry>,
        cancel_id: String,
        token: CancelToken,
    ) -> Self {
        registry.register(cancel_id.clone(), token).await;
        Self {
            registry,
            cancel_id: Some(cancel_id),
        }
    }
}

impl Drop for CancelGuard {
    fn drop(&mut self) {
        if let Some(cancel_id) = self.cancel_id.take() {
            let registry = self.registry.clone();
            tokio::spawn(async move {
                registry.remove(&cancel_id).await;
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_starts_uncancelled() {
        let t = CancelToken::new();
        assert!(!t.is_cancelled());
    }

    #[test]
    fn cancel_is_visible_via_clone() {
        let t = CancelToken::new();
        let clone = t.clone();
        assert!(!clone.is_cancelled());
        t.cancel();
        assert!(clone.is_cancelled());
    }

    #[test]
    fn cancel_is_idempotent() {
        let t = CancelToken::new();
        t.cancel();
        t.cancel();
        assert!(t.is_cancelled());
    }

    #[tokio::test]
    async fn registry_cancel_unknown_id_is_false() {
        let r = CancelRegistry::new();
        assert!(!r.cancel("never-registered").await);
    }

    #[tokio::test]
    async fn registry_cancel_trips_registered_token() {
        let r = CancelRegistry::new();
        let token = CancelToken::new();
        r.register("q-1".into(), token.clone()).await;
        assert_eq!(r.in_flight().await, 1);
        assert!(r.cancel("q-1").await);
        assert!(token.is_cancelled());
    }

    #[tokio::test]
    async fn registry_remove_clears_entry() {
        let r = CancelRegistry::new();
        r.register("q-1".into(), CancelToken::new()).await;
        r.remove("q-1").await;
        assert_eq!(r.in_flight().await, 0);
        assert!(!r.cancel("q-1").await);
    }

    #[tokio::test]
    async fn guard_unregisters_on_drop() {
        let r = Arc::new(CancelRegistry::new());
        let token = CancelToken::new();
        {
            let _g = CancelGuard::register(r.clone(), "q-1".into(), token.clone()).await;
            assert_eq!(r.in_flight().await, 1);
        }
        // Drop spawns a cleanup task; yield until it runs.
        for _ in 0..100 {
            if r.in_flight().await == 0 {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(r.in_flight().await, 0);
    }
}
