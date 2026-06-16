### Fix: cold-start mount race that wedged the daemon

`Workspace.Mount` now serializes its open-the-store critical section. The
idempotency check dropped its lock before `Store::open`'s `.await`, so the
startup prewarm and an explicit `Mount` RPC (or two concurrent RPCs) could
both open the same redb file — redb refused the second open with "Database
already open" and the daemon wedged, returning `STORAGE_FULL` on every
later request until killed. A new `mount_serialize` guard makes mounts
mutually exclusive: the first opens the store; the rest take the idempotent
path (and now correctly hold a mount ref). The guarded wait is
cancel-aware, so a `Daemon.Cancel` no longer hangs a queued mount.
