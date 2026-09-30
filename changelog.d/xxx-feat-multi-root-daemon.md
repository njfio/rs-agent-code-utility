### Multi-root: one daemon (and one `rts-mcp`) serves many workspace roots

A daemon used to be pinned to the first `Workspace.Mount` path — a second
mount of a different path returned `WORKSPACE_MISMATCH`. A swarm of agents in
separate git worktrees therefore needed one daemon per worktree, and every
tool call made against the "wrong" daemon answered from the wrong tree: stale
code, different line numbers, an index that answers a different question than
the one asked.

**`DaemonState` now holds a mount table** (`mounts: Mutex<MountTable>`) instead
of one pinned `workspace` / `store` / `watcher` / `writer_cancel` slot. Each
mounted root owns its index (`${XDG_STATE_HOME}/rts/<workspace_id>/db.redb`),
file watcher, writer task, and persisted-cold-mount decision, and is addressed
by its `workspace_id` (the fingerprint id `Workspace.Mount` already returned).
The per-root refcount keeps the #150 mount/unmount semantics; a root's watcher,
writer, index handle, and entry are released when its last reference goes away,
and the idle-shutdown timer still ends the daemon once nothing is mounted.

**Wire:** the mounted-root selector is `workspace_id` in the request
**envelope** (capability `multi_root`), alongside `cancel_id` / `deadline_ms` —
no method's param schema declares it, and no tool asks the model for a root.
`Workspace.Mount` accepts a second root; `Workspace.Unmount { root }` releases
one (absent → the default root, i.e. the oldest root mounted);
`Workspace.Status { root }` reports one. Both responses carry `mounted_roots`,
so a client can see every root the daemon serves. An `Index.*` call naming an
unmounted root returns `WORKSPACE_MISMATCH` (with the live `mounted_roots` in
`error.data`) rather than a silent substitution.

**`rts-mcp` infers the root per call** from the call's own path arguments
(`file`, `glob`, `file_glob`, `edits[].file`, `claims[].file`): an absolute
path under a mounted root routes there (longest match wins, so
`/repo/.wt/alpha/…` routes to the worktree), a relative path routes only when
exactly one mounted root has it, and a glob routes by its literal prefix. When
nothing resolves — a bare symbol name, or a relative path present under every
root — the call is served by the start-up root and the response says so in a
`_root` block (`path`, `workspace_id`, `resolved_by`, and a `note` on a
default). Absolute path arguments are handed to the daemon in the chosen
root's coordinate system, which is what the daemon's `file`/`file_glob` filters
expect. Extra roots come from repeated `--workspace` flags or `RTS_MCP_ROOTS`
and mount lazily on first use. No tool gained a root parameter.

**Caches are keyed per root.** The outline and symbol-PageRank caches were
keyed on `index_generation` alone; with N roots sitting at the same generation
that would hand one root's answer to another, so both keys now include the
`workspace_id` (the signature and content-version caches already key on
absolute paths).

**Verification:** `cargo test -p rts-daemon -p rts-mcp` — new integration tests
`multi_root_round_trip::one_daemon_serves_two_roots_by_workspace_id` (two roots
with the same symbol defined differently, per-root answers, join/refcount,
unmount of one leaving the other serving, `WORKSPACE_MISMATCH` for a released
root, idle shutdown after the last release) and
`multi_root_routing::mcp_routes_each_tool_call_to_the_root_its_paths_name`
(real `rts-mcp` + daemon over stdio), plus `roots` unit tests for the
resolution rules and path relativisation.
