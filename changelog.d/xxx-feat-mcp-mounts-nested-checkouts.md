### Feat: `rts-mcp` mounts the checkout an absolute path names

Multi-root routing only considered roots the shim already had, so a caller working in a git
worktree got the enclosing repo's index. Measured, with a worktree at `<repo>/.wt/w-c13` and
the shim started with `--workspace <repo>`:
`grep {file_glob: "<repo>/.wt/w-c13/src/**"}` was routed to `<repo>` by rule 1 (the longest
*mounted* prefix), and the repo's index skips `.wt/` — gitignored — so the call came back
`files_scanned: 0`. The absolute path is the documented way to address a worktree, and it
was the one shape that could not work.

`RootSet::resolve` now has a fourth rule: when an absolute argument's longest mounted prefix
is a root that does not *index* it, the deepest ancestor of the argument that holds a `.git`
entry becomes the root and is mounted for the call through the existing
`ConnectionManager::mount_root` path. A `git worktree add` writes a `.git` *file* pointing at
the parent repository's gitdir, so a worktree is detected the same way as a nested clone; the
checkout is canonicalised and must sit under the shim's **start-up root**, so no tool call can
make the shim mount an arbitrary filesystem directory, and it must be strictly deeper than the
root rule 1 matched, so a root that already serves a path keeps it. Ordinary subdirectories,
and paths with no directory of their own, keep today's behaviour exactly; relative paths are
untouched (they exist under every root and carry no information).

`_root` gains a distinct `resolved_by: "mounted"` for that route plus `mounted_now`, which
reports whether *this* call mounted the root or reused a mount an earlier call made — so a
reader can tell a root the shim was started with (`path_match`) from one a call's own path
brought in. No tool gained a `root` parameter; the model still never names a root.
