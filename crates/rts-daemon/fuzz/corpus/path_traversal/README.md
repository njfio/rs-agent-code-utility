# `path_traversal` adversarial-input corpus

Seeds covering the path-traversal threat model. These are NOT consumed
by a libFuzzer harness directly (no fuzz target for `Workspace.Mount`
ships in this PR — the path resolution is an OS syscall, not a parse,
so libFuzzer would mostly find `ENOENT`). They're consumed by the
proptest property `path_canonicalization_never_escapes_root` in
`crates/rts-daemon/tests/adversarial_proptest.rs`, which fires each
seed against a real daemon and asserts the canonicalisation either
succeeds with the workspace's canonical root OR rejects with a
documented error code.

## What's covered

| File | Class | Why |
|---|---|---|
| `etc_passwd_relative` | dotdot escape | `../../../etc/passwd` — the classic relative-path escape. Daemon refuses any `..` segments. |
| `etc_passwd_absolute` | absolute escape | `/etc/passwd` — absolute path outside the mounted workspace. |
| `dev_zero` | special file | `/dev/zero` — infinite-bytes character device; canonicalize should not return it as a workspace. |
| `proc_self_mem` | special file | `/proc/self/mem` — Linux process memory; never legitimate. |
| `dotdot_chain_long` | escape from very deep | 18 layers of `..` to root + passwd. Tests the `..` refusal is depth-independent. |

## Promise validated

RESILIENCE.md §"Path traversal".
