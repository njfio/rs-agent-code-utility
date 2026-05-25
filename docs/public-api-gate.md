# Public-API drift gate

Two `cargo test`-time checks lock the public Rust API of the
workspace's library crates (`rust_tree_sitter` / rts-core and
`rts_mcp`). Any change to a public item — added, removed, renamed,
or re-typed — fails the corresponding test until the snapshot is
regenerated and committed in the same PR.

The pattern is the cargo-public-api library's [canonical CI
recipe][cargo-public-api]: a Rust test using
`public_api::assert_eq_or_update`, no separate CI workflow. The
test runs as part of `cargo test --workspace` — the workspace's
existing CI invocation picks it up automatically. This mirrors PR
\#122's schema-drift gate for the daemon's protocol surface.

[cargo-public-api]: https://github.com/cargo-public-api/cargo-public-api

## Where the gate lives

| Crate | Test file | Snapshot file |
|-------|-----------|---------------|
| `rust_tree_sitter` (rts-core) | `crates/rts-core/tests/public_api.rs` | `crates/rts-core/tests/snapshots/public-api.txt` |
| `rts_mcp` | `crates/rts-mcp/tests/public_api.rs` | `crates/rts-mcp/tests/snapshots/public-api.txt` |

`rts-daemon` and `rts-bench` are not gated: the daemon is binary-
only with no library surface, and `rts-bench`'s lib surface is
internal scaffolding for the bench binary (no out-of-crate
consumers).

## What the gate catches

The snapshot files render every `pub` item the crate exposes —
modules, types, functions, traits, impls, constants, generic
bounds, and re-exports — at a stability level matching what
[`cargo public-api`][cargo-public-api] would print. A change to any
of those surfaces produces a unified diff against the committed
snapshot and a failed test.

Specifically:

- A new `pub fn` / `pub struct` / `pub mod` → diff line added
- A removed or renamed public item → diff line removed
- A changed signature (parameter type, return type, generic bound,
  visibility) → both old and new lines in the diff
- A new `impl` block on a public type → diff lines added
- A new `pub use` re-export → diff line added

## Regenerating the snapshots

After making intentional public-API changes, regenerate the
snapshots in the same PR that introduces the change:

```sh
UPDATE_SNAPSHOTS=yes cargo test --workspace -- public_api
```

Per-crate regen if only one is affected:

```sh
UPDATE_SNAPSHOTS=yes cargo test -p rust_tree_sitter --test public_api
UPDATE_SNAPSHOTS=yes cargo test -p rts-mcp        --test public_api
```

Commit the updated `tests/snapshots/public-api.txt` files alongside
the source change. Reviewers should read the snapshot diff as part
of the API-review surface.

## Nightly Rust pinning

The `public-api` crate exposes the constant
[`MINIMUM_NIGHTLY_RUST_VERSION`][const]. The test references it
directly via `rustup_toolchain::install(public_api::MINIMUM_NIGHTLY_RUST_VERSION)`,
so the nightly version is sourced from the library, not pinned
separately. To roll the nightly forward deliberately:

1. Bump the `public-api` dev-dep version in both
   `crates/rts-core/Cargo.toml` and `crates/rts-mcp/Cargo.toml`.
2. Regenerate the snapshots (the constant resolves to the newer
   nightly automatically).
3. Commit the dep bump + snapshot regen together.

[const]: https://docs.rs/public-api/latest/public_api/constant.MINIMUM_NIGHTLY_RUST_VERSION.html

## Why test-based, not a CI workflow

The plan's first draft proposed `cargo public-api --deny=all` in a
dedicated GitHub Actions workflow. That flag does not exist on the
bare command — it requires the `--diff-git-checkouts` subcommand
flow and a different mechanism. The Rust-test mechanism documented
here is the cargo-public-api maintainers' [canonical
recommendation][canonical] for crate authors who want a gate that
fires on `cargo test`. It runs in the workspace's existing CI
invocation with no new workflow file to maintain.

[canonical]: https://github.com/cargo-public-api/cargo-public-api/blob/main/public-api/README.md#-as-a-ci-check

## Related institutional patterns

- PR #122 — Protocol-v0 JSON Schema drift gate
  (`crates/rts-daemon/tests/protocol_schemas.rs`). Same test-based
  shape applied to the daemon's wire protocol.
- PR #121 — MCP tool-description regression tests. Same pattern
  applied to the prose surface agents see.

This gate completes the trio: protocol shape, tool descriptions,
and Rust public API are each locked behind a `cargo test`-time
diff against a committed baseline.
