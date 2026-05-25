//! Drift-defense for the `rust_tree_sitter` (rts-core) public API.
//!
//! Builds the crate's rustdoc JSON via `rustdoc-json`, renders the
//! public-API surface via `public-api`, and asserts equality against
//! the committed snapshot at `tests/snapshots/public-api.txt`. Any
//! change to the public surface (added, removed, renamed, or
//! re-typed items) requires regenerating the snapshot.
//!
//! Regenerate after intentional API changes:
//!
//! ```text
//! UPDATE_SNAPSHOTS=yes cargo test -p rust_tree_sitter --test public_api
//! ```
//!
//! Or across both library crates that carry this gate:
//!
//! ```text
//! UPDATE_SNAPSHOTS=yes cargo test --workspace -- public_api
//! ```
//!
//! The mechanism is the cargo-public-api library's canonical CI
//! pattern (see <https://github.com/cargo-public-api/cargo-public-api>).
//! Pinning is done via the library-exposed
//! `public_api::MINIMUM_NIGHTLY_RUST_VERSION` constant — bump the
//! dev-dep version of `public-api` to roll the nightly forward
//! deliberately, then regen.
//!
//! This test runs as part of `cargo test --workspace` — no new CI
//! workflow file. The institutional pattern mirrors PR #122's
//! protocol-v0 schema-drift gate.

#[test]
fn public_api() {
    rustup_toolchain::install(public_api::MINIMUM_NIGHTLY_RUST_VERSION).unwrap();
    let rustdoc_json = rustdoc_json::Builder::default()
        .toolchain(public_api::MINIMUM_NIGHTLY_RUST_VERSION)
        .build()
        .unwrap();
    let public_api = public_api::Builder::from_rustdoc_json(rustdoc_json)
        .build()
        .unwrap();
    public_api.assert_eq_or_update("./tests/snapshots/public-api.txt");
}
