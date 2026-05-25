### Removed unused dependencies (cargo-shear)

Stripped 28 unused dependency declarations across the workspace, flagged
by [`cargo-shear`](https://github.com/Boshen/cargo-shear). These were
left orphaned by the v0.6 pre-pivot cleanup (deletion of
`CodebaseAnalyzer` and the pre-pivot weight in `rts-core`); nothing in
the surviving code paths referenced them.

- **rts-core (`rust_tree_sitter`)**: `serde_json`, `serde_yaml`, `regex`,
  `sha2`, `rayon`, `petgraph`, `ignore`, `walkdir`, `parking_lot`,
  `crossbeam-channel`, `memmap2`, `dashmap`, `num_cpus`, `chrono`,
  `uuid`, `dirs`, `tracing`, `tracing-subscriber`, and the `criterion`
  dev-dependency.
- **rts-daemon**: `tokio-stream`, `futures-util`.
- **rts-mcp**: `thiserror`, `hex`, `unicode-normalization`, `nix`,
  `libc`.
- **rts-bench**: `thiserror`, `ignore`.

No false positives: every removal was verified against
`cargo build --workspace --all-targets`, `--all-features`, the
per-crate `telemetry`/`experimental` feature builds, and
`cargo test --workspace`. No cargo-shear ignore list was needed.
