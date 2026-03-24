# Feature Flags

This document tracks the current dependency-to-feature mapping for `rust_tree_sitter` after the Phase 1.1 feature stratification work.

## Active Feature Sets

| Feature | Purpose | Enables |
|---|---|---|
| `std` | Baseline library surface | No additional dependencies |
| `serde` | Compatibility marker for the default feature set | No additional dependencies |
| `cli` | Command-line binaries and CLI-only formatting | `clap`, `colored`, `indicatif`, `rustyline`, `syntect`, `tabled`, `tracing-subscriber` |
| `ml` | Embeddings and model-backed intent mapping | `anyhow`, `candle-core`, `candle-nn`, `candle-transformers`, `tokenizers`, `hf-hub` |
| `net` | Network/runtime-backed providers and rate-limited HTTP | `anyhow`, `reqwest`, `tokio`, `governor`, `tower`, `config` |
| `mmap` | Real memory-mapped file support for the advanced memory manager | `memmap2` |
| `db` | Database-backed infrastructure | `anyhow`, `sqlx`, `config` |
| `wiki` | Static wiki generation with markdown + network-backed enrichment | `pulldown-cmark`, `net` |
| `demo` | Example binaries only | `uuid` |
| `full` | Restore the previous broad behavior surface | `std`, `serde`, `ml`, `net`, `db`, `cli`, `wiki`, `mmap` |

## Direct Dependency Mapping

| Dependency | Feature Gate | Notes |
|---|---|---|
| `clap` | `cli` | CLI parsing for `tree-sitter-cli` and `rts-cli` |
| `colored` | `cli` | CLI-only presentation |
| `indicatif` | `cli` | CLI progress bars |
| `rustyline` | `cli` | Interactive CLI mode |
| `syntect` | `cli` | Interactive syntax highlighting |
| `tabled` | `cli` | CLI table rendering |
| `tracing-subscriber` | `cli` | CLI log initialization |
| `candle-core` | `ml` | ML inference/runtime |
| `candle-nn` | `ml` | ML inference/runtime |
| `candle-transformers` | `ml` | ML inference/runtime |
| `tokenizers` | `ml` | Tokenization for model-backed flows |
| `hf-hub` | `ml` | Model downloads |
| `reqwest` | `net` | HTTP clients and provider calls |
| `tokio` | `net` | Async runtime for provider/database/wiki flows |
| `governor` | `net` | Rate limiting |
| `tower` | `net` | Retry/timeout middleware |
| `anyhow` | `ml`, `net`, `db` | Ergonomic error aggregation for feature-gated ML and infrastructure modules |
| `config` | `net`, `db` | Environment/file-backed infrastructure configuration loading |
| `memmap2` | `mmap` | True OS-backed memory mapping for `advanced_memory` |
| `sqlx` | `db` | SQLite-backed persistence |
| `uuid` | `demo` | Typed UUID identifiers in the gated demo example |
| `pulldown-cmark` | `wiki` | Markdown rendering for wiki output |

## Always-On Direct Dependencies

These remain part of the core build today and still dominate the dependency footprint:

- `tree-sitter` and the language grammar crates
- `serde`, `serde_json`, `serde_yaml`, `toml`
- `regex`, `sha2`, `rand`, `rayon`, `petgraph`, `ignore`
- `crc32fast`, `flate2`, `crossbeam-channel`, `parking_lot`, `walkdir`, `base64`
- `chrono`, `tracing`

## Binary and Example Gating

- `tree-sitter-cli` requires `cli`
- `rts-cli` requires `cli`
- Accessibility examples require `demo,cli`
- AI security, AST security, and `gpt5_ultimate_demo` require `demo,net`
- All other examples remain gated behind `demo`

## Current Measurements

Measured on 2026-03-24 after gating `memmap2` behind `mmap`, removing always-on `num_cpus`, replacing direct `dirs` usage with internal std-based path resolution, swapping the cache backend off the direct `dashmap` dependency, gating the external `config` crate behind infrastructure features, removing the unused `exponential-backoff` dependency, replacing direct `async-trait` usage with boxed std futures, gating `anyhow` behind feature-local modules, and moving `uuid` behind the gated demo example, using rough `cargo tree | wc -l` counts:

| Surface | Command | Lines |
|---|---|---|
| Core/no-default | `cargo tree --no-default-features | wc -l` | `498` |
| Default | `cargo tree | wc -l` | `498` |
| All features | `cargo tree --all-features | wc -l` | `1386` |

Notes:

- These are rough line counts from `cargo tree`, not deduplicated unique-crate counts.
- The Phase 1.1 split succeeded in moving `cli`, `wiki`, `ml`, `net`, `db`, and `mmap` out of the default feature set.
- `memmap2` is absent from `cargo tree --no-default-features` and reappears when `mmap` is enabled.
- `num_cpus` is no longer a direct core dependency; default thread sizing now uses `std::thread::available_parallelism()`.
- `dirs` is no longer a direct core dependency; infrastructure default paths are resolved with internal std-based helpers, although `dirs` still appears transitively under `ml` through `hf-hub`.
- `dashmap` is no longer a direct core dependency; the in-memory cache now uses `parking_lot::RwLock<HashMap<...>>`, although `dashmap` still appears transitively under `net` through `governor`.
- `config` is no longer a direct core dependency; it now only appears when `net` or `db` infrastructure is requested.
- `exponential-backoff` is no longer in the dependency graph; HTTP retry logic already uses a small internal exponential backoff implementation.
- `async-trait` is no longer a direct core dependency; async dyn-trait surfaces now use boxed std futures, although `async-trait` still appears transitively under `net`/`db` through `config` and in dev-only `wiremock`.
- `anyhow` is no longer a direct core dependency; it now only appears when `ml`, `net`, or `db` is enabled, although `anyhow` still appears transitively in the no-default graph through dev-only `wiremock`.
- `uuid` is no longer a direct core dependency; runtime string IDs now use a crate-local generator, `cargo tree -i uuid --no-default-features` no longer matches anything, and the `uuid` crate now only appears when the gated `demo` example feature is enabled.
- The crate-count target from the plan is still not met. The next reduction pass should focus on the remaining always-on direct dependencies and the tree-sitter grammar footprint.
