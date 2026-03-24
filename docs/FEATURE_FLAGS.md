# Feature Flags

This document tracks the current dependency-to-feature mapping for `rust_tree_sitter` after the Phase 1.1 feature stratification work.

## Active Feature Sets

| Feature | Purpose | Enables |
|---|---|---|
| `std` | Baseline library surface | No additional dependencies |
| `serde` | Compatibility marker for the default feature set | No additional dependencies |
| `cli` | Command-line binaries and CLI-only formatting | `clap`, `colored`, `indicatif`, `rustyline`, `syntect`, `tabled`, `tracing`, `tracing-subscriber` |
| `ml` | Embeddings and model-backed intent mapping | `anyhow`, `candle-core`, `candle-nn`, `candle-transformers`, `tokenizers`, `hf-hub` |
| `net` | Network/runtime-backed providers and rate-limited HTTP | `anyhow`, `reqwest`, `tokio`, `governor`, `tower`, `config`, `tracing` |
| `mmap` | Real memory-mapped file support for the advanced memory manager | `memmap2` |
| `db` | Database-backed infrastructure | `anyhow`, `sqlx`, `config`, `chrono`, `tracing` |
| `wiki` | Static wiki generation with markdown + network-backed enrichment | `crc32fast`, `pulldown-cmark`, `net` |
| `extended-languages` | Secondary tree-sitter grammars kept out of the baseline build | `tree-sitter-javascript`, `tree-sitter-python`, `tree-sitter-c`, `tree-sitter-cpp`, `tree-sitter-typescript`, `tree-sitter-go`, `tree-sitter-java`, `tree-sitter-php`, `tree-sitter-ruby`, `tree-sitter-swift`, `tree-sitter-kotlin` |
| `demo` | Example binaries only | `uuid` |
| `full` | Restore the previous broad behavior surface | `std`, `serde`, `ml`, `net`, `db`, `cli`, `wiki`, `mmap`, `extended-languages` |

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
| `crc32fast` | `wiki` | Stable filename and diagram node hashing for generated wiki output |
| `chrono` | `db` | Typed advisory/database timestamps for SQLite-backed persistence paths |
| `tracing` | `cli`, `net`, `db` | Structured logging for CLI initialization and feature-gated infra/runtime paths |
| `memmap2` | `mmap` | True OS-backed memory mapping for `advanced_memory` |
| `tree-sitter-javascript` | `extended-languages` | JavaScript grammar kept out of the baseline parser surface |
| `tree-sitter-python` | `extended-languages` | Python grammar kept out of the baseline parser surface |
| `tree-sitter-c` | `extended-languages` | C grammar kept out of the baseline parser surface |
| `tree-sitter-cpp` | `extended-languages` | C++ grammar kept out of the baseline parser surface |
| `tree-sitter-typescript` | `extended-languages` | TypeScript grammar kept out of the baseline parser surface |
| `tree-sitter-go` | `extended-languages` | Go grammar kept out of the baseline parser surface |
| `tree-sitter-java` | `extended-languages` | Java grammar kept out of the baseline parser surface |
| `tree-sitter-php` | `extended-languages` | PHP grammar kept out of the baseline parser surface |
| `tree-sitter-ruby` | `extended-languages` | Ruby grammar kept out of the baseline parser surface |
| `tree-sitter-swift` | `extended-languages` | Swift grammar kept out of the baseline parser surface |
| `tree-sitter-kotlin` | `extended-languages` | Kotlin grammar kept out of the baseline parser surface |
| `sqlx` | `db` | SQLite-backed persistence |
| `uuid` | `demo` | Typed UUID identifiers in the gated demo example |
| `pulldown-cmark` | `wiki` | Markdown rendering for wiki output |

## Always-On Direct Dependencies

These remain part of the core build today and still dominate the dependency footprint:

- `tree-sitter` plus the core grammar set: Rust
- `serde`, `serde_json`, `serde_yaml`, `toml`
- `regex`, `rand`, `rayon`, `petgraph`, `ignore`
- No remaining always-on direct utility crates beyond the Rust-only parser/core stack

## Binary and Example Gating

- `tree-sitter-cli` requires `cli`
- `rts-cli` requires `cli`
- Accessibility examples require `demo,cli`
- AI security, AST security, and `gpt5_ultimate_demo` require `demo,net`
- All other examples remain gated behind `demo`

## Current Measurements

Measured on 2026-03-24 after gating `memmap2` behind `mmap`, removing always-on `num_cpus`, replacing direct `dirs` usage with internal std-based path resolution, swapping the cache backend off the direct `dashmap` dependency, gating the external `config` crate behind infrastructure features, removing the unused `exponential-backoff` dependency, removing the unused `sha2` dependency, replacing direct `async-trait` usage with boxed std futures, gating `anyhow` behind feature-local modules, moving `uuid` behind the gated demo example, restricting `chrono` to the database feature after replacing core/reporting timestamps with std-based helpers, gating `tracing` behind `cli`/`net`/`db` with crate-local no-op log shims for the core build, moving `crc32fast` behind `wiki`, moving the JavaScript/Python/C/C++/TypeScript/Go/Java/PHP/Ruby/Swift/Kotlin grammars behind `extended-languages`, switching `advanced_cache` disk persistence from gzip-compressed JSON to plain JSON so `flate2` is no longer always-on, replacing `walkdir` usage in declarative rule loading plus AST security file discovery with std-based recursive traversal, replacing the `advanced_parallel` scheduler's direct `crossbeam-channel` usage with std `mpsc`, replacing the secrets detector's direct `base64` usage with a crate-local base64url decoder for JWT validation, and replacing the last direct `parking_lot` locks in infrastructure caching plus advanced parallel scheduling with std `RwLock` plus poison-tolerant helpers, using rough `cargo tree | wc -l` counts:

| Surface | Command | Lines |
|---|---|---|
| Core/no-default | `cargo tree --no-default-features | wc -l` | `420` |
| Default | `cargo tree | wc -l` | `420` |
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
- `sha2` is no longer in the dependency graph; the direct dependency was unused and has been removed from the crate.
- `async-trait` is no longer a direct core dependency; async dyn-trait surfaces now use boxed std futures, although `async-trait` still appears transitively under `net`/`db` through `config` and in dev-only `wiremock`.
- `anyhow` is no longer a direct core dependency; it now only appears when `ml`, `net`, or `db` is enabled, although `anyhow` still appears transitively in the no-default graph through dev-only `wiremock`.
- `uuid` is no longer a direct core dependency; runtime string IDs now use a crate-local generator, `cargo tree -i uuid --no-default-features` no longer matches anything, and the `uuid` crate now only appears when the gated `demo` example feature is enabled.
- `chrono` is no longer a direct core dependency; security reports and CLI output now use crate-local std-based timestamp formatting, the infrastructure cache now stores epoch-millisecond metadata, `cargo tree -i chrono --no-default-features` no longer matches anything, and the `chrono` crate now only appears when `db` is enabled.
- `tracing` is no longer a direct core dependency; default/core builds route log macros through crate-local no-op shims, while `tracing` now only appears as a direct dependency when `cli`, `net`, or `db` is enabled. It still appears transitively in the no-default graph through dev-only `wiremock -> hyper -> h2`.
- `crc32fast` is no longer a direct core dependency; wiki filename sanitization and diagram node hashing now keep it behind the `wiki` feature, `cargo tree --no-default-features | rg crc32fast` no longer matches anything, and it still appears in `--all-features` both directly through `wiki` and transitively through `syntect -> flate2` and `candle-core -> zip`.
- `flate2` is no longer a direct core dependency; `advanced_cache` now persists plain JSON `.cache` files on disk instead of gzip-compressed JSON, `cargo tree --no-default-features | rg flate2` no longer matches anything, and `flate2` now only shows up transitively when `cli` is enabled through `syntect`.
- `walkdir` is no longer a direct core dependency; declarative rule loading and AST security file discovery now recurse with std-based directory traversal, which keeps the reduced-build rule engine usable without the direct crate edge. `walkdir` still appears transitively in the no-default graph through always-on `ignore` and dev-only `criterion`.
- `crossbeam-channel` is no longer a direct core dependency; the `advanced_parallel` scheduler now uses std `mpsc` channels for both its bounded worker mailbox and shared global queue, and `cargo tree --no-default-features | rg crossbeam-channel` no longer matches anything.
- `base64` is no longer a direct core dependency; JWT validation in the secrets detector now uses a crate-local base64url decoder, and `cargo tree --no-default-features -i base64@0.21.7` now only matches the dev-only `wiremock` path. The reduced tree still shows transitive `base64` versions through that dev dependency.
- `parking_lot` is no longer a direct core dependency; the infrastructure cache and advanced parallel scheduler now use std `RwLock` plus poison-tolerant helper accessors, and `cargo tree --no-default-features -i parking_lot` now only matches the dev-only `tokio`/`wiremock` path.
- `tree-sitter-javascript`, `tree-sitter-python`, `tree-sitter-c`, `tree-sitter-cpp`, `tree-sitter-typescript`, `tree-sitter-go`, `tree-sitter-java`, `tree-sitter-php`, `tree-sitter-ruby`, `tree-sitter-swift`, and `tree-sitter-kotlin` are no longer direct core dependencies; they now only appear when `extended-languages` is enabled. The top-level public helper surface omits those languages from the default build, while internal feature-aware analysis paths still detect them when the feature is enabled.
- The crate-count target from the plan is still not met. The next reduction pass would need deeper changes to the remaining always-on parser/utility stack around the Rust-only baseline and the broader utility graph.
