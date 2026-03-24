# Rust Tree-sitter Agent Code Utility

`rust_tree_sitter` is a tree-sitter-first code intelligence toolkit for codebases and AI agents. It provides multi-language parsing, repository analysis, dependency analysis, a confidence-scored security pipeline, semantic graph export, cross-file taint analysis, an opt-in CLI, and a typed MCP adapter that exposes the stable JSON CLI surface to agent runtimes.

The current direction is deliberately narrower than the original "AI everything" footprint. Default installs are small compared with the old broad default surface, the canonical security path is centered on [`src/security/pipeline.rs`](src/security/pipeline.rs), and the MCP adapter in [`integration/mcp`](integration/mcp) is the main agent-facing integration.

## What Ships Now

- Multi-language parsing and repository analysis via `CodebaseAnalyzer`
- Dependency analysis for common manifests, with more credible counts and vulnerability plumbing
- Canonical security pipeline combining AST findings, declarative `.scm` rules, heuristic OWASP detections, and taint-confirmed confidence upgrades
- Semantic graph export plus adapter-side `query_semantic_graph`
- Cross-file taint propagation across Rust and JavaScript call boundaries
- Feature-gated CLI binaries: `tree-sitter-cli` and `rts-cli`
- TypeScript MCP adapter with 6 audited tools
- Criterion benchmarks plus a CI regression gate for parser performance

## Install

Core library only:

```bash
cargo add rust_tree_sitter
```

CLI surface:

```bash
cargo install --path . --bin tree-sitter-cli --features cli
```

Broad opt-in surface similar to the older default behavior:

```bash
cargo add rust_tree_sitter --features full
```

## Feature Flags

Default features are intentionally minimal:

| Feature | Purpose |
|---|---|
| `std` | Baseline library surface |
| `serde` | Default compatibility marker |
| `cli` | CLI binaries and terminal-only dependencies |
| `ml` | Model-backed intent-mapping and embedding code |
| `net` | Network/runtime-backed providers and HTTP clients |
| `db` | Database-backed infrastructure |
| `wiki` | Wiki generation and markdown enrichment |
| `demo` | Examples only |
| `full` | Restores the broad opt-in capability set |

See [`docs/FEATURE_FLAGS.md`](docs/FEATURE_FLAGS.md) for the full dependency-to-feature mapping and current `cargo tree` measurements.

## Quick Start

Analyze a repository:

```rust
use rust_tree_sitter::CodebaseAnalyzer;

fn main() -> Result<(), rust_tree_sitter::Error> {
    let mut analyzer = CodebaseAnalyzer::new()?;
    let result = analyzer.analyze_directory("src")?;

    println!("files: {}", result.total_files);
    println!("symbols: {}", result.files.iter().map(|f| f.symbols.len()).sum::<usize>());

    Ok(())
}
```

Run the canonical security pipeline on in-memory code:

```rust
use rust_tree_sitter::{Language, SecurityPipeline};
use std::path::Path;

fn main() -> Result<(), rust_tree_sitter::Error> {
    let pipeline = SecurityPipeline::new()?;
    let findings = pipeline.analyze_with_path(
        "fn run(user_cmd: &str) { std::process::Command::new(user_cmd); }",
        Path::new("src/demo.rs"),
        Language::Rust,
    )?;

    println!("findings: {}", findings.len());
    Ok(())
}
```

## CLI Surface

The current CLI commands are:

- `analyze`
- `query`
- `stats`
- `find`
- `symbols`
- `languages`
- `interactive`
- `map`
- `security`
- `ast-security`
- `dependencies`
- `watch`

Use command-specific help for the exact flags:

```bash
tree-sitter-cli --help
tree-sitter-cli security --help
tree-sitter-cli analyze --help
```

For current CLI usage notes, see [`docs/CLI.md`](docs/CLI.md).

## MCP Adapter

The adapter in [`integration/mcp`](integration/mcp) wraps the CLI's stable JSON output in a typed MCP envelope. The current tool set is:

- `analyze_codebase`
- `get_symbols`
- `query_code`
- `scan_security`
- `analyze_dependencies`
- `query_semantic_graph`

Schema files live in [`integration/mcp/schemas`](integration/mcp/schemas), and the adapter implementation lives under [`integration/mcp/server`](integration/mcp/server).

## Repository Guide

- [`ARCHITECTURE.md`](ARCHITECTURE.md): module layout, security pipeline, feature hierarchy, MCP surface
- [`docs/FEATURE_FLAGS.md`](docs/FEATURE_FLAGS.md): dependency-to-feature mapping
- [`docs/CLI.md`](docs/CLI.md): current CLI command overview
- [`docs/SECURITY_SCANNER_GUIDE.md`](docs/SECURITY_SCANNER_GUIDE.md): scanner-specific behavior and output details
- [`integration/mcp/README.md`](integration/mcp/README.md): MCP adapter contract and development notes

## Development

Core validation:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings -W clippy::redundant_clone
cargo test --workspace
```

CLI build:

```bash
cargo build --bin tree-sitter-cli --features cli
```

Benchmarks:

```bash
cargo bench --bench parser_bench --bench security_bench
```

MCP adapter:

```bash
cargo build --bin tree-sitter-cli --features cli
cd integration/mcp/server
npm ci
npm run build
npm test
```

## License

Licensed under either MIT or Apache-2.0.
