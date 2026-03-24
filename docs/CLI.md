# CLI Documentation

The CLI binaries are feature-gated. Build them with `--features cli`.

## Install

Build locally:

```bash
cargo build --bin tree-sitter-cli --features cli
```

Install from the repository checkout:

```bash
cargo install --path . --bin tree-sitter-cli --features cli
```

## Commands

Current commands from `tree-sitter-cli --help`:

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

## Common Usage

Analyze a repository:

```bash
tree-sitter-cli analyze ./src --format json
tree-sitter-cli analyze ./src --format json --include-graph
```

Run the canonical security scan:

```bash
tree-sitter-cli security ./src --format json
tree-sitter-cli ast-security ./src --format sarif
```

Inspect symbols:

```bash
tree-sitter-cli symbols ./src --format json
tree-sitter-cli find ./src --name parser
```

Analyze dependencies:

```bash
tree-sitter-cli dependencies . --format json --graph
```

## Help

Use built-in help for the current flag set instead of relying on stale examples:

```bash
tree-sitter-cli --help
tree-sitter-cli analyze --help
tree-sitter-cli security --help
tree-sitter-cli dependencies --help
```

This is especially important because the CLI surface is feature-gated and has changed materially during the repository cleanup work.
