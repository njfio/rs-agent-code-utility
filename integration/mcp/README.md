# MCP Integration

This directory contains the MCP adapter for `rust_tree_sitter`.

## Audit Result

The implementation plan originally assumed a checked-in TypeScript MCP server with 9 registered tools. The repository state on March 24, 2026 did not match that assumption:

- `integration/mcp/server/` existed, but only contained `node_modules/`
- no `package.json`, TypeScript source, or tests were checked in
- `node_modules/.package-lock.json` showed a prior package footprint named `codex-mcp-integration`
- the recovered package footprint used `@modelcontextprotocol/sdk@1.18.0`

The recreated checked-in package upgrades the SDK to `@modelcontextprotocol/sdk@1.27.1`, which clears the production advisories affecting the recovered footprint.

This adapter recreates the missing package around the current working CLI surface instead of assuming a server already exists.

## Implemented Tool Surface

The initial MCP tool set is intentionally limited to CLI commands that already exist and return stable JSON today:

- `analyze_codebase` -> `tree-sitter-cli analyze --format json`
- `get_symbols` -> `tree-sitter-cli symbols --format json`
- `query_code` -> `tree-sitter-cli query --format json`
- `scan_security` -> `tree-sitter-cli security --format json`
- `analyze_dependencies` -> `tree-sitter-cli dependencies --format json`
- `query_semantic_graph` -> `tree-sitter-cli analyze --format json --include-graph` plus adapter-side graph filtering/traversal

`analyze_codebase` supports `includeGraph: true`, which maps to `tree-sitter-cli analyze --format json --include-graph` and returns a serialized semantic graph inside the CLI report.

Checked-in schemas for these tools live in `integration/mcp/schemas/`:

- `analyze_codebase.v1.json`
- `get_symbols.v1.json`
- `query_code.v1.json`
- `scan_security.v1.json`
- `analyze_dependencies.v1.json`
- `query_semantic_graph.v1.json`

## Honest Limitations

These planned tools are not exposed yet because the current CLI does not offer a stable dedicated JSON contract for them:

- `parse_file`
- `analyze_complexity`
- `analyze_taint`
- `analyze_performance`

The adapter wraps the CLI's raw JSON output under a stable MCP envelope:

```json
{
  "schema_version": "1",
  "tool": "analyze_codebase",
  "command": "analyze",
  "path": "/repo",
  "report": {}
}
```

## Development

The package lives in `integration/mcp/server/`.

Useful commands:

```bash
cd /path/to/rust_tree_sitter
cargo build --bin tree-sitter-cli --features cli
cd integration/mcp/server
npm ci
npm run build
npm test
npm run dev
```

The server expects a built CLI binary at `target/debug/tree-sitter-cli`. Override with `RTS_CLI_PATH` if needed.

The adapter implementation lives in `integration/mcp/server/src/`. Tool registration currently happens in `tool-definitions.ts`, and semantic graph filtering for `query_semantic_graph` happens in `semantic-graph.ts`.
