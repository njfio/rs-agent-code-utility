# Security Scanner Guide

This guide explains how to run the security scanners, tune false‑positive filtering, use baselines in CI, and export SARIF for code scanning integrations.

## Commands

- CLI security scan (mixed heuristics + AI/ML filtering):
  `tree-sitter-cli security <PATH> [OPTIONS]`

- AST-based security scan (deterministic, low FP):
  `tree-sitter-cli ast-security <PATH> [OPTIONS]`

## Key Flags

- `--format table|json|markdown|sarif`: Output format; use `sarif` for CI integrations.
- `--min-severity critical|high|medium|low|info`: Filter by severity.
- `--min-confidence low|medium|high` (security): Gate by finding confidence.
- `--fail-on <severity>`: Exit non‑zero if any finding ≥ level.
- `--no-ai-filter` (security): Disable AI/ML filtering.
- `--filter-mode strict|balanced|permissive` (security): Deterministic filter strength applied before thresholds.
- `--baseline <file>`: Suppress unchanged findings using a JSON baseline.
- `--update-baseline`: Rewrite baseline with current fingerprints.
- `--include-tests|--include-examples|--include-non-code`: Expand scope; defaults exclude docs/tests/examples.
- `--max-file-kb <N>`: Skip oversized files.

## Baselines

Use a baseline to prevent noise in CI by suppressing pre‑existing findings. Fingerprints are stable within a file:

- Security: `{file}:{start_line}:{title}:{severity}`
- AST security: `{file_path}:{line_number}:{title}:{severity}`

Workflow:

1) Create/refresh baseline locally:
`tree-sitter-cli security . --update-baseline --baseline .ci/security-baseline.json`

2) Use baseline in CI with a quality gate:
`tree-sitter-cli security . --baseline .ci/security-baseline.json --fail-on high`

SARIF includes `baselineState` as `new` or `unchanged` when a baseline is provided.

## Tuning False Positives

- Start with `--filter-mode balanced` (default). If you still see noise, try `strict`.
- If you need more findings for triage, use `permissive`, then rely on `--min-confidence`/`--min-severity`.
- Add scope flags (`--include-tests`, etc.) only when you need coverage in those areas.
- Inline suppression for secrets: add `// secret-scan:ignore reason` on the same line; fixtures/mocks/docs are auto‑down‑weighted.

## SARIF Integration

Export SARIF and upload to your code scanning platform:

`tree-sitter-cli security . --format sarif -o security.sarif`

SARIF is also available for the AST scanner:

`tree-sitter-cli ast-security . --format sarif -o ast-security.sarif`

## Examples

- CI quality gate with baseline:
`tree-sitter-cli security . --baseline .ci/security-baseline.json --fail-on high --format json > security.json`

- Strict, AI‑disabled local triage:
`tree-sitter-cli security . --filter-mode strict --no-ai-filter --min-severity medium`

- AST-based quick pass with a size budget:
`tree-sitter-cli ast-security . --format table --max-file-kb 512`

## Tips

- Use `--no-color` for clean logs.
- Keep baselines in version control and refresh intentionally with `--update-baseline`.
- Pair the security scanner with `docs/DEPENDENCY_AUDIT_REPORT.md` for a full security posture view.

