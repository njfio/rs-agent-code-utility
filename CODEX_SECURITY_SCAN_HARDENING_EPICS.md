# Security Scan Hardening: Epics, Stories, Milestones

This plan reduces false positives and improves clarity for the security engine across this repository. It targets inflated counts like “648 critical” and “95 hardcoded secrets,” plus output issues showing `ColoredString { ... }`.

## Epic 1: Output Fidelity and UX
- Stories:
  - Replace debug printing with display in CLI (e.g., use `{}` not `{:?}` for colored text in `src/cli/commands/security.rs`).
  - Normalize severity/priority rendering; remove type internals from output; add `--no-color`.
  - Snapshot tests for `--help` and typical reports (table/markdown/json).
- Milestones:
  - M1 CLI prints clean priorities and severities; snapshots stable.

## Epic 2: Source Scoping and Defaults
- Stories:
  - Default exclude tests, examples, docs, vendored, and generated assets for security scans (`tests/`, `test_*.rs`, `examples/`, `docs/`, `.github/`, `target/`, `cache/`).
  - Add file-type filters (ignore `.md`, images, large binaries) unless `--include-non-code`.
  - Respect `--include-tests`/`--include-examples` across all security paths, not only AST analyzer.
- Milestones:
  - M1 Baseline scan count drops on this repo by >90% without losing real issues.

## Epic 3: Secrets Detection Precision
- Stories:
  - Add entropy + checksum gates and prefix validation (e.g., AWS key pair validation) to `security::secrets_detector`.
  - Ignore common placeholders (`YOUR_KEY_HERE`, `example`, `test`, fake JWTs) and code fences in docs.
  - Path- and context-based allowlist (fixtures, mocks, snapshots) with inline suppression comment (`// secret-scan:ignore reason`).
- Milestones:
  - M1 False positives on docs/tests reduced to near-zero with fixtures in `test_files/`.

## Epic 4: Rule Precision and Severity Calibration
- Stories:
  - Introduce confidence scoring per finding; threshold configurable via CLI (`--min-confidence`).
  - Calibrate OWASP/CWE severities; demote best-practice hints from Critical → Medium/Low.
  - Add language-aware patterns to avoid naïve matches (e.g., strings in examples).
- Milestones:
  - M1 Severity distribution aligns with expectations on golden corpus; docs updated.

## Epic 5: False-Positive Filters (Deterministic)
- Stories:
  - Implement lightweight AST/heuristic filter independent of network/ML; deterministic and fast.
  - Golden test suite: known-TP/FP samples with acceptance thresholds.
  - Expose `--no-ai-filter` and `--filter=strict|balanced|permissive` modes.
- Milestones:
  - M1 Balanced mode default; FP rate <5% on corpus.

## Epic 6: Triage, Baselines, and Suppression
- Stories:
  - Baseline file support (record current findings, only alert on deltas in CI).
  - SARIF suppression and inline suppression comments honored with reasons.
  - `--fail-on=critical|high|...` gating for CI.
- Milestones:
  - M1 Clean CI with baseline; actionable diffs only.

## Epic 7: Performance Budgets and Timeouts
- Stories:
  - Add time/memory budgets per file and per scan; skip oversized files with a warning.
  - Parallelism tuning with backpressure for very large repos.
- Milestones:
  - M1 Scan completes within target SLO locally and in CI.

## Epic 8: CI Matrix and Quality Gates
- Stories:
  - Add jobs for minimal and full features; run security scan with defaults and with `--include-tests` separately.
  - Store JSON and SARIF artifacts; diff against baseline.
- Milestones:
  - M1 CI publishes artifacts; PRs show concise summaries.

## Epic 9: Telemetry and Logs (Opt-in)
- Stories:
  - Structured tracing around detectors; `--log-level` flag.
- Milestones:
  - M1 Tracing aids local debugging; logs documented.

## Epic 10: Documentation and Developer Experience
- Stories:
  - Update `CLI_README.md` with examples, suppression syntax, baseline usage.
  - Add “Security Scanner Guide” in `docs/` with FP troubleshooting and tuning.
- Milestones:
  - M1 Docs merged; contributors follow consistent workflows.

## File-Level Action Pointers (Where to Change)
- Output fixes: `src/cli/commands/security.rs` and `src/cli/commands/dependencies.rs` (use `{}` with colored strings; avoid `{:?}` on `ColoredString`).
- Scoping defaults: `src/cli/utils.rs` (default excludes) and `src/cli/commands/*` respecting include flags consistently; ensure `CodebaseAnalyzer` receives these.
- Secrets precision: `src/security/secrets_detector.rs` (validators, entropy, placeholders), plus inline suppression parsing in analyzers.
- Confidence/severity: `src/advanced_security.rs` (scoring, thresholds) and `src/cli/utils.rs` (new flags and parsing).
- Baseline/SARIF: `src/cli/output.rs` and `src/cli/sarif.rs` for suppression and baseline handling.

## Acceptance Criteria (Repository)
- Running `tree-sitter-cli security .` yields realistic counts, cleanly formatted priorities, and passes snapshot tests.
- FP rate on repo-linked corpus <5%; zero `ColoredString` debug output leaks; CI artifacts generated and diffed.

---

Progress Update

- Epic 1 (Output fidelity and UX): Implemented.
  - Replaced debug prints with display formatting in security CLI; added `--no-color` flag and global color control.
  - Added tests (`tests/security_output_no_colored_debug.rs`) ensuring no `ColoredString { … }` leaks and no ANSI codes with `--no-color`.
  - Verified `cargo test` with the new tests; existing suite passes locally except for an unrelated environment-specific wiki test.
- Bug fix: Adjusted secrets detector context heuristics to avoid marking real secrets as false positives when preceding lines contain example comments.
  - Added line-sensitive comment handling and placeholder-aware variable-name checks.
  - Fixed failing test `filters_comments_and_examples` (now passing).

- Epic 2 (Source scoping and defaults): Implemented.
  - Security CLI adds `--include-tests`, `--include-examples`, and `--include-non-code` flags.
  - Defaults exclude `tests/`, `examples/`, `docs/`, `.github/`, and `cache/`; filter `.md`/`markdown` and non-code unless explicitly included.
  - Added tests (`tests/security_scoping.rs`) verifying docs/tests are excluded by default and can be included with flags.

Next (Epics 2–3 follow-up hot spots)
- Add `--no-color` to help text and CLI README examples; add a few output snapshots for markdown/json reports.
- Tighten secrets placeholder patterns and add more fixtures to keep FP rate low across docs/examples.
