# CODEX: MCP + Rust Analysis Integration Plan

This document defines the full integration and implementation plan to combine the Project MCP Server (Node.js) with our Rust analysis and security engines. It includes epics, user stories, milestones, dependencies, code touchpoints, integration structures, testing strategy, and progress tracking. This document should be updated continuously as work progresses.

Last updated: 2025-09-12

---

## Objectives

- Expose our code-structure and security analysis capabilities through the Project MCP server as composable tools/resources.
- Persist and contextualize findings within a project knowledge graph to power accurate, reusable “context bundles” for AI agents and humans.
- Maintain low false positives, high performance, and clear UX with stable schemas and tests.

## High-Level Architecture

- Client (e.g., Claude Desktop) connects to a single MCP server: Project MCP.
- MCP Server adds adapter tools that call our Rust CLI (`tree-sitter-cli`) to analyze code/security and import results into the MCP knowledge graph (memory.json + sessions.json).
- Graph becomes the canonical context store, linking code components, dependencies, issues, risks, tasks, and documents (reports).
- Context Bundles are assembled on demand for triage, guidance, and planning workflows.

## Epics, Stories, Milestones

### Epic 1: MCP Adapters for Rust CLI
- Goal: Add MCP tools in the Node MCP server to invoke our CLI and ingest results.
- Stories:
  - Tool: `analyzeCodebase(path, options)` — run `analyze/symbols` and import components (files, functions, classes), sizes, languages, complexity.
  - Tool: `buildCodeGraph(path)` — construct and persist code dependency/call graphs; add `graph://code` resource.
  - Tool: `scanSecurity(path, options)` — run `security --format json|sarif --no-color` and import findings (severity, confidence, CWE/OWASP); add `graph://security` and document entities for SARIF/JSON.
  - Tool: `getSecurityOverview(project/path)` — aggregate counts by severity, confidence, and top risk components.
  - Tool: `planRemediations(project/path, policy)` — transform findings → tasks; link `issue → task` with `resolved_by` relations.
  - Tool: `updateBaseline(path)` — call `--update-baseline` and register the baseline as a document reference.
  - Tool: `getCodeContext(query|symbol|path)` — assemble a context bundle (components + relations + snippets + issues + tasks).
- Milestones:
  - M1: `scanSecurity` and `analyzeCodebase` available; results visible via `graph` resource.
  - M2: `buildCodeGraph`, `getSecurityOverview`, `getCodeContext` implemented with stable schemas.
  - M3: `planRemediations`, `updateBaseline` complete; end-to-end flows validated.
- Dependencies:
  - Our CLI available on PATH; `NO_COLOR=1` honored; stable JSON/SARIF fields.

### Epic 2: Schema and Data Model Mapping
- Goal: Define versioned schemas for imported entities/relations and MCP responses.
- Stories:
  - Map entities: `component` (module/file/function/class), `issue` (security finding), `risk`, `document`, `task`.
  - Map relations: `part_of`, `depends_on`, `discovered_in`, `impacted_by`, `resolved_by`, `has_status`, `has_priority`, `precedes`.
  - Version and validate imported payloads; store source/commit/timestamp metadata.
  - Normalize severity/priorities across tools; align with OWASP/CWE categories.
- Milestones:
  - M1: v1 schema documented (Markdown + JSON examples); validation helpers in Node MCP.
  - M2: Backward compatibility guardrails + migration notes.
- Dependencies:
  - CLI formats (`table|json|markdown|sarif`) and fields as currently emitted.

### Epic 3: Context Bundles and Ranking
- Goal: Deliver targeted contexts for tasks, reviews, and triage with deterministic, rankable contents.
- Stories:
  - Build “Context Pack” generator with modes: `triage`, `fix-guidance`, `review`, `planning`.
  - Ranking signals: severity/confidence, dependency/call proximity, symbol relevance, optional churn/recency, file size limits.
  - Include code snippets (path + line range), issues with remediation summaries, minimal dependency edges, and related tasks/documents.
- Milestones:
  - M1: `getCodeContext` returns stable packs with size budgets.
  - M2: Snapshot tests and golden samples for deterministic outputs.

### Epic 4: Baselines and CI Quality Gates
- Goal: Respect baselines and produce actionable diffs.
- Stories:
  - Baseline support via `--baseline`/`--update-baseline`; store reference as a `document` entity.
  - Provide MCP responses that summarize new vs unchanged issues; expose `baselineState` if available.
- Milestones:
  - M1: Baseline-aware `scanSecurity` responses; verification tests with fixtures.

### Epic 5: Documentation and Developer Experience
- Stories:
  - Update MCP README: usage, configuration, example flows with our CLI.
  - Add “Context Engineering Guide” for assembling packs and tuning scope/thresholds.
  - Document environment variables (e.g., `MEMORY_FILE_PATH`, `SESSIONS_FILE_PATH`, `NO_COLOR`, `RUST_LOG`).
- Milestones:
  - M1: Docs merged with examples and JSON/SARIF snippets.

### Epic 6: Testing and Validation (Comprehensive)
- Goal: Fully test functionality and integration paths.
- Stories:
  - Unit tests (Node MCP): tool parameter validation, schema mappers, graph mutations.
  - CLI invocation tests: mockable shell adapters; goldens for stdout/stderr and exit codes.
  - Integration tests: ephemeral temp repos; run adapters; assert graph entities/relations/documents.
  - Snapshot tests: context bundles, security overviews, code graphs (size-limited to be stable).
  - Performance tests: large repo sampling with file size and scope budgets; timeout behavior.
  - Security/privacy tests: secrets masking policies; exclude raw secret material from graph.
  - E2E: Claude Desktop config using MCP tools and verifying results/resources.
- Milestones:
  - M1: Core unit + integration tests green for `scanSecurity`/`analyzeCodebase`.
  - M2: Snapshot stability for `getCodeContext` + overviews; perf smoke.

### Epic 7: Telemetry and Logging
- Stories:
  - Wire `--log-level` to `tracing_subscriber` (Rust) and structured logging (Node).
  - Ensure logs are opt-in; sanitize sensitive strings; doc usage.
- Milestones:
  - M1: Logs usable for local debugging and CI troubleshooting.

### Epic 8: Security and Privacy Hardening
- Stories:
  - Never store raw secret values in graph; store fingerprints/locations/classifications only.
  - Redact matched_text in MCP responses when type=secret; include only preview+hash.
  - Validate path scoping defaults to avoid docs/tests unless explicitly requested.
- Milestones:
  - M1: Redaction enforced and tested; scope flags validated.

### Epic 9: Performance and Reliability
- Stories:
  - Add timeouts/backoffs for CLI calls; concurrency caps; resilient retries.
  - Cache recent analysis; detect changed files to reduce recomputation (future improvement).
- Milestones:
  - M1: Timeouts + caps; smoke perf tests; large repo handling guidance.

### Epic 10: Rollout and Migration
- Stories:
  - Phased enablement via feature flag in MCP; default off, opt-in per session.
  - Success metrics: context accuracy (qualitative), FP rate, time-to-context, stability of snapshots.
- Milestones:
  - M1: Pilot in internal repos; M2: General availability; M3: Optional gRPC/HTTP bridge replacing shell-outs (future).

---

## Requirements and Dependencies

- Node 18+ and npm for the MCP server; Rust stable toolchain for our CLI.
- Our CLI on PATH (`tree-sitter-cli`), configured with `NO_COLOR=1` for clean JSON.
- Baseline file path (e.g., `.ci/security-baseline.json`) if used.
- Network access: not required for core flows; offline-capable.

## Code Touchpoints (Planned Changes — No code changes in this plan)

External MCP repo (Node):
- `index.ts`
  - Add tools: analyzeCodebase, buildCodeGraph, scanSecurity, getSecurityOverview, planRemediations, updateBaseline, getCodeContext.
  - Add resources: `graph://code`, `graph://security` (JSON payloads reflecting imported data).
  - Add schema mappers/validators and redaction utilities.
  - Add robust shell execution helper (timeouts, env var pass-through, error normalization).
- `package.json`
  - Scripts for tests and type-check; optional CLI setup checks.
- `tests/`
  - Unit, integration, snapshot suites as per Testing section.
- `README.md`
  - Usage examples for new tools; Claude Desktop config samples.

Our Rust repo (this project):
- No required changes for initial integration. Optional enhancements (future):
  - Validate JSON fields documented here remain stable; consider adding a `--output fields:<list>` for minimal payloads.
  - Expose “context pack” JSON natively (optional) if a direct Rust MCP server is pursued later.

## Integration Structures

- Shell-out adapter (Node) → Rust CLI
  - Deterministic flags: `--format json|sarif`, `--no-color`, `--min-severity`, `--min-confidence`, scope flags (`--include-tests|examples|non-code`), `--baseline`, `--update-baseline`, `--max-file-kb`.
  - Parse and validate JSON; attach provenance (command, cwd, timestamp).
  - Build/import graph nodes/edges; store large payloads as `document` entities and expose resources.

- Schema (v1) highlights
  - component: `{ name, kind: module|file|function|class, path, language, size, complexity, observations[] }`
  - issue: `{ id, title, description, severity, confidence, cwe?, owasp?, location:{file,start,end}, remediation:{summary}, fingerprint }`
  - relations: `part_of`, `depends_on`, `discovered_in`, `impacted_by`, `resolved_by`, `has_status`, `has_priority`, `precedes`
  - document: `{ name, type: json|sarif, uri, created_at, source }`

- Context Bundle (v1)
  - Inputs: `query|symbol|path|filters` + `mode`
  - Outputs: `{ components:[{path,lines}], issues:[…], deps:[…], tasks:[…], documents:[…], summary }`

## Testing Strategy

Unit (Node):
- Validate tool inputs (zod schemas), shell helper error paths, redaction behavior, schema mappers.

CLI Invocation (Node):
- Mock shell for error injection; real invocations in CI behind a “slow” tag; assert exit codes and structured stdout.

Integration (Node + Rust):
- Create temp repos with fixtures: safe files, intentional security samples (non-sensitive), dependency patterns.
- Run `analyzeCodebase` and `scanSecurity`; assert graph entities/relations/documents created; ensure scope flags behave.

Snapshot Tests:
- `getCodeContext` outputs per mode; `getSecurityOverview`; ensure deterministic ordering and size budgets.

Performance:
- Large directory with mixed files; ensure respects `--max-file-kb`, default excludes; timeouts not exceeded; provide metrics.

Security/Privacy:
- Ensure no raw secrets are stored; matched_text redacted/masked; baselines referenced by path only.

E2E (MCP Client):
- Claude Desktop config using GitHub npx install; run flows and verify `graph://*` resources and tool outputs.

## Rollout Plan

Phase 1 (Pilot):
- Implement `scanSecurity` + `analyzeCodebase`; basic ingestion and resources; minimal docs; unit/integration tests; pilot in one repo.

Phase 2 (Core):
- Add `buildCodeGraph`, `getSecurityOverview`, `getCodeContext`; add snapshot tests; improve docs; adopt in 2–3 repos.

Phase 3 (Advanced):
- Add `planRemediations`, `updateBaseline`; CI gate examples; performance knobs; optional caching.

Phase 4 (Future):
- Optional Rust-side MCP or gRPC/HTTP bridge; incremental/changed-file scanning.

## Acceptance Criteria

- MCP tools return valid, documented JSON; resources expose code/security graphs; context bundles are stable and useful.
- Baselines suppress unchanged issues; diffs are accurate; redaction policies enforced.
- Test suites (unit/integration/snapshot/perf smoke) pass in CI; docs updated with working examples.

## Progress Tracker

- Epic 1: MCP Adapters — Status: Planned
- Epic 2: Schema Mapping — Status: Planned
- Epic 3: Context Bundles — Status: Planned
- Epic 4: Baselines — Status: Planned
- Epic 5: Docs & DX — Status: Planned
- Epic 6: Testing — Status: Planned
- Epic 7: Telemetry — Status: Planned
- Epic 8: Security/Privacy — Status: Planned
- Epic 9: Performance — Status: Planned
- Epic 10: Rollout — Status: Planned

Update this section with dates, owners, and notes as milestones are completed.

