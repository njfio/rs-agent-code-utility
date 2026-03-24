---
title: "follow-up: unwrap hardening batches"
type: follow-up
status: proposed
date: 2026-03-24
origin: docs/plans/2026-03-23-001-refactor-comprehensive-codebase-improvement-plan.md
---

## Goal

Track the remaining modules still explicitly gated with `#[allow(clippy::unwrap_used, clippy::expect_used)]` after the initial Phase 0 hardening pass.

The core parsing/query/analyzer/CLI path is already covered by:
- `c65e26d` `refactor(core): deny unwraps in parser and query path`
- `07ddc87` `refactor(cli): deny unwraps in command tests`

This document breaks the remaining modules into reviewable follow-up PR batches.

## Current State

- Crate root already enforces `#![deny(clippy::unwrap_used, clippy::expect_used)]` in [src/lib.rs](../../src/lib.rs)
- 15 module declarations still carry explicit local `#[allow(...)]` escapes
- Remaining work should remove those escapes batch-by-batch, not as one large refactor

## Batch Plan

### Batch 1: Analysis Surface

Status: complete on 2026-03-24

- `analysis_common`
- `analysis_utils`
- `complexity_analysis`
- `performance_analysis`
- `refactoring`
- `test_coverage`

Verification:
- `cargo test --lib`
- `cargo clippy --lib -- -D warnings -W clippy::unwrap_used -W clippy::expect_used`

### Batch 2: Security Detectors

Status: complete on 2026-03-24

Note: module-level allow removal is landing incrementally, but the full
`cargo clippy --all-targets --all-features -- -D warnings -W clippy::unwrap_used -W clippy::expect_used`
gate is still blocked by separate integration-test cleanup under `tests/`.

- Complete:
  - `advanced_security`
  - `command_injection_detector`
  - `security`
  - `sql_injection_detector`
  - `semantic_context`
  - `enhanced_security`
  - `taint_analysis`

Verification:
- `cargo test --test security_pipeline --all-features`
- `cargo test --test cross_file_taint`
- `cargo clippy --all-targets --all-features -- -D warnings -W clippy::unwrap_used -W clippy::expect_used`

### Batch 3: Graph and Symbol Infrastructure

Status: complete on 2026-03-24

- Complete:
  - `control_flow`
  - `symbol_table`
  - `semantic_graph`
  - `code_map`
  - `code_evolution`
  - `languages`

- `control_flow`
- `symbol_table`
- `semantic_graph`
- `code_map`
- `code_evolution`
- `languages`

Verification:
- `cargo test --test semantic_graph_tests`
- `cargo clippy --lib --tests -- -A warnings -W clippy::unwrap_used -W clippy::expect_used`

### Batch 4: Storage and Runtime Infrastructure

- `advanced_cache`
- `advanced_memory`
- `file_cache`
- `infrastructure`
- `memory_tracker`
- `constants`
- `error`

Verification:
- `cargo test --lib`
- `cargo check --no-default-features`
- `cargo check --features net`
- `cargo check --features db`

### Batch 5: Parallelism and Transformation

- `advanced_parallel`
- `ast_transformation`
- `dependency_analysis`

Verification:
- `cargo test --lib`
- `cargo clippy --lib --tests -- -A warnings -W clippy::unwrap_used -W clippy::expect_used`

### Batch 6: Feature-Gated AI/ML Surface

- `ai`
- `intent_mapping`
- `intent_mapping_stub`
- `embeddings`
- `wiki`

Verification:
- `cargo check --features net`
- `cargo check --features ml`
- `cargo check --features wiki`
- `cargo clippy --all-targets --all-features -- -D warnings -W clippy::unwrap_used -W clippy::expect_used`

## Exit Criteria

- Remove the module-level `#[allow(clippy::unwrap_used, clippy::expect_used)]` from each batch only after that batch passes its verification commands.
- Keep changes mechanical and local to panic handling; do not mix with unrelated feature work.
- Prefer converting test helpers and fixtures first, then runtime paths, then deleting the local `#[allow(...)]`.
