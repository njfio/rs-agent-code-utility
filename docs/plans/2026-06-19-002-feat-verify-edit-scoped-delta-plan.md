---
title: "feat: verify_edit (scoped delta) + edit-quality metrics (verify-v0 P3)"
type: feat
status: draft
date: 2026-06-19
origin: spikes/p1-1-verify-edit-delta/RESULTS.md
---

# feat: verify_edit (scoped delta) + edit-quality metrics (verify-v0 P3)

**Goal:** Validate a *proposed patch* against the index before it's written — `verify_edit` returns a structured pass/warn/fail verdict (broken callers, dangling refs, signature breaks, new symbols) — plus the EVR/BCIR edit-quality metrics and a CLI gate.

**Architecture (gated by the p1-1 spike):** a **scoped in-memory delta**, NOT a copy-on-write shadow index. For each patched file, re-parse old + new content to diff its defs/refs, then reuse the live index + `impact`/`verify_impact` for callers. Per-file delta cost is p50 6.8ms / p95 25.6ms; parsing parallelises trivially; large patches are bounded by a files-analysed cap with a partial-result signal. A shadow index would be *slower* (whole-DB redb file-copy) — see `spikes/p1-1-verify-edit-delta/RESULTS.md`.

## Scope decisions
- **Input = full post-edit file contents**, `{ edits: [{file, content}] }` — not a unified diff (no diff-parsing dep; unambiguous; matches the Write tool's payload). Range-based edits are a future option.
- **`test_coverage` check DEFERRED** — rts has no test-reachability data (a separate plan). `verify_edit` ships the other four checks.
- **Read-only**: the delta is in-memory; the live index is never mutated.

## Reuse map (from the spike)
| Check | Reuses |
| :-- | :-- |
| `broken_callers` | `impact::compute` / `Store::refs_to_symbol` + F4 `signature_shape` arity |
| `signature_breaks` | F4 `signature_shape` (old vs new) vs each caller's `call_arity` (F3) |
| `dangling_refs` | removed defs still referenced in the live index (`refs_to_symbol`) |
| `new_symbols` | patched defs whose name is absent from `NAME_TO_SID` |
| defs/refs of patched content | `rust_tree_sitter::parse_content` + `verify::extract_references` / `crate::refs::references_with_ranges` |

---

## Implementation Units

### U1 — `Index.VerifyEdit` / `verify_edit` (the scoped-delta engine)

**Files:** new `crates/rts-daemon/src/verify_edit.rs` (the delta engine — pure, testable), `methods/index.rs` (handler), `methods/mod.rs` (dispatch+cancellable), `state.rs` (counter), `schemas/v0/methods/Index.VerifyEdit.{req,resp}.schema.json`, `crates/rts-mcp/src/server.rs` (tool), tests.

**Input:** `{ edits: [{ file: String, content: String }], checks?: [..] }` — `content` is the full proposed post-edit file. `checks` defaults to all of `["broken_callers","dangling_refs","signature_breaks","new_symbols"]`.

**Engine (`verify_edit.rs`, per file, parallelised via `spawn_blocking`):**
1. OLD content = read `file` from the live workspace (missing file → treated as a new file, no old defs).
2. `parse_content(old)` → old defs; `parse_content(new)` → new defs; `extract_references(new)` → new use-sites.
3. Diff defs by (parent, name): **removed** (old∖new), **added** (new∖old), **sig-changed** (in both, `signature_shape` differs).
4. Per check (skip callers that live *inside* the patched fileset — they're re-checked via their own new content):
   - **new_symbols** (info): added def absent from `NAME_TO_SID`.
   - **dangling_refs** (warning): a removed def still has live callers outside the patch.
   - **broken_callers / signature_breaks** (critical): for a sig-changed def, F4 old vs new arity differs and a live caller's `call_arity` ≠ new arity. For a removed def, every live caller is a broken caller.
5. **Verdict policy** (configurable): any `critical` → `fail`; only `warning`/`info` → `warn`; clean → `pass`.
6. **Bounds:** cap files-analysed (default 50); beyond the cap, list the file in `files_skipped` and never let a skipped file read as a clean pass.

**Output (freeze names):**
```
{ "verdict": "fail",                       // pass | warn | fail
  "summary": { "critical": 1, "warning": 2, "info": 3 },
  "findings": [ { "severity": "critical", "kind": "broken_caller",
                  "symbol": "store::Store::commit_batch",
                  "site": { "file": "src/store/mod.rs", "line": 1588, "enclosing": "find_symbols_batch" },
                  "detail": "callee arity 1 -> 2; call site passes 1 arg" } ],
  "files_analyzed": 3,
  "files_skipped": [],
  "content_version_base": "…" }
```
Register `"Index.VerifyEdit"` (dispatch + counter + cancellable). MCP tool `verify_edit`. Read-only assertion test.

**Tests** (engine unit tests on the pure `verify_edit.rs` with a small in-memory index fixture or daemon round-trip): (1) removing a called fn → `fail` + `broken_caller`; (2) arity-changing a called fn → `fail` + arity detail; (3) adding a new fn → `pass` + `new_symbol` info; (4) an arity-preserving body edit → `pass`; (5) clean unrelated edit → `pass`; (6) a >cap fileset → `files_skipped` populated, verdict not falsely `pass`. Plus schema round-trip + MCP `tool_descriptions`.

### U2 — EVR/BCIR metrics + `rts verify-edit` CLI gate

**Files:** `crates/rts-bench/src/verify_metrics.rs` (extend), `crates/rts-mcp/src/bin/rts.rs` (`rts verify-edit`), a reusable CI snippet/Action, changelog, AGENTS.md.

- **EVR** (Edit Validity Rate) = fraction of corpus patches with `verify_edit` verdict `pass`. **BCIR** (Broken-Caller Introduction Rate) = fraction introducing ≥1 `broken_caller`. Add to the `HallucinationReport` family (honest denominators).
- **`rts verify-edit --edits <json>` (or `--file f --content -`)** → runs `Index.VerifyEdit`, prints findings, exit `0` pass / `1` warn / `2` fail (so `--fail-on critical` gates CI). Mirrors `rts verify` plumbing.
- **CI gate**: a documented `rts verify-edit` invocation for PR diffs (the enterprise pre-merge story). Annotate-only by default; `--fail-on` opt-in.

---

## Acceptance criteria
- `verify_edit` returns `fail` + a `broken_caller`/`signature_break` finding for a caller-breaking edit, `pass` for a safe edit, `new_symbol` info for additions; never falsely `pass` when files were skipped.
- Single-edit (1–10 files) latency well under 1s (parallel parse); read-only (no write lock).
- Schema-validated; `rts verify-edit` exit codes gate CI; EVR/BCIR computed with denominators.
- `cargo test --workspace` green; `cargo fmt --check` clean; no new clippy warnings.

## Deferred
- `test_coverage` check / `uncovered_after_change` (needs test-reachability edges) — own plan.
- Range-based edits + unified-diff input — future (full-content is the v0 contract).
- Blocking PreToolUse edit hook wired to `verify_edit` — a follow-up once the verdict shape settles.

## Requirements trace
| Spec § | Covered by |
| :-- | :-- |
| §3.5 verify_edit + checks | U1 (minus test_coverage) |
| §5 EVR/BCIR | U2 |
| §6.3 CI gate | U2 (`rts verify-edit --fail-on`) |
| §9 shadow-index spike | `spikes/p1-1-verify-edit-delta` (done → scoped delta) |
