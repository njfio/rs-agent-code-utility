---
title: "feat: Verification & Anti-Hallucination Layer (verify-v0)"
type: feat
status: draft
date: 2026-06-18
origin: /home/n/Downloads/rts-verification-v0-spec.md
---

# feat: Verification & Anti-Hallucination Layer (`verify-v0`)

> **For agentic workers:** execute this plan unit-by-unit with the
> subagent-driven-development workflow. Each unit produces working, tested
> software on its own; the phases (P1→P4) are independently shippable and the
> later ones (P3/P4) should be re-planned after P1/P2 land and their spikes resolve.

**Goal:** Give rts a deterministic, read-only `verify_*` capability that checks an agent's *claims* (does this symbol/signature/import exist?) and *edits* (will this patch break callers?) against the ground-truth AST graph rts already maintains — turning "better code search" into "the coding agent's fact-checker."

**Architecture:** New `Index.Verify*` JSON-RPC methods in `rts-daemon` (additive to protocol-v0), backed by query shapes over the existing redb graph (`DEFS`/`REFS`/`NAME_TO_SID`) plus four new **shared primitives** the spec quietly assumes but the codebase lacks. Each method gets a paired MCP tool in `rts-mcp` and req/resp JSON Schemas. Metrics (SHR/SMR/IHR/…) land in `rts-bench`; the A/B/C benchmark extends `agent-bench`. All verification is read-only: edit verification (P3) runs against an ephemeral shadow index, never the live one.

**Tech Stack:** Rust 2024 (rts-core/daemon/mcp/bench), redb, tree-sitter (12 langs), serde/serde_json, `rmcp` (MCP), JSON Schema 2020-12, Python (agent-bench harness).

---

## Overview

The spec (§1–§9) proposes six tools across two modes (claim vs edit verification), a confidence/resolution model, a hallucination-rate metric suite, three integration surfaces (agent tools, hooks, CI gate), and a paired benchmark. This plan grounds that spec in the **actual** rts codebase and re-phases it around four capability **gaps** the exploration found — gaps the spec treats as free but which are real build work.

### What already exists (reuse verbatim)

| Capability | Location |
| :-- | :-- |
| Daemon method dispatch (match router) | `crates/rts-daemon/src/methods/mod.rs:~125` |
| Param parse / `snapshot` / `check_budget` helpers | `crates/rts-daemon/src/methods/index.rs:~383` |
| `content_version` composer (`blake3[:16]@mtime+gen`) | `crates/rts-daemon/src/methods/index.rs:~471` |
| Exact symbol lookup | `Store::find_symbol` `crates/rts-daemon/src/store/mod.rs:1101` |
| Name→sid, reverse call graph, outgoing refs | `Store::sid_for_name`, `refs_to_symbol:1002`, `refs_from_symbol:1024` |
| Transitive impact (BFS over `REFS`) | `crates/rts-daemon/src/impact.rs` (`impact_of`) |
| Per-symbol PageRank | `crates/rts-daemon/src/symbol_pagerank.rs` |
| Raw signature rendering (string only) | `crates/rts-core/src/signature.rs:33` (`render_rust`, …) |
| Snippet parse → **defined** symbols | `crates/rts-core/src/lib.rs:87` (`parse_content`) |
| MCP tool pattern (`#[tool]` → `call_daemon`) | `crates/rts-mcp/src/server.rs:~353` (`find_symbol`) |
| Schema CI enforcement | `crates/rts-daemon/tests/protocol_schemas.rs`, `.github/workflows/schemas-check.yml` |
| A/B harness (Control vs +rts), Wilson CI | `agent-bench/agent_bench/{run,report}.py` |
| Token/precision benches | `crates/rts-bench/src/{token,semantic,report}.rs` |

### The four gaps that drive phasing

1. **No fuzzy/near-miss lookup.** Only exact-name + shell-glob exist. The spec's "always offer the near-miss" (§2.3) — the whole self-correction loop — needs edit-distance ranking over the name pool. → **Primitive F2.**
2. **No structured signature.** `signature.rs` renders a *string*; there is no arity/params/returns. `verify_signature` and SMR need a parser. → **Primitive F4.**
3. **No reference extraction.** `parse_content` returns *definitions*, not the symbols/imports a snippet *references*. Every §5 metric (parse the agent's generated patch → check its references) depends on this. → **Primitive F3.**
4. **No import/module resolution.** Bare names only; `use foo::Bar` is not resolved to a def. A faithful `verify_import` (§3.3) is a subsystem, not a query — so it is scoped down in P1 (final-segment + `indeterminate`) and flagged for its own plan.

Plus the spec's own acknowledged hard part: **the shadow index** for `verify_edit` (§9), gated behind a spike.

### Phasing (re-derived from the gaps)

| Phase | Ships | Depends on | Risk |
| :-- | :-- | :-- | :-- |
| **F (foundations)** | F1 resolution model · F2 fuzzy candidates · F3 `extract_references` · F4 signature parse | — | low–med (F3/F4 per-language) |
| **P1** | `verify_symbol`, `verify_claims`, `verify_signature`, thin `verify_import` + SHR/IHR/SMR metric | F | low (graph queries) |
| **P2** | `verify_impact` + Pre/PostToolUse hooks + CER | P1 | low–med |
| **P3** | `verify_edit` (shadow index) + EVR/BCIR + CI gate | P2 + spike | **med–high** |
| **P4** | A/B/C benchmark + write-up | P1–P3 | med |

This document details **F + P1** to executable units. **P2–P4** are specified as milestone units with their spikes and re-plan triggers — do not execute them before their dependencies land.

---

## Problem Statement / Motivation

Coding agents hallucinate symbols, mis-call APIs, invent imports, and make edits that silently break callers — then thrash trying to fix invented problems (the "doom loop", spec §7 H3). rts is the only component holding a verified, queryable AST graph of the workspace, so it is uniquely able to answer "is this true?" deterministically, sub-millisecond, with **no LLM in the path** (spec §2.1). Doing so (a) reduces agent error rates, (b) produces the deterministic hallucination metrics that prove *every* rts pillar and fill the README's missing public agent-bench baseline (spec §1, §7), and (c) opens a defensible category ("the coding agent's fact-checker") no cloud-RAG or IDE-search competitor can occupy (spec §1).

---

## Proposed Solution

Build four shared primitives, then layer the tools on top phase by phase. Every `verify_*` result carries a `resolution` (`exact | not_found | indeterminate`) — the credibility safeguard (spec §4) — and every failed existence check returns ranked `candidates` so the agent self-corrects in the same turn (spec §2.3). Names are frozen on ship (protocol grammar `^[A-Z][a-z]+\.[A-Z][A-Za-z]+$`, `crates/rts-daemon/src/protocol.rs:~84`), so the method/tool names below are chosen deliberately.

**Frozen public names (decide now, freeze on ship):**

| MCP tool | Daemon method | Phase |
| :-- | :-- | :-- |
| `verify_symbol` | `Index.VerifySymbol` | P1 |
| `verify_signature` | `Index.VerifySignature` | P1 |
| `verify_import` | `Index.VerifyImport` | P1 |
| `verify_claims` | `Index.VerifyClaims` | P1 |
| `verify_impact` | `Index.VerifyImpact` | P2 |
| `verify_edit` | `Index.VerifyEdit` | P3 |

---

## Implementation Units

### Phase F — Shared primitives

#### F1. Resolution & confidence model

**Files:** Create `crates/rts-core/src/verify/mod.rs` and `crates/rts-core/src/verify/resolution.rs`; export from `crates/rts-core/src/lib.rs`.

The one type every verify result embeds. Keep it in `rts-core` so both daemon handlers and `rts-bench` metrics share it.

```rust
// crates/rts-core/src/verify/resolution.rs
use serde::{Deserialize, Serialize};

/// Why a verification answer is what it is. NEVER upgrade `Indeterminate` to
/// `NotFound` — that would let a benchmark game itself by counting "unknown"
/// as "grounded" (spec §4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Resolution {
    /// AST-precise: a direct def/ref edge in the graph.
    Exact,
    /// Confidently absent after exhaustive index lookup.
    NotFound,
    /// rts cannot be certain (dynamic dispatch, reflection, macro-generated,
    /// FFI, regex-fallback edges). Carries a machine reason.
    Indeterminate,
}

/// Concrete reasons we degrade to `Indeterminate`, so callers/metrics can
/// report coverage (spec §4, §9 "indeterminate coverage").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IndeterminateReason {
    DynamicDispatch,
    MacroGenerated,
    Ffi,
    UnresolvedRef, // present in UNRESOLVED_REFS, not yet bound
    Reflection,
    AmbiguousOverload, // multiple defs share the name; receiver type unknown
}
```

**Tests** (`crates/rts-core/src/verify/resolution.rs` `#[cfg(test)]`): serde round-trips to the exact wire strings `"exact"`/`"not_found"`/`"indeterminate"`; reason strings snake_case. These wire strings are frozen — assert them literally.

**Done when:** type compiles, exported, serde strings pinned by test.

---

#### F2. Fuzzy candidate ranking (near-miss)

**Files:** Create `crates/rts-core/src/verify/candidates.rs`. Pure function — no I/O — so the daemon passes in the name pool it already has from `NAME_TO_SID`.

```rust
// crates/rts-core/src/verify/candidates.rs
/// A near-miss for a not-found name, ranked by closeness then importance.
#[derive(Debug, Clone, Serialize)]
pub struct Candidate {
    pub qualified_name: String,
    pub edit_distance: u32,
    pub pagerank: f64,
}

/// Rank `pool` (qualified_name, pagerank) against `target`. Damerau-Levenshtein
/// on the *final* path segment; tie-break by pagerank desc. Caps at `limit`.
/// Drops anything with edit_distance > max(2, target.len()/3) so we never
/// surface absurd "near"-misses.
pub fn rank_candidates(
    target: &str,
    pool: impl Iterator<Item = (String, f64)>,
    limit: usize,
) -> Vec<Candidate> { /* … */ }

fn damerau_levenshtein(a: &str, b: &str) -> u32 { /* iterative DP, O(a*b) */ }
```

**Tests:** `commit_batch` vs pool `{commit_batches:0.01, commit:0.02, unrelated:0.9}` → returns `commit_batches` (dist 1) before `commit` (dist 5) regardless of pagerank; `unrelated` dropped by the distance cap; identical string → dist 0; empty pool → `[]`; `limit` honored.

**Done when:** ranking matches spec §3.1's candidate example ordering (edit-distance primary, pagerank tiebreak), unit-tested.

---

#### F3. Reference extraction (`extract_references`) — keystone

**Files:** Create `crates/rts-core/src/verify/references.rs`; add `pub fn extract_references` to `crates/rts-core/src/lib.rs` next to `parse_content` (`:87`). Reuses the existing `Parser` (`crates/rts-core/src/parser.rs`) and tree-sitter grammars.

Parses an arbitrary snippet/patch hunk and emits **use sites** (calls, type uses, imports) — the inverse of today's definition extraction. This is what every §5 metric consumes.

```rust
// crates/rts-core/src/verify/references.rs
#[derive(Debug, Clone, Serialize)]
pub enum RefKind { Call, Type, Import, Path }

#[derive(Debug, Clone, Serialize)]
pub struct Reference {
    pub name: String,          // bare or last path segment
    pub qualified: Option<String>, // e.g. "crate::store::CommitOptions" for imports
    pub kind: RefKind,
    pub line: usize,           // 1-based, within the snippet
    pub column: usize,
    pub call_arity: Option<u32>, // arg count when kind == Call (feeds SMR)
}

/// Walk the parse tree for `content` in `language`, returning every referenced
/// symbol/import (NOT definitions). Per-language tree-sitter node-kind queries
/// (`call_expression`, `scoped_identifier`, `use_declaration`, …).
pub fn extract_references(content: &[u8], language: Language) -> Vec<Reference>;
```

**Scope discipline (YAGNI):** ship Rust + TypeScript + Python node-kind queries in F3 (covers the dogfood + the bulk of SWE-bench-lite); the remaining 9 languages are added incrementally in P4 prep — each is a node-kind query table, not new architecture. Track coverage explicitly so metrics report which languages are decidable.

**Tests:** golden snippets per language — a Rust fn calling `commit_batch(x)` and `use crate::store::CommitOptions;` yields a `Call{name:"commit_batch", call_arity:1}` and an `Import{qualified:"crate::store::CommitOptions"}`; a macro invocation yields a `Reference` flagged for `IndeterminateReason::MacroGenerated`; comments/strings yield nothing (AST-precision, the whole point).

**Done when:** Rust/TS/Python golden tests pass; languages-supported list exported for metric coverage reporting.

---

#### F4. Structured signature parsing

**Files:** Add `crates/rts-core/src/verify/signature_shape.rs`; build on `crates/rts-core/src/signature.rs`.

```rust
// crates/rts-core/src/verify/signature_shape.rs
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SignatureShape {
    pub arity: u32,
    pub params: Vec<String>,   // param names in order (best-effort)
    pub returns: Option<String>,
}

/// Extract arity/params/returns from a definition's tree-sitter node.
/// Returns None (→ caller emits Indeterminate) when the language's params can't
/// be decided (e.g. variadics, macro-generated signatures).
pub fn signature_shape(def_node: tree_sitter::Node, src: &[u8], lang: Language)
    -> Option<SignatureShape>;
```

**Scope:** Rust/TS/Python in F4 (same set as F3); others degrade to `Indeterminate` until added. Variadic/`...args`/`**kwargs` → `None` → `Indeterminate`, never a confident wrong arity (spec §2.2).

**Tests:** `fn commit_batch(&mut self, entries: Vec<Entry>) -> Result<()>` → `{arity:1, params:["entries"], returns:"Result<()>"}` (receiver excluded); Python `def f(a, b=2, *rest)` → arity decidable as range or `None` (decide + test the rule); TS optional params counted.

**Done when:** the three languages parse to the spec §3.2 `actual` shape; undecidable cases return `None`.

---

### Phase P1 — Claim verification + first metrics

Each P1 tool unit follows the same six-touch pattern (from the `find_callers` exemplar, `index.rs:2016`): **(a)** params struct + handler in `methods/index.rs`; **(b)** dispatch arm + counter in `methods/mod.rs` + `state.rs`; **(c)** req/resp schema in `schemas/v0/methods/`; **(d)** MCP args + `#[tool]` in `rts-mcp/src/server.rs`; **(e)** handler unit tests + schema round-trip test; **(f)** changelog fragment.

#### P1.U1 — `Index.VerifySymbol` / `verify_symbol`

**Files:** `crates/rts-daemon/src/methods/index.rs` (handler), `methods/mod.rs` (dispatch+cancellable), `src/state.rs` (counter), `schemas/v0/methods/Index.VerifySymbol.{req,resp}.schema.json`, `crates/rts-mcp/src/server.rs` (tool), `changelog.d/`.

Catches the most common hallucination — an invented function/type/method (spec §3.1).

```rust
// methods/index.rs
#[derive(Deserialize)]
struct VerifySymbolParams {
    name: String,                       // bare or qualified (Store::commit_batch)
    #[serde(default)] kind: Option<String>,
    #[serde(default)] lang: Option<String>,
    #[serde(default)] file: Option<String>,
    #[serde(default)] content_version: Option<String>, // optional assertion
}

pub async fn verify_symbol(params, state, token) -> Result<Value, ProtocolError> {
    let p: VerifySymbolParams = parse_params(params)?;
    // validate name 1..=256 (mirror find_callers)
    let (_root, store) = snapshot(state)?;
    // 1. exact/qualified lookup via find_symbol + parent synthesis
    // 2. apply optional kind/lang/file filters
    // 3. exists=true  -> matches[] (qualified_name,kind,file,line,signature,pagerank), resolution=Exact
    //    exists=false -> candidates via F2 rank_candidates over store name pool, resolution=NotFound
    //    ambiguous overload / unresolved -> resolution=Indeterminate (+reason)
    // 4. attach content_version (index.rs:471 helper)
}
```

Response mirrors spec §3.1 exactly (`exists`, `resolution`, `matches[]`, `candidates[]`, `content_version`). Register in dispatch as `"Index.VerifySymbol"`; add to `is_cancellable_method` (graph walk over name pool).

**Tests:** indexed symbol → `exists:true, resolution:"exact"`, correct match line/signature; misspelling → `exists:false, resolution:"not_found"` with the real symbol as top candidate; name with two defs and no `file`/`kind` filter → `resolution:"indeterminate"` (`ambiguous_overload`); `find_symbol`-miss but present in `UNRESOLVED_REFS` → `indeterminate`(`unresolved_ref`); schema round-trip via `protocol_schemas.rs`.

#### P1.U2 — `Index.VerifySignature` / `verify_signature`

Uses **F4**. Input `{name, claimed:{arity,params,returns}}`; output `{match, resolution, actual, diff[]}` (spec §3.2). `diff[]` entries: `arity`, `unknown_param`, `param_order`, `return_shape`. When F4 returns `None` → `resolution:"indeterminate"`, `match` omitted (never a false negative). Same six touches.

**Tests:** wrong arity (2 vs 1) → `match:false`, diff `{issue:"arity"}`; bogus param `flush` → `{issue:"unknown_param"}`; variadic callee → `indeterminate`.

#### P1.U3 — `Index.VerifyImport` / `verify_import` (thin)

**Scope decision (gap #4):** full module resolution does not exist. P1 ships a **thin, honest** version: resolve the import's final segment against `NAME_TO_SID`; if found as a module/type → `resolves:true, resolution:"exact"`; if the segment is absent → `resolves:false, resolution:"not_found"` + F2 candidates; if the path has unresolvable intermediate segments → `resolution:"indeterminate"` (don't claim a confident `false` we can't prove). A real path-aware resolver is **deferred to its own plan** (`verify-import-resolution`), noted in §Dependencies. This keeps IHR honest (it only counts decidable imports).

**Tests:** `crate::store::CommitConfig` present → resolves; `crate::store::CommitOptions` absent (sibling present) → not_found + candidate `CommitConfig`; deep external path → indeterminate.

#### P1.U4 — `Index.VerifyClaims` / `verify_claims`

Batch dispatcher over U1–U3 + a `location` claim type (symbol at file:line). Input `{claims:[{type:"symbol"|"signature"|"import"|"location", …}]}`; output `{results[], grounded, total, grounding_rate}` (spec §3.6), excluding `indeterminate` from the denominator per the §5 decidability rule. Pure composition — no new graph code, just fan-out to U1–U3 handlers.

**Tests:** mixed batch of 4 (2 grounded, 1 not_found, 1 indeterminate) → `grounded:2, total:3` (indeterminate excluded), `grounding_rate:0.667`; empty → `grounding_rate` null not NaN.

#### P1.U5 — Hallucination metrics in `rts-bench`

**Files:** `crates/rts-bench/src/verify_metrics.rs` (new), wire a `Verify` subcommand into `crates/rts-bench/src/main.rs` `Cmd` enum (`:49`), extend `report.rs` `BenchReport`. New corpus `corpus/verify-eval-*.toml`.

Computes the spec §5 metrics deterministically: parse agent-generated patches with **F3** `extract_references`, check each reference via the daemon's `Index.Verify*`, exclude `indeterminate` from denominators, and report:

- **SHR** = not_found symbol refs / decidable symbol refs; **RGR** = 1−SHR.
- **SMR** = call sites whose `call_arity`/params mismatch callee (F3 `call_arity` × U2).
- **IHR** = unresolved imports / decidable imports.
- Every metric reports its **denominator** and the **indeterminate count excluded** (spec §5, §9).

Self-validation harness: run it over rts's *own* corpus + a fixture of deliberately-hallucinated patches (known SHR) to prove the metric detects what it should.

**Tests:** fixture patch with 3 real + 2 invented symbol refs and 1 macro ref → `SHR = 2/5 = 0.4`, `indeterminate_excluded = 1`, denominator reported.

#### P1.U6 — Agent guidance + hook nudge

**Files:** `AGENTS.md` tool table (`:~184`) — add `verify_symbol`/`verify_signature`/`verify_import` rows ("verify before you claim a symbol exists", spec §6.1); extend `.claude/hooks/rts-nudge.sh` to suggest `verify_*` when the agent asserts a symbol/signature. No code changes — guidance only. (The push hook that *blocks* edits is P2.)

**Done (P1) when:** all four tools answer correctly against a live index, schemas pass `schemas-check.yml`, `rts-bench verify` emits SHR/SMR/IHR with denominators on the dogfood corpus, and AGENTS.md documents the tools.

---

### Phase P2 — Impact verification + the live loop (milestone unit; re-plan before exec)

- **`Index.VerifyImpact` / `verify_impact`:** verification-framed wrapper over existing `impact_of` (`crates/rts-daemon/src/impact.rs`). Input `{symbol, change: signature|remove|rename, new_signature?}`; output `{verdict: would_break|safe, affected_callers[], affected_count, uncovered_after_change[]}` (spec §3.4). Reuses `refs_to_symbol` for the caller set; verdict from F4 signature delta vs each call site's `call_arity`.
- **Hooks (the doom-loop breaker, spec §6.2):** extend `.claude/` hooks — a **PreToolUse** hook on edit/write runs `verify_impact`/(later) `verify_edit` and blocks/annotates on `critical`; a **PostToolUse** hook runs `verify_claims` over generated code (via F3) and feeds failures back. This is where **CER** (correction efficiency, spec §5) becomes measurable — instrument the hook to log flag→fix turns.
- **Re-plan trigger:** the hook contract (block vs annotate, JSON shape the agent harness consumes) needs its own small design pass against the target harness (Claude Code hooks today; pi-rts `tool_call` for the pi stack).

### Phase P3 — `verify_edit` + shadow index (milestone unit; **spike first**)

- **Spike (spec §9, the one non-trivial build):** can we apply a unified diff / edit set to a **copy-on-write overlay** of the redb index and answer within the sub-second budget? Prototype in `spikes/p1-shadow-index/` (the repo's spike convention, workspace-excluded). Measure overlay-apply + re-resolve latency on tokio/flask fixtures. **Gate P3 on this result** — if overlay is too slow, fall back to a scoped in-memory delta graph (only the patched files + their reverse-dep closure).
- **`Index.VerifyEdit` / `verify_edit`:** input `{patch | edits[], checks[]}`; apply to shadow index; output `{verdict: pass|warn|fail, summary{critical,warning,info}, findings[], content_version_base}` (spec §3.5). Checks: `broken_callers` (F4 delta × call sites), `dangling_refs` (removed defs still referenced), `signature_breaks`, `test_coverage` (no test reaches symbol post-change), `new_symbols`. Verdict policy configurable (any critical → fail).
- **Metrics:** EVR (patches with verdict pass), BCIR (patches breaking ≥1 caller) into `rts-bench`.
- **CI gate:** `rts verify-edit --diff <PR.diff> --fail-on critical` — a new `rts` CLI subcommand + a reusable GitHub Action (spec §6.3). Enterprise selling point: deterministic local pre-merge correctness.

### Phase P4 — Public A/B/C benchmark (milestone unit; after P1–P3)

- Extend `agent-bench` (`agent_bench/run.py` `ArmConfig:112`) with a **third arm C** (`+rts +verify` wired into the loop via P2 hooks) alongside A (grep+read) and B (rts retrieval). Reuse Wilson-CI reporting (`report.py:38`).
- **Per-arm metrics:** SWE-bench-lite resolved, tokens/$/wall-clock/turns, **and** SHR/SMR/IHR/BCIR/EVR (from P1/P3).
- **Corpus:** SWE-bench-lite (pinned, public) + rts's audited corpus, spanning the 12 languages — gated on F3/F4 language coverage reaching all 12 (prep work folded into late P1/P2).
- **Rigor (spec §7):** N≥ few hundred tasks, ≥3 seeds, mean±95% CI, paired deltas via **McNemar**, pinned model/agent/commit versions, raw logs + harness published. Label non-reproducible figures directional.
- **H1/H2/H3** the explicit hypotheses; headline only after measured.

---

## Technical Considerations

- **Names freeze on ship.** `Index.Verify{Symbol,Signature,Import,Claims,Impact,Edit}` and the six tool names are committed by this plan; misspellings persist forever (protocol grammar at `protocol.rs:~84`). Reviewed against the `^[A-Z][a-z]+\.[A-Z][A-Za-z]+$` grammar — all pass.
- **Precision over recall (spec §2.2).** Every handler must prefer `indeterminate` to a confident wrong answer. Code review gate: any path that returns `not_found`/`match:false` must prove exhaustive lookup; ambiguity → `indeterminate` + reason.
- **Read-only invariant (spec §1, Pillar-5).** No verify path may mutate the workspace or live index. P3's shadow index is ephemeral and copy-on-write. Add a daemon-level assertion/test that verify methods take no write lock.
- **Budget parity.** Verify methods reuse `check_budget` and the cancellable-method registry; target the same sub-ms single-call budget as existing queries (latency bench in P1 acceptance).
- **Schema-first.** Because `protocol_schemas.rs` validates live responses against `schemas/v0/methods/*`, write the `.req`/`.resp` schema in the same unit as the handler or CI fails.
- **F3/F4 language coverage is the long pole** for §5/§7 — track it as a first-class coverage number, never silently partial.

## System-Wide Impact

- **Interaction graph:** `rts-mcp verify_* → daemon Index.Verify* → Store/impact/F1–F4`. Metrics: `rts-bench verify → F3 extract_references → daemon Index.Verify*`. Hooks (P2): `agent edit → PreToolUse → verify_impact/edit`.
- **API surface parity:** each new daemon method needs CLI parity consideration (the repo tracks CLI↔MCP asymmetry deliberately; `impact_of` already has none). Decide per tool — `verify_edit` *needs* a CLI twin (CI gate); the claim tools may stay MCP-only in P1.
- **Error propagation:** reuse `ErrorCode` (`error.rs`); add no new codes in P1 (use `InvalidParams`/`SymbolNotFound`/`IndexNotReady`). `verify_*` never errors on "not found" — that's a *result*, not an error.
- **State lifecycle:** verify reads the same `index_generation`-versioned store; stale-read detection via `content_version` echo. P3 shadow index must not bump `index_generation`.

## Acceptance Criteria

**Functional (P1, user-visible):**
- `verify_symbol` returns `exact`+match for an indexed symbol and `not_found`+ranked candidates for a misspelling, in one call.
- `verify_signature` flags arity/param mismatches; `indeterminate` on variadics.
- `verify_import` (thin) resolves present imports, flags absent ones, `indeterminate` on unresolvable paths.
- `verify_claims` batches all of the above with an honest `grounding_rate` (indeterminate excluded).
- `rts-bench verify` emits SHR/SMR/IHR with denominators + indeterminate counts on the dogfood corpus.

**Non-functional (gates):**
- Single-call verify latency within the existing query budget (p95 measured in `rts-bench latency`).
- All new methods have passing `protocol_schemas.rs` round-trips; `schemas-check.yml` green.
- Read-only assertion test passes (no write lock taken).
- Resolution wire strings (`exact`/`not_found`/`indeterminate`) pinned by test.

**Quality gates:** `cargo test` workspace-green; `cargo clippy` clean (repo denies `unsafe_code`); changelog fragments per unit; AGENTS.md updated.

## Success Metrics

- **Capability:** four P1 tools live + schema-validated.
- **Proof (the point):** first deterministic SHR/IHR/SMR numbers on rts's own corpus + a hallucinated-patch fixture, with reported decidability coverage — the numbers that fill the README's missing baseline (spec §1, §7).
- **Downstream (P4):** C reduces SHR/BCIR vs B **and** raises SWE-bench-lite task success (H2), with McNemar significance.

## Dependencies & Risks

- **Spike-gated:** P3 shadow-index latency (spec §9) — prototype before committing P3 scope.
- **Deferred to own plans:** (1) `verify-import-resolution` (real cross-module path resolver — gap #4); (2) F3/F4 coverage for the remaining 9 languages (incremental, pre-P4).
- **Loop attribution risk (spec §9):** H2/H3 only hold if the agent acts on verify output — P2 hooks must wire and log the feedback, or arm C collapses to B. Mitigate by instrumenting CER from day one of P2.
- **Indeterminate honesty:** dynamic/reflective/C-C++ regex-fallback code lowers decidability — always report it; never count it as grounded.
- **Don't oversell pre-benchmark (spec §9):** verify is internal capability until P4 lands measured numbers. No headline claims before P4.

## Requirements Trace

| Spec § | Covered by |
| :-- | :-- |
| §2.2 precision-over-recall, §4 resolution model | F1, handler review gate |
| §2.3 near-miss candidates | F2, used in U1/U3 |
| §3.1 verify_symbol | P1.U1 |
| §3.2 verify_signature | F4 + P1.U2 |
| §3.3 verify_import | P1.U3 (thin) + deferred resolver plan |
| §3.4 verify_impact | P2 |
| §3.5 verify_edit + shadow index | P3 (spike-gated) |
| §3.6 verify_claims | P1.U4 |
| §5 SHR/SMR/IHR/BCIR/EVR/CER | F3 + P1.U5 (SHR/SMR/IHR); P3 (BCIR/EVR); P2 (CER) |
| §6 integration (tools/hooks/CI) | P1.U6 (tools), P2 (hooks), P3 (CI gate) |
| §7 benchmark A/B/C | P4 |
| §9 risks | §Dependencies & Risks above |

## Sources & References

- Spec: `/home/n/Downloads/rts-verification-v0-spec.md` (verify-v0 draft, 2026-06-18).
- Codebase anchors: see "What already exists" table (verified via exploration 2026-06-18).
- Exemplar method end-to-end: `crates/rts-daemon/src/methods/index.rs:2016` (`find_callers`).
- MCP tool exemplar: `crates/rts-mcp/src/server.rs:~353` (`find_symbol`).
- Schema CI: `crates/rts-daemon/tests/protocol_schemas.rs`, `.github/workflows/schemas-check.yml`.
- Benchmark harness: `agent-bench/agent_bench/run.py`, `report.py`.
