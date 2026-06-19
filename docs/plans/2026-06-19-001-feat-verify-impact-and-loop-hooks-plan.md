---
title: "feat: verify_impact + verification loop hooks (verify-v0 P2)"
type: feat
status: draft
date: 2026-06-19
origin: docs/plans/2026-06-18-001-feat-verification-anti-hallucination-layer-plan.md
---

# feat: verify_impact + verification loop hooks (verify-v0 P2)

**Goal:** Add the pre-edit blast-radius gate (`verify_impact`) and wire verification into the agent's live edit loop via a Claude Code hook, so the agent catches breaking changes and hallucinated references as it writes — not at compile time.

**Architecture:** `Index.VerifyImpact` wraps the existing `impact_of` reverse-call-graph walk with a pass/fail verdict; a new `rts verify` CLI makes single-file reference-checking scriptable; a PostToolUse hook calls it on each Write/Edit and feeds hallucinated symbols back to the agent.

**Grounding (from exploration):** `impact_of` = `crate::impact::compute` (`crates/rts-daemon/src/impact.rs:242`) → `ImpactResult{ impact: Vec<ImpactEntry{qualified_name,kind,file,start_line,...,depth,rank_score}> }`; anchor resolved via `Store::sid_for_name` (`store/mod.rs:938`). Handler exemplar `impact_of` at `methods/index.rs:3345`. CLI = `crates/rts-mcp/src/bin/rts.rs` (`Cmd` enum + `run_command`), daemon calls via `cli::call_method`. Hooks = `.claude/hooks/rts-nudge.sh` (+ `.claude/hooks/tests/run-tests.sh`, `.claude/settings.json`). **No** test-coverage tracking and **no** PostToolUse hook exist yet.

---

## Scope decisions

- **`uncovered_after_change` is DEFERRED.** The index has no test-reachability edges (would need a new `TEST_EDGES` table + writer work). `verify_impact` ships the caller blast-radius + verdict; the coverage field lands with P3's `verify_edit`/coverage checks.
- **CER (correction-efficiency) is a P4 benchmark metric**, not a standalone P2 build — it only means something measured over a task corpus with the loop wired. P2 makes the loop *exist and observable*; P4 measures it.
- **Hook target = Claude Code** (the repo's existing hook stack). The `rts verify` CLI is the harness-agnostic core, so the same capability is reusable from the pi stack's `tool_call` hook later.

---

## Implementation Units

### U1 — `Index.VerifyImpact` / `verify_impact`

**Files:** `crates/rts-daemon/src/methods/index.rs` (handler), `methods/mod.rs` (dispatch+cancellable), `state.rs` (counter), `schemas/v0/methods/Index.VerifyImpact.{req,resp}.schema.json`, `crates/rts-mcp/src/server.rs` (tool), `crates/rts-mcp/src/bin/rts.rs` (`rts impact` CLI subcommand), tests.

A verification-framed wrapper over `impact_of`: the agent declares an intended change and gets the blast radius **as a verdict**.

**Input:** `{ symbol, change: "signature"|"remove"|"rename", new_signature?, depth? }`.

**Output:**
```
{ "resolution": "exact",                 // exact | not_found | indeterminate
  "verdict": "would_break",              // would_break | safe
  "change": "signature",
  "affected_count": 5,
  "affected_callers": [
    { "file": "src/store/mod.rs", "line": 1532, "enclosing": "commit_round_trips",
      "depth": 1, "reason": "arity 1 -> 2" } ],
  "symbol": "store::Store::commit_batch" }
```

**Verdict logic (conservative — a false "would_break" only costs a review; a false "safe" ships a break):**
- Resolve `symbol` via `sid_for_name`. Not indexed → `{resolution:"not_found", exists:false, candidates:[…]}` (reuse P1's `verify_candidate_pool` + `rank_candidates`); no verdict.
- Found → run `impact::compute` (direct callers; `depth` default 1, reuse `ImpactBounds`). Build `affected_callers` from `ImpactEntry` (file, start_line→`line`, qualified_name→`enclosing`, depth).
- `remove` / `rename`: `would_break` iff `affected_count > 0`, else `safe`. `reason` = "references removed symbol" / "references old name".
- `signature`: extract old shape (F4 `signature_shape` on the indexed def — reuse U2's `actual_signature_shape` helper from P1) and, if `new_signature` is given, the new shape (parse the string as a fn, F4). Both decidable + **arity differs** → `would_break`, `reason` = "arity N -> M". Both decidable + arity equal → `safe` (arity-compatible; callers still listed for review). `new_signature` absent or shape undecidable → `would_break` when callers exist (can't prove safe), `resolution:"indeterminate"`, else `safe`.

Register `"Index.VerifyImpact"` (dispatch + counter + `is_cancellable_method`). MCP tool `verify_impact`. CLI `rts impact <symbol> --change <c> [--new-signature S]` rendering callers like `render_callers_tree`.

**Tests:** remove with callers → `would_break`; remove of an uncalled symbol → `safe`; signature arity 1→2 with callers → `would_break` + per-caller "arity 1 -> 2"; signature arity-preserving → `safe`; unknown symbol → `not_found` + candidates; schema round-trip in `protocol_schemas.rs`; MCP `tool_descriptions` audit.

### U2 — `rts verify` CLI + PostToolUse loop hook

**Files:** `crates/rts-mcp/src/bin/rts.rs` (+ `cli.rs` render) for `rts verify`; `.claude/hooks/rts-verify.sh` (new); `.claude/settings.json` (register PostToolUse on Write|Edit); `.claude/hooks/tests/` (new cases); `AGENTS.md` (document the hook + opt-out).

**`rts verify <path>` (or `--stdin --lang <l>`):** read the file, `extract_references` (F3), call `verify_symbol`/`verify_import` on each decidable reference via the daemon, print the `not_found` ones (`file:line  symbol  (did you mean: <candidate>?)`). Exit code: `0` clean, `1` hallucinations found, `3` daemon error (so a hook can branch). Skips unsupported languages cleanly. Reuses the F3→verify routing from `rts-bench`'s `verify_metrics` (factor the shared bit if clean; else mirror it — keep it small).

**`.claude/hooks/rts-verify.sh` (PostToolUse, matcher `Write`/`Edit`):** soft-enforcement contract identical to `rts-nudge.sh` (exit 0 always; `RTS_HOOK_DISABLED` opt-out; daemon-down → silent; cached health probe). On a Write/Edit to a source file, run `rts verify <tool_input.file_path>`; if it reports hallucinations, emit them via `hookSpecificOutput.additionalContext` so the agent self-corrects next turn. Never block (P2 is annotate-only; the blocking PreToolUse-on-edit gate is P3, gated on `verify_edit`).

**Tests:** extend `.claude/hooks/tests/run-tests.sh` — a Write of a file referencing a real symbol → silent; a Write referencing an invented symbol → nudge naming it; `RTS_HOOK_DISABLED=1` → silent; daemon-down → silent. Plus Rust CLI tests for `rts verify` exit codes.

---

## Acceptance criteria

- `verify_impact` returns `would_break` with the affected-caller list for remove/rename/arity-changing-signature on a called symbol, and `safe` when there are no callers or the change is arity-preserving; unknown symbol → `not_found` + candidates. Schema-validated; CLI parity (`rts impact`).
- `rts verify <file>` exits non-zero and names hallucinated references on a file with an invented symbol; exits 0 on a clean file; degrades cleanly when the daemon is down or the language is unsupported.
- The PostToolUse hook surfaces hallucinations after a Write/Edit, is silent on clean writes, and honors `RTS_HOOK_DISABLED`; covered by the bash hook-test harness.
- Read-only throughout; `cargo test --workspace` green; `cargo fmt --check` clean; no new plain-clippy warnings.

## Deferred / follow-ups
- `uncovered_after_change` (needs test-reachability edges) → P3.
- PreToolUse **blocking** edit gate → P3 (needs `verify_edit`'s shadow-index patch verdict).
- CER (correction-efficiency) measurement → P4 benchmark.

## Requirements trace
| Spec § | Covered by |
| :-- | :-- |
| §3.4 verify_impact | U1 (minus `uncovered_after_change`, deferred) |
| §6.2 hooks (push, loop-breaker) | U2 (PostToolUse annotate; PreToolUse-block deferred to P3) |
| §5 CER | deferred to P4 (documented) |
