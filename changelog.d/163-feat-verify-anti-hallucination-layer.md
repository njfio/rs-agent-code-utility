### Feat: verification layer — `verify_*` tools + hallucination metrics

rts can now fact-check an agent's claims against the ground-truth AST graph,
deterministically and with no LLM in the path. New protocol-v0 methods + MCP
tools:

- `verify_symbol` — does this symbol exist? Returns `exact`/`not_found`/
  `indeterminate`, and on a miss, ranked near-misses (edit-distance + PageRank)
  so the agent self-corrects in the same turn.
- `verify_signature` — does a call match the definition (arity, params, return)?
- `verify_import` — does an import path resolve? (thin v0: final-segment resolution;
  full cross-module resolution is deferred.)
- `verify_claims` — batch grounding check over symbol/signature/import/location
  claims, reporting a `grounding_rate` that excludes undecidable claims.

Every result carries a `resolution` (`exact` | `not_found` | `indeterminate`);
`indeterminate` is never upgraded to `not_found`, so a benchmark can't game
itself. All tools are read-only.

`rts-bench verify` computes the deterministic hallucination metrics — Symbol
Hallucination Rate (SHR), Import Hallucination Rate (IHR), and (arity-only in v0)
Signature Mismatch Rate (SMR) — by parsing agent-generated code with rts's own
tree-sitter pipeline, extracting its references, and checking each against the
index. Each metric reports its denominator and the count of `indeterminate`
references excluded, so coverage is visible rather than cherry-picked.

`AGENTS.md` now guides agents to verify before they claim.
