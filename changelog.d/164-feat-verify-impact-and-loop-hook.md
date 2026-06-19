### Feat: `verify_impact` pre-edit gate + a verification loop hook

Extends the verification layer (verify-v0 P2) from checking *claims* to gating
*edits* and wiring verification into the live agent loop.

- **`verify_impact` / `Index.VerifyImpact`** — declare an intended change to a
  symbol (`signature` | `remove` | `rename`) and get the blast radius as a
  pass/fail `verdict` (`would_break` | `safe`). Wraps the reverse-call-graph
  walk: lists `affected_callers[]` with a per-caller `reason`, and for a
  `signature` change compares the proposed arity to the real one (pass
  `new_signature`). Conservative — `safe` means no *arity* break (v0 checks
  arity only). Honors qualified names (`Foo::method`); unknown symbol →
  `not_found` + ranked candidates. Available as the `rts impact` CLI too.

- **`rts verify <file>`** — check a file's symbol/import references against the
  index and report hallucinated (not_found) ones as `FILE:LINE  name  (did you
  mean: …?)`. Exit 0 clean, 1 hallucinations found, 3/4 daemon error.

- **PostToolUse loop hook** (`.claude/hooks/rts-verify.sh`) — after each
  Write/Edit, runs `rts verify` on the changed file and feeds any hallucinated
  references back to the agent so it self-corrects next turn. Annotate-only
  (never blocks), silent when the daemon is down, opt out with
  `RTS_HOOK_DISABLED=1`.

Deferred: the `uncovered_after_change` coverage field (needs test-reachability
edges) and a *blocking* pre-edit gate both land with `verify_edit` (P3).
