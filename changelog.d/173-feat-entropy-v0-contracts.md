### Feat: entropy-v0 contract subcommands (experimental)

Three new `rts` CLI subcommands implementing the entropy-v0 §7 contract
(golden fixtures live in the entropy starter repo, `fixtures/rts/*.json`).
All three are gated behind `--features experimental` per the experimental
surface gate, and run **in-process** over rts-core (`rust_tree_sitter`)
rather than through the daemon — they're whole-workspace batch scans that
must work headless inside `timeout 2` chat hooks, so no socket/auto-spawn.

- **`rts context --for <text> --k N --token-budget N --format hook-json`** —
  ranks workspace symbols against a task description (lexical name/doc/path
  token overlap) and emits `{"offered":[…],"rendered":"…"}`: per-symbol
  `symbol_id` (stable `crate::qualified@path#Lline`), name, kind, path,
  line, signature (body stripped via the core `signature::render_*`
  helpers), `doc_first_line`, rank, score. `rendered` is a markdown block of
  names + doc first lines — never bodies — hard-capped at the token budget,
  truncating lowest-ranked first. ~1.3s cold on this repo (120k LOC).
- **`rts clones [--min-mass-tokens N] --format json|summary`** — Type-1/
  Type-2 clone detection via post-order normalized AST-subtree hashing
  (identifier leaves → `ID`, literal leaves → `LIT`, comments dropped;
  blake3, first 8 bytes as `cluster_id`). Only maximal clusters are kept
  (sites contained in a larger accepted cluster's sites are dropped).
  `json` emits clusters sorted by `score = mass_tokens × spread_files`
  descending; `summary` emits `{"dup_pct", "clusters"}` where `dup_pct` is
  the % of indexed leaf tokens inside some cluster.
- **`rts snapshot --format json`** — repo-level entropy stats: `rev`
  (`git rev-parse --short HEAD`), `loc`, `symbols`, `dup_pct`,
  `clone_clusters`, plus `mean_fan_in` / `mean_fan_out` / `deps_direct` /
  `deps_transitive` emitted as `null` (nullable per the contract; rts
  doesn't compute them yet).

New module `rts_mcp::entropy` (`#[cfg(feature = "experimental")]`, so the
default-features public API surface is unchanged). Verified against the
entropy starter's `tests/test_rts_contract.sh` — all four cases green.
