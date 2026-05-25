### Semantic-eval corpora — negative controls recalibrated post-cleanup

The pre-pivot cleanup (PRs #132–#134) deleted a large rts-core symbol
surface. During that cleanup the negative-control queries in both
semantic-eval corpora were *removed* rather than recalibrated, because
the vocabulary shift made the old probes hallucinate confident top-1
hits (`not_supported_error`, `Handler`, `cache`, `rate_limit_error`, …).

This re-adds 6 negative controls per corpus, calibrated against the
**current** (post-cleanup) rts-core symbol pool:

- `corpus/semantic-eval-rts-core.toml`: cipher/AES, DNS/TTL, SMTP,
  GraphQL, Kafka, Bluetooth.
- `corpus/semantic-eval-rts-core-blind-v2.toml`: HTTP router, WebSocket,
  DB migrations, cron scheduler, TLS certificates, GPU shader.

Each topic was chosen so its content tokens have zero lexical overlap
with any pooled symbol (including `test_files/` and `tests/`, which the
CI-mounted `crates/rts-core` workspace contains), avoiding the live
fuzzy-neighbor traps — the `error.rs` builder family, `constants.rs`
remnants, the `cache_*` family, and the per-language `render_*` family.
Each control was verified to return an unrelated PageRank-fallback top-1
(e.g. `clone_parser`, `render_go`, `new`, `duration`), not a confident
topical match.

`expected_top_k = []` excludes these queries from `answerable_coverage`,
so the CI semantic-eval gate is unaffected: v1 holds at 1.000 (gate
0.95) and blind-v2 at 0.857 (gate 0.75).
