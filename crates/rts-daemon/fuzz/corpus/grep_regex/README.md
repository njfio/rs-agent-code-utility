# `grep_regex` fuzz corpus

Seeds for `fuzz_targets/grep_regex.rs`. Each file is one input — a
bytes payload fed verbatim to the target. libFuzzer mutates from these
seeds outward; well-curated seeds find bugs faster than random bytes.

## What's covered

| File | Class | Why |
|---|---|---|
| `redos_aplus_aplus` | catastrophic backtracking | The OWASP canonical `(a+)+` pattern. Worst-case exponential against `aaaaaaaaaaaaaaaaX`. |
| `redos_dotplus_plus` | catastrophic backtracking | `(.+)+` — same exponential class, different alphabet. |
| `redos_astar_star` | catastrophic backtracking | `(?:a*)*` — nested star with non-capturing group. |
| `redos_alternation_a_aa` | catastrophic backtracking | `(a\|aa)*` — alternation with overlapping prefixes. |
| `redos_multiline_dotstar` | DFA blow-up | `(?s).*` — dotall over arbitrary buffers; tests the multiline DFA budget. |
| `redos_dotstar_repeat` | bounded blow-up | `(.*a){50}` — bounded but still pathological. |
| `wellformed_fn_signature` | sanity | `fn\s+\w+\([^)]*\)\s*->\s*\w+` — a real query the daemon should run fast on. |
| `wellformed_literal` | sanity | Plain text the daemon should literally match. |

## Consumer

`crates/rts-daemon/fuzz/fuzz_targets/grep_regex.rs`

## Promise validated

RESILIENCE.md §"ReDoS (catastrophic backtracking)".
