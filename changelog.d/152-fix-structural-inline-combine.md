### Fix: structural grep + text/regex no longer truncates on large scopes

`rts grep --structural-query … <text>` applied the literal/regex
intersection filter *after* the structural scan was capped at
`STRUCTURAL_MAX_ROWS` (4096), so on a large scope the cap consumed raw
structural nodes before the filter ran and real matches past the first
4096 nodes were silently dropped. The filter now runs **inline** during
the scan, so the cap counts only matches that satisfy both the structural
query and the text/regex filter. Regex compile errors fail fast before the
scan; the per-file post-pass (and its extra file reads) is gone.
