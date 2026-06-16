### Fix: structural grep `--limit` bounds returned matches, not the raw scan

`rts grep --structural-query … --limit N` previously capped the raw
tree-sitter node scan at N *before* applying the text filter, so a match
sitting past the first N nodes was never found (e.g. `--limit 1` on a
file whose target identifier is the last node returned nothing). The
limit now bounds the *returned* match set: the scan continues past
filtered-out nodes until N real matches are collected or the file ends.
