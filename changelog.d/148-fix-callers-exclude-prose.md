### Fix: `find_callers` / `impact_of` no longer surface prose mentions

The reference graph's identifier-regex fallback treated Markdown like
code, so a function name written in prose (``See `commit_batch` for…``)
became a fake call site. Markdown is now excluded from that regex
fallback, so `find_callers` and `impact_of` report only real,
AST-derived call edges. Markdown headings remain first-class
`find_symbol` targets — only the spurious *caller* edges are removed.
