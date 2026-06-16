### Feature: `rts grep --structural-query` — tree-sitter structural filtering

`rts grep` now accepts `--structural-query '<s-expr>'` with a required
`--language <lang>`, filtering matches to tree-sitter node kinds. This
expresses searches plain grep cannot: *string literals containing X*
(`--structural-query '(string_literal) @s' <text>`) or *identifier
usages of Y* (`(identifier) @i`). Companion flags: `--within-symbol`
(scope matches to one symbol's byte range),
`--within-symbol-allow-overload`, and `--multiline` (regex across line
boundaries). Output keeps the ripgrep-shaped `path:line:col:content`
contract; the captured node text is the content field.
