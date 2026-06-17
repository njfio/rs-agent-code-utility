### Feature: overload disambiguation via parent scope

Definitions now carry a `parent` — the nearest enclosing container
(`impl`/`class`/`struct`/`trait`/…). `find_symbol`/`read_symbol` render
`qualified_name` as `parent::name` (uniform `::`), expose a `parent`
field, and accept a `parent` exact-match filter, so same-named defs
across types are finally distinguishable (`QueryBuilder::new` vs
`Parser::new`). All 12 code languages (Go via method receiver); markdown
headings keep their hierarchical names. New capability `parent_scope`.
The reference graph and `find_callers` are unchanged (still name-level).
The on-disk index schema bumped; the daemon rebuilds automatically on
first run after upgrade.
