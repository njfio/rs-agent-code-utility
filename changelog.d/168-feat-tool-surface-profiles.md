### Feat: `--tools` — selectable tool surfaces

`tools/list` is part of every request's context, and all sixteen tools come to roughly 7,700
tokens per call once their pinned descriptions and schemas are counted — more than some
harnesses budget for their entire tool surface, and those harnesses will filter us down
anyway rather than pay it.

`--tools` (or `RTS_MCP_TOOLS`) now selects the surface: `all` (default, unchanged), `core`
(the eight lookup tools), `verify` (lookup plus the six `verify_*` gates), or a
comma-separated list of tool names. Under a profile the descriptions become one line each —
0.7 KB instead of 11.1 KB — because the pinned comparative paragraphs exist to win the
tool-selection moment against `Bash(grep)`, and a surface of eight tools each named for its
job is its own steering. The schemas do not shrink, so the honest effect is roughly halving:
7,723 tokens for `all`, 3,764 for `core`, 1,374 for a three-tool list, measured by driving
`tools/list` against this repository.

A tool outside the surface is refused, not merely unlisted. That is enforced in
`RtsServer::call_tool` rather than left to `ToolRouter::disable_route`, whose documentation
says `call` rejects a disabled tool while this rmcp version dispatches it anyway — found by
probing the built server, which is also how two profile names that did not exist
(`check_call`, `check_patch`) were caught before they shipped. Both are now pinned by tests:
`tool_surface.rs` drives a real session end to end, and `server.rs` asserts every name in a
profile is a tool the router actually has.
