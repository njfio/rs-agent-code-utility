# Changelog fragments

This directory holds **per-PR changelog fragments**. Each fragment is one
Markdown file that documents a single change. At release time, all
fragments are concatenated into `CHANGELOG.md` under the new version
header, and this directory is emptied.

## Why

The pre-v0.5.5 workflow had every PR edit `CHANGELOG.md`'s `[Unreleased]`
section directly. With 9 PRs in flight at once (which happened in the
v0.5.4 cycle), this guaranteed merge conflicts on every rebase —
roughly 30 minutes of mechanical conflict resolution per release queue.

Per-PR fragments eliminate the conflict. Each PR adds a unique file;
PRs touch independent paths.

## File naming

Use this shape so the release script can sort fragments deterministically:

```
changelog.d/<PR-number>-<kind>-<short-slug>.md
```

Examples:

- `changelog.d/93-feat-grep-regex-mode.md`
- `changelog.d/94-fix-cold-mount-retry-loop.md`
- `changelog.d/95-docs-readme-sync.md`

Recognized kinds: `feat`, `fix`, `refactor`, `perf`, `docs`, `chore`,
`release`. Match the conventional-commit prefix of the PR title.

If the PR doesn't yet have a number assigned (drafting before push),
use `xxx-<kind>-<slug>.md` and rename before merge.

## Fragment shape

A fragment is just regular Markdown — no front-matter, no special
syntax. The release script will copy it verbatim under the version
header. Example:

```markdown
### `Index.Grep.params.regex` — opt-in regex syntax

Pre-v0.5.5 `Index.Grep` accepted literal substrings only. v0.5.5+
accepts `regex: true` to interpret `text` as a regex pattern…
```

Use a top-level `###` header so the fragments fit under the
`## [x.y.z]` heading the release script generates. Keep entries
self-contained — readers shouldn't need to chase context across
multiple fragments.

## Releasing

Run:

```sh
./scripts/build-changelog.sh <version>
```

This:

1. Reads every `*.md` (except `README.md`) in `changelog.d/`, sorted by filename
2. Concatenates them under a new `## [<version>] - <today>` heading
3. Inserts the new section at the top of `CHANGELOG.md` under `## [Unreleased]`
4. Deletes the consumed fragments (leaves `README.md`)
5. Prints the resulting CHANGELOG header for review

The release commit then bundles:

- `CHANGELOG.md` update
- `changelog.d/` deletions
- `Cargo.toml` version bump

…in a single commit titled `release: vX.Y.Z — <theme>`, tagged when
the PR merges.
