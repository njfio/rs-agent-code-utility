### Fix: `build-changelog.sh` keeps `_Nothing yet._` under `[Unreleased]`

The release rollup injected the new `## [x.y.z]` header immediately
after the `## [Unreleased]` line, which stranded the `_Nothing yet._`
placeholder at the foot of the new section and left `[Unreleased]`
empty. It now inserts the new section *after* the `[Unreleased]` block
(just before the previous version header), preserving the placeholder.
Covered by a new regression test (`scripts/build-changelog.test.sh`,
run in CI).
