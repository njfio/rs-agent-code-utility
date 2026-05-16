### `changelog.d/` fragments — kill the per-PR CHANGELOG conflict

The v0.5.4 release queue (9 PRs) every concurrent PR collided on `CHANGELOG.md`'s `[Unreleased]` section. Each rebase produced the same shape of conflict; ~30 minutes of mechanical resolution per release.

v0.5.5+ adopts the "changelog fragments" pattern (familiar from Towncrier, mkdocs, etc.): each PR adds a unique file to `changelog.d/`. At release time, `scripts/build-changelog.sh <version>` concatenates them under a new version header in `CHANGELOG.md` and clears the fragments dir.

#### Surface

- `changelog.d/README.md` — workflow spec + file naming convention
- `scripts/build-changelog.sh` — the release script (dry-run supported)
- `AGENTS.md` — updated with the new workflow

#### Migration

Existing entries in `CHANGELOG.md`'s `[Unreleased]` section (if any) stay where they are — the script inserts AFTER the `[Unreleased]` header but BEFORE the new version section. Manual entries and fragment entries coexist during the transition.

This PR itself is the first one to use the new pattern: the fragment you're reading came from `changelog.d/93-chore-changelog-fragments.md`.

#### Out of scope (filed for follow-up)

- A pre-commit hook that warns when a PR touches `crates/` but not `changelog.d/`. Catches the "I forgot to add a fragment" case at commit time rather than at release time.
- Per-kind subdirectories (`changelog.d/feat/`, `changelog.d/fix/`) so the release header groups by change type. Probably unnecessary at our volume but worth considering if we hit 20+ PRs/cycle.
