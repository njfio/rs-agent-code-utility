### `README.md` rewrite + `docs/demo.md` + `docs/development.md` split

The repo's `README.md` had grown into a 403-line maintenance doc — phase tables, known-limitations essays, internal architecture notes, contribution workflow — all of which is **useful to someone already invested in the project**, none of which is the *pitch* a first-time visitor needs.

After eight rounds of *"is the product great?"* reflection, the structural answer was clearer: the product works, the observability is complete, the habit intervention is live, the measurement harness is in flight — but the README isn't reaching anyone outside this conversation, which keeps the user count at 1. README's are the first 60 seconds of every potential adoption.

#### What changed

- **`README.md`**: rewritten from 403 → 142 lines. Pitch-first ("AST-precise code search for AI coding agents"). Real side-by-side `rg` vs `rts find-callers` example in the third paragraph showing the load-bearing difference: bash grep returns *where the match appears*; `rts` returns *which function contains it*. Token-reduction table. Quick-start install + `claude mcp add` one-liner. Eight-tool surface in a single intent → tool table. Architecture diagram + 2 sentences. Honest status section noting what's *not* done (Windows port, public agent-bench baseline, Docker patch-eval).
- **`docs/development.md`** (new, ~250 lines): the maintainer content lifted out of the old README — phase status table, known limitations, building from source, crate / dir layout, full benchmark commands, full eight-tool schemas, contributing workflow. Cross-references back to `AGENTS.md` for coding standards.
- **`docs/demo.md`** (new, ~130 lines): five reproducible side-by-side demos against the rts repo itself: `find_callers`, `read_symbol`, `find_symbol --pattern '*'` (PageRank ranking), `grep` with enclosing-function names, and Unix-pipe composability. Every command is paste-runnable. Asciinema-recording instructions at the end.

#### Decisions worth flagging

- **Pitch lead is one sentence.** Tagline ("AST-precise code search for AI coding agents") plus *"99.9% less context for the same answer."* If a visitor doesn't bounce in the first sentence, the second paragraph commits them with the killer demo.
- **The headline demo is `find_callers`, not `find_symbol`.** find_symbol is what the agent uses most — but `find_callers` is the one that *can't be matched by `rg`*, so it's the visceral pitch. Two screenshots' worth of side-by-side; the reader sees the value without scrolling.
- **Status section says "Active pre-1.0, used daily by the author."** Honest. Doesn't oversell. Explicitly asks for outside users via the issue tracker.
- **Eight-tool table replaces seven sub-headings.** Maintenance pressure was the seven-tools section growing every time a tool was added; the table format scales.
- **`agent-bench/` gets one line in the status section + one pointer in More documentation.** Resists the temptation to over-promote a Phase-2 PR-A that hasn't shipped its first real measurement yet.

#### Verification

- All cross-references in the new README + `docs/development.md` resolve (verified via a grep of `[text](path)` link extraction + filesystem `[[ -e ]]`; external URLs not checked).
- README front matter renders correctly on GitHub (shield badges, table, fenced code blocks).
- Original token-reduction numbers in the table preserved verbatim from prior README (`docs/development.md` retains the full reproducer commands).

#### Out of scope (filed for follow-up)

- **Asciinema recording.** The `docs/demo.md` script is ready to record; the actual `.cast` file lands when the next session has a fresh terminal. Adding a recorded gif/cast to README's demo block is the next visible-discoverability step.
- **Homebrew formula.** Currently install is `curl | tar -xz` or `cargo build`. A `brew install rts` path is the lowest-friction discovery moment after the README + demo lands.
- **GitHub topic tags + repo description.** The repository's own metadata (topics, description, README preview snippet) is set via the GitHub UI, not committed in this PR.
- **Public agent-bench baseline result.** Once Phase 2 PR-B (`agent-bench/` runner + corpus + first run) lands, the README's "Why" section can quote a real tool-use-ratio number instead of an anecdotal pitch.
