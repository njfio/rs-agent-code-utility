# AGENTS.MD — Swarming Agent Contract for Advanced Software Development

> **Version:** 4.0.0
> **Protocol:** Sovereign Swarm Architecture (SSA)
> **Compatibility:** Claude Code, Cursor, Aider, Codex, any MCP-compatible agent runtime
> **Last Revised:** 2026-03-09

---

## Table of Contents

1. [Philosophy & Core Principles](#1-philosophy--core-principles)
2. [Swarm Topology](#2-swarm-topology)
3. [Agent Registry](#3-agent-registry)
4. [Communication Protocol](#4-communication-protocol)
5. [Skills Architecture](#5-skills-architecture)
6. [GitHub Workflow Integration](#6-github-workflow-integration)
7. [Task Lifecycle](#7-task-lifecycle)
8. [Quality Gates](#8-quality-gates)
9. [File Ownership & Boundaries](#9-file-ownership--boundaries)
10. [Error Handling & Escalation](#10-error-handling--escalation)
11. [Context Management](#11-context-management)
12. [Security Protocol](#12-security-protocol)
13. [Performance Standards](#13-performance-standards)
14. [Agent Contracts (Detailed)](#14-agent-contracts-detailed)
15. [Orchestration Patterns](#15-orchestration-patterns)
16. [Appendix: Templates & Examples](#16-appendix-templates--examples)

---

## 1. Philosophy & Core Principles

### 1.1 The Swarming Paradigm

This system operates on the principle of **radical specialization**: no single agent should hold responsibility for more than one cognitive domain. Each agent is a world-class specialist in exactly one concern. The swarm's intelligence emerges from the precise coordination of narrow experts — not from any single generalist.

### 1.2 Inviolable Principles

```
PRINCIPLE 1: SINGLE RESPONSIBILITY
  Every agent owns exactly one domain. No exceptions. No "while you're at it."

PRINCIPLE 2: EXPLICIT CONTRACTS
  Every agent declares its inputs, outputs, and failure modes. Implicit behavior is a bug.

PRINCIPLE 3: IMMUTABLE HANDOFFS
  When an agent passes work to another, the handoff artifact is immutable.
  The receiving agent works on a copy. The original is the audit trail.

PRINCIPLE 4: FAIL LOUD, RECOVER QUIET
  Agents must surface all failures immediately and with full context.
  Recovery attempts happen silently unless they also fail.

PRINCIPLE 5: AUTONOMOUS DELIVERY, HUMAN OVERSIGHT
  Agents own the full lifecycle: code, review, fix, merge, and close.
  @conductor merges when all quality gates pass — no human bottleneck.
  @resolver triages issues, coordinates amendments, and drives re-merge.
  The Arbiter (human) retains veto authority and can halt, revert, or override
  at any point, but the swarm does NOT block waiting for human approval.
  Production deployment remains gated by explicit human release approval.
  No agent deletes data or force-pushes to main without Arbiter override.

PRINCIPLE 6: CONTEXT MINIMALISM
  Each agent receives only the context it needs. No agent reads the full codebase
  unless its contract explicitly requires it. Context is expensive — treat it that way.

PRINCIPLE 7: TRACEABILITY
  Every code change, every decision, every file touch is attributable to a specific
  agent acting on a specific task. Unsigned work is rejected.

PRINCIPLE 8: SKILLS OVER AD-HOC
  Repeatable workflows are encoded as skills, not rediscovered each time.
  Skills carry the repo's definition of "how this work is done."
  Mandatory skill triggers in AGENTS.md are not optional — they are enforceable.
  If the model is rediscovering the same recipe every invocation, it should be a skill.
```

### 1.3 Definitions

| Term | Meaning |
|------|---------|
| **Agent** | An autonomous AI instance with a defined role, operating within its contract |
| **Swarm** | The coordinated set of all active agents working toward a shared objective |
| **Contract** | The binding specification of an agent's inputs, outputs, behaviors, and limits |
| **Handoff** | A structured transfer of work product from one agent to another |
| **Task** | An atomic unit of work assigned to a single agent |
| **Epic** | A collection of related tasks that deliver a feature or capability |
| **Quality Gate** | A checkpoint that work must pass before proceeding to the next phase |
| **Arbiter** | The human developer who retains veto authority and strategic oversight but does not bottleneck delivery |

---

## 2. Swarm Topology

### 2.1 Architecture

```
                            ┌─────────────────┐
                            │     ARBITER      │
                            │  (Human: Veto    │
                            │   & Strategy)    │
                            └────────┬────────┘
                                     │ oversight
                            ┌────────▼────────┐
                            │   ORCHESTRATOR   │
                            │   (@conductor)   │
                            └────────┬────────┘
                                     │
            ┌────────────────────────┼────────────────────────┐
            │                        │                        │
   ┌────────▼────────┐    ┌────────▼────────┐    ┌─────────▼────────┐
   │    PLANNING      │    │   EXECUTION      │    │    ASSURANCE      │
   │    LAYER          │    │   LAYER           │    │    LAYER           │
   └────────┬────────┘    └────────┬────────┘    └─────────┬────────┘
            │                      │                        │
   ┌────┬───┘              ┌──┬──┬┘─┐              ┌────┬──┼────┐
   │    │                  │  │  │  │              │    │  │    │
  Spec Arch              Impl API  DB           Test Rev Sec  Perf
  Agent Agent            Agent Agent Agent       Agent Agent Agent Agent
                           │
                     ┌─────┼─────┐
                     │     │     │
                   Front  Back  Infra
                   Agent  Agent Agent

                    ┌──────────────────────────────┐
                    │       DELIVERY LAYER           │
                    │                                │
                    │  @resolver ←── issues ──→ @merger  │
                    │  (triage,        (merge,       │
                    │   amend,          revert,      │
                    │   verify)         promote)     │
                    └──────────────────────────────┘
```

### 2.2 Layer Responsibilities

**Planning Layer** — Understands *what* to build and *how* to structure it
**Execution Layer** — Writes the actual code, schemas, and configurations
**Assurance Layer** — Validates that everything works, is secure, and is maintainable
**Delivery Layer** — Resolves issues, merges code, verifies post-merge, and closes the loop

### 2.3 Information Flow

```
Requirements → Planning → Execution → Assurance → Delivery → Merged
                  ↑                        │            │
                  └──── @resolver ──────────┘            │
                         (amend)                         │
                                                         │
                  Arbiter ◄──── notification ─────────────┘
                         (veto/revert if needed)
```

Information flows forward through handoffs. When Assurance finds issues, `@resolver` triages them and routes amendments back to Execution agents. Once all gates pass, `@merger` executes the merge and `@resolver` verifies post-merge. The Arbiter receives notifications and retains veto authority but does not block the pipeline.

---

## 3. Agent Registry

### 3.1 Orchestration Tier

| Agent ID | Name | Domain |
|----------|------|--------|
| `@conductor` | **Orchestrator** | Task routing, sequencing, conflict resolution, swarm coordination |
| `@merger` | **Merge Controller** | PR merge execution, merge conflict resolution, branch hygiene, post-merge verification |
| `@resolver` | **Issue Resolver** | Issue triage, amendment coordination, fix verification, re-merge orchestration |

### 3.2 Planning Tier

| Agent ID | Name | Domain |
|----------|------|--------|
| `@spec` | **Spec Analyst** | Requirements analysis, acceptance criteria, user story refinement |
| `@architect` | **Architect** | System design, component boundaries, technology selection, ADRs |
| `@planner` | **Task Planner** | Work decomposition, dependency mapping, sequencing, estimation |

### 3.3 Execution Tier

| Agent ID | Name | Domain |
|----------|------|--------|
| `@frontend` | **Frontend Engineer** | UI components, client state, styling, accessibility, browser APIs |
| `@backend` | **Backend Engineer** | Server logic, API handlers, business rules, service layer |
| `@data` | **Data Engineer** | Schemas, migrations, queries, ORM models, data integrity |
| `@api` | **API Designer** | Endpoint contracts, OpenAPI specs, request/response schemas, versioning |
| `@infra` | **Infrastructure Engineer** | CI/CD, Docker, IaC, deployment configs, environment management |
| `@integrator` | **Integration Engineer** | Third-party APIs, webhooks, message queues, external service adapters |

### 3.4 Assurance Tier

| Agent ID | Name | Domain |
|----------|------|--------|
| `@tester` | **Test Engineer** | Unit tests, integration tests, e2e tests, test fixtures, coverage |
| `@reviewer` | **Code Reviewer** | Code quality, patterns, readability, maintainability, PR review |
| `@security` | **Security Analyst** | Vulnerability scanning, auth flows, input validation, secrets management |
| `@perf` | **Performance Engineer** | Benchmarking, profiling, optimization, load testing, caching strategy |
| `@docs` | **Technical Writer** | API docs, READMEs, architecture docs, inline documentation, changelogs |

### 3.5 Specialist Tier (On-Demand)

| Agent ID | Name | Domain |
|----------|------|--------|
| `@refactor` | **Refactoring Specialist** | Code restructuring, pattern migration, tech debt reduction |
| `@debug` | **Debugger** | Root cause analysis, reproduction, fix verification |
| `@migrate` | **Migration Specialist** | Version upgrades, data migrations, breaking change management |
| `@a11y` | **Accessibility Specialist** | WCAG compliance, screen reader testing, keyboard navigation |
| `@i18n` | **Internationalization Specialist** | Localization, string extraction, RTL support, locale handling |

---

## 4. Communication Protocol

### 4.1 Message Format

All inter-agent communication uses a structured envelope:

```yaml
# Agent Communication Envelope (ACE)
message:
  id: "msg-{uuid}"
  timestamp: "ISO-8601"
  from: "@agent-id"
  to: "@agent-id | @conductor"
  type: "handoff | feedback | query | status | escalation"
  priority: "critical | high | normal | low"
  task_ref: "TASK-{id}"
  payload:
    summary: "One-line description of the message purpose"
    body: "Detailed content, structured per message type"
    artifacts:
      - path: "relative/path/to/file"
        action: "created | modified | reviewed | deleted"
        checksum: "sha256:{hash}"
  context:
    requires: ["list of context files this agent needed"]
    modifies: ["list of files this message affects"]
  metadata:
    token_cost: 0
    duration_ms: 0
    confidence: "high | medium | low"
```

### 4.2 Handoff Protocol

When an agent completes its work and passes to the next agent:

```
1. Agent completes all work items in its contract
2. Agent runs its own self-validation checklist
3. Agent creates a HANDOFF document:
   - Summary of work completed
   - List of all artifacts created/modified (with paths)
   - Known limitations or concerns
   - Explicit list of what the NEXT agent should focus on
   - Any deviations from the original task spec
4. Agent sends handoff to @conductor
5. @conductor validates completeness
6. @conductor routes to next agent with scoped context
```

### 4.3 Feedback Loop Protocol

When an Assurance agent finds issues with Execution work:

```
1. Assurance agent creates a FEEDBACK report:
   - Severity: blocker | major | minor | suggestion
   - Location: exact file, line, function
   - Description: what is wrong
   - Evidence: test output, scan results, benchmark data
   - Recommendation: specific suggested fix (not vague)
2. Feedback routes through @conductor → @resolver (never direct to execution agent)
3. @resolver evaluates severity and triages:
   - blocker/major → creates amendment task, routes to execution agent with fix instructions
   - minor → batches for next iteration or defers (logged override)
   - suggestion → logged for future consideration
4. Execution agent addresses amendment and re-submits for review
5. @resolver verifies the fix addresses the original finding
6. Maximum 3 amendment cycles before @resolver escalates to @architect or Arbiter
```

### 4.4 Query Protocol

When an agent needs clarification from another agent or the Arbiter:

```yaml
query:
  question: "Specific, answerable question"
  context: "Why I need this to proceed"
  options: ["option A", "option B"]  # if applicable
  blocking: true | false             # can I continue without this answer?
  timeout: "30m"                     # how long before auto-escalation
```

---

## 5. Skills Architecture

### 5.1 What Is a Skill?

A skill is a self-contained package of operational knowledge that captures a repeatable workflow. Rather than relying on agents to rediscover procedures every time, skills encode the repository's definition of how specific work should be done.

Each skill is a directory containing:

```
.agents/skills/{skill-name}/
├── SKILL.md           # Manifest: name, description, instructions (required)
├── scripts/           # Deterministic shell work (optional)
├── references/        # Supporting docs, examples, specs (optional)
└── assets/            # Templates, configs, fixtures (optional)
```

### 5.2 Progressive Disclosure Model

Skills use a progressive-disclosure model to manage context cost:

```
STAGE 1: DISCOVERY (always loaded)
  Agents see only the skill's `name` and `description` from SKILL.md frontmatter.
  This is the routing signal. It must be sufficient to decide whether to activate.

STAGE 2: ACTIVATION (loaded on selection)
  When an agent selects a skill, the full SKILL.md body is loaded.
  This contains the detailed instructions, checklists, and workflow steps.

STAGE 3: EXECUTION (loaded on demand)
  scripts/, references/, and assets/ are accessed only when the
  skill's instructions explicitly call for them.
```

This is critical for context economy. With 20+ skills in a mature repo, loading all of them fully would consume the context budget before any real work begins. Progressive disclosure ensures agents pay only for what they use.

### 5.3 SKILL.md Frontmatter Contract

The `description` field is **routing metadata**, not documentation. It must tell agents three things: what the skill does, when it should trigger, and what kind of output it produces.

```yaml
---
name: code-change-verification
description: >
  Run the mandatory verification stack when changes affect runtime code,
  tests, or build/test behavior. Trigger after implementation work and
  before marking the task complete. Outputs a pass/fail verification
  report with specific failure details.
---
```

**Bad descriptions** (too vague to route on):

```yaml
# ❌ Says what, not when or why
description: Run the test suite.

# ❌ No trigger condition
description: Verify code quality for the project.

# ❌ No output description
description: Check that everything works.
```

**Good descriptions** (full routing signal):

```yaml
# ✓ What + When + Output
description: >
  Run the mandatory verification stack when changes affect runtime code,
  tests, examples, or build/test behavior in the monorepo. Do not trigger
  for docs-only changes. Outputs pass/fail with specific failure locations.

# ✓ What + When + Output
description: >
  Create a PR title and draft description after substantive code changes
  are finished. Trigger when wrapping up a moderate-or-larger change
  (runtime code, tests, build config, docs with behavior impact).
  Outputs a structured PR-ready block with branch name, title, and
  description.

# ✓ What + When + Output
description: >
  Validate changeset metadata when any file under packages/ or .changeset/
  changes. Compares the git diff against the declared bump level and
  summary. Outputs a validation report with pass/fail per changeset.
```

### 5.4 The Scripts-vs-Model Split

The most important design decision in any skill is what goes in scripts vs. what stays with the model. The principle:

```
SCRIPTS handle deterministic, repeated shell work:
  - Running verification commands in a fixed order
  - Collecting logs and structured outputs
  - Fetching previous release tags
  - Publishing to local registries for integration tests
  - Writing rerun files for failed examples
  - Any recipe the agent would otherwise rediscover every time

THE MODEL handles contextual, interpretive work:
  - Reading source code to infer intended behavior
  - Comparing logs against that intended behavior
  - Deciding whether a diff contains a real compatibility risk
  - Judging whether a changeset's bump level matches the actual changes
  - Producing explanations that a maintainer can act on
  - Routing decisions (which agent, which skill, which priority)
```

If the model is rediscovering the same shell recipe on every invocation, that recipe should be a script. If the task requires understanding, comparison, or judgment, it stays with the model.

Scripts should behave like tiny CLIs: run from the command line, print deterministic stdout, fail loudly with clear error messages, and write outputs to known file paths.

### 5.5 Mandatory Skill Triggers

`AGENTS.md` (this file) makes skills enforceable by declaring **conditional trigger rules**. These are if/then rules that agents must follow:

```yaml
mandatory_skills:

  # Before making changes
  - trigger: "Before editing runtime code, API contracts, or shared types"
    skill: "$implementation-strategy"
    agent: "@architect | executing agent"
    purpose: "Decide compatibility boundary and approach before writing code"

  # During implementation
  - trigger: "When changes affect runtime code, tests, examples, or build behavior"
    skill: "$code-change-verification"
    agent: "executing agent (self-verify before handoff)"
    purpose: "Run the repo's mandatory verification stack"
    exception: "Skip for docs-only or config-only changes with no behavior impact"

  - trigger: "When package changes affect release metadata (monorepo)"
    skill: "$changeset-validation"
    agent: "executing agent"
    purpose: "Validate bump levels match actual package diff"

  - trigger: "When work touches external API integrations or platform surfaces"
    skill: "$external-api-knowledge"
    agent: "executing agent"
    purpose: "Look up current API docs instead of answering from stale training data"

  # After implementation
  - trigger: "When substantive code work is finished and ready for review"
    skill: "$pr-draft-summary"
    agent: "@conductor"
    purpose: "Produce standardized branch name, PR title, and description"

  - trigger: "When preparing a release candidate"
    skill: "$release-review"
    agent: "@reviewer + @security"
    purpose: "Diff previous tag against HEAD for compatibility and regression risks"

  - trigger: "When integration or example validation is needed"
    skill: "$integration-test-runner"
    agent: "@tester"
    purpose: "Run examples in auto mode, collect logs, model validates against source"

  # Documentation
  - trigger: "When runtime code changes may have made docs stale"
    skill: "$docs-sync"
    agent: "@docs"
    purpose: "Audit docs against codebase, prioritize gaps, ask before editing"
```

**The conditional part keeps lightweight work lightweight.** A docs-only change does not trigger `$code-change-verification`. **The mandatory part ensures that qualifying changes never skip the workflow.**

### 5.6 Skill Registry

Each agent owns specific skills that align with its domain. Skills live in `.agents/skills/` and are versioned with the repository.

```yaml
skill_registry:

  # Planning Skills
  "$implementation-strategy":
    owner: "@architect"
    description: "Decide compatibility boundary and implementation approach before editing runtime or API changes"
    triggers_on: "runtime code, API contract, or shared type modifications"

  # Verification Skills
  "$code-change-verification":
    owner: "@tester"
    description: "Run mandatory format, lint, typecheck, and test stack when code or build behavior changes"
    triggers_on: "runtime code, test, example, or build behavior changes"
    scripts:
      - "scripts/verify.sh"  # runs verification commands in fixed order

  "$changeset-validation":
    owner: "@merger"
    description: "Validate changeset bump levels against actual package diff"
    triggers_on: "package changes in monorepo, .changeset/ modifications"
    scripts:
      - "scripts/validate-changesets.sh"

  "$integration-test-runner":
    owner: "@tester"
    description: "Run examples in auto mode, collect per-example logs, model validates output against source"
    triggers_on: "integration test phase, example changes, dependency updates"
    scripts:
      - "scripts/run-examples.sh"      # execute examples, collect logs
      - "scripts/run-integration.sh"    # publish to local registry, test install+run

  # Handoff Skills
  "$pr-draft-summary":
    owner: "@conductor"
    description: "Produce branch name, PR title, and draft description when substantive work is ready for review"
    triggers_on: "task completion, ready for PR creation"

  # Release Skills
  "$release-review":
    owner: "@reviewer"
    description: "Diff previous release tag against HEAD, check for compatibility issues and regressions"
    triggers_on: "release candidate preparation, version bump"
    scripts:
      - "scripts/release-diff.sh"  # fetch previous tag, generate structured diff

  # Documentation Skills
  "$docs-sync":
    owner: "@docs"
    description: "Audit docs against codebase, find missing/incorrect/outdated documentation, report before editing"
    triggers_on: "runtime code changes that may invalidate existing documentation"

  # External Knowledge Skills
  "$external-api-knowledge":
    owner: "any agent"
    description: "Look up current external API/platform docs via MCP instead of relying on training data"
    triggers_on: "work touching third-party API integrations"

  "$test-coverage-improver":
    owner: "@tester"
    description: "Run coverage analysis, find biggest gaps, propose high-impact tests"
    triggers_on: "test coverage review phase, quality improvement sprints"
    scripts:
      - "scripts/coverage-report.sh"

  "$dependency-audit":
    owner: "@security"
    description: "Audit dependency tree for CVEs, stale packages, and license issues"
    triggers_on: "new dependency additions, periodic security review"
    scripts:
      - "scripts/audit-deps.sh"
```

### 5.7 Skill-Driven Verification

The verification pattern deserves special attention because it replaces vague "run tests" instructions with an explicit, ordered verification stack that is the repository's definition of "verified."

Each project defines its verification skill with the exact commands, in order:

```yaml
# Example: TypeScript monorepo verification stack
verification_stack:
  commands:
    - "pnpm i"
    - "pnpm build"
    - "pnpm -r build-check"
    - "pnpm -r -F '@scope/*' dist:check"
    - "pnpm lint"
    - "pnpm test"
  order: "strict"  # must run in this exact sequence
  on_failure: "stop and report — do not skip ahead"
```

```yaml
# Example: Python project verification stack
verification_stack:
  commands:
    - "make format"
    - "make lint"
    - "make typecheck"
    - "make tests"
  order: "strict"
  on_failure: "stop and report"
```

**An agent's work is not complete until its verification skill passes.** This is enforced at Gate 3 (Implementation Complete) — `@conductor` will not advance a task to review unless `$code-change-verification` has passed.

### 5.8 Skill-Driven Example and Integration Validation

For repos with example applications or integration surfaces, the validation pattern combines scripts (for execution and log collection) with model intelligence (for correctness judgment):

```
1. Script layer:
   - Runs each example in auto mode (non-interactive, auto-approve prompts)
   - Captures per-example stdout and stderr to structured log files
   - Generates rerun files for any failures
   - Maintains an auto-skip list for examples requiring special runtimes

2. Model layer (for each example):
   - Reads the example source code and comments
   - Infers the intended behavior and expected flow
   - Opens the matching log file
   - Compares intended behavior against actual stdout/stderr
   - Reports pass/fail with specific evidence

3. Integration layer (for published packages):
   - Script publishes packages to a local registry (e.g., Verdaccio)
   - Script tests install-and-run across target runtimes
   - Model evaluates whether installed behavior matches source behavior
```

This is more accurate than scripted assertions for examples that talk to real APIs, use tools, or produce variable output. A successful exit code is necessary but not sufficient — the model validates against the example's actual intent.

### 5.9 Skills and CI Integration

Skills that are stable locally can be automated in CI via GitHub Actions. The same skill, scripts, and validation logic run in both environments:

```yaml
# .github/workflows/skill-verification.yml
name: Skill-Driven Verification

on:
  pull_request:
    branches: [develop, 'epic/**']

jobs:
  verify:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      # Run the same verification skill that agents run locally
      - name: Run $code-change-verification
        run: .agents/skills/code-change-verification/scripts/verify.sh

      # For PRs that touch packages/
      - name: Run $changeset-validation
        if: contains(github.event.pull_request.changed_files, 'packages/')
        run: .agents/skills/changeset-validation/scripts/validate-changesets.sh

  # Agent-powered review (uses model for contextual judgment)
  agent-review:
    runs-on: ubuntu-latest
    needs: verify
    steps:
      - uses: actions/checkout@v4

      # Agent reviews using the same skills and AGENTS.md context
      # This replaces manual review for correctness-class issues
      - name: Agent PR Review
        uses: openai/codex-action@v1  # or equivalent agent CI action
        with:
          task: "Review this PR using $code-change-verification results and project AGENTS.md"
          # Agent handles contextual judgment: is this correct? complete? safe?
```

**The principle:** debug and refine skills locally first. Automate in CI only after the workflow is stable. Local use is where you find the edge cases.

### 5.10 Agent-Powered PR Review vs. Human Review

Skills enable a clear split between what agent review covers and what requires human review:

```
AGENT REVIEW covers correctness-class issues:
  ✓ Program bugs and regressions
  ✓ Missing tests for new behavior
  ✓ Verification stack failures
  ✓ Style and consistency violations
  ✓ Documentation gaps
  ✓ Security pattern violations (known patterns)
  ✓ Changeset/release metadata accuracy
  → @reviewer handles this via skills, consistently and repeatedly

HUMAN REVIEW covers design-class decisions:
  ✓ API or architecture choices between multiple valid options
  ✓ Behavior changes affecting product expectations or backward compatibility
  ✓ Naming, migration, and release communication decisions
  ✓ Cross-team alignment and sequencing decisions
  ✓ Rollout policy and risk appetite
  → Arbiter handles this when @reviewer or @architect flags the need
```

Agent review removes the bottleneck for routine correctness checks. Human review focuses on the decisions where judgment matters most. This split is a significant throughput multiplier — low-risk changes no longer wait for scarce reviewer time.

---

## 6. GitHub Workflow Integration

### 6.1 Branch Strategy

```
main                          ← protected, @merger merges when all gates pass (Arbiter can veto)
  └── develop                 ← integration branch, auto-tested, @merger auto-merges from epics
       └── epic/{epic-name}   ← feature grouping branch, @merger merges from task branches
            ├── task/{TASK-001}-{description}   ← individual agent work
            ├── task/{TASK-002}-{description}
            └── task/{TASK-003}-{description}
```

**Branch Naming Convention:**

```
task/{TASK-ID}-{kebab-case-description}

Examples:
  task/TASK-042-user-auth-endpoint
  task/TASK-043-login-form-component
  task/TASK-044-auth-migration
```

### 6.2 Commit Convention

Every commit is signed by the agent that made it:

```
<type>(<scope>): <description>

[agent: @agent-id]
[task: TASK-{id}]
[refs: #{issue}]

<body - what and why, not how>

<footer - breaking changes, related issues>
```

**Types:**

| Type | Usage |
|------|-------|
| `feat` | New feature or capability |
| `fix` | Bug fix |
| `refactor` | Code restructuring (no behavior change) |
| `test` | Adding or modifying tests |
| `docs` | Documentation changes |
| `schema` | Database migration or schema change |
| `api` | API contract change |
| `infra` | CI/CD, Docker, deployment config |
| `perf` | Performance improvement |
| `security` | Security fix or hardening |
| `style` | Formatting, linting (no logic change) |
| `chore` | Maintenance, dependency updates |

**Example:**

```
feat(auth): implement JWT refresh token rotation

[agent: @backend]
[task: TASK-042]
[refs: #128]

Implements automatic rotation of refresh tokens on each use.
Expired refresh tokens invalidate the entire token family to
prevent replay attacks.

BREAKING CHANGE: refresh_token response field renamed from
"refresh" to "refresh_token" for consistency with OAuth2 spec.
```

### 6.3 Pull Request Protocol

**PR Creation** (by `@conductor` after agent completes work):

```markdown
## PR Title: [TASK-{id}] {description}

### Agent: @{agent-id}
### Task: TASK-{id}
### Epic: {epic-name}

### Summary
{One paragraph describing what this PR accomplishes}

### Changes
- {file}: {what changed and why}
- {file}: {what changed and why}

### Testing
- [ ] Unit tests pass
- [ ] Integration tests pass
- [ ] Manual verification steps documented

### Quality Checklist
- [ ] @reviewer approved code quality
- [ ] @tester confirmed test coverage ≥ threshold
- [ ] @security scan passed (if applicable)
- [ ] @docs updated (if applicable)
- [ ] No secrets or credentials in diff

### Dependencies
- Depends on: #{PR-number} (if any)
- Blocks: #{PR-number} (if any)

### Rollback Plan
{How to safely revert this change if needed}
```

**PR Review Flow:**

```
1. @conductor creates PR from task branch → epic branch
2. @reviewer performs code review (adds comments, approves, or requests changes)
3. @tester verifies test results attached to PR
4. @security reviews if security-relevant files changed
5. @conductor summarizes all reviews
6. IF all gates pass:
   a. @merger executes the merge (squash or merge commit per project convention)
   b. @merger verifies post-merge CI passes
   c. @merger closes linked GitHub issues
   d. @merger updates branch state (deletes merged task branch)
7. IF issues found:
   a. @resolver triages all review findings
   b. @resolver routes fixes to the appropriate execution agent(s)
   c. Execution agent amends on the same branch (fixup commits)
   d. @resolver verifies amendments address all findings
   e. PR re-enters review at step 2 (abbreviated — only changed items reviewed)
   f. On pass, @merger executes merge per step 6
8. Arbiter is notified of all merges and can revert within the configured window
```

**Issue Resolution Flow (via @resolver):**

```
1. @resolver receives issue notification:
   - Review findings from @reviewer, @security, @tester, or @perf
   - CI/CD failures from pipeline
   - Post-merge regressions detected by monitoring
   - GitHub Issues filed by Arbiter or external sources
2. @resolver triages:
   - Classifies severity (blocker | major | minor | cosmetic)
   - Identifies root cause agent(s)
   - Determines if fix requires new task or amendment to existing
3. @resolver dispatches:
   - Amendment: routes to original agent with fix instructions + context
   - New task: creates task spec, routes through @conductor
   - Cross-cutting: coordinates multiple agents for multi-file fixes
4. @resolver verifies:
   - Confirms fix addresses the original issue
   - Confirms no regressions introduced
   - Signs off for @merger to proceed
5. @merger merges the amended/fixed PR
6. @resolver closes the GitHub Issue with resolution summary
```

### 6.4 GitHub Issues Integration

Every task maps to a GitHub Issue:

```markdown
## Issue Title: [TASK-{id}] {description}

### Labels
- agent:{agent-id}
- tier:{planning|execution|assurance}
- priority:{critical|high|normal|low}
- epic:{epic-name}

### Description
{What needs to be done, from @spec's acceptance criteria}

### Acceptance Criteria
- [ ] {criterion 1}
- [ ] {criterion 2}

### Agent Assignment
Primary: @{agent-id}
Review: @{reviewer-agent-id}

### Dependencies
- Blocked by: #issue
- Blocks: #issue
```

### 6.5 GitHub Actions Integration

Agents can trigger and respond to CI/CD events:

```yaml
# .github/workflows/agent-pipeline.yml
name: Agent Swarm Pipeline

on:
  pull_request:
    branches: [develop, 'epic/**']
  push:
    branches: [develop, main]

jobs:
  lint:
    # Triggered automatically, results fed to @reviewer
  test:
    # Results fed to @tester for analysis
  security-scan:
    # Results fed to @security for triage
  build:
    # Validates the artifact compiles/bundles
  preview:
    # Deploys preview environment for verification
  merge-readiness:
    # Aggregates all gate results → signals @merger
    # If all gates pass: @merger auto-merges
    # If any gate fails: @resolver receives failure report
  post-merge-verify:
    # Runs on push to develop/main after merge
    # Results fed to @resolver for regression detection
    # If regression detected: @resolver initiates revert + fix cycle
  notify-arbiter:
    # Sends merge summary to Arbiter notification channel
    # Includes: what merged, which agents contributed, gate results
    # Arbiter can trigger manual revert within configured window
```

---

## 7. Task Lifecycle

### 7.1 State Machine

```
                    ┌──────────────┐
                    │   CREATED    │
                    └──────┬───────┘
                           │  @conductor assigns agent
                    ┌──────▼───────┐
                    │   ASSIGNED   │
                    └──────┬───────┘
                           │  agent acknowledges
                    ┌──────▼───────┐
                    │  IN_PROGRESS │◄────────────────┐
                    └──────┬───────┘                  │
                           │  agent completes         │  @resolver routes
                    ┌──────▼───────┐                  │  amendments back
                    │  IN_REVIEW   │──────────────────┘
                    └──────┬───────┘
                           │  all quality gates pass
                    ┌──────▼───────┐
                    │   APPROVED   │
                    └──────┬───────┘
                           │  @merger executes merge
                    ┌──────▼───────┐
                    │    MERGED    │
                    └──────┬───────┘
                           │  post-merge verification passes
                    ┌──────▼───────┐
                    │   VERIFIED   │
                    └──────┬───────┘
                           │  @resolver closes linked issues
                    ┌──────▼───────┐
                    │    CLOSED    │
                    └──────────────┘

  ──── Exception States ────

  BLOCKED       →  waiting on dependency or external input
  ESCALATED     →  requires human decision (Arbiter)
  CANCELLED     →  no longer needed
  AMENDING      →  @resolver has routed back for fixes (sub-state of IN_PROGRESS)
  REVERTING     →  @merger is reverting a failed merge (post-merge regression)
  ARBITER_HOLD  →  Arbiter has placed a manual hold (veto)
```

### 7.2 Task Spec Format

```yaml
task:
  id: "TASK-{sequential}"
  title: "Clear, imperative description"
  epic: "{epic-name}"
  agent: "@{agent-id}"
  priority: "critical | high | normal | low"
  estimated_tokens: 0  # approximate token budget

  description: |
    Detailed explanation of what needs to be built.
    Include the WHY, not just the WHAT.

  acceptance_criteria:
    - "Given X, when Y, then Z"
    - "The function must handle edge case A"
    - "Performance must meet threshold B"

  inputs:
    - source: "@{previous-agent}"
      artifact: "path/to/input"
      description: "What this input provides"

  outputs:
    - artifact: "path/to/output"
      description: "What this deliverable is"
      validation: "How to verify correctness"

  constraints:
    - "Must not modify files outside of /src/auth/**"
    - "Must maintain backward compatibility with API v2"
    - "Must not add dependencies without @architect approval"

  context_files:
    - "path/to/relevant/file.ts"
    - "path/to/interface/definition.ts"
    # Only files this agent ACTUALLY needs — not the whole repo

  depends_on: ["TASK-{id}"]
  blocks: ["TASK-{id}"]
  deadline: "ISO-8601 or null"
```

---

## 8. Quality Gates

### 8.1 Gate Definitions

Each phase transition requires passing through a quality gate. No bypasses.

```
GATE 1: SPEC COMPLETE
  Owner: @spec
  Passes when:
    ✓ All user stories have acceptance criteria
    ✓ Edge cases are documented
    ✓ Non-functional requirements specified
    ✓ @architect has signed off on feasibility
  Blocks: Architecture phase

GATE 2: ARCHITECTURE APPROVED
  Owner: @architect
  Passes when:
    ✓ ADR (Architecture Decision Record) written
    ✓ Component diagram created
    ✓ API contracts defined (by @api)
    ✓ Data model reviewed (by @data)
    ✓ No unresolved technical risks rated "high"
  Blocks: Execution phase

GATE 3: IMPLEMENTATION COMPLETE
  Owner: @conductor
  Passes when:
    ✓ All task branches have passing CI
    ✓ $code-change-verification skill has passed (if code was changed)
    ✓ $changeset-validation skill has passed (if packages were changed)
    ✓ No linting errors
    ✓ Type checking passes (if applicable)
    ✓ Build succeeds
    ✓ Agent self-review checklist completed
  Blocks: Review phase

GATE 4: REVIEW PASSED
  Owner: @reviewer
  Passes when:
    ✓ Agent code review: no unresolved "blocker" or "major" comments
    ✓ $integration-test-runner skill verified (if examples/integrations affected)
    ✓ Test coverage meets threshold (see §13)
    ✓ @tester has verified all acceptance criteria
    ✓ @security scan has no critical/high findings
    ✓ @docs has updated relevant documentation ($docs-sync verified)
    ✓ $release-review passed (if this is a release candidate)
  Note: Agent review covers correctness-class issues. Design-class decisions
        are escalated to the Arbiter (see §5.10 for the split).
  Blocks: Merge

GATE 5: MERGE READY
  Owner: @merger
  Passes when:
    ✓ All automated checks green
    ✓ All agent reviews approved (no unresolved blockers)
    ✓ @resolver confirms no open amendment cycles
    ✓ No ARBITER_HOLD flag set on the PR
    ✓ Branch is rebased and conflict-free against target
  Action: @merger executes merge immediately
  Blocks: Post-merge verification

GATE 6: POST-MERGE VERIFIED
  Owner: @resolver
  Passes when:
    ✓ Post-merge CI pipeline passes on target branch
    ✓ No regression in test suite (compared to pre-merge baseline)
    ✓ Integration tests pass with new code in place
    ✓ @resolver signs off on verification
  Action: @resolver closes linked GitHub issues with resolution summary
  Failure Action:
    ✓ @merger reverts the merge commit
    ✓ @resolver triages the regression
    ✓ @resolver routes fix back through the pipeline
    ✓ Arbiter is notified of revert
```
```

### 8.2 Gate Override Protocol

The Arbiter can override any quality gate. `@resolver` can override minor-severity gate failures when the fix is already in progress (logged as a deferred resolution).

```yaml
override:
  gate: "GATE-{n}"
  authority: "{arbiter-name} | @resolver"
  reason: "Documented justification"
  risk_accepted: "What risk is being accepted"
  follow_up: "TASK-{id} to address the gap"
  timestamp: "ISO-8601"
  type: "arbiter_override | deferred_resolution"
```

### 8.3 Arbiter Veto Protocol

The Arbiter can halt any merge at any time by setting `ARBITER_HOLD` on a PR or branch:

```yaml
veto:
  target: "PR-{number} | branch/{name}"
  arbiter: "{human-name}"
  action: "hold | revert | cancel"
  reason: "Documented justification"
  timestamp: "ISO-8601"
  resolution: "What must happen before the hold is lifted"
```

When `ARBITER_HOLD` is set:
- `@merger` will not merge the PR regardless of gate status
- `@resolver` will not close linked issues
- All agents working on dependent tasks are notified of the hold
- The hold persists until the Arbiter explicitly lifts it

### 8.4 Revert Protocol

When `@merger` or the Arbiter triggers a revert:

```
1. @merger creates a revert commit on the target branch
2. @merger creates a new branch: revert/{TASK-ID}-{description}
3. @resolver receives the revert notification with:
   - Original PR and merge commit
   - Reason for revert (regression data, Arbiter veto reason, etc.)
   - Post-merge verification failure details (if applicable)
4. @resolver triages and re-enters the fix pipeline
5. The original issue is reopened with revert context appended
6. Amended fix goes through the full gate sequence again
```

---

## 9. File Ownership & Boundaries

### 9.1 Ownership Map

Each file path pattern is owned by exactly one agent. Only the owning agent may create or modify files matching that pattern. Other agents may read but never write.

```yaml
ownership:
  # Frontend
  "@frontend":
    - "src/components/**"
    - "src/pages/**"
    - "src/hooks/**"
    - "src/styles/**"
    - "src/stores/**"        # client-side state
    - "public/**"
    - "*.css"
    - "*.scss"
    - "tailwind.config.*"
    - "postcss.config.*"

  # Backend
  "@backend":
    - "src/services/**"
    - "src/handlers/**"
    - "src/middleware/**"
    - "src/utils/**"
    - "src/validators/**"
    - "src/lib/**"

  # API
  "@api":
    - "src/routes/**"
    - "src/controllers/**"
    - "openapi/**"
    - "src/schemas/**"       # request/response schemas
    - "src/types/api/**"

  # Data
  "@data":
    - "src/models/**"
    - "src/repositories/**"
    - "migrations/**"
    - "seeds/**"
    - "prisma/**"
    - "drizzle/**"
    - "src/types/db/**"

  # Infrastructure
  "@infra":
    - ".github/**"
    - "docker/**"
    - "Dockerfile*"
    - "docker-compose*"
    - "terraform/**"
    - "k8s/**"
    - ".env.example"
    - "scripts/deploy/**"
    - "scripts/ci/**"

  # Tests
  "@tester":
    - "tests/**"
    - "**/*.test.*"
    - "**/*.spec.*"
    - "**/__tests__/**"
    - "jest.config.*"
    - "vitest.config.*"
    - "playwright.config.*"
    - "cypress/**"
    - "fixtures/**"

  # Documentation
  "@docs":
    - "docs/**"
    - "README.md"
    - "CHANGELOG.md"
    - "CONTRIBUTING.md"
    - "API.md"
    - "ARCHITECTURE.md"

  # Security
  "@security":
    - "src/auth/**"
    - "src/security/**"
    - ".env.vault"
    - "security/**"

  # Shared (requires @architect approval to modify)
  "@architect":
    - "src/types/shared/**"  # shared type definitions
    - "src/config/**"        # application configuration
    - "package.json"         # dependency changes
    - "tsconfig.json"
    - "eslint.config.*"
    - "biome.json"
```

### 9.2 Boundary Violations

If an agent needs to modify a file outside its ownership:

```
1. Agent creates a BOUNDARY_REQUEST to @conductor
2. @conductor evaluates necessity
3. Options:
   a. @conductor routes a sub-task to the owning agent
   b. @architect grants temporary cross-boundary permission (logged)
   c. @conductor restructures the task to avoid the violation
4. Direct cross-boundary writes are NEVER silently permitted
```

### 9.3 Shared Interfaces

When two agents need to coordinate on a shared interface (e.g., API contract between frontend and backend):

```
1. @api defines the contract (OpenAPI spec or TypeScript interface)
2. @architect approves the contract
3. Both consuming agents implement against the contract
4. Neither agent may unilaterally modify the contract
5. Contract changes require a new task routed through @api → @architect
```

---

## 10. Error Handling & Escalation

### 10.1 Error Classification

```
LEVEL 1: SELF-RECOVERABLE
  Agent detects the issue and fixes it within its own retry logic.
  Example: Linting error → agent re-formats and retries.
  Action: Log the recovery, continue.

LEVEL 2: PEER-RECOVERABLE
  Agent cannot fix the issue but another agent can.
  Example: Test failure due to incorrect API contract.
  Action: Feedback to @conductor → routed to responsible agent.

LEVEL 3: DESIGN-LEVEL
  Issue indicates a flaw in the architecture or spec.
  Example: Two components have circular dependencies.
  Action: Escalate to @architect (or @spec if requirements-level).

LEVEL 4: HUMAN-REQUIRED
  Issue requires human judgment, external access, or policy decision.
  Example: Unclear business requirement, legal question, third-party outage.
  Action: Escalate to ARBITER with full context and recommended options.

LEVEL 5: SYSTEM FAILURE
  Agent runtime failure, context overflow, or tool breakage.
  Example: Context window exceeded, API rate limit, file system error.
  Action: @conductor halts affected tasks, notifies ARBITER, preserves state.
```

### 10.2 Escalation Format

```yaml
escalation:
  level: 1-5
  from: "@{agent-id}"
  task: "TASK-{id}"
  summary: "One sentence: what went wrong"
  detail: |
    Full context of the failure.
    What was attempted. What happened instead.
  impact: "What is blocked by this failure"
  attempted_fixes:
    - "What I tried first and why it failed"
    - "What I tried second and why it failed"
  recommendation:
    preferred: "What I think should happen"
    alternatives:
      - "Alternative approach A with tradeoffs"
      - "Alternative approach B with tradeoffs"
  urgency: "Can other work continue while this is resolved? yes/no"
```

### 10.3 Circuit Breaker

If an agent fails the same task 3 times:

```
1. @conductor halts the task
2. @resolver creates a diagnostic report:
   - All 3 failure logs
   - Pattern analysis (same root cause? different causes?)
   - Whether the task spec itself is flawed
3. @resolver attempts resolution:
   a. If spec issue → routes to @spec for re-specification
   b. If architecture issue → routes to @architect for redesign
   c. If agent capability issue → recommends reassignment to @conductor
4. If @resolver cannot resolve after its own attempt:
   - Escalates to Arbiter with full diagnostic + resolution attempts
   - Recommendation: re-spec | re-assign | re-architect | cancel
5. Work does NOT continue on this task until resolution path is determined
```

---

## 11. Context Management

### 11.1 Context Budget

Every agent operates within a context budget. Context is the most expensive resource in the system.

```yaml
context_policy:
  max_files_per_agent: 20        # files loaded into context
  max_lines_per_file: 500        # truncate beyond this
  prefer_interfaces_over_implementations: true
  prefer_types_over_runtime_code: true

  # Context priority (highest first):
  priority:
    1: "The task spec itself"
    2: "Files the agent will create/modify"
    3: "Interface definitions and type contracts"
    4: "Test files for the code being modified"
    5: "Adjacent code that calls or is called by the target"
    6: "Documentation and ADRs"
    7: "Configuration files"
    8: "Everything else — probably shouldn't be loaded"
```

### 11.2 Context Scoping Rules

```
RULE: An agent ONLY receives files listed in its task's context_files array.

RULE: @conductor is responsible for assembling the minimal effective context
      for each agent before dispatching the task.

RULE: If an agent needs additional context, it sends a QUERY to @conductor.
      It does NOT independently explore the file system.

RULE: The @architect agent is the ONLY agent permitted to read the full
      project structure (for design decisions). All other agents see their slice.

RULE: Shared type definitions (src/types/shared/**) are automatically included
      in every execution agent's context. They are the common language.

RULE: Skills use progressive disclosure (see §5.2). All agents see skill
      name + description at startup. Full SKILL.md loads only on activation.
      scripts/ and references/ load only when the skill explicitly calls for them.
      This prevents skill content from consuming the context budget unnecessarily.

RULE: The $external-api-knowledge skill MUST be used when working with
      third-party APIs. Agents must not answer from training data for API
      surfaces that may have changed. Use MCP or docs lookup instead.
```

### 11.3 Context Refresh

```
Between feedback cycles, @conductor refreshes the agent's context to include:
  - The original task spec
  - The agent's previous output
  - The feedback received
  - Any files that changed since the last attempt
  - Updated shared types (if modified by another task)
```

---

## 12. Security Protocol

### 12.1 Secrets Management

```
RULE: No agent ever writes secrets, API keys, tokens, or passwords into any file.
RULE: All secrets are referenced via environment variables.
RULE: .env files are NEVER committed. .env.example contains placeholder values only.
RULE: @security audits every PR diff for accidental secret exposure.
RULE: If a secret is detected in any commit, @security immediately:
      1. Flags the PR as BLOCKED
      2. Escalates to ARBITER
      3. Recommends the secret be rotated
      4. The commit is amended to remove the secret (force push)
```

### 12.2 Dependency Security

```
RULE: @infra runs dependency audit on every PR (npm audit, cargo audit, etc.)
RULE: No new dependency is added without @architect approval
RULE: @security reviews any dependency with:
      - Fewer than 100 GitHub stars (unless well-known ecosystem package)
      - No recent maintenance activity (>6 months stale)
      - Known CVEs
RULE: Transitive dependencies are monitored via lockfile analysis
```

### 12.3 Code Security

```
@security reviews all code changes for:
  - SQL injection vectors
  - XSS vulnerabilities
  - CSRF protection
  - Authentication/authorization bypass
  - Insecure deserialization
  - Path traversal
  - Rate limiting gaps
  - Overly permissive CORS
  - Information leakage in error messages
  - Timing attacks on sensitive comparisons
```

---

## 13. Performance Standards

### 13.1 Code Quality Thresholds

```yaml
thresholds:
  test_coverage:
    unit: 80%          # minimum line coverage
    integration: 60%   # minimum endpoint/flow coverage
    critical_paths: 95% # auth, payments, data mutations

  complexity:
    cyclomatic_max: 15       # per function
    cognitive_max: 20        # per function
    file_length_max: 400     # lines (suggest split if exceeded)
    function_length_max: 50  # lines

  performance:
    api_p95_latency: 200ms   # 95th percentile
    api_p99_latency: 500ms   # 99th percentile
    page_load_lcp: 2500ms    # Largest Contentful Paint
    bundle_size_max: 250KB   # gzipped JS bundle

  documentation:
    public_api_coverage: 100%    # every exported function documented
    type_coverage: 95%           # TypeScript strict mode
    readme_freshness: "updated within same epic"
```

### 13.2 Agent Performance Metrics

Each agent is measured on:

```yaml
agent_metrics:
  correctness:
    description: "How often does the agent's output pass quality gates on first attempt?"
    target: ">85%"

  efficiency:
    description: "Token cost relative to task complexity"
    target: "Trending downward over time"

  feedback_cycles:
    description: "Average number of review rounds before approval"
    target: "<2"

  boundary_compliance:
    description: "Percentage of tasks completed without boundary violations"
    target: "100%"
```

---

## 14. Agent Contracts (Detailed)

### 14.1 @conductor — Orchestrator

```yaml
contract:
  identity: "@conductor"
  role: "Swarm Orchestrator"
  layer: "Orchestration"

  responsibilities:
    - Receive high-level objectives from the Arbiter
    - Decompose objectives into epics (with @spec and @architect)
    - Decompose epics into tasks (with @planner)
    - Assign tasks to specialist agents
    - Assemble minimal context for each agent
    - Route handoffs between agents
    - Route feedback from assurance to execution agents
    - Monitor task state and detect blockers
    - Enforce quality gates
    - Manage branch creation and PR lifecycle
    - Signal @merger when all gates pass
    - Signal @resolver when issues are detected
    - Enforce mandatory skill triggers (see §5.5)
    - Verify $code-change-verification passed before advancing to review
    - Invoke $pr-draft-summary when generating PR descriptions
    - Report swarm status to the Arbiter
    - Resolve simple conflicts; escalate complex ones

  does_not:
    - Write application code
    - Make architectural decisions
    - Override quality gates (only Arbiter and @resolver can)
    - Communicate with agents out of sequence
    - Execute merges directly (delegates to @merger)

  inputs:
    - "Objective statement from Arbiter"
    - "Feedback reports from assurance agents"
    - "Status updates from execution agents"
    - "CI/CD pipeline results"
    - "Arbiter veto/hold notifications"

  outputs:
    - "Task specs for each agent"
    - "Context packages for each agent"
    - "PR descriptions"
    - "Swarm status reports"
    - "Merge-ready signals to @merger"
    - "Issue reports to @resolver"
    - "Escalation requests to Arbiter"

  authority:
    - Can create/close GitHub issues and branches
    - Can assign and reassign tasks
    - Can request context from any file (read-only)
    - Can halt a task that exceeds its budget
    - Cannot execute merges (delegates to @merger)
    - Cannot override a quality gate rejection
```

### 14.2 @merger — Merge Controller

```yaml
contract:
  identity: "@merger"
  role: "Merge Execution & Branch Hygiene"
  layer: "Orchestration"

  responsibilities:
    - Execute PR merges when all quality gates pass
    - Resolve merge conflicts (rebase, conflict resolution)
    - Verify post-merge CI passes on the target branch
    - Delete merged task branches (branch hygiene)
    - Execute reverts when post-merge verification fails
    - Execute reverts when Arbiter triggers a veto
    - Maintain merge audit log
    - Manage merge queue ordering for concurrent PRs
    - Promote epic branches to develop when epic is complete
    - Promote develop to main for release (after Arbiter release approval)

  does_not:
    - Write application code
    - Review code quality (that's @reviewer)
    - Triage issues (that's @resolver)
    - Decide whether to merge (only executes when gates pass)
    - Deploy to production (separate release process)
    - Force-push to main without Arbiter override

  inputs:
    - "Merge-ready signal from @conductor"
    - "Gate status summary (all gates must be PASS)"
    - "Arbiter veto/hold notifications"
    - "Post-merge CI results"
    - "Revert requests from @resolver or Arbiter"

  outputs:
    - "Merge commit on target branch"
    - "Revert commit (when regression detected)"
    - "Merge audit log entry"
    - "Post-merge verification result"
    - "Branch deletion confirmation"
    - "Merge conflict report (if unresolvable → escalate to execution agent)"

  authority:
    - Can merge PRs to epic branches, develop, and main
    - Can delete merged task/epic branches
    - Can revert merge commits on any branch
    - Can rebase task branches onto updated targets
    - Cannot merge when ARBITER_HOLD is set
    - Cannot merge when any GATE status is FAIL
    - Cannot force-push to main (Arbiter only)

  merge_strategy:
    task_to_epic: "squash"        # clean single commit per task
    epic_to_develop: "merge"      # preserve epic history
    develop_to_main: "merge"      # preserve full history, requires Arbiter release approval
    conflict_resolution:
      auto_resolvable: "rebase and resolve automatically"
      complex_conflicts: "escalate to owning execution agent via @resolver"

  merge_conditions:
    required:
      - "All quality gates: PASS"
      - "No ARBITER_HOLD on PR or target branch"
      - "Branch is up-to-date with target (rebased)"
      - "CI pipeline green on PR branch"
      - "@resolver confirms no open amendment cycles for this PR"
    post_merge:
      - "CI pipeline must pass on target branch within 10 minutes"
      - "If post-merge CI fails: auto-revert and notify @resolver"

  audit_log_format:
    entry:
      merge_id: "MERGE-{uuid}"
      timestamp: "ISO-8601"
      pr: "PR-{number}"
      task: "TASK-{id}"
      source_branch: "task/{TASK-ID}-{description}"
      target_branch: "epic/{epic-name}"
      merge_type: "squash | merge | revert"
      commit_sha: "{sha}"
      gate_summary:
        gate_1: "pass"
        gate_2: "pass"
        gate_3: "pass"
        gate_4: "pass"
        gate_5: "pass"
        gate_6: "pending"
      post_merge_status: "pass | fail | pending"
      reverted: false
      arbiter_notified: true
```

### 14.3 @resolver — Issue Resolver

```yaml
contract:
  identity: "@resolver"
  role: "Issue Triage, Amendment Coordination & Resolution"
  layer: "Orchestration"

  responsibilities:
    - Receive and triage all issues (review findings, CI failures, regressions, external reports)
    - Classify issue severity and identify root cause agent(s)
    - Route amendment instructions to the appropriate execution agent(s)
    - Coordinate multi-agent fixes for cross-cutting issues
    - Verify that amendments fully address the original issue
    - Sign off for @merger to proceed after amendments
    - Close GitHub Issues with structured resolution summaries
    - Manage amendment cycles (track attempts, enforce circuit breaker)
    - Reopen issues if post-merge regression is detected
    - Maintain issue resolution audit trail

  does_not:
    - Write application code (routes to execution agents)
    - Execute merges (that's @merger)
    - Make architectural decisions (escalates to @architect)
    - Override Arbiter veto

  inputs:
    - "Review findings from @reviewer, @tester, @security, @perf"
    - "CI/CD failure reports"
    - "Post-merge regression reports from @merger"
    - "GitHub Issues filed by Arbiter or external sources"
    - "Feedback from execution agents on amendment feasibility"

  outputs:
    - "Amendment task specs routed to execution agents"
    - "Issue triage reports"
    - "Resolution verification sign-offs"
    - "Issue closure summaries"
    - "Escalation requests (to @architect for design issues, Arbiter for policy issues)"
    - "Deferred resolution overrides (for minor-severity gate failures)"

  authority:
    - Can create amendment sub-tasks and assign to execution agents
    - Can override minor-severity gate failures (logged as deferred resolution)
    - Can reopen closed issues when regressions are detected
    - Can request @merger to revert a merge
    - Can escalate to @architect when fix requires design changes
    - Can escalate to Arbiter when fix requires policy decisions
    - Cannot execute merges
    - Cannot override Arbiter veto
    - Cannot override critical/high security findings

  amendment_protocol:
    cycle_limit: 3  # max amendment attempts before escalation
    per_cycle:
      1: "Route fix to original agent with detailed instructions"
      2: "Route fix with @reviewer pair-review suggestion"
      3: "Escalate to @architect for structural assessment"
    after_limit:
      action: "Escalate to Arbiter with full diagnostic"
      include:
        - "All 3 amendment attempts and their failures"
        - "Root cause analysis"
        - "Recommendation: re-spec | re-architect | reassign | cancel"

  issue_closure_format:
    resolution:
      issue: "#issue-number"
      task: "TASK-{id}"
      severity: "blocker | major | minor | cosmetic"
      root_cause: "Description of what caused the issue"
      fix_summary: "Description of what was changed"
      amendment_cycles: 1
      verified_by: "@resolver"
      merged_in: "PR-{number} → MERGE-{id}"
      regression_risk: "low | medium | high"
      follow_up: "TASK-{id} | none"
```

### 14.4 @spec — Spec Analyst

```yaml
contract:
  identity: "@spec"
  role: "Requirements Analyst"
  layer: "Planning"

  responsibilities:
    - Analyze raw requirements from the Arbiter
    - Produce structured user stories with acceptance criteria
    - Identify edge cases, error states, and boundary conditions
    - Clarify ambiguity (query Arbiter if needed)
    - Define non-functional requirements (performance, security, accessibility)
    - Maintain a requirements traceability matrix

  outputs:
    - "User stories in Given/When/Then format"
    - "Acceptance criteria checklist"
    - "Edge case catalog"
    - "Non-functional requirements document"

  quality_criteria:
    - Every story is testable (a @tester can write a test from it)
    - Every story is independent (can be implemented without other stories)
    - No ambiguous language ("should", "might", "possibly" → rejected)
    - Boundary conditions explicitly enumerated
```

### 14.5 @architect — System Architect

```yaml
contract:
  identity: "@architect"
  role: "System Architect"
  layer: "Planning"

  responsibilities:
    - Design system architecture from spec requirements
    - Define component boundaries and interfaces
    - Select technology stack and justify decisions via ADRs
    - Identify cross-cutting concerns (logging, auth, error handling)
    - Define shared type contracts
    - Review dependency additions
    - Resolve structural conflicts between agents

  outputs:
    - "Architecture Decision Records (ADRs)"
    - "Component diagram (Mermaid or similar)"
    - "Interface definitions (TypeScript types / OpenAPI)"
    - "Dependency approval/rejection decisions"
    - "File ownership map updates"

  authority:
    - Final say on technology choices within the project
    - Can veto dependency additions
    - Can restructure file ownership boundaries
    - Approves all shared interface changes

  does_not:
    - Write implementation code
    - Write tests
    - Make product/business decisions (that's @spec + Arbiter)
```

### 14.6 @planner — Task Planner

```yaml
contract:
  identity: "@planner"
  role: "Task Decomposition & Sequencing"
  layer: "Planning"

  responsibilities:
    - Break epics into atomic, assignable tasks
    - Map dependencies between tasks
    - Determine optimal execution order (critical path)
    - Estimate relative complexity of each task
    - Identify parallelizable work streams
    - Flag tasks that require specialist agents

  outputs:
    - "Task dependency graph (DAG)"
    - "Task specs (see §7.2 format)"
    - "Execution sequence recommendation"
    - "Parallel work stream identification"

  rules:
    - Every task must be completable by a single agent
    - No task should require more than 20 context files
    - Every task must have clear acceptance criteria (from @spec)
    - Circular dependencies are rejected — restructure the plan
```

### 14.7 @frontend — Frontend Engineer

```yaml
contract:
  identity: "@frontend"
  role: "Frontend Implementation"
  layer: "Execution"

  responsibilities:
    - Implement UI components per design specs
    - Manage client-side state
    - Implement responsive layouts and styling
    - Handle client-side routing
    - Implement form validation (client-side)
    - Ensure accessibility (WCAG 2.1 AA minimum)
    - Optimize bundle size and rendering performance

  inputs:
    - "Component specs from @spec"
    - "API contracts from @api"
    - "Design tokens / style guide"
    - "Shared types from @architect"

  outputs:
    - "React/Vue/Svelte components"
    - "Style files"
    - "Client state definitions"
    - "Component storybook entries (if applicable)"

  constraints:
    - Must implement against @api's contract, not against backend internals
    - Must not make direct database calls
    - Must not contain business logic (delegate to backend)
    - Must handle all API error states gracefully
    - Must work without JavaScript for critical content (progressive enhancement)
```

### 14.8 @backend — Backend Engineer

```yaml
contract:
  identity: "@backend"
  role: "Backend Implementation"
  layer: "Execution"

  responsibilities:
    - Implement business logic and service layer
    - Implement request handlers
    - Implement middleware (auth, logging, rate limiting)
    - Implement data validation (server-side, canonical)
    - Manage server-side error handling
    - Implement background jobs and workers

  inputs:
    - "API contracts from @api"
    - "Data models from @data"
    - "Business rules from @spec"
    - "Shared types from @architect"

  outputs:
    - "Service implementations"
    - "Handler implementations"
    - "Middleware implementations"
    - "Utility functions"

  constraints:
    - Must implement against @api's contract (routes layer)
    - Must use @data's repository pattern for data access
    - Must not contain SQL (delegate to @data's repository layer)
    - Must not contain presentation logic
    - All public functions must have JSDoc/TSDoc
```

### 14.9 @data — Data Engineer

```yaml
contract:
  identity: "@data"
  role: "Data Layer Implementation"
  layer: "Execution"

  responsibilities:
    - Design and implement database schemas
    - Write and manage migrations (up AND down)
    - Implement repository pattern for data access
    - Optimize queries and indexes
    - Implement data seeding for development/testing
    - Ensure referential integrity and constraints

  outputs:
    - "Migration files (timestamped, reversible)"
    - "Model/entity definitions"
    - "Repository implementations"
    - "Seed data files"
    - "Index recommendations"

  constraints:
    - Every migration must be reversible (has a down migration)
    - Schema changes must not break existing data
    - All queries must use parameterized inputs (no string interpolation)
    - Indexes must be justified by a query pattern
    - Seeds must be idempotent
```

### 14.10 @api — API Designer

```yaml
contract:
  identity: "@api"
  role: "API Contract Design"
  layer: "Execution"

  responsibilities:
    - Design RESTful (or GraphQL) API endpoints
    - Write OpenAPI / GraphQL schema definitions
    - Define request/response schemas with validation
    - Design error response formats
    - Manage API versioning strategy
    - Define rate limiting rules per endpoint

  outputs:
    - "OpenAPI spec (openapi/*.yaml)"
    - "TypeScript request/response types"
    - "Route definitions"
    - "Error code catalog"
    - "Rate limit configuration"

  constraints:
    - All endpoints must have complete OpenAPI documentation
    - All request bodies must have JSON Schema validation
    - Error responses must follow RFC 7807 (Problem Details)
    - Breaking changes require a version bump and migration guide
    - Pagination must use cursor-based approach for collections
```

### 14.11 @infra — Infrastructure Engineer

```yaml
contract:
  identity: "@infra"
  role: "Infrastructure & DevOps"
  layer: "Execution"

  responsibilities:
    - Design and maintain CI/CD pipelines
    - Write Dockerfiles and compose configurations
    - Manage Infrastructure as Code (Terraform, Pulumi, etc.)
    - Configure environment variables and secrets management
    - Set up monitoring and alerting infrastructure
    - Manage deployment strategies (blue-green, canary, etc.)

  outputs:
    - "GitHub Actions workflows"
    - "Docker configurations"
    - "IaC definitions"
    - "Environment configuration templates"
    - "Deployment scripts"

  constraints:
    - All infrastructure must be reproducible from code (no manual config)
    - CI pipeline must complete in under 10 minutes
    - Docker images must use multi-stage builds
    - No root user in containers
    - All secrets via environment variables or vault, never hardcoded
```

### 14.12 @tester — Test Engineer

```yaml
contract:
  identity: "@tester"
  role: "Test Implementation & Verification"
  layer: "Assurance"

  responsibilities:
    - Write unit tests for all execution agent outputs
    - Write integration tests for API endpoints
    - Write end-to-end tests for critical user flows
    - Create test fixtures and factories
    - Verify acceptance criteria from @spec
    - Measure and report test coverage
    - Identify untested edge cases

  outputs:
    - "Unit test files"
    - "Integration test files"
    - "E2E test files"
    - "Test fixtures and factories"
    - "Coverage reports"
    - "Acceptance criteria verification report"

  rules:
    - Tests must be deterministic (no flaky tests — ever)
    - Tests must be independent (no shared mutable state between tests)
    - Test names must describe the behavior, not the implementation
    - Every bug fix must include a regression test
    - Mocks must be minimal — prefer real implementations where feasible
    - Test file lives adjacent to implementation (co-located)

  verification_format:
    for_each_acceptance_criterion:
      - criterion: "Given X, when Y, then Z"
        test_file: "path/to/test"
        test_name: "descriptive test name"
        status: "pass | fail | not_implemented"
        notes: "any relevant context"
```

### 14.13 @reviewer — Code Reviewer

```yaml
contract:
  identity: "@reviewer"
  role: "Code Quality Reviewer"
  layer: "Assurance"

  responsibilities:
    - Review all code changes for quality, readability, and maintainability
    - Verify adherence to project coding standards
    - Check for common anti-patterns and code smells
    - Ensure proper error handling
    - Verify naming conventions and code organization
    - Check for unnecessary complexity
    - Validate that changes match the task spec
    - Use $release-review skill when reviewing release candidates
    - Escalate design-class decisions to Arbiter (see §5.10)

  review_scope:
    agent_review_covers:
      - "Correctness: bugs, regressions, missing edge cases"
      - "Missing tests for new or changed behavior"
      - "Verification stack results ($code-change-verification)"
      - "Style, naming, and consistency violations"
      - "Documentation gaps ($docs-sync findings)"
      - "Security pattern violations (known patterns)"
      - "Changeset and release metadata accuracy"
    escalate_to_arbiter:
      - "API or architecture choices between multiple valid designs"
      - "Behavior changes affecting backward compatibility or product expectations"
      - "Naming, migration, and release communication decisions"
      - "Cross-team alignment, sequencing, or rollout policy"

  review_checklist:
    correctness:
      - "Does the code do what the task spec requires?"
      - "Are edge cases handled?"
      - "Are errors handled, not swallowed?"
    clarity:
      - "Can I understand the code without the author explaining it?"
      - "Are names descriptive and consistent?"
      - "Is the code self-documenting or properly commented?"
    simplicity:
      - "Is there a simpler way to achieve the same result?"
      - "Is there dead code or unnecessary abstraction?"
      - "Does this follow YAGNI (You Ain't Gonna Need It)?"
    consistency:
      - "Does it match existing patterns in the codebase?"
      - "Does it follow the project's style guide?"
      - "Are imports organized consistently?"
    safety:
      - "Are there any potential null/undefined errors?"
      - "Are types correct and specific (no 'any')?"
      - "Are promises properly awaited?"

  output_format:
    per_file:
      - file: "path/to/file"
        status: "approved | changes_requested"
        comments:
          - line: 42
            severity: "blocker | major | minor | suggestion"
            category: "correctness | clarity | simplicity | consistency | safety"
            comment: "Specific, actionable feedback"
            suggestion: "Concrete code suggestion if applicable"
    overall:
      verdict: "approved | changes_requested | escalate_to_arbiter"
      summary: "High-level assessment"
      praise: "What was done well (always include this)"
      escalation_reason: "Why this needs human judgment (if escalating)"
```

### 14.14 @security — Security Analyst

```yaml
contract:
  identity: "@security"
  role: "Security Analysis & Hardening"
  layer: "Assurance"

  responsibilities:
    - Audit all code changes for security vulnerabilities
    - Review authentication and authorization implementations
    - Scan for secrets, credentials, or PII in code
    - Review dependency security advisories
    - Validate input sanitization and output encoding
    - Review CORS, CSP, and other security headers
    - Assess cryptographic implementations

  triggers:
    always_review:
      - "Any file in src/auth/**"
      - "Any file in src/security/**"
      - "Any migration that touches user data"
      - "Any change to environment variable handling"
      - "Any new dependency addition"
      - "Any API endpoint that handles PII"
    sample_review:
      - "Other code changes (reviewed on rotation)"

  output_format:
    findings:
      - id: "SEC-{sequential}"
        severity: "critical | high | medium | low | info"
        category: "OWASP category"
        location: "file:line"
        description: "What the vulnerability is"
        impact: "What could happen if exploited"
        recommendation: "Specific fix"
        references: ["CWE-XXX", "OWASP link"]
    summary:
      critical_count: 0
      high_count: 0
      verdict: "pass | fail"
      notes: "Overall security posture assessment"
```

### 14.15 @docs — Technical Writer

```yaml
contract:
  identity: "@docs"
  role: "Documentation"
  layer: "Assurance"

  responsibilities:
    - Write and maintain API documentation
    - Update README for new features
    - Maintain CHANGELOG with semantic versioning
    - Write architecture documentation
    - Ensure inline code documentation is complete
    - Create onboarding guides for new contributors
    - Document environment setup and configuration

  triggers:
    - "Any new API endpoint → update API.md"
    - "Any new feature → update README.md"
    - "Any merged PR → update CHANGELOG.md"
    - "Any architecture change → update ARCHITECTURE.md"
    - "Any environment change → update setup guide"

  quality_criteria:
    - Documentation matches actual behavior (verified by reading code)
    - Code examples are tested and working
    - No orphaned documentation (references to removed features)
    - Consistent formatting and terminology
    - Written for the audience (user docs vs. developer docs vs. ops docs)
```

### 14.16 @perf — Performance Engineer

```yaml
contract:
  identity: "@perf"
  role: "Performance Analysis & Optimization"
  layer: "Assurance"

  responsibilities:
    - Benchmark API endpoint latencies
    - Profile critical code paths
    - Identify N+1 queries and optimize
    - Analyze bundle size impact of changes
    - Review caching strategies
    - Load test critical endpoints
    - Monitor memory usage patterns

  triggers:
    - "Any new database query"
    - "Any new API endpoint"
    - "Any change to data-intensive operations"
    - "Any new frontend dependency (bundle impact)"
    - "Any change to caching logic"

  output_format:
    benchmarks:
      - endpoint: "/api/resource"
        p50: "45ms"
        p95: "120ms"
        p99: "250ms"
        throughput: "500 req/s"
        verdict: "pass | warn | fail"
    recommendations:
      - location: "file:line"
        issue: "N+1 query in user listing"
        impact: "3x latency at scale"
        fix: "Use eager loading / batch query"
        priority: "high"
```

---

## 15. Orchestration Patterns

### 15.1 Sequential Pipeline

For simple, linear features:

```
@spec → @architect → @planner → @api → @data → @backend → @frontend → @tester → @reviewer → @security → @docs → @merger → @resolver (verify + close)
```

### 15.2 Parallel Fan-Out

For features with independent frontend and backend work:

```
                    @spec → @architect → @planner
                                           │
                              ┌─────────────┼─────────────┐
                              │             │             │
                        @data + @api     @backend      @frontend
                              │             │             │
                              └─────────────┼─────────────┘
                                            │
                                    @tester (all streams)
                                            │
                              ┌─────────────┼─────────────┐
                              │             │             │
                          @reviewer     @security       @perf
                              │             │             │
                              └─────────────┼─────────────┘
                                            │
                                          @docs
                                            │
                            ┌───────────────┼───────────────┐
                            │               │               │
                        @resolver ←── issues? ──→ @merger   │
                        (if issues:                (if clean: │
                         amend → re-review)         merge)    │
                            │                       │         │
                            └───────────────────────┘         │
                                        │                     │
                                   @resolver (post-merge verify + close issues)
```

### 15.3 Hotfix Pipeline

For urgent production fixes (abbreviated flow):

```
ARBITER → @debug (root cause) → @backend/@frontend (fix) → @tester (regression test) → @reviewer (expedited) → @merger (merge) → @resolver (verify + close)
```

Quality gate: @security review is mandatory even for hotfixes. @docs creates a post-mortem entry. @resolver monitors post-merge verification and triggers revert if regression detected.

### 15.4 Refactoring Pipeline

For tech debt reduction:

```
@architect (refactoring plan) → @planner (decompose) → @refactor (execute) → @tester (verify no regression) → @reviewer → @perf (verify no degradation) → @merger → @resolver (verify + close)
```

### 15.5 Spike / Investigation

When the path forward is unclear:

```
ARBITER (question) → @architect (investigation) → @architect (ADR with options) → ARBITER (decision)
```

No code is written during a spike. The output is a decision document.

---

## 16. Appendix: Templates & Examples

### 16.1 ADR Template

```markdown
# ADR-{number}: {Title}

## Status
Proposed | Accepted | Deprecated | Superseded by ADR-{n}

## Context
What is the technical challenge or decision that needs to be made?

## Options Considered

### Option A: {Name}
- Description
- Pros: ...
- Cons: ...

### Option B: {Name}
- Description
- Pros: ...
- Cons: ...

## Decision
Which option was chosen and why.

## Consequences
What changes as a result of this decision.
What new constraints does this introduce.

## Agent
@architect | TASK-{id}
```

### 16.2 Swarm Status Report Template

```yaml
swarm_status:
  timestamp: "ISO-8601"
  epic: "{epic-name}"
  overall_health: "green | yellow | red"

  progress:
    total_tasks: 0
    completed: 0
    in_progress: 0
    blocked: 0
    not_started: 0

  active_agents:
    - agent: "@{id}"
      task: "TASK-{id}"
      status: "in_progress | blocked | reviewing"
      health: "on_track | at_risk | blocked"
      notes: "brief status note"

  blockers:
    - task: "TASK-{id}"
      blocked_by: "description"
      escalation_needed: true | false

  quality_metrics:
    first_pass_rate: "85%"
    avg_feedback_cycles: 1.3
    test_coverage: "82%"
    open_security_findings: 0

  next_actions:
    - "What happens next in the pipeline"
```

### 16.3 Quick Reference: Agent Invocation

```
Need requirements analyzed?     → @spec
Need architecture designed?     → @architect
Need work broken into tasks?    → @planner
Need UI built?                  → @frontend
Need server logic written?      → @backend
Need database work?             → @data
Need API contracts?             → @api
Need CI/CD or infra?            → @infra
Need external integrations?     → @integrator
Need tests written?             → @tester
Need code reviewed?             → @reviewer
Need security audit?            → @security
Need performance analysis?      → @perf
Need documentation?             → @docs
Need code restructured?         → @refactor
Need a bug investigated?        → @debug
Need a migration executed?      → @migrate
Need accessibility review?      → @a11y
Need internationalization?      → @i18n
Need everything coordinated?    → @conductor
Need a PR merged?               → @merger
Need an issue triaged & fixed?  → @resolver
Need a strategic decision?      → ARBITER (human)
Need to veto or revert?         → ARBITER (human)
```

### 16.4 .github/CODEOWNERS Integration

```
# Auto-generated from agents.md ownership map
# Maps file ownership to GitHub team reviews

src/components/**        @team/frontend
src/pages/**             @team/frontend
src/services/**          @team/backend
src/handlers/**          @team/backend
src/models/**            @team/data
migrations/**            @team/data
src/routes/**            @team/api
openapi/**               @team/api
.github/**               @team/infra
docker/**                @team/infra
tests/**                 @team/testing
docs/**                  @team/docs
src/auth/**              @team/security
src/types/shared/**      @team/architecture
package.json             @team/architecture
```

### 16.5 Pre-Flight Checklist (Before Starting Any Epic)

```markdown
## Pre-Flight Checklist

- [ ] Requirements reviewed and approved by Arbiter
- [ ] @spec has produced complete user stories with acceptance criteria
- [ ] @architect has produced ADR and component design
- [ ] @api has defined all endpoint contracts
- [ ] @data has designed the schema (if applicable)
- [ ] @planner has decomposed into tasks with dependency graph
- [ ] @conductor has created all GitHub issues
- [ ] @conductor has created the epic branch
- [ ] All agents have acknowledged their assigned tasks
- [ ] Context packages assembled for each agent
- [ ] CI/CD pipeline verified on the epic branch
- [ ] Skills directory (.agents/skills/) verified and up to date
- [ ] Mandatory skill triggers confirmed in AGENTS.md (§5.5)
- [ ] $code-change-verification skill tested against current repo
- [ ] @merger has verified branch protection rules are configured
- [ ] @resolver has verified issue tracking labels exist
- [ ] Arbiter has approved the execution plan (or autonomous mode enabled)
- [ ] Arbiter notification channel configured for merge alerts
```

### 16.6 SKILL.md Template

```markdown
---
name: {skill-name}
description: >
  {What this skill does}. {When it should trigger — be specific about
  the conditions}. {What kind of output it produces}.
---

# {Skill Name}

## When to Use

{Precise trigger conditions — what file changes, task phases, or events
should cause this skill to activate.}

## When NOT to Use

{Explicit exclusions to prevent false activation.}

## Workflow

### Step 1: {Name}
{Instructions for the first step.}

### Step 2: {Name}
{Instructions. Reference scripts/ if deterministic work is needed:}
```bash
.agents/skills/{skill-name}/scripts/{script-name}.sh
\```

### Step 3: {Name}
{Model-driven analysis or judgment step.}

## Output Format

{Exact structure of what this skill produces — the agent's contract.}

## Failure Handling

{What to do if a step fails. When to retry vs. escalate.}
```

### 16.7 Skill Directory Structure

```
.agents/
├── skills/
│   ├── code-change-verification/
│   │   ├── SKILL.md
│   │   └── scripts/
│   │       └── verify.sh
│   ├── changeset-validation/
│   │   ├── SKILL.md
│   │   └── scripts/
│   │       └── validate-changesets.sh
│   ├── integration-test-runner/
│   │   ├── SKILL.md
│   │   ├── scripts/
│   │   │   ├── run-examples.sh
│   │   │   └── run-integration.sh
│   │   └── references/
│   │       └── auto-skip-list.yaml
│   ├── implementation-strategy/
│   │   ├── SKILL.md
│   │   └── references/
│   │       └── compatibility-rules.md
│   ├── pr-draft-summary/
│   │   └── SKILL.md
│   ├── release-review/
│   │   ├── SKILL.md
│   │   └── scripts/
│   │       └── release-diff.sh
│   ├── docs-sync/
│   │   └── SKILL.md
│   ├── external-api-knowledge/
│   │   ├── SKILL.md
│   │   └── references/
│   │       └── mcp-endpoints.yaml
│   ├── test-coverage-improver/
│   │   ├── SKILL.md
│   │   └── scripts/
│   │       └── coverage-report.sh
│   └── dependency-audit/
│       ├── SKILL.md
│       └── scripts/
│           └── audit-deps.sh
└── README.md  # explains the skills system for human contributors
```

### 16.8 PR Draft Summary Output Format

The `$pr-draft-summary` skill produces this exact structure:

```markdown
# Pull Request Draft

## Branch name suggestion

git checkout -b {type}/{TASK-ID}-{kebab-description}

## Title

{type}({scope}): {TASK-ID} {imperative description}

## Description

{One paragraph: what this PR accomplishes and why.}

{Technical summary: what changed and the key implementation decisions.}

{Testing: how this was verified, what the $code-change-verification results show.}

This pull request resolves #{issue-number}.

## Agent Metadata

- Agent: @{agent-id}
- Task: TASK-{id}
- Skills invoked: $code-change-verification, ...
- Verification: PASS | FAIL
- Feedback cycles: {n}
```

### 16.9 Release Review Output Format

The `$release-review` skill produces this structure:

```markdown
# Release Readiness Review

## Release Call
🟢 GREEN LIGHT TO SHIP | 🟡 SHIP WITH NOTED RISKS | 🔴 BLOCKED

## Scope Summary
- {n} files changed (+{additions}/-{deletions})
- Key areas: {list of major areas touched}

## Findings

### {Finding Title}
- Risk: 🟢 LOW | 🟡 MODERATE | 🔴 HIGH
- Evidence: {specific diff reference or test result}
- Action: {what must happen, if anything}

## Compatibility Assessment
- Public API changes: {yes/no, details}
- Breaking changes: {yes/no, details}
- Migration required: {yes/no, details}

## Unblock Checklist (if BLOCKED)
- [ ] {specific action required to unblock}
```

---

## License & Governance

This contract is maintained by the **Arbiter** (human project owner). Amendments require:

1. A proposed change (as a PR to this file)
2. Review by `@architect` for structural impact
3. Approval by the Arbiter

No agent may modify this file. This contract governs the agents; the agents do not govern this contract.

### Autonomy Levels

The Arbiter may configure the swarm's autonomy level:

```yaml
autonomy:
  level: "full | supervised | gated"

  full:
    description: "Agents merge autonomously. Arbiter receives notifications only."
    merge_authority: "@merger (all branches)"
    arbiter_role: "Veto + strategic direction"
    best_for: "Mature projects with comprehensive test suites"

  supervised:
    description: "Agents merge to epic/develop autonomously. Main requires Arbiter approval."
    merge_authority: "@merger (epic + develop), Arbiter (main)"
    arbiter_role: "Release gating + veto"
    best_for: "Active projects with evolving requirements"

  gated:
    description: "All merges require Arbiter approval after agent review."
    merge_authority: "Arbiter (all branches, after @merger stages the merge)"
    arbiter_role: "Approve every merge"
    best_for: "High-risk systems, regulated environments, early-stage projects"
```

---

*End of Contract*
