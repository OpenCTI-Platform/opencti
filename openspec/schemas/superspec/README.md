# Superspec Schema

Integrates OpenSpec's artifact governance workflow with Superpowers' execution skills into a single unified workflow.

## What This Schema Solves

OpenSpec manages the "what" (proposal → specs → design → tasks), while Superpowers manages the "how" (brainstorming, writing-plans, subagent-driven-development). Both are excellent on their own, but three structural problems emerge when alternating between them during real development:

1. **Duplicate outputs** — Brainstorming produces design documents in the Superpowers directory (`docs/superpowers/specs/`), and OpenSpec writes proposal/design again in the change directory, with highly overlapping content.
2. **Task fragmentation** — OpenSpec's `tasks.md` (coarse-grained checkboxes) and Superpowers' plan (micro TDD steps) describe the same work, but their format, location, and status tracking are each independent.
3. **Manual orchestration** — Users must decide on their own "which skill should I use now"; there is no automatic handoff between the two systems.

### Why a Custom Schema Instead of Modifying Existing Skills

Two alternatives were considered:

- **Adding custom fields to config.yaml** (e.g., `skill_bindings`): The OpenSpec CLI doesn't recognize these fields — no validation, no discoverability, and multiple SKILL.md files would need modification to read them.
- **Directly modifying opsx skill files**: Highly invasive, affects all changes, and gets overwritten on SKILL.md upgrades.

A custom schema leverages OpenSpec's **natively supported project-level schema mechanism**:
- The CLI validates the schema structure
- `openspec schemas` lists it automatically
- Each change can independently select a schema (`--schema spec-driven` or `--schema superspec`)
- No existing SKILL.md or command files are modified

---

## Workflow Overview

```text
brainstorm ──→ proposal ──→ specs ──→ tasks ──→ plan ──→ apply ──→ verify ──→ finalize
                  │                     ↑
                  └──→ design ──────────┘
```

Differences from `spec-driven`:

| | spec-driven | superspec (v4) |
|---|---|---|
| Starting point | proposal (written manually) | **brainstorm** (invokes brainstorming skill) |
| Endpoint | tasks (coarse-grained) | **finalize** (the git-side closeout: merge worktree → feature branch + push the branch + if a PR exists, post code-reviewer onboarding comment; archive follows as a CLI step) |
| apply requires | tasks | **plan** |
| apply method | Standard task-by-task | **worktree + subagent-driven-development** |
| Additional artifacts | — | brainstorm, plan, apply (receipt), **finalize (receipt)** |
| verify requires | tasks | **apply** (v2 — was plan in v1) |
| finalize requires | — | **verify** (v3) |

---

## Integrated Superpowers Skills

| Schema Phase | Superpowers Skill Invoked | Trigger |
|------------|------------------------|---------|
| brainstorm artifact | `superpowers:brainstorming` | artifact instruction |
| plan artifact | `superpowers:writing-plans` | artifact instruction |
| apply phase | `superpowers:using-git-worktrees` | apply instruction |
| apply phase | `superpowers:subagent-driven-development` | apply instruction |
| finalize artifact | `superpowers:finishing-a-development-branch` | **Manual escape hatch only (v4)** — the git-side closeout is executed by the schema directly |

All integrations are achieved through the `instruction` field in schema.yaml — directing the AI to invoke the corresponding skill at the appropriate time via the Skill tool. No Superpowers skill files are modified.

### Output Redirection

Superpowers skills have default output paths (e.g., brainstorming writes to `docs/superpowers/specs/`). In this schema, artifact instructions include redirection directives that tell the invoked skill to write output into the change directory:

- brainstorming → `openspec/changes/<name>/brainstorm.md` (+ optional `design.md`)
- writing-plans → `openspec/changes/<name>/plan.md`

This is achieved through context injection (appending directives when invoking the skill), not by modifying skill code.

---

## Usage

### Quick Flow (Recommended)
```bash
/opsx:ff my-feature    # End-to-end: create directory + brainstorm + proposal + design + specs + tasks + plan
/opsx:apply            # worktree + subagent-driven-development (writes apply.md)
/opsx:verify           # 5 OpenSpec checks (writes verify.md; requires apply.md)
/opsx:continue         # → finalize (the git-side closeout: merges worktree → feature branch, pushes branch, updates PR if one exists, writes finalize.md, posts code-reviewer comment if PR exists; v4)
/opsx:archive          # sync delta specs + archive change dir
```

### Step-by-Step Flow
```bash
/opsx:new my-feature --schema superspec
/opsx:continue         # → brainstorm (interactive conversation)
/opsx:continue         # → proposal
/opsx:continue         # → design (optional, only when technical decisions need explanation)
/opsx:continue         # → specs
/opsx:continue         # → tasks
/opsx:continue         # → plan
/opsx:apply            # writes apply.md
/opsx:verify           # writes verify.md (requires apply.md)
/opsx:continue         # → finalize (the git-side closeout: merges worktree → feature branch, pushes branch, updates PR if one exists, writes finalize.md, posts code-reviewer comment if PR exists; v4)
/opsx:archive          # sync delta specs + archive change dir
```

### Switching Back to spec-driven
```bash
# Use a different schema for a single change
/opsx:new my-simple-fix --schema spec-driven

# Or change the project default
# openspec/config.yaml: schema: spec-driven
```

---

## Design Decision Log

### Why brainstorm Is an Artifact, Not a Hook

Brainstorming is an interactive multi-turn conversation that requires user participation. Making it the first artifact rather than a schema-level hook has two benefits:
1. **Skippable** — If the user already knows what to build, they can create brainstorm.md directly without invoking the skill
2. **Trackable** — `openspec status` can show whether brainstorm is complete, and subsequent artifacts have explicit dependency relationships

### Why plan Is Separate from tasks

`tasks.md` contains coarse-grained checkboxes ("Add PdfServiceTest"), while `plan.md` contains micro steps ("Create test skeleton → Write downloadPdf test → Run → Commit"). The two differ in granularity and purpose:
- `tasks.md` → Tracks overall progress (the apply phase's `tracks` field parses checkboxes)
- `plan.md` → Guides subagents through step-by-step implementation (input for the executor)

The apply phase requires `plan` rather than `tasks` because the executor needs micro steps to work effectively. However, `tracks: tasks.md` ensures progress is still tracked via coarse-grained checkboxes.

### Why apply Is Both an Artifact and a Phase Block (v2)

The OpenSpec CLI builds its DAG strictly from the `artifacts:` list, and the `ApplyPhase` zod schema has no `generates` field — so the apply phase alone cannot mark itself complete or be referenced by another artifact's `requires`. In v1 this manifested as `verify.requires: [plan]` plus an inline comment saying "actually verify needs apply, but the schema can't say so." Agents predictably ran verify before apply.

v2 solves this by representing apply twice: a real artifact (`generates: apply.md`, `requires: [plan]`) so `verify.requires: [apply]` is honest, *and* the existing `apply:` top-level block so `/opsx:apply` CLI behavior is unchanged (the handler reads `schema.apply.instruction` and would not see the artifact's instruction). To avoid drift, the canonical body lives in the `apply:` block; the apply artifact's instruction is a short redirect.

### Why finalize Is a DAG Artifact (v3)

In v2 the post-verify git closeout (PR creation / merge / worktree cleanup) lived only in the apply: block's step 5 — a place an agent that just ran `/opsx:verify` typically doesn't re-read. The verify artifact's PASS bullets said "proceed" without naming the next call site, so agents routinely jumped straight to `/opsx:archive`, skipping `superpowers:finishing-a-development-branch` entirely.

v3 promotes `finalize` to a real DAG artifact (`generates: finalize.md`, `requires: [verify]`). `/opsx:continue` surfaces its instruction after verify completes, which invokes `superpowers:finishing-a-development-branch` and records the outcome. The recommended retrospective guidance moves from the apply: block (where it was misplaced — apply ends with verify) into finalize's instruction, where it belongs as a pre-archive activity. `/opsx:archive` is unchanged; it remains an OpenSpec CLI command that runs after finalize and is documented in `docs/workflow-details.md` Phase 6 with the canonical archive-before-merge golden path.

### Why We Own the Git-Side Closeout's Logic Instead of Calling the Skill (v4)

The v3 finalize artifact invoked `superpowers:finishing-a-development-branch` and let its 4-option menu drive the closeout. In practice this produced two failure modes for any team using the canonical Superspec PR-pre-review workflow:

1. **finalize.md ended up off the PR branch.** The skill ran Option 2 (push + create PR) before finalize.md was written; the agent then wrote finalize.md from whatever CWD it landed in (typically the main checkout, on the user's feature branch). The PR — created from the worktree branch — did not contain finalize.md.
2. **Two related branches ended up on remote.** The user's feature branch (with artifacts and pre-review PR) sat orphaned while the skill opened a new PR from the worktree branch.

The skill's "base branch" is `main`; its "feature branch" is the worktree branch. Neither aligns with Superspec's "merge worktree into the user's feature branch, then push" intent. Overriding the skill's interpretation from the schema instruction was attempted and judged too brittle.

v4's resolution: the schema executes the git-side closeout directly (merge worktree → feature branch → push → code-reviewer comment if a PR exists). Two narrow pieces are borrowed from the skill with explicit attribution and a documented recreation method — the worktree-cleanup provenance guard and the test-verify → merge → test-verify → cleanup structural pattern. The schema-executed closeout handles both the "spec pre-review PR exists" and "no PR yet" cases cleanly — when a PR exists, the push updates it and the comment subroutine posts; when no PR exists, the push creates the remote tracking branch and the comment subroutine self-skips. The skill remains a first-class manual escape hatch for the truly off-canonical flows (solo merge-to-main, brand-new PR via the skill, keep-as-is, discard).

### Fallback Strategy

If Superpowers skills are unavailable (not installed, version incompatible, etc.), each instruction includes a fallback path:
- brainstorm → Manually write brainstorm.md
- plan → Manually write plan.md
- apply → Standard task-by-task manual implementation
- finalize → Run the git operations manually (merge / push / open PR / comment) and author finalize.md directly from templates/finalize.md
