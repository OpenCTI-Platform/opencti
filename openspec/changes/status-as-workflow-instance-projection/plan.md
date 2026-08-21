# Enterprise Workflow Engine Migration (Status → WorkflowInstance CQRS) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development
> (recommended) or superpowers:executing-plans to implement this plan task-by-task.
> Steps use checkbox (`- [ ]`) syntax for tracking.
>
> **Scope note:** This spec spans 7 largely independent capabilities. This is a
> **master coordination plan** at task-group granularity (mirrors `tasks.md`).
> Before starting implementation on a given Task below, run
> `superpowers:writing-plans` again scoped to that Task/capability to produce a
> full micro-step TDD plan with exact code — do this at the point that phase is
> picked up, since precise call sites in files not yet fully explored (playbook
> action definitions, mass-operation background tasks, closing-reason UI) need
> a fresh read before committing to exact diffs.

**Goal:** Make `WorkflowInstance.currentState` the source of truth for status
on every entity type with a published workflow, projecting it onto the
existing `Status`/`x_opencti_workflow_id` field so all current sort/filter/
widget query consumers keep working unchanged, with no bulk entity
migration. **Not unchanged:** the number/ordering of update events emitted
per transition increases (see Global Constraints and Task 13) — this is an
explicit, accepted change in event cardinality, not a gap.

**Architecture:** CQRS projection: `WorkflowInstance` (write side, source of
truth) → deterministic projection function → `Status`/`x_opencti_workflow_id`
(read side, unchanged query surface), written through the existing
attribute-patch flow so history/stream/notifications stay intact. Legacy
`Status` remains authoritative for entity types with no published workflow.

**Tech Stack:** Node.js/TypeScript GraphQL backend (`opencti-graphql`),
React/TypeScript + Relay frontend (`opencti-front`), ElasticSearch-backed
store (`createEntity`, `updateAttribute`, `storeLoadById`), Vitest for unit
tests.

**Spec:** [openspec/changes/status-as-workflow-instance-projection/design.md](design.md),
[specs/workflow-status-projection/spec.md](specs/workflow-status-projection/spec.md),
[specs/workflow-entity-extension/spec.md](specs/workflow-entity-extension/spec.md),
[specs/workflow-definition-migration/spec.md](specs/workflow-definition-migration/spec.md),
[specs/workflow-request-access/spec.md](specs/workflow-request-access/spec.md),
[specs/workflow-concurrent-writers/spec.md](specs/workflow-concurrent-writers/spec.md),
[specs/workflow-transition-actions/spec.md](specs/workflow-transition-actions/spec.md),
[specs/workflow-closing-reason/spec.md](specs/workflow-closing-reason/spec.md)

## Global Constraints

- **Two independent gates, do not conflate them:** (1) the `ENTITIES_WORKFLOW`
  flag gates only user-visible/UI wiring (Tasks 5, 9-12) for entity types
  other than `DraftWorkspace`; (2) backend mechanics (Tasks 1-3, 6-8) are
  gated purely by **whether a given entity type has a published
  `WorkflowDefinition`** — they run regardless of the UI flag, so Task 8's
  hook into `updateAttribute` and the sync-manager/public API paths MUST
  check "does this entity's type have a published `WorkflowDefinition`"
  (existing `getWorkflowConfig`/`getDefinitionData` no-op pattern) before
  doing anything; entity types with no published workflow are completely
  unaffected by any Task 1-8 code path. State this check explicitly at the
  top of every hook added in Tasks 2 and 8, not just implied by no-op
  behavior. **This supersedes the older, looser phrasing "a single flag
  gates all backend wiring" used earlier in discussion — that phrasing is
  incorrect and should not be treated as a separate rule.**
- No mass entity-document migration: `WorkflowInstance` is created eagerly
  on new entities and lazily backfilled on first read for existing ones.
- Projection writes MUST use the normal attribute-patch flow
  (`updateAttribute`/equivalent), never a direct ES write, so stream/
  history/notifications are unaffected in shape (their **cardinality**
  does change — see below).
- **Accepted event-cardinality change:** a single workflow transition now
  triggers two writes — the `WorkflowInstance` update and the projected
  `Status` update — so downstream stream consumers see at least two update
  events per transition instead of one. This must be validated against known
  stream consumers before `ENTITIES_WORKFLOW` is enabled broadly (Task 13).
  **Timing correction (per review):** do not defer this validation to Task
  13 (the last task) purely because that's where the formal checklist item
  lives — if any known major stream consumer (SIEM connector, XSOAR,
  custom poller) genuinely cannot tolerate cardinality/ordering changes,
  that is an architecture-level blocker, not a bug to fix after 12 tasks of
  work are already built. Run this as a lightweight spike (confirm with the
  owners of known high-value stream integrations) before starting Task 2,
  and only proceed with the full projection design if the answer is
  tolerable. Task 13's checklist item remains as the final confirmation, not
  the first one.
  **Scope of who's actually affected (per review, round 17, clarifying
  nuance — narrows the blast radius of this spike):** the second event is
  a write on the **new `WorkflowInstance` entity**, not a second event on
  the target entity itself — a playbook/rule/automation listening for
  updates on e.g. `Report` (filtered by entity type) still sees exactly one
  update event on `Report`, same as today, since the projected
  `x_opencti_workflow_id` write is itself just that one `Report` update
  (fixed write order above means the `WorkflowInstance` event precedes it,
  it doesn't multiply it). What actually changes for a `Report`-scoped
  consumer is the **new `event_external`/`event_bypass` history-entry
  types** appearing in that same entity's history (Step 5.1 below), not
  event count. The consumers genuinely exposed to raw cardinality growth
  are **generic "consume everything on the stream" integrations** (SIEMs,
  custom pollers, XSOAR) that don't filter by entity type and would now
  also see `WorkflowInstance` create/update events interleaved with
  every other entity type's events. Scope the spike's outreach accordingly
  — per-entity-type playbook triggers are not a priority to re-validate;
  whole-stream consumers are.
- Fixed write order: `WorkflowInstance.currentState` persisted before the
  projected `x_opencti_workflow_id` is updated.
- Statuses referenced by a published `WorkflowDefinition` cannot be
  deleted; orphaned ones are deleted on republish once unreferenced by any
  entity or state (accepted tradeoff: historical event/history entries that
  reference a deleted `Status` id will show an unresolvable id going
  forward — consistent with the Key Decision that legacy history
  reconstruction is out of scope).
- **Concurrent write race semantics:** when a workflow transition and a
  direct external write (Task 8) race on the same entity, the last write to
  reach `updateAttribute` wins (no compare-and-set/versioning is introduced
  by this plan). This is an explicit accepted limitation, not a silent gap
  — flag to a maintainer during Task 8 implementation if optimistic
  concurrency (e.g. a version/lock attribute) is required before GA.
  **Not low-risk (per review, round 16):** this change doubles write volume
  per transition (instance write + projection write) across the same set of
  concurrent writers (playbooks, connectors, manual edits, sync manager) —
  collision probability scales with write volume, so treat this as a
  concrete risk to monitor post-rollout, not a theoretical edge case.
- **CE resource-cost callout (per review, round 16):** eager `WorkflowInstance`
  creation (Task 3) and doubled writes per transition are **not** EE-gated —
  only the RBAC/automated-action features are. Every Community Edition
  install incurs the extra storage (one `WorkflowInstance` document per
  entity of a migrated type) and ES write-throughput cost the moment a type
  is migrated (Task 6), regardless of license tier or the `ENTITIES_WORKFLOW`
  flag. Call this out explicitly to a maintainer before migrating
  high-cardinality types (Indicators, Observables) broadly.
- **Flag mechanism is config/restart-based, not a live toggle (per review,
  round 16, confirmed):** `ENABLED_FEATURE_FLAGS` reads from
  `nconf.get('app:enabled_dev_features')` (`conf.js`) — a static config value
  loaded at startup. Flipping `ENTITIES_WORKFLOW` requires a config change +
  restart, unlike Task 6's migration (which is a per-entity-type, one-time
  action taken via the API/admin action, not a config flag). Don't describe
  these as equivalent "staged rollout" levers in rollout docs — they have
  different operational mechanics and different blast radii.
- **Accepted admin-facing breaking change:** `statusDelete` (individual
  `Status` deletion) gains a workflow-usage guard it does not have today
  (Task 1) — any existing admin tooling/automation that deletes a `Status`
  referenced by a published `WorkflowDefinition` will start receiving a
  `FunctionalError` where it previously succeeded. This is intentional
  (matches `statusTemplateDelete`'s existing behavior) but must be called
  out in release notes, not discovered via support tickets.
- EE gating: RBAC transition restriction and automated on-transition/
  on-status actions require Enterprise Edition, matching `DraftWorkspace`
  precedent; core enforced-ordering mechanics are Community Edition.
- **RBAC-bypass decision required (per review, real inconsistency):**
  "who can transition" restriction (an EE governance feature) is only
  meaningful if enforced on `triggerWorkflowEvent`. But Task 8's tolerant
  direct-write sync and Task 9's `setWorkflowStatus` bypass mutation both
  change `WorkflowInstance.currentState` without going through
  `allowedTransitions`/RBAC-transition checks — gated only by generic
  `KNOWLEDGE_KNUPDATE`. Note: no such per-transition RBAC-restriction
  enforcement mechanism was found in the current codebase during this
  review (only `EE_ONLY_ACTION_TYPES` gating specific *action types* like
  `updateAuthorizedMembers`), so this may be a future/aspirational EE
  feature rather than something actively broken today — but the plan as
  written would undermine it the moment it's built, via either path. This
  needs an explicit product decision before Task 8/9 ship, not a silent
  default: (a) document that governance restrictions apply only to the
  "official" transition path and are advisory against tolerant/bypass
  writes, or (b) gate `setWorkflowStatus` and the external-sync's resulting
  state change by the same per-transition RBAC restriction the normal
  transition enforces (rejecting bypass/external writes that would land on
  a state the caller isn't authorized to reach). Default to (a) unless a
  maintainer confirms (b) is required before GA — (b) is a larger scope
  addition (needs the restriction check to run against arbitrary target
  states, not just declared transition edges). **Escalation (per review,
  round 14): do not let (a) be a silent default** — get explicit product
  sign-off before Tasks 8/9 ship if RBAC transition restriction is marketed
  as an EE access-control guarantee anywhere (docs, sales material), since
  (a) means that guarantee is decorative against tolerant/bypass writes for
  any user with plain `KNOWLEDGE_KNUPDATE` — which is the common case.
- Phase 1.1 (state ordering + full mapping invariant) is blocking for all
  later phases.
- **Execution order override (per review, corrected — the previous
  "Task 3 fully before Task 2" directive was itself a deadlock, since Task 3
  Step 2.5 calls Task 2's `projectWorkflowState`):** the real dependency is
  finer-grained than "one task before the other":
  1. Implement Task 2's Steps 1.1-1.3 first (`projectWorkflowState` itself,
     the pure state→status write function) — its unit tests can stub
     `scope: 'standard'` and do not need Task 3.
  2. Implement Task 3 in full, including Step 2.5 (which now calls the real
     `projectWorkflowState` from step 1) and Step 5 (`WorkflowInstance.scope`
     field).
  3. Return to Task 2 for Steps 0 (real scope wiring, no longer stubbed),
     2-6 (wiring into `triggerWorkflowEvent`/async completion, read-repair,
     the `currentStatus` freeze, and the integration test) — these do
     require Task 3's scope field and creation/backfill hooks to exist.
  This is not a documentation nicety: implementing Task 2 or Task 3 fully in
  one pass without this split will hit the circular requirement directly.
- **Task 7's scope-routing mechanism is load-bearing, not independent of
  Tasks 1-3/6 (per review, round 18 — corrects the previous framing below,
  confirmed wrong by reading the actual code):** the `scope` field on
  `WorkflowInstance` (Task 3) is justified by the pre-existing `Status.scope`
  field, independent of Task 7 — that much still holds, and Tasks 1-3 can
  start regardless of Task 7's timing. **However**, verified directly in
  `workflow-domain.ts` (`getDefinitionData`/`getWorkflowConfig`, ~line 198-260):
  today's lookup resolves exactly **one** `WorkflowDefinition` via the
  singular `EntitySetting.workflow_id` field — there is no scope parameter
  anywhere in the current signature. Task 7's Steps 1.2/1.3 (add
  `RequestAccessFlow.workflow_definition_id`; extend `getWorkflowConfig`/
  `getDefinitionData` to accept a `scope` and route accordingly) are the
  **only** place this scope-aware routing gets built. Task 2's
  `projectWorkflowState` and Task 8's `syncWorkflowInstanceFromExternalWrite`
  both need to resolve a `request_access`-scoped `WorkflowInstance` against
  its **own** `request_access`-scoped `WorkflowDefinition`, not the standard
  one (conflating them would violate Task 1's own scope-keyed mapping rule).
  Without Task 7's routing extension, that resolution has nowhere to go.
  **Consequence: Task 7 cannot default to "skip" for any entity type that
  actually has `request_access`-scoped `Status` data today** (confirmed live
  for `CaseRfi` via `requestAccess-domain.ts`'s `firstStatus`/`approved_workflow_id`/
  `declined_workflow_id`) — if that type is migrated, Task 7's Steps 1.1-2.3
  are mandatory prerequisites for Task 2/8 to function correctly for that
  type's `request_access`-scoped entities, not an optional enhancement. Task
  7 is only genuinely skippable for a migrated entity type that has **no**
  `request_access`-scoped `Status` data at all (nothing to route). Determine
  this per-type from Task 6's migration preview (`workflowMigrationPreview`'s
  `byScope` output already reports which scopes exist per type) rather than
  as a single blanket plan-wide decision.

---

## Task 1: Workflow state ordering & full mapping invariant (blocking)

**Capability:** `workflow-status-projection` (tasks.md group 1)

**Files:**
- Modify: `opencti-platform/opencti-graphql/src/modules/workflow/types/workflow-types.ts` (add `order` to state type)
- Modify: `opencti-platform/opencti-graphql/src/modules/workflow/domain/workflow-domain.ts` (publish/republish flow — see `publishWorkflowDefinition` and `getDefinitionData` already in this file; also home of the existing `isStatusTemplateUsedInWorkflows`)
- Modify: `opencti-platform/opencti-graphql/src/domain/status.ts` (existing `statusTemplateDelete` already guards via `isStatusTemplateUsedInWorkflows` — extend, don't duplicate; existing `statusDelete` has **no** workflow-usage guard today — add one)
- Create: `opencti-platform/opencti-graphql/src/modules/workflow/domain/workflow-ordering.ts` (topological + manual-order computation)
- Test: `opencti-platform/opencti-graphql/tests/01-unit/modules/workflow-ordering-test.ts`
- Test: `opencti-platform/opencti-graphql/tests/01-unit/domain/status-test.ts` (deletion guard cases)

> **Correction from review:** a deletion guard already exists —
> `statusTemplateDelete` (`src/domain/status.ts`) calls
> `isStatusTemplateUsedInWorkflows` (`workflow-domain.ts`) and blocks deletion
> if the template is referenced by **either** the draft or published version
> of any workflow, then cascades to delete all `Status` records using that
> template. Do not add a second, parallel guard in `workflow-validation.ts` —
> extend `isStatusTemplateUsedInWorkflows`/reuse it from `statusDelete` (the
> per-`Status`-entity deletion path used by the legacy workflow_configuration
> screen), which currently has no such check at all. **Frozen decision (per
> review, no longer open):** keep the existing draft+published scope
> unchanged for both the template-level and the new `Status`-level guard —
> do not narrow to published-only. This preserves current admin-facing
> behavior exactly; no UX/migration impact to document since nothing
> changes for existing callers.

**Interfaces:**
- Produces: `computeStateOrder(definitionData): Map<stateId, order>` — used by Task 2's projection function and by frontend sort display.
- Produces: `ensureFullStatusMapping(context, user, entitySetting, definitionData): Promise<void>` — called from `publishWorkflowDefinition`.
- Consumes: existing `getWorkflowConfig`, `getDefinitionData`, `publishWorkflowDefinition` from `workflow-domain.ts`.

> **Critical correction from review:** `Status` entities carry a `scope`
> field (`StatusScope.Global` vs. request-access scope — confirmed in
> `domain/status.ts`'s `batchGlobalStatusesByType`, which filters explicitly
> on `scope: Global`). The state→status mapping key MUST be **(entity type,
> scope, state/template id)**, not just (entity type, state/template id) —
> otherwise `ensureFullStatusMapping` can create or pick a `Status` in the
> wrong scope (e.g. a global one when a request-access-scoped one was
> intended, or vice versa), and the Task 2 projection function inherits the
  same ambiguity. **Correction (per review, round 18):** Task 7 cannot
  actually be descoped for entity types with `request_access`-scoped
  `Status` data (see the corrected Global Constraints note above) — the
  mapping still needs the scope key regardless, but do not plan around a
  "Task 7 descoped" scenario as if it were a routine, low-stakes default;
  for such types, Task 7's routing extension is a hard prerequisite.

- [ ] **Step 1.1: Add `order` field to workflow state schema/types**
  - Add `order?: number` to the state definition type in `workflow-types.ts`.
  - Add a GraphQL schema field `order: Int` on the workflow state type in the workflow `.graphql` file.
- [ ] **Step 1.2: Write failing unit tests for topological ordering**
  - In `workflow-ordering-test.ts`, test that a linear chain `open → in_progress → resolved → closed` yields orders `0,1,2,3`.
  - Test a branching-but-convergent graph (`open → {A, B} → merged`) yields a valid order where `A` and `B` may share the same order value (ties among sibling branches are expected and fine — see the ambiguity rule below), and `merged` sorts after both.
  - Test a genuinely ambiguous case (see ambiguity rule) returns `null`/needs-manual-order signal.
- [ ] **Step 1.3: Run tests to verify failure** — `yarn workspace opencti-graphql vitest run tests/01-unit/modules/workflow-ordering-test.ts`
- [ ] **Step 1.4: Implement `computeStateOrder`** in `workflow-ordering.ts`: BFS/topological sort from `definitionData.initialState` counting minimum transitions; **corrected ambiguity rule (per review, previous rule was self-contradictory):** ties among sibling branch states at the same BFS depth are NOT ambiguous — they simply share an order value, which is expected in branch/merge graphs and is fine for both validation-ordering and display-sort purposes. Ambiguity (return `null`, forcing manual-order fallback) is reserved strictly for cases where BFS/topological depth cannot be computed at all for one or more states reachable from the initial state — i.e. a cycle exists among states such that no finite shortest-path count exists. A branching-then-converging acyclic graph is never ambiguous under this rule.
- [ ] **Step 1.5: Run tests to verify pass**
- [ ] **Step 2.1: Write failing test for manual-order fallback**
  - When `computeStateOrder` returns `null`, verify the system falls back to a manually supplied `order` field per state.
- [ ] **Step 2.2: Implement fallback**: in the publish path, if topological ordering is ambiguous, require/read the manual `order` values already stored on each state.
- [ ] **Step 2.3: Run tests to verify pass**
- [ ] **Step 3.1: Write failing test for full-mapping creation on publish**
  - Given a `WorkflowDefinition` with 3 states and an attached entity type with only 1 existing `Status`, publishing creates the 2 missing `Status` records (one per missing state).
- [ ] **Step 3.2: Write failing test for canonical state-key normalization** (per review): a workflow state defined with only `name` (no `statusId`) is rejected at publish time with a `FunctionalError` — confirmed via `workflow-validation.ts`/`workflow-schema.ts` that `statusId` (`StatusTemplate` internal id) is optional in the serialized state schema today, but the mapping/projection mechanism requires a resolvable canonical key. Publish-time normalization closes this gap rather than leaving it to drift between projection (Task 2) and external sync (Task 8).
- [ ] **Step 3.3: Remediation guidance for pre-existing definitions** (per review, high — this is an admin-facing compatibility break): today's runtime does not enforce `statusId` at publish, so an existing published `WorkflowDefinition` (currently only `DraftWorkspace`'s) could in theory have a name-only state that would suddenly fail to republish once this validation lands. Add a **preflight/dry-run** path — reuse `workflowMigrationPreview`-style diagnostics (Task 6) or a lightweight dedicated check — that lists exactly which states in an existing definition are missing `statusId` *before* an admin attempts to republish, with a clear remediation message ("add a status template reference to state X"), rather than a bare `FunctionalError` with no guidance.
- [ ] **Step 3.4: Implement the publish-time `statusId` requirement** (reject publish if any state lacks a `statusId`) alongside `ensureFullStatusMapping`.
- [ ] **Step 3.5: Write failing test for disconnected/unreachable states** (per review, high): a state declared in the definition but not reachable from `initialState` via any transition path is neither a cycle nor a valid tie under the ambiguity rule (Step 1.4) — it simply never gets a BFS depth. Publish MUST reject a definition containing such a state with a clear error identifying it, rather than silently producing a partial order that later logic (full-mapping, projection) assumes is total.
- [ ] **Step 3.6: Implement the reachability check** in `computeStateOrder`/publish validation: every declared state must be reachable from `initialState`; unreachable states fail publish, they are not treated as needing manual order (a manual order doesn't fix "this state can never be entered," which is a definition bug).
- [ ] **Step 3.7: Implement `ensureFullStatusMapping`**: for each attached entity type, diff states vs. existing `Status` records keyed by **(entity type, scope, template/state id)** — not template/state id alone — create missing ones via existing `createEntity`-based `Status` creation path, preserving each `Status`'s existing `scope`.
- [ ] **Step 3.8: Wire `ensureFullStatusMapping` into `publishWorkflowDefinition`** (before it marks the definition published).
- [ ] **Step 3.9: Run tests to verify pass**
- [ ] **Step 4.1: Write failing test for orphan deletion on republish**
  - A state removed from a new published version whose mapped `Status` has no entity referencing it and no other state mapping to it gets deleted.
- [ ] **Step 4.2: Write failing test — request-access-referenced status is never deleted as orphan** (per review, critical): a `Status` referenced by an `EntitySetting.request_access_workflow.approved_workflow_id` or `.declined_workflow_id` (confirmed live in `requestAccess-domain.ts`) must be excluded from orphan deletion even if no entity's `x_opencti_workflow_id` currently points to it and no workflow state maps to it — these fields are a separate reference path the original criteria missed entirely.
- [ ] **Step 4.3: Implement orphan detection** in the republish path: unreferenced = no entity `x_opencti_workflow_id` points to it, AND no state in the new definition maps to it, AND no `EntitySetting.request_access_workflow.{approved_workflow_id,declined_workflow_id}` (across all entity-setting configs, not just the one being republished) references it.
- [ ] **Step 4.4: Storage contract for soft-delete** (per review, expanded from a one-line note into a concrete subtask block): add `to_be_deleted_at?: Date` to the `Status` store type/schema (`BasicWorkflowStatus`) and GraphQL schema; no migration/backfill is needed for existing `Status` rows since the field is optional and absent means "not pending deletion" by construction.
- [ ] **Step 4.5: Implement mark-for-deletion** in the republish orphan-detection path (Step 4.3): set `to_be_deleted_at = now + 30 days` on newly-orphaned `Status` records via `updateAttribute`, instead of calling delete directly.
- [ ] **Step 4.6: Write failing test — restore-vs-purge race**: if a republish later reintroduces a state that maps back to a `Status` still pending deletion (within its grace window), the mark is cleared (`to_be_deleted_at = null`) and the `Status` is treated as active again — restoring must win over a concurrent purge attempt for the same record.
- [ ] **Step 4.7: Implement the cleanup executor** (per review, ownership/schedule must be explicit): a scheduled manager task (follow the existing manager pattern used elsewhere in this codebase, e.g. `src/manager/`) runs on a fixed interval (e.g. daily), queries `Status` records where `to_be_deleted_at <= now`, re-verifies each is still unreferenced (re-run the same three checks from Step 4.3 — entity, state mapping, request-access — since state can change during the grace window), and only then hard-deletes. Idempotent by construction: re-running the check-then-delete on an already-deleted record is a no-op (the record no longer exists to query).
- [ ] **Step 4.8: Run tests to verify pass**
- [ ] **Step 4.9: Regression-test the new invariant logic against the one real, already-published `WorkflowDefinition` in production (per review, round 20 — this task's new orphan-detection/full-mapping logic had never been exercised against live data before this)**: `DraftWorkspace` is the only entity type with an actually-published `WorkflowDefinition` in existing installs today. Before this task's `ensureFullStatusMapping`/orphan-detection/`statusId`-requirement logic (Steps 3.4-4.7) is considered done, write an integration test that seeds a `DraftWorkspace`-shaped definition/status set matching realistic existing production data (states with `statusId` already set, as `DraftWorkspace` states already have them — see Step 3.3's preflight note) and republishes it, asserting: no existing `Status` record is unexpectedly deleted or recreated with a new id, `ensureFullStatusMapping` is a no-op when the mapping is already complete, and the orphan-detection path does not mark anything for deletion when nothing was actually removed from the definition. This closes the gap between "the new logic is unit-tested in isolation" and "the new logic is safe to run against the one dataset that already exists in the wild."
- [ ] **Step 5.1: Write failing test — no Status changes on draft save**
  - Saving an unpublished draft version of a `WorkflowDefinition` must not call `ensureFullStatusMapping` or the deletion path.
- [ ] **Step 5.2: Verify/guard**: confirm the draft-save code path (`setWorkflowDefinition` with draft target) does not invoke the publish-only functions above.
- [ ] **Step 5.3: Run tests to verify pass**
- [ ] **Step 6.1: Write failing test for deletion guard on individual `Status` deletion**
  - Attempting to delete a `Status` (via `statusDelete`) referenced by a published `WorkflowDefinition` throws a `FunctionalError`, mirroring `statusTemplateDelete`'s existing behavior.
- [ ] **Step 6.2: Add the guard to `statusDelete`** in `src/domain/status.ts`, reusing `isStatusTemplateUsedInWorkflows` (extended if needed to check by `Status` id, not just `StatusTemplate` id) — do not create a parallel checker. **Note (per review):** `isStatusTemplateUsedInWorkflows` currently matches via `content.includes(statusTemplateId)`/`JSON.stringify(content).includes(...)` — a substring check over serialized JSON, not exact structured-field matching. Extending it for `Status`-id checks (which don't even appear in `content` today, only `StatusTemplate` ids do — requires resolving `Status` → its `template_id` first) should parse `content` and compare exact `template_id`/state values, not substring-match, to avoid false positives/negatives from partial id overlaps.
- [ ] **Step 6.3: Run tests to verify pass**
- [ ] **Step 7: Commit**
  ```bash
  git add opencti-platform/opencti-graphql/src/modules/workflow/ opencti-platform/opencti-graphql/src/domain/status.ts opencti-platform/opencti-graphql/tests/01-unit/modules/workflow-ordering-test.ts opencti-platform/opencti-graphql/tests/01-unit/domain/status-test.ts
  git commit -m "feat(workflow): add state ordering and full status-mapping invariant on publish"
  ```

---

## Task 2: Status projection

**Capability:** `workflow-status-projection` (tasks.md group 2)

**Files:**
- Modify: `opencti-platform/opencti-graphql/src/modules/workflow/domain/workflow-domain.ts` (`triggerWorkflowEvent`, async completion path — see existing code around line 900-1040 in this file)
- Create: `opencti-platform/opencti-graphql/src/modules/workflow/domain/workflow-projection.ts`
- Modify: `opencti-platform/opencti-graphql/src/modules/workflow/domain/workflow-async-completion.ts` (async completion path)
- Test: `opencti-platform/opencti-graphql/tests/01-unit/modules/workflow-projection-test.ts`
- Test: `opencti-platform/opencti-graphql/tests/03-integration/02-resolvers/workflow-test.ts` (extend existing integration suite)

**Interfaces:**
- Consumes: `computeStateOrder`/state→`Status` mapping built in Task 1 (keyed by entity type + scope + state/template id, per Task 1's corrected mapping key); `WorkflowInstance.scope` field added by Task 3.
- Produces: `projectWorkflowState(context, entity, stateId, scope): Promise<void>` — **scope is an explicit parameter, not re-derived ad hoc** (per review: the mapping key includes scope, so every caller must supply it). Called from both the sync transition path (`triggerWorkflowEvent`) and the async completion path, both of which already have the `WorkflowInstance` in hand and read its `scope` field directly.

> **Scope-derivation correction (per review):** the mapping key requires
> scope, but no prior step said where a call site gets it from. Fix: add a
> `scope` field to `WorkflowInstance` itself, set once at creation time,
> so `projectWorkflowState` and `syncWorkflowInstanceFromExternalWrite`
> (Task 8) simply read `instance.scope` instead of re-deriving it from
> context each time. This also removes any ambiguity at read-repair time,
> since the persisted instance already carries its scope.
>
> **Task-ordering correction (per review, corrected across two rounds —
> see Global Constraints for the authoritative, non-contradictory order):**
> the `scope` field itself is bootstrapped by **Task 3**
> (`initializeWorkflowInstance`/`ensureWorkflowInstance`, which own
> `WorkflowInstance` creation). But Task 3's Step 2.5 calls this task's
> `projectWorkflowState` (Step 1), so neither task can be fully completed
> strictly before the other in one pass — split as follows: implement this
> task's Steps 1.1-1.3 (the `projectWorkflowState` function, scope stubbed
> in tests) **before** Task 3; implement this task's remaining steps (0,
> 2-6, which need the real `scope` field and creation/backfill hooks)
> **after** Task 3 is complete. Do not duplicate the `scope` field
> implementation here — see Task 3's Step 5.

> **Execution-identity correction (per review, critical):** `getWorkflowInstance`
> is called from ordinary read paths (list/detail queries) by arbitrary
> readers, some of whom have no update rights on the entity. Read-repair
> MUST NOT run `projectWorkflowState`/`updateAttribute` under the *caller's*
> user context (which could fail with a permission error and, worse, fail
> the read itself). Fix: read-repair writes run under the existing
> `WORKFLOW_MANAGER_USER` system identity already used elsewhere in this
> module for engine-driven writes (see `workflow-domain.ts`'s
> `workflowContext.user: WORKFLOW_MANAGER_USER` pattern in `ensureWorkflowInstance`),
> never the reading caller's user. On write failure (e.g. transient store
> error), catch it, log via `logApp.warn`, and return the pre-repair read
> value to the caller unchanged — a failed repair must never fail or delay
> the read response.

- [ ] **Part A — implement before Task 3, no dependency on it:**
- [ ] **Step 1.1: Write failing unit test for projection function**
  - `projectWorkflowState` given an entity, a target state id, and a scope calls `updateAttribute` with `x_opencti_workflow_id` set to the `Status` mapped for that exact (entity type, scope, state).
- [ ] **Step 1.2: Implement `projectWorkflowState`** in `workflow-projection.ts` using the existing `updateAttribute` middleware (same one used elsewhere in `workflow-domain.ts`).
- [ ] **Step 1.3: Run test to verify pass**
- [ ] **Part B — implement after Task 3 is complete (needs its `WorkflowInstance.scope` field, Step 5, and its creation/backfill hooks):**
- [ ] **Step 0.1: Write failing test — `WorkflowInstance.scope` already exists** (implemented by Task 3, Step 5): `projectWorkflowState`'s callers read `instance.scope` without re-deriving it.
- [ ] **Step 0.2: Run test to verify pass**
- [ ] **Step 2.1: Write failing test — sync transition calls projection after instance update**
  - Assert `updateAttribute` (instance) is called, then `projectWorkflowState`, in that order, using a mock/spy.
- [ ] **Step 2.2: Wire `projectWorkflowState` into `triggerWorkflowEvent`** immediately after `history` is updated (existing code around `{ key: 'history', value: [...] }` update in `workflow-domain.ts`).
- [ ] **Step 2.3: Run test to verify pass**
- [ ] **Step 3.1: Write failing test — async completion calls projection**
- [ ] **Step 3.2: Wire `projectWorkflowState` into the async completion handler** (`workflow-async-completion.ts`).
- [ ] **Step 3.3: Run test to verify pass**
- [ ] **Step 4.1: Write failing test for read-repair**
  - `getWorkflowInstance` given an entity whose `x_opencti_workflow_id` doesn't match the `Status` mapped to `currentState` triggers a projection correction before returning.
- [ ] **Step 4.2: Implement read-repair** inside `getWorkflowInstance` (existing function in `workflow-domain.ts`), calling `projectWorkflowState` under the `WORKFLOW_MANAGER_USER` system identity (never the caller's user), passing `instance.scope`, when divergence detected.
- [ ] **Step 4.3: Write failing test — repair failure does not fail the read**: if `projectWorkflowState` throws during read-repair, `getWorkflowInstance` still returns the (unrepaired) instance data to the caller rather than propagating the error.
- [ ] **Step 4.4: Implement the catch/log/continue behavior** per the note above.
- [ ] **Step 4.5: Run tests to verify pass**
- [ ] **Step 4.6: Implement a concrete read-repair rate limit** (hardened per review, not left as a future note): maintain a short-lived in-process cache (e.g. a `Map<entityId, timestamp>` with a fixed 5-second TTL, evicted lazily on read) inside `getWorkflowInstance`; skip the repair write if the entity was already repaired within the TTL window and return the read value as-is. Write a test asserting a second `getWorkflowInstance` call within the TTL window does not call `projectWorkflowState` again. **Known limitation (per review):** this cache is per-process; in a multi-node deployment each node can independently repair the same entity within its own TTL window, so repeated repairs across nodes are still possible under load. Accept this for phase 1 (repairs are idempotent no-ops when already consistent, so correctness isn't affected, only redundant writes); revisit with a shared cache (e.g. Redis) only if monitoring shows this materially adds write/stream load.
- [ ] **Step 4.7: Add read-repair observability** (per review, previously missing): emit a counter/log metric each time a repair write actually happens (reuse the existing `telemetry`/`logApp` patterns already used elsewhere in `domain/status.ts`), tagged by entity type. This gives operators a concrete signal (repairs/minute) to decide if the TTL needs tuning or a shared cache is warranted, without requiring new infrastructure now. **Telemetry docs (per review):** if this becomes a formal OpenTelemetry metric (not just a `logApp` line), it must follow this repo's telemetry instructions — add/update the metric in `opencti-graphql/src/telemetry/` and `docs/docs/reference/usage-telemetry.md` per `telemetry.instructions.md`. If it stays a plain log line, no telemetry doc update is required; decide which at implementation time and note the choice in the PR description.
- [ ] **Step 4.8: Add a config-based kill switch** (per review, concrete operational guardrail): a boolean config flag (e.g. `workflow:disable_read_repair`, following the existing `nconf.get(...)` pattern used elsewhere in this codebase) that, when set, makes `getWorkflowInstance` skip repair writes entirely and fall back to the pre-this-change in-memory-only behavior, while still returning correct read data. This gives operators an immediate lever if repair rates spike during rollout, without needing a code deploy to disable it. Write a test confirming no `projectWorkflowState` call happens when the flag is set.
- [ ] **Step 5.1: Freeze the `currentStatus` GraphQL contract (option a, per review)**: keep `currentStatus.id`/`template_id` semantics unchanged — both continue to resolve to the `StatusTemplate` id from `currentState`, exactly as `workflow-resolvers.ts` does today. Do not change this in this change; the real, entity-type-scoped projected `Status` remains accessible only via the entity's own `status`/`x_opencti_workflow_id` field. Revisit only if a maintainer confirms no consumer depends on the current shape. **Documentation requirement (per review):** this dual-semantics split (`WorkflowInstance.currentStatus.id` = `StatusTemplate` id; entity `status`/`x_opencti_workflow_id` = real `Status` id) MUST be called out explicitly in the GraphQL API changelog/docs for this change and in `client-python`'s release notes if it consumes either field, not left as an implicit detail future integrators have to discover by inspecting resolver code.
- [ ] **Step 5.2: Write a test asserting `currentStatus.id`/`template_id` are unchanged** after Tasks 1-2 land (regression guard against accidental contract drift).
- [ ] **Step 6.1: Write integration test** — extend `tests/03-integration/02-resolvers/workflow-test.ts`: trigger a real workflow event and assert both `workflowInstance.currentState` and the entity's `status`/`x_opencti_workflow_id` reflect the new state, and a stream update event is emitted.
- [ ] **Step 6.2: Run integration tests** — `yarn workspace opencti-graphql test:integration -- workflow-test`
- [ ] **Step 7: Commit**
  ```bash
  git add opencti-platform/opencti-graphql/src/modules/workflow/ opencti-platform/opencti-graphql/tests/01-unit/modules/workflow-projection-test.ts opencti-platform/opencti-graphql/tests/03-integration/02-resolvers/workflow-test.ts
  git commit -m "feat(workflow): project WorkflowInstance state onto legacy Status field"
  ```

---

## Task 3: Eager instance creation & lazy backfill

**Capability:** `workflow-entity-extension` (tasks.md group 3)

> **Correction from review (high, architecture):** `createEntity`
> (`middleware.ts:4045`) is genuinely the single centralized creation
> function — but `workflow-domain.ts` (home of `initializeEntityWorkflow`)
> already imports `createEntity`/`updateAttribute` **from** `middleware.ts`.
> Calling `initializeEntityWorkflow` directly from inside `createEntity`
> would make `middleware.ts` import back from `workflow-domain.ts`, a
> circular dependency. There is no existing precedent for `middleware.ts`
> calling out to a feature module this way (the one existing post-create
> hook, `triggerCreateEntityAutoEnrichment`, is defined locally inside
> `middleware.ts` itself, not imported). Fix: introduce a decoupled hook
> registry instead of a direct import — see Step 1.2 below.

**Files:**
- Create: `opencti-platform/opencti-graphql/src/database/entity-lifecycle-hooks.ts` (tiny registry: `registerPostEntityCreationHook(fn)` / `runPostEntityCreationHooks(context, user, entity)`, no imports from feature modules)
- Modify: `opencti-platform/opencti-graphql/src/database/middleware.ts` (`createEntity`, call `runPostEntityCreationHooks` after `data.isCreation`, importing only the registry file, not workflow-domain)
- Modify: `opencti-platform/opencti-graphql/src/modules/workflow/domain/workflow-domain.ts` (register `initializeEntityWorkflow` into the hook registry at module load, e.g. via the module's existing registration/bootstrap file)
- Test: `opencti-platform/opencti-graphql/tests/01-unit/database/entity-lifecycle-hooks-test.ts`
- Test: `opencti-platform/opencti-graphql/tests/01-unit/modules/workflow-domain-test.ts`

**Interfaces:**
- Produces: `registerPostEntityCreationHook(fn: (context, user, entity) => Promise<void>): void` and `runPostEntityCreationHooks(context, user, entity): Promise<void>` in the new registry file — `middleware.ts` depends only on this tiny file, never on `workflow-domain.ts`. Produces `WorkflowInstance.scope` (see Step 5 below), consumed by Task 2/8.
- Consumes: existing `initializeEntityWorkflow(context, user, entity)`, `getWorkflowInstance`, `ensureWorkflowInstance` (already implemented in `workflow-domain.ts` for `DraftWorkspace` today).

> **Idempotent registration (per review):** `src/modules/index.ts` imports
> the workflow module from **two separate paths** — `./workflow/workflow`
> (line 45) and `./workflow/api/workflow-graphql` (line 172). Node/ES module
> caching means a given file's top-level code only runs once even if
> imported from both, but do not rely on that alone: make
> `registerPostEntityCreationHook`/`registerPostAttributeUpdateHook`
> idempotent by construction (e.g. de-dupe by function reference, or a
> one-time `registered` guard inside `registerWorkflowLifecycleHooks()`
> itself), and call `registerWorkflowLifecycleHooks()` from exactly **one**
> central bootstrap call site (Step 1.4), never from both workflow module
> entry points. Add a test that calling `registerWorkflowLifecycleHooks()`
> twice does not result in the hook firing twice per entity.

- [ ] **Step 1.1: Write failing test for the hook registry** — a registered hook is invoked with the created entity after `createEntity` completes; an entity type with no hooks registered is unaffected.
- [ ] **Step 1.2: Implement the registry** in `entity-lifecycle-hooks.ts` and wire `runPostEntityCreationHooks` into `createEntity` right after the existing `triggerCreateEntityAutoEnrichment` call. Registration functions de-dupe by function reference so repeated registration calls are no-ops.
- [ ] **Step 1.3: Register `initializeEntityWorkflow`** into the registry from `workflow-domain.ts`'s module-load path (verify no import cycle results — `workflow-domain.ts` importing the registry file is fine since the registry file imports nothing feature-specific).
- [ ] **Step 1.4: Guarantee bootstrap order (per review, previously unspecified)**: do not rely on ES module import-order side effects alone. Add an explicit `registerWorkflowLifecycleHooks()` export from `workflow-domain.ts`, called once, synchronously, from the server's central bootstrap sequence (the same place GraphQL resolvers/schema are assembled before the server starts accepting connections) — before any mutation handling begins. Add a startup assertion test verifying the hook is registered prior to the first simulated `createEntity` call in the test suite, and a duplicate-registration test per the idempotency note above.
- [ ] **Step 1.5: Run test to verify pass**
- [ ] **Step 2.1: Write failing test — eager creation on generic entity add**
  - Create an entity of a type with a published workflow through the generic creation path (not `draftWorkspaceAdd`); assert a real `WorkflowInstance` exists immediately (not an `initial-...` id).
- [ ] **Step 2.2: Run test to verify pass** (should now pass via the registered hook from Step 1.3)
- [ ] **Step 2.3: Remove the now-redundant explicit call** in `draftWorkspace-resolvers.ts` if the generic hook path also covers draft creation; otherwise document why it must remain (e.g. draft creation bypasses the generic `createEntity` path).
- [ ] **Step 2.4: Write failing test — creation-time overwrite of an explicitly-supplied status** (per review, critical, biggest blast radius found so far): `x_opencti_workflow_id` is an ordinary, publicly-settable creation field — confirmed every pycti entity constructor and `requestAccess-domain.ts`'s `CaseRfiAddInput` (`x_opencti_workflow_id: firstStatus.id`) set it directly at creation time. A naive unconditional "project `initialState`" hook (as drafted) would silently discard that caller-supplied status the moment a type is migrated (Task 6), with no error — breaking every pycti connector doing a status-aware bulk import for that type, even before the `ENTITIES_WORKFLOW` UI flag is enabled (backend gating is by workflow existence, not the flag). **Three cases, corrected (per review, round 19 — the previous two-case wording was self-contradictory: it told the hook to both "default to `initialState`" and "do not silently fall back to `initialState`" for the same case):**
  - **(a) Explicit status supplied, resolves to a valid state:** initialize `WorkflowInstance.currentState` at that resolved state (and `scope` from the resolved `Status.scope`, Step 5.1); the entity's `x_opencti_workflow_id` is left untouched (no projection write — it's already correct).
  - **(b) Explicit status supplied, does NOT resolve to any state in the published definition** (foreign/stale id — e.g. a status id from a different entity type/scope, or one predating the definition): initialize `WorkflowInstance.currentState` at `initialState` anyway (the instance needs a valid starting engine state — `currentState` is a required field on the store type, there is no "no state" representation), but record a `pendingError` diagnostic on the instance (reusing the existing `pendingError?: string | null` field already on `WorkflowInstance`) noting the supplied status id didn't resolve. **Critically, do NOT project/overwrite the entity's `x_opencti_workflow_id`** — the caller's originally-supplied (if unrecognized) value is preserved as-is, exactly as case (a) preserves a resolvable one; only the *instance's* internal engine state defaults to `initialState`, not the entity's own field. This is the creation-time analogue of Task 8's unmapped-write policy, adapted because no prior `currentState` exists yet to "leave unchanged" at creation time (Task 8's own note, applied verbatim, doesn't compose here for exactly that reason).
  - **(c) No `x_opencti_workflow_id` supplied at all:** initialize at `initialState` and call `projectWorkflowState` once, writing the projected `Status` onto the entity's `x_opencti_workflow_id` (this is the only case where this hook writes that field).
- [ ] **Step 2.5: Implement resolve-then-project** per the three cases in Step 2.4: reuse the state↔status mapping resolver from Task 1/2 to look up whether the entity's `x_opencti_workflow_id` (if present at creation) maps to a state in the published definition; case (a) initializes from that resolution with no projection write; case (b) initializes at `initialState` with a `pendingError` diagnostic and no projection write; case (c) initializes at `initialState` and calls `projectWorkflowState` once. This closes the "fresh entity briefly inconsistent" window without ever overwriting caller intent in cases (a) or (b).
- [ ] **Step 2.5b: Write a failing test for case (b)** — an entity created with an `x_opencti_workflow_id` that doesn't resolve to any state in the published definition gets a `WorkflowInstance` at `initialState` with a non-null `pendingError`, and its own `x_opencti_workflow_id` field is unchanged from the caller-supplied value (not overwritten with the projected `initialState`'s `Status`).
- [ ] **Step 2.6: Run test to verify pass**
- [ ] **Step 3.1: Write failing test — lazy backfill on first read**
  - `getWorkflowInstance` for a pre-existing entity (created before this change, no `WorkflowInstance` row) with a published workflow persists a real instance and returns it.
- [ ] **Step 3.2: Write failing test — lazy backfill runs under system identity and is non-fatal** (per review, critical: this write-on-read path had less protection than Task 2's read-repair): the backfill write in `ensureWorkflowInstance` runs under `WORKFLOW_MANAGER_USER` (same pattern as Task 2's read-repair), not the reading caller's user — today's `initializeWorkflowInstance`/`ensureWorkflowInstance` use `bypassDraftContext(context).user` (the caller), which this task changes. If the backfill write fails (e.g. transient store error or, previously, a permission error under caller identity), `getWorkflowInstance` still returns a synthesized in-memory result to the caller (the pre-this-change `initial-...` behavior as a fallback) rather than failing the read.
- [ ] **Step 3.3: Modify `getWorkflowInstance`** to call `ensureWorkflowInstance` (already defined in this file, currently only used by `triggerWorkflowEvent`) instead of only computing `id: \`initial-${effectiveEntityId}\`` in memory, passing the `WORKFLOW_MANAGER_USER` identity and wrapping the call in the same catch/log/continue pattern as Task 2's read-repair.
- [ ] **Step 3.4: Run test to verify pass**
- [ ] **Step 4.1: Write failing test — idempotent backfill**
  - Calling `getWorkflowInstance` twice in a row for the same entity creates exactly one `WorkflowInstance`.
- [ ] **Step 4.2: Verify** `ensureWorkflowInstance`'s existing `findWorkflowInstanceEntity` early-return handles this (it already does per current code); add regression test only.
- [ ] **Step 4.3: Run test to verify pass**
- [ ] **Step 5.1: Write failing test — `WorkflowInstance.scope` is set at creation** (per review, moved here from Task 2 to fix ordering): a `WorkflowInstance` created via `initializeWorkflowInstance`/`ensureWorkflowInstance` has `scope: 'standard'` by default. **Corrected (per review, fixes the Task 1/Task 6 scope-fallback inconsistency):** when the entity was created with an explicit `x_opencti_workflow_id` (Step 2.4/2.5), `scope` is derived from that resolved `Status`'s own `scope` field, not hardcoded to `'standard'` — this is what makes a `request_access`-created entity (whose `Status` is `request_access`-scoped, per `requestAccess-domain.ts`'s `firstStatus`) get a correctly-scoped `WorkflowInstance` even if Task 7 is skipped, instead of silently conflating it with the standard scope.
- [ ] **Step 5.2: Add `scope` to the `WorkflowInstance` store type and GraphQL schema**, set in `initializeWorkflowInstance`/`ensureWorkflowInstance` from the resolved `Status.scope` when one was supplied at creation (Step 2.4/2.5), else `'standard'`. **Backward-compatibility fallback (per review, high):** every `WorkflowInstance` row created before this task ships (today, only `DraftWorkspace` instances) has no `scope` value in the store. All readers of `instance.scope` (Task 2's `projectWorkflowState`, Task 8's `syncWorkflowInstanceFromExternalWrite`) MUST treat a missing/undefined `scope` as `'standard'` (`instance.scope ?? 'standard'`), never as an error or an ambiguous case — this is correct by construction since `DraftWorkspace` never had request-access scoping. No backfill migration is needed for this field specifically.
- [ ] **Step 5.3: Write a test asserting the `'standard'` fallback** for a `WorkflowInstance` document with no `scope` field set.
- [ ] **Step 5.4: Run test to verify pass** — this unblocks Task 2's Step 0/1 and Task 8's scope-aware sync.
- [ ] **Step 6: Commit**
  ```bash
  git add opencti-platform/opencti-graphql/src/database/entity-lifecycle-hooks.ts opencti-platform/opencti-graphql/src/database/middleware.ts opencti-platform/opencti-graphql/src/modules/workflow/ opencti-platform/opencti-graphql/tests/01-unit/database/entity-lifecycle-hooks-test.ts opencti-platform/opencti-graphql/tests/01-unit/modules/workflow-domain-test.ts
  git commit -m "feat(workflow): generalize eager creation and lazy backfill to all entity types via decoupled hook registry"
  ```

---

## Task 4: Generalized filtering

**Capability:** `workflow-entity-extension` (tasks.md group 4)

> **Correction from review (critical):** `completeSpecialFilterKeys(context, user,
> inputFilters, opts?)` in `filtering-completeSpecialFilterKeys.ts` has **no
> entity-type parameter** — it processes a filter group generically for
> whatever query is calling it. The existing `resolveWorkflowInstanceStatusFilter`
> in `draftWorkspace-domain.ts` only works today because it's called from a
> `DraftWorkspace`-specific query handler that already knows the entity type.
> A naive move into the shared adapter cannot tell workflow-instance-based
> filtering apart from legacy-status filtering without that context. Two
> viable fixes — decide which before implementing:
> (a) thread an explicit `entityTypes`/target-type hint into
> `completeSpecialFilterKeys`'s signature and callers, or
> (b) keep the resolution at the domain-query layer (one shared helper
> function called explicitly by each entity type's list resolver, the way
> `draftWorkspace-domain.ts` does today) rather than inside the generic
> special-filter-key adapter. Option (b) is lower-risk (no signature change
> to a widely-called shared function) and is the default unless a follow-up
> investigation shows (a) is cleaner.

**Files:**
- Modify: `opencti-platform/opencti-graphql/src/utils/filtering/filtering-completeSpecialFilterKeys.ts` (only if option (a) is chosen)
- Create: `opencti-platform/opencti-graphql/src/utils/filtering/workflow-status-filter.ts` (shared helper, option (b) default)
- Modify: `opencti-platform/opencti-graphql/src/modules/draftWorkspace/draftWorkspace-domain.ts` (redirect `resolveWorkflowInstanceStatusFilter` to call the shared helper)
- Test: `opencti-platform/opencti-graphql/tests/01-unit/domain/draft-workspace-test.ts` (existing suite covers current filter — extend/relocate)
- Test: `opencti-platform/opencti-graphql/tests/01-unit/utils/workflow-status-filter-test.ts`

**Interfaces:**
- Consumes: `WORKFLOW_INSTANCE_STATUS_FILTER` constant (`filtering-constants.ts`), `ENTITY_TYPE_WORKFLOW_INSTANCE`, `fullEntitiesList`, `getWorkflowConfig`-style lookup.
- Produces: `resolveWorkflowStatusFilter(context, user, entityType, args)` — a shared helper explicitly parameterized by entity type, called from each workflow-enabled entity type's list resolver (mirroring how `DraftWorkspace` calls it today), not injected into the generic special-filter-key pipeline.

> **Phase-1 rollout surface (per review, avoid partial behavior):** wire the
> shared helper into exactly the list resolvers for entity types that already
> have (or are expected to have, per this change's scope) a published
> `WorkflowDefinition` when this task ships — do not attempt to wire all ~40
> entity types that merely expose `x_opencti_workflow_id` in their GraphQL
> schema (most have no workflow configured and must keep using the legacy
> filter path untouched). Confirm the concrete list against whichever entity
> types have a `WorkflowDefinition` published at the time this task is
> implemented, rather than a static list decided now.
>
> **Scope correction (per review, this finding recurred across multiple
> rounds — resolving by descoping rather than re-documenting; supersedes any
> earlier note in this task suggesting all four query surfaces are in scope
> here):** the `first: 5000` bound makes `count`/`distribution`/`timeSeries`
> numbers unreliable at scale, and generalizing workflow-based filtering to
> those surfaces without fixing it would ship a known-truncating analytics
> surface for every newly-enabled entity type, not just `DraftWorkspace`
> (where it's a pre-existing, narrower-blast-radius issue today). **Phase 1
> of this task covers list/pagination filtering only — this is the single
> rule for this task's scope, not a coexisting option.** Wiring
> `count`/`distribution`/`timeSeries` through the shared helper is explicitly
> deferred to a follow-up task, gated on either (a) fixing the bounded-scan
> limitation (search-after pagination or an indexable field), or (b) an
> explicit, documented decision to accept the truncation risk for those
> surfaces specifically. Do not wire count/distribution/timeSeries in this
> task.
>
> **Clarification (per review, easy to misread):** this task's scope is
> workflow-status *filtering* (a query rewritten into an id-list). Plain
> aggregation **by** `x_opencti_workflow_id` (already whitelisted in
> `engine.ts`) is unaffected either way, since the projected field stays
> populated for workflow-enabled types — widgets that aggregate on status
> without a workflow-specific filter keep working unchanged. Only
> widgets/queries that *filter* by workflow status inherit this task's
> list-only scope.

- [ ] **Step 0: Proceed with option (b) by default** (per review: made deterministic to avoid re-litigating this each pass) — resolve workflow-status filtering at the domain-query layer via a shared, explicitly-parameterized helper, not by changing `completeSpecialFilterKeys`'s signature. Only switch to option (a) if a maintainer explicitly requests it before this task starts; otherwise implement (b) directly, no further confirmation step needed.
- [ ] **Step 1.1: Write failing test** for the shared helper resolving a non-draft entity type by workflow status to an id-list filter, mirroring the existing `resolveWorkflowInstanceStatusFilter` behavior in `draftWorkspace-domain.ts`.
- [ ] **Step 1.2: Extract the logic** from `resolveWorkflowInstanceStatusFilter` in `draftWorkspace-domain.ts` into the shared helper, generalized to accept an explicit entity type parameter (remove the draft-specific assumptions).
- [ ] **Step 1.3: Wire the shared helper** into each workflow-enabled entity type's list resolver, passing its own entity type explicitly.
- [ ] **Step 1.4: Update `draftWorkspace-domain.ts`** to call into the shared helper instead of its own copy.
- [ ] **Step 1.5: Run tests to verify pass**
- [ ] **Step 2.1: Write test — legacy entity types unaffected** (no workflow configured → filter still resolves via legacy `Status`).
- [ ] **Step 2.2: Run test to verify pass**
- [ ] **Step 3.1: Manual check — bounded query, not full scan**: confirm the generalized resolver still uses `first: 5000`/bounded `fullEntitiesList` calls as the current draft implementation does, not an unbounded scan.
- [ ] **Step 3.2: Document the 5000-item bound's scope (per review, corrected — this affects list correctness itself, not only analytics)**: the `first: 5000` cap already exists in `draftWorkspace-domain.ts` today. Its effect is not limited to `count`/`distribution`/`timeSeries` — the filter-resolution step rewrites a status filter into a bounded id-list (at most 5000 ids), and that id-list is what actually feeds list/pagination results too. If more than 5000 entities of a given type match a given status, list filtering itself silently omits matches beyond the cap, not just widget counts. This is a pre-existing limitation this task inherits and generalizes to more entity types, same as the already-descoped analytics surfaces — call it out identically in release notes rather than treating list filtering as "safe" while analytics is "unsafe." **Prioritization note (per review, round 15):** for high-cardinality entity types (Indicators, Observables), this is a realistic support-ticket generator, not a hypothetical edge case — recommend prioritizing the search-after pagination fix ahead of enabling `ENTITIES_WORKFLOW` broadly for those specific types, rather than shipping the truncation risk widely and fixing it reactively.
- [ ] **Step 4: Commit**
  ```bash
  git add opencti-platform/opencti-graphql/src/utils/filtering/ opencti-platform/opencti-graphql/src/modules/draftWorkspace/ opencti-platform/opencti-graphql/tests/01-unit/domain/draft-workspace-test.ts opencti-platform/opencti-graphql/tests/01-unit/utils/workflow-status-filter-test.ts
  git commit -m "feat(workflow): generalize workflow-status filtering to all entity types"
  ```

---

## Task 5: Feature flag & new workflow UI

**Capability:** `workflow-entity-extension` (tasks.md group 5)

> **Prerequisite added from review (critical):** the `workflowInstance`
> field is currently resolvable **as an embedded field on the `DraftWorkspace`
> GraphQL type only** (`workflow-resolvers.ts`: `DraftWorkspace: {
> workflowInstance: ... }`). A generic, standalone `Query.workflowInstance(entityId)`
> already exists and works for any entity id — the gap is specifically
> **field-level embedding** (`entity { workflowInstance { ... } }` inside a
> list/detail query for non-`DraftWorkspace` types), not total unavailability
> of workflow-instance data. This task cannot add embedded-field UI support
> until that embedding gap is closed — see Step 0 below.

> **Duplicate resolver ownership (per review, must resolve first):**
> `DraftWorkspace.workflowInstance` is currently defined **twice** —
> `workflow-resolvers.ts` (`DraftWorkspace: { workflowInstance: ... }`) and
> `draftWorkspace-resolvers.ts:67` (`workflowInstance: (draft, _, context) =>
> getWorkflowInstance(...)`) — both calling `getWorkflowInstance` with
> functionally identical logic. Whichever is merged last into the combined
> resolver map silently wins today; this must be resolved to a single
> authoritative owner **before** generalizing to other entity types, or the
> ambiguity multiplies across every newly-added type. Consolidate into
> `workflow-resolvers.ts` (the more logical home given Task 5 generalizes
> this field there) and remove the duplicate from `draftWorkspace-resolvers.ts`.

> **Auth directive matrix (per review, frozen, not left open):** the
> existing field is gated `@auth(for: [KNOWLEDGE_KNUPDATE], forDraft:
> [KNOWLEDGE_KNUPDATE])` in `workflow.graphql`. Every newly-embedded
> `workflowInstance` field on other entity types uses the **same**
> `@auth(for: [KNOWLEDGE_KNUPDATE])` directive (the `forDraft` variant is
> `DraftWorkspace`-specific and does not apply elsewhere) — do not leave the
> auth level to be decided per entity type ad hoc, and add a test per
> strategy (A/B, Step 0.2) confirming a user without `KNOWLEDGE_KNUPDATE` on
> a given entity gets a forbidden error, not silent null or overexposed data.

**Files:**
- Modify: workflow `.graphql` schema and each relevant entity type's `.graphql` file (or a shared interface/mixin if the schema supports one) to add a `workflowInstance` field resolvable on every entity type with a configurable workflow
- Modify: `opencti-platform/opencti-graphql/src/modules/workflow/api/workflow-resolvers.ts` (generalize the field resolver beyond the `DraftWorkspace` block, reusing the same `getWorkflowInstance(context, user, entityId)` call)
- Modify: feature-flag registry (locate existing flag pattern, e.g. `opencti-platform/opencti-graphql/src/config/` and frontend `opencti-platform/opencti-front/src/utils/` flag helpers)
- Modify: `opencti-platform/opencti-front/src/private/components/common/workflow/` (reuse `WorkflowStatus.tsx`, `WorkflowTransitions.tsx` components already built for `DraftWorkspace`; extend `WorkflowStatus.graphql.ts`'s fragment, currently typed on `DraftWorkspace` only, to a union/interface or per-type fragment)
- Modify: `opencti-platform/opencti-front/src/private/components/common/form/StatusField.tsx` and every one of its ~40 call sites across entity edition forms (`ReportEditionOverview.jsx`, `IndicatorEditionOverview.tsx`, `CaseIncidentEditionOverview.tsx`, etc. — confirmed via grep: 40+ files under `opencti-platform/opencti-front/src/private/components/**`) — see the new Step 4.5 below.
- Test: existing `WorkflowStatus.test.tsx`, `WorkflowTransitions.test.tsx` (extend for non-draft entity types), `StatusField.test.tsx`

> Before implementing this task, re-run `writing-plans` scoped to this task
> after reading the current feature-flag registration pattern and the full
> `WorkflowStatus.tsx`/`WorkflowTransitions.tsx` components — not yet read in
> full during this planning pass.

> **`StatusField` is a free-choice bypass of enforced transitions (per
> review, round 17 — the single biggest functional hole found across all
> review rounds):** confirmed via code read (`StatusField.tsx:1-120`) that
> this component is a plain autocomplete over **all** `Status` rows for a
> given `(type, scope)`, wired via ordinary `fieldPatch` into ~40 entity
> edition forms (Report, Indicator, Grouping, Note, Opinion, CaseIncident,
> CaseRfi, CaseRft, Feedback, Task, Individual, Organization, City,
> Infrastructure, AttackPattern, Campaign, IntrusionSet, ThreatActor, etc. —
> confirmed by grep across `opencti-front/src/private/components/**`, 40+
> files). It performs **no ordering/transition-graph enforcement** — any
> user with plain edit rights on the entity can jump to any status in any
> order, in the existing UI, today. Task 9 adds a *new* transition-aware UI,
> but leaves this pre-existing dropdown fully functional and untouched
> unless explicitly addressed here. Since Task 8 intentionally keeps direct
> `x_opencti_workflow_id`/`fieldPatch` writes tolerant (for connector/pycti
> compatibility), `StatusField` is not a hypothetical gap — it is the
> **exact same write path** Task 8 is designed to stay compatible with,
> except originating from OpenCTI's own first-party UI rather than an
> external system. Leaving it as-is makes "enforced state transitions" purely
> decorative for any migrated entity type: a user can always bypass the new
> transition UI by using the pre-existing field. This is broader than the
> RBAC-bypass Global Constraints item (which is about *who* can transition
> under EE governance) — this is about whether *ordering enforcement itself*
> has any teeth in the UI at all, for every license tier, once a type is
> migrated.

- [ ] **Step 0.1: Write failing test** — querying `workflowInstance` as a field on a non-`DraftWorkspace` entity type (e.g. through its GraphQL type) returns instance data instead of a schema error.
- [ ] **Step 0.2: Consolidate the duplicate resolver** (per review): remove `draftWorkspace-resolvers.ts:67`'s `workflowInstance` field resolver, keeping `workflow-resolvers.ts`'s `DraftWorkspace.workflowInstance` as the single authoritative owner. Add a test confirming `DraftWorkspace.workflowInstance` behavior is unchanged after removal.
- [ ] **Step 0.3: Expand the schema/resolver** so `workflowInstance` is resolvable on every entity type with a configurable workflow, using `@auth(for: [KNOWLEDGE_KNUPDATE])` on each new field per the frozen auth matrix above. **Proceed with strategy (A) by default** (per review: made deterministic) — add the field individually to each workflow-enabled entity type's `.graphql`/resolver, matching the existing per-type `x_opencti_workflow_id` pattern. Only switch to strategy (B) (a shared GraphQL interface, e.g. `WorkflowEnabled`, implemented by those types) if a maintainer explicitly requests it before this task starts; otherwise implement (A) directly, no further confirmation step needed.
- [ ] **Step 0.4: Write a test for the auth matrix** — a user without `KNOWLEDGE_KNUPDATE` on a given entity gets a forbidden error when querying its embedded `workflowInstance` field, for at least one non-`DraftWorkspace` type.
- [ ] **Step 0.5: Run tests to verify pass**
- [ ] **Step 0.6: Write a failing test for batched resolution** (per review, real gap: the field resolver as speced just calls `getWorkflowInstance(context, user, entityId)` per row, with no batching — the per-process 5s read-repair TTL cache from Task 2 only dedupes repeat visits to the *same* entity, not a burst across many *different* entities on one list page, which is exactly what happens once this field is embedded on paginated list views like Reports/Indicators/Cases): resolving `workflowInstance` for a page of N entities issues at most 1 batched lookup, not N sequential ones.
- [ ] **Step 0.7: Implement a DataLoader (or equivalent batching)** for the `workflowInstance` field resolver, batching `WorkflowInstance` lookups by `entity_id` across a single GraphQL request (follow an existing DataLoader pattern already used elsewhere in this codebase, e.g. `batchLoader` in `middleware.ts`, rather than introducing a new batching mechanism). This must land before this field is embedded on any list/dashboard view (Task 12), not only detail views, since list views are the actual high-fan-out case. **Write-burst gap not solved by read batching (per review, round 16):** the DataLoader batches *reads*; it does nothing for the *write* burst when many rows on one page independently diverge and each triggers a read-repair write (e.g. right after a type is migrated, before any backfill has happened) — the per-entity TTL cache (Task 2, Step 4.6) only dedupes repeats of the *same* entity, not a burst across many *different* entities in one request. Add a simple per-request cap (e.g. at most K repair writes per GraphQL request/list resolution, tracked in a request-scoped counter) so a single page load of N stale entities can't fire N concurrent `updateAttribute` calls; entities beyond the cap are returned unrepaired for that request (read-repair still corrects them on a subsequent request/read). Write a test asserting a page of entities exceeding the cap only issues the capped number of repair writes.
- [ ] **Step 0.8: Run test to verify pass**
- [ ] **Step 1: Add `ENTITIES_WORKFLOW` flag** following the existing feature-flag registration pattern used elsewhere in the codebase (locate one similar flag as a template).
- [ ] **Step 2: Gate workflow UI rendering** on entity views behind the flag for non-`DraftWorkspace` types, reusing `WorkflowStatus`/`WorkflowTransitions` components.
- [ ] **Step 3: Hide validate-draft action and skip its validation** for non-`DraftWorkspace` types (locate validate-draft action component and its validation check).
- [ ] **Step 4: Hide Authorized Members actions for Container entities** and add the corresponding validation check.
- [ ] **Step 4.5: Write a failing test asserting `StatusField` is disabled/hidden** on an entity edition form for an entity type that (a) has `ENTITIES_WORKFLOW` enabled and (b) has a published `WorkflowDefinition` — then make it pass by adding a guard in `StatusField.tsx` (or its call sites) that renders it read-only (showing current status only, with a pointer to the new transition UI) instead of an editable autocomplete, when both conditions hold. When either condition is false (flag off, or no published definition for that type), `StatusField` keeps its current free-choice behavior unchanged — this must not regress any non-migrated entity type. Apply this per call site across all ~40 forms (a single shared guard inside `StatusField.tsx` itself, keyed on `type`/`scope` props it already receives, is preferable to editing every call site individually).
- [ ] **Step 4.6: Run test to verify pass**
- [ ] **Step 5: Frontend tests** for flagged behavior per entity type category (draft, container, other).
- [ ] **Step 6: Commit**
  ```bash
  git add opencti-platform/opencti-front/src/private/components/common/workflow/
  git commit -m "feat(workflow): gate extended workflow UI behind ENTITIES_WORKFLOW flag"
  ```

---

## Task 6: Definition migration

**Capability:** `workflow-definition-migration` (tasks.md group 6)

> **Critical correction from review:** `order`, `scope`, and `type` (target
> entity type) live on the `Status` entity (`BasicWorkflowStatus` in
> `store.d.ts`), **not** on `StatusTemplate` (`BasicWorkflowTemplateEntity`,
> which only has `name`/`color`). A converter keyed on `StatusTemplate[]`
> loses exactly the per-entity-type ordering and scope information needed to
> build a correct `WorkflowDefinition`. The converter input must be
> `Status[]` (grouped by `type`/`scope`), joined with `StatusTemplate` only
> for the human-readable name.

**Files:**
- Create: `opencti-platform/opencti-graphql/src/modules/workflow/migration/status-to-definition-converter.ts` (pure function + diagnostics types)
- Modify: `opencti-platform/opencti-graphql/src/modules/workflow/api/workflow-resolvers.ts` (add preview query resolver)
- Modify: workflow `.graphql` schema (add `workflowMigrationPreview(entityType: String!): WorkflowMigrationPreview` query type)
- Create: `opencti-platform/opencti-graphql/src/migrations/<timestamp>-workflow-definition-migration.js` (follow existing migration file pattern in `src/migrations/`, see `1651939301056-workflow_rename.js` for format)
- Test: `opencti-platform/opencti-graphql/tests/01-unit/modules/status-to-definition-converter-test.ts`

**Interfaces:**
- Produces: `convertStatusToDefinition(statuses: BasicWorkflowStatus[], templates: BasicWorkflowTemplateEntity[]): { byScope: Record<StatusScope, { definition: WorkflowDefinitionInput; diagnostics: Diagnostic[] }> }` — pure, no I/O. **Scope-explicit output (per review, critical):** since the mapping key established in Tasks 1/2/8 is (entity type, scope, state), and an entity type can have both global and `request_access`-scoped `Status` sets coexisting (confirmed via `Status.scope`/`StatusScope`), a single merged `definition` per entity type would be ambiguous or silently wrong when both scopes are present. The function groups `statuses` by `scope` first and returns one conversion result **per scope**, never a single blended definition; `templates` supplies display names via `template_id` for each group.

- [ ] **Step 1.1: Write failing tests for the pure conversion function** covering: well-formed ordered `Status[]` (with `order` set) → valid definition with empty diagnostics; missing `order` → diagnostic + best-effort definition; name conflicts (via joined `StatusTemplate.name`) → diagnostic; **mixed `scope` values within one entity type → two separate entries in `byScope`, each independently valid/diagnosed, never merged into one definition** (per review, corrects the earlier "diagnostic only" treatment).
- [ ] **Step 1.1b: Decide and document the transition-synthesis policy (per review, round 18 — a genuine, previously-unstated design gap):** legacy `Status` data has no edge/transition concept at all, only a flat `order` integer, and today's `StatusField` UI lets users jump to any status in any order (no enforcement). `convertStatusToDefinition` must synthesize `WorkflowSerializedTransition[]` (`from`/`to`/`event`) from that flat ordering, and the choice is a real behavior decision, not an implementation detail: **default to fully-connected transitions** (every state can transition to every other state) rather than a linear forward-only or forward+backward-adjacent-only chain — this exactly preserves today's unenforced, jump-anywhere behavior for migrated data, so the migration itself introduces zero new ordering restrictions. Any *narrowing* to a stricter transition graph (e.g. sequential-only) is a separate, explicit, opt-in follow-up an admin can apply after migration by editing the generated `WorkflowDefinition` — not something this migration imposes automatically. **Flag to a maintainer/PO before this task starts:** teams using statuses as unordered parallel labels (e.g. "duplicate"/"false positive" closing reasons) must not be silently forced into sequential ordering by this migration; the fully-connected default avoids that, but confirm this default matches product intent, since it directly determines how disruptive Task 5's `StatusField` lockdown (Step 4.5/4.6) will feel to existing users on day one of migration.
- [ ] **Step 1.1c: Write a test asserting the fully-connected default** — given N ordered statuses with no explicit transition/edge data, the synthesized definition contains transitions allowing every state to reach every other state (not just adjacent-order pairs).
- [ ] **Step 1.2: Implement `convertStatusToDefinition`** as a pure function (no context/user/store access) in `status-to-definition-converter.ts`, grouping by `scope` before converting each group independently, and synthesizing fully-connected transitions per Step 1.1b's decision.
- [ ] **Step 1.3: Run tests to verify pass**
- [ ] **Step 2.1: Add GraphQL preview query** `workflowMigrationPreview(entityType: String!): WorkflowMigrationPreview` returning **one result per scope present** for that entity type's current `Status` set (matching `convertStatusToDefinition`'s `byScope` shape), read-only. **RBAC (frozen per review):** gate with `@auth(for: [SETTINGS_SETCUSTOMIZATION])`, matching the existing `workflowDefinition`/`workflowDefinitionSet` pattern in `workflow.graphql` — this is a config-preview surface for admins, not a general knowledge-read query.
- [ ] **Step 2.2: Integration test**: query preview for a sample entity type with both global and `request_access`-scoped statuses configured; assert two distinct, independently-correct results are returned (not one merged/ambiguous definition), and no persisted changes occur.
- [ ] **Step 3.1: Implement the versioned migration** reusing `convertStatusToDefinition`, following the existing migration file format (`params`, `up`/`next` function shape as in `1651939301056-workflow_rename.js`), creating one `WorkflowDefinition` **per scope** returned by `byScope` and setting the corresponding `EntitySetting.workflow_id` (standard scope). **Corrected ordering dependency (per review, round 18 — supersedes the round-16 "not dead data" note, which incorrectly assumed a scope-aware lookup mechanism already existed without Task 7):** for the `request_access` scope, this migration MUST set `RequestAccessFlow.workflow_definition_id` (the field added by Task 7 Step 1.2) to the newly-created `request_access`-scoped `WorkflowDefinition`'s id — there is no other field through which Task 2/8 can resolve it (verified: `getDefinitionData` only reads the singular `EntitySetting.workflow_id`, added scope-awareness only by Task 7 Step 1.3). **This means Task 7's Steps 1.1-1.3 (schema field + scope-aware `getWorkflowConfig`/`getDefinitionData`) must land before this migration runs for any entity type with `request_access`-scoped `Status` data** — add this as an explicit precondition check in the migration (fail loudly, not silently, if `request_access`-scoped statuses are found for a type but the `workflow_definition_id` field/routing doesn't exist yet on the running codebase). For entity types with no `request_access`-scoped `Status` data, this ordering dependency does not apply.
- [ ] **Step 3.2: Integration test**: run migration against seeded status data, assert preview output matches actual created definition.
- [ ] **Step 3.3: Canary rollout guidance (per review)**: running this migration sets `EntitySetting.workflow_id`, which — per Global Constraints — immediately activates backend mechanics (Tasks 1-3, 6-8) for that entity type regardless of the `ENTITIES_WORKFLOW` UI flag, since backend gating is by workflow existence, not the flag. This is intentional (staged backend-then-UI rollout) but must be run per-entity-type as an explicit canary, not in bulk: migrate one low-traffic entity type first, monitor read-repair metrics (Step 4.7 of Task 2) and stream event volume for a defined observation window, then proceed to the next type. Rollback = clear `EntitySetting.workflow_id` for that type (existing `workflowDefinitionDelete`-style path), which reverts reads/writes to legacy `Status` behavior immediately since Task 2's projection/Task 8's sync both no-op without a published definition. **Rollback completeness (per review):** clearing `workflow_id` does not delete already-created `WorkflowInstance` rows, their history, or any recorded `pendingError` diagnostics for that entity type — these become inert (no longer read or written by Tasks 2/8 once ungated) rather than actively harmful, so no cleanup step is required for correctness. Any downstream consumer that had started handling `event_external`/`event_bypass` history entries simply stops receiving new ones after rollback; existing ones already delivered are not retracted, which is the expected, accepted behavior of an event stream (no retroactive un-send).
- [ ] **Step 3.4: Fix the rollback/re-enable asymmetry (per review, round 19 — a real data-loss scenario, not just a documentation gap):** confirmed by tracing the actual read/write paths: while `workflow_id` is cleared (rolled back), Task 5's `StatusField` read-only guard also un-gates (it's keyed on "has a published definition"), so users can once again freely edit `x_opencti_workflow_id` directly — and since Task 8's sync also no-ops without a published definition, those edits are **not** reflected into `WorkflowInstance.currentState`, which goes stale. If `workflow_id` is later re-set (re-enabling the same type), the **next read** of an affected entity triggers Task 2's read-repair, which treats `currentState` as authoritative and unconditionally overwrites `x_opencti_workflow_id` back to match it — **silently discarding the legitimate edit made during the rollback window**, with no diff/merge and no warning. This is asymmetric with Task 8's own external-write handling (which treats a direct `Status` write as authoritative, the opposite direction), and it only manifests via a plain read racing ahead of any write-triggered sync. **Fix, required before Task 6's canary rollout guidance can be trusted operationally:** on re-enabling `workflow_id` for a previously-rolled-back entity type, run a one-time reconciliation pass (not a full migration) over entities of that type whose `x_opencti_workflow_id`-bearing attribute was modified more recently than their `WorkflowInstance`'s last update — for exactly those entities, invoke Task 8's `syncWorkflowInstanceFromExternalWrite` logic (Status-write-wins direction) once, instead of allowing the next ordinary read to invoke Task 2's read-repair (instance-wins direction) on them. Entities untouched during the rollback window are unaffected either way and need no special handling. Add an integration test: roll back, edit `x_opencti_workflow_id` on an entity directly, re-enable, read the entity, and assert the manual edit survives (is reflected into `WorkflowInstance.currentState`), not overwritten.
- [ ] **Step 3.5: Add a throughput/latency benchmark gate before migrating any high-cardinality type (per review, round 19 — no prior task quantifies this, only qualitatively flags "extra cost" in Global Constraints):** Task 3's `runPostEntityCreationHooks` runs synchronously inside `createEntity`'s hot path, adding one extra store round-trip per entity creation. For bulk STIX-bundle ingestion (workers/connectors creating thousands of entities per batch), this multiplies across the whole batch. Before migrating a representative high-cardinality type (Indicators or Observables), run an ingestion-throughput benchmark comparing bulk-import duration before/after that type's migration (reuse existing worker/connector bulk-import test fixtures if available), and record the result as part of that type's canary observation window (Step 3.3) alongside read-repair/event-volume metrics — not left as a purely qualitative cost callout.
- [ ] **Step 4: Commit**
  ```bash
  git add opencti-platform/opencti-graphql/src/modules/workflow/migration/ opencti-platform/opencti-graphql/src/migrations/ opencti-platform/opencti-graphql/src/modules/workflow/api/workflow-resolvers.ts opencti-platform/opencti-graphql/tests/01-unit/modules/status-to-definition-converter-test.ts
  git commit -m "feat(workflow): add Status-to-WorkflowDefinition conversion, preview query, and migration"
  ```

---

## Task 7: Request access dual workflows

**Capability:** `workflow-request-access` (tasks.md group 7)

> **Correction from review (high):** `EntitySetting` already has a
> `request_access_workflow` object (`RequestAccessFlow`: `approved_workflow_id`,
> `declined_workflow_id`, `approval_admin`) used extensively in
> `requestAccess-domain.ts` — this is the existing mechanism that directly
> writes a target `Status` id when an RFI is approved/declined. Do **not**
> introduce a new top-level `request_access_workflow_id` scalar; it would be
> a parallel, confusingly-named source of truth. Instead, add a new field
> **inside** the existing `RequestAccessFlow` object/type, e.g.
> `workflow_definition_id`, to hold the reference to the dedicated
> `request_access` `WorkflowDefinition`. Note that once Task 8 lands, the
> existing `approved_workflow_id`/`declined_workflow_id` direct writes will
> already flow through the external-state-jump sync — so re-validate with a
> maintainer whether this Task is still needed as a separate `WorkflowDefinition`
> selection mechanism, or whether Task 8's generic sync makes it redundant
> (the RFI approve/decline flow may not need its own definition if direct
> writes already reconcile into whatever definition is standard for the type).

**Files:**
- Modify: `opencti-platform/opencti-graphql/src/modules/requestAccess/requestAccess-domain.ts` (existing `x_opencti_workflow_id`/status-setting code around line 426, and `RequestAccessFlow` usage around lines 118-346)
- Modify: `opencti-platform/opencti-graphql/src/modules/entitySetting/entitySetting-types.ts` (extend `RequestAccessFlow` interface with `workflow_definition_id?: string`)
- Modify: `opencti-platform/opencti-graphql/src/modules/requestAccess/requestAccess.graphql` (add `workflow_definition_id: String` alongside existing `approved_workflow_id`/`declined_workflow_id`)
- Modify: `opencti-platform/opencti-graphql/src/modules/workflow/domain/workflow-domain.ts` (`getWorkflowConfig`/`getDefinitionData` to accept a scope parameter)
- Test: `opencti-platform/opencti-graphql/tests/01-unit/modules/workflow-domain-test.ts`

**Interfaces:**
- Consumes: existing `getWorkflowConfig(context, user, targetType)`, existing `RequestAccessFlow` type.
- Produces: `getWorkflowConfig(context, user, targetType, { scope: 'request_access' | 'standard' })` — extends the existing signature with an optional scope parameter, defaulting to `'standard'`.

- [ ] **Step 0: Determine per-type applicability, not a blanket skip (corrected per review, round 18 — the previous "default to skip" framing was wrong: `getWorkflowConfig`/`getDefinitionData` has no scope parameter without this task, confirmed by reading `workflow-domain.ts`, so Task 8's "generic sync already reconciles it" reasoning does not hold).** For each migrated entity type, check Task 6's `workflowMigrationPreview`/`byScope` output: if that type has **no** `request_access`-scoped `Status` data, this task's Steps 1-3 are genuinely inapplicable for that type (nothing to route) — skip only for that type, and note it in the migration's rollout checklist. If the type **does** have `request_access`-scoped `Status` data (confirmed today for `CaseRfi` via `requestAccess-domain.ts`), Steps 1.1-2.3 below are a **mandatory prerequisite**, not an optional enhancement — implement them before or alongside Task 6's migration for that type (see Task 6 Step 3.1's corrected ordering note).
- [ ] **Step 1.1: Write failing test** — entity type with both a standard and `request_access` workflow definition; creating an entity within `request_access` scope initializes against the `request_access` definition.
- [ ] **Step 1.2: Add `workflow_definition_id`** to the existing `RequestAccessFlow` type/schema (not a new top-level field).
- [ ] **Step 1.3: Extend `getWorkflowConfig`/`getDefinitionData`** to accept a scope and look up the corresponding field.
- [ ] **Step 1.4: Wire scope detection** at entity-creation time in `requestAccess-domain.ts` into `initializeEntityWorkflow`'s call to `getWorkflowConfig`.
- [ ] **Step 1.5: Run test to verify pass**
- [ ] **Step 2.1: Write failing test — fallback to standard definition** when no `workflow_definition_id` is configured in `RequestAccessFlow`.
- [ ] **Step 2.2: Implement fallback** in `getWorkflowConfig`.
- [ ] **Step 2.3: Run test to verify pass**
- [ ] **Step 3: Commit**
  ```bash
  git add opencti-platform/opencti-graphql/src/modules/requestAccess/ opencti-platform/opencti-graphql/src/modules/workflow/ opencti-platform/opencti-graphql/src/modules/entitySetting/entitySetting-types.ts opencti-platform/opencti-graphql/tests/01-unit/modules/workflow-domain-test.ts
  git commit -m "feat(workflow): support dual workflow definitions for request_access scope"
  ```

---

## Task 8: Concurrent/direct status writers

**Capability:** `workflow-concurrent-writers` (tasks.md group 8)

> **Correction from review (high):** the previous draft of this task cited
> `middleware.ts:932`/`979` as the write-path hook — those lines are actually
> inside distribution/aggregation code (`field === 'x_opencti_workflow_id'`
> used to decide how to bucket aggregation results), not an attribute-write
> interceptor. The real generic write entry point is
> `updateAttribute` (`middleware.ts:2981`). More importantly: **Task 2's own
> projection write and this task's external-write listener both touch
> `x_opencti_workflow_id`**, which risks a feedback loop (transition → project
> write → Task 8 sees the write → treats it as "external" → re-syncs the
> instance → could re-trigger projection). This task MUST include an explicit
> anti-loop marker (e.g. an internal option flag passed to `updateAttribute`
> such as `{ workflowInternalWrite: true }`, checked and stripped before the
> external-sync listener runs) and an idempotence contract: syncing from an
> already-consistent state is a no-op (see Step 2 below).
>
> **Reintroduced-cycle correction (per review):** the previous draft of this
> task still had `middleware.ts` calling `syncWorkflowInstanceFromExternalWrite`
> directly from `workflow-domain.ts` — but `workflow-domain.ts` already
> imports `createEntity`/`updateAttribute`/`createRelation`/`loadEntity` from
> `middleware.ts` (confirmed at the top of that file), so this reintroduces
> exactly the cycle Task 3 was designed to avoid. **Fix: reuse Task 3's
> decoupled hook registry**, extended with a second hook kind
> (`registerPostAttributeUpdateHook`/`runPostAttributeUpdateHooks` in the
> same `entity-lifecycle-hooks.ts`, or a sibling file with the same
> zero-feature-imports property), so `middleware.ts` only ever depends on
> that tiny registry file, never on `workflow-domain.ts`.

> **Unmapped-status write policy (per review, previously undefined):** when a
> direct write sets `x_opencti_workflow_id` to a `Status` that has **no**
> corresponding state in the entity's current published `WorkflowDefinition`
> (e.g. a stale/orphaned `Status`, or one belonging to a different
> entity-type/scope combination), the system SHALL **not** guess a "nearest"
> state and SHALL **not** reject the write. Instead: keep the `Status` write
> as-is (tolerant mode is preserved), leave `WorkflowInstance.currentState`
> unchanged, and record a `pendingError`-style diagnostic (reusing the
> existing `pendingError` field pattern already on `WorkflowInstance`) so the
> divergence is visible rather than silent. This must be covered by an
> explicit test (Step 3 below).

**Files:**
- Modify: `opencti-platform/opencti-graphql/src/modules/workflow/domain/workflow-domain.ts` (add external-sync hook near projection code from Task 2; register it via the shared registry, not a direct middleware import)
- Modify: `opencti-platform/opencti-graphql/src/database/entity-lifecycle-hooks.ts` (add `registerPostAttributeUpdateHook`/`runPostAttributeUpdateHooks`, same zero-feature-import property as the Task 3 registry)
- Modify: `opencti-platform/opencti-graphql/src/database/middleware.ts` (`updateAttribute`, `middleware.ts:2981` — add the internal-write marker option, and call `runPostAttributeUpdateHooks` when the marker is absent, importing only the registry file)
- Test: `opencti-platform/opencti-graphql/tests/01-unit/modules/workflow-domain-test.ts`
- Test: `opencti-platform/opencti-graphql/tests/01-unit/database/entity-lifecycle-hooks-test.ts`

**Interfaces:**
- Produces: `syncWorkflowInstanceFromExternalWrite(context, entity, newStatusId): Promise<void>` — registered into the shared hook registry by `workflow-domain.ts`, invoked generically by `middleware.ts` for any attribute update matching `x_opencti_workflow_id` (playbooks' `manipulate-knowledge-component.ts`, `requestAccess-domain.ts`, public API attribute update path, sync manager all go through `updateAttribute`, so no per-caller wiring is needed), but **not** called when the write originates from Task 2's own projection (marked internal). Like `projectWorkflowState`, this reads `scope` from the existing `WorkflowInstance.scope` field (Task 2, Step 0) rather than re-deriving it, and runs any resulting instance update under `WORKFLOW_MANAGER_USER` (same execution-identity rule as Task 2's read-repair), not the caller who made the direct write.

- [ ] **Step 0.1: Write failing test — gated by published workflow existence**
  - `syncWorkflowInstanceFromExternalWrite` is not called (and the hook in `updateAttribute` no-ops) for an entity whose type has no published `WorkflowDefinition`, regardless of `ENTITIES_WORKFLOW` flag state — confirms this task's gating is by workflow existence, not the UI flag (see Global Constraints).
- [ ] **Step 0.2: Write failing test — no feedback loop**
  - Task 2's `projectWorkflowState` calls `updateAttribute` with the internal-write marker set; assert `syncWorkflowInstanceFromExternalWrite` is never invoked for that write.
- [ ] **Step 0.3: Add the internal-write marker option** to `updateAttribute`'s options parameter.
- [ ] **Step 0.4: Extend the shared registry** (`entity-lifecycle-hooks.ts`) with `registerPostAttributeUpdateHook`/`runPostAttributeUpdateHooks`; wire `runPostAttributeUpdateHooks` into `updateAttribute`, gated on the internal-write marker being absent and the field being `x_opencti_workflow_id`.
- [ ] **Step 0.5: Register `syncWorkflowInstanceFromExternalWrite`** into the registry from `workflow-domain.ts`, following the same bootstrap-order guarantee established in Task 3 (Step 1.4).
- [ ] **Step 0.6: Implement the published-workflow-existence gate** as the first check inside `syncWorkflowInstanceFromExternalWrite` (reuse `getWorkflowConfig`/`getDefinitionData`'s existing no-op pattern).
- [ ] **Step 0.7: Run tests to verify pass**
- [ ] **Step 1.1: Write failing test** — a direct write of `x_opencti_workflow_id` (without the internal marker) to a `Status` mapped to a different state than the current `WorkflowInstance.currentState` updates the instance and appends an `event_external` history entry.
- [ ] **Step 1.2: Implement `syncWorkflowInstanceFromExternalWrite`** in `workflow-domain.ts`, reusing the state↔status mapping from Task 1/2.
- [ ] **Step 1.3: Verify the hook wiring from Step 0.4/0.5 reaches this function** for a real `updateAttribute` call (no direct import needed beyond the registry).
- [ ] **Step 1.4: Run test to verify pass**
- [ ] **Step 2.1: Write failing test — no-op when status unchanged** (direct write to the already-current mapped status records no new history entry, and is idempotent under repeated calls).
- [ ] **Step 2.2: Implement the no-op guard** in `syncWorkflowInstanceFromExternalWrite`.
- [ ] **Step 2.3: Run test to verify pass**
- [ ] **Step 3.1: Write failing test — unmapped status write**
  - A direct write sets `x_opencti_workflow_id` to a `Status` with no matching state in the current published `WorkflowDefinition` for that entity type/scope; assert the write succeeds, `currentState` is unchanged, and a `pendingError`-style diagnostic is recorded.
- [ ] **Step 3.2: Implement the unmapped-write policy** per the note above.
- [ ] **Step 3.3: Run test to verify pass**
- [ ] **Step 3.4: Write-path audit (per review, previously missing)**: `updateAttribute` is the primary write path, but it is not the *only* one. Grep the codebase for other paths that can mutate `x_opencti_workflow_id` outside `updateAttribute` (e.g. bulk/batch ES update helpers, versioned migrations that write directly via `internalCreateEntityRaw`/raw ES calls, background-task bulk operations). **Confirmed example (per review):** `requestAccess-domain.ts`'s `x_opencti_workflow_id: firstStatus.id` is set directly inside the `CaseRfiAddInput` passed to `addCaseRfi` at **creation** time, not via a subsequent `updateAttribute` call \u2014 this bypasses both Task 3's eager-creation hook (which runs for the RFI entity itself and would project the *workflow's* initial state, not this directly-chosen `firstStatus`) and Task 8's `updateAttribute` hook. Resolve explicitly: either call `syncWorkflowInstanceFromExternalWrite` directly from `requestAccess-domain.ts` right after this creation (treating it the same as any other direct write), or document it as an intentional exclusion with rationale. For each other path found, either route it through `updateAttribute` (preferred) or explicitly document it as an intentional exclusion from sync (with rationale) in this file. Do not leave this open-ended \u2014 the audit result (list of paths + decision per path) must be recorded as a comment in `syncWorkflowInstanceFromExternalWrite`'s implementation.
- [ ] **Step 3.4b: Note the interaction with the existing pre-persistence type filter (per review, round 20, clarifying \u2014 confirmed by reading code, not a new bug):** `middleware.ts`'s `prepareAttributesForUpdate` already silently drops (`return null`) any `x_opencti_workflow_id` write whose value isn't a `Status` of the entity's `entity_type` \u2014 but this existing filter checks **type only, not scope** (`platformStatuses.filter((status) => status.type === instance.entity_type)`). A write of the correct type but wrong scope (e.g. a `request_access`-scoped `Status` id on an entity whose `WorkflowInstance.scope` is `'standard'`) passes this pre-existing gate unmodified and reaches this task's scope-aware sync hook, which is exactly where it belongs: `syncWorkflowInstanceFromExternalWrite`'s (type, scope, state) mapping lookup will find no matching state and correctly falls into the unmapped-write policy above (pendingError, no guess). No fix is needed here \u2014 this note exists so a future implementer doesn't mistake the pre-existing type-only filter for a scope-aware guard, or attempt to duplicate scope-checking logic into `prepareAttributesForUpdate` that already lives correctly in this task's sync hook.
- [ ] **Step 4: Commit**
  ```bash
  git add opencti-platform/opencti-graphql/src/modules/workflow/ opencti-platform/opencti-graphql/src/database/middleware.ts opencti-platform/opencti-graphql/src/database/entity-lifecycle-hooks.ts opencti-platform/opencti-graphql/tests/01-unit/modules/workflow-domain-test.ts opencti-platform/opencti-graphql/tests/01-unit/database/entity-lifecycle-hooks-test.ts
  git commit -m "feat(workflow): sync WorkflowInstance state on direct Status writes via decoupled hook"
  ```
- [ ] **Step 5: History blob pruning (per review, no cap existed anywhere in this plan)**: `WorkflowInstance.history` is one JSON-serialized array rewritten wholesale on every event, including every `event_external` entry Task 8 appends on routine connector re-writes of `x_opencti_workflow_id` — a hot entity touched repeatedly by connectors can accumulate an ever-growing, ever-rewritten blob. Add a cap (e.g. keep the last N entries, or entries within the last M days, configurable) applied when appending, not as a separate cleanup job. Write a test asserting history length is bounded after exceeding the cap. **Deeper concern flagged, not fully resolved by the cap (per review, round 15):** a size cap bounds the blob's size but not the write-frequency cost — a monolithic array rewritten wholesale on every touch means a full-document reindex per status flip, regardless of history length. For entity types with high-frequency status changes (e.g. playbook/enrichment-driven), flag to a maintainer whether an append-only substore (e.g. a separate small entity per history entry, or a capped/rolling external log) is needed instead of a single rewritten array before this is used at scale — do not silently assume the size cap alone solves the performance concern.

---

## Task 9: Transition & bypass UI

**Capability:** `workflow-transition-actions` (tasks.md group 9)

> **Correction from review (high):** this task conflated two distinct
> operations. Freeze the API contract before implementing:
> - **`triggerWorkflowEvent(entityId, eventName)`** (existing) — fires a
>   named transition edge; validated against `allowedTransitions`; always
>   runs onExit/onEnter/history exactly as today. Used by "apply-transition"
>   (Step 1 below).
> - **New: a direct status-set operation**, e.g.
>   `setWorkflowStatus(entityId, targetStatusId, applyTransitionActions:
>   boolean)` — used by the "bypass update" popover, which lets a user pick
>   *any* target status, not necessarily one reachable via a defined
>   transition edge. This does **not** go through `triggerWorkflowEvent`'s
>   `allowedTransitions` validation (bypass = intentionally skip enforced
>   ordering). When `applyTransitionActions` is true, it still runs **only**
>   the current state's onExit and target state's onEnter actions-on-status
>   (never edge-level actions-on-transition, since bypass has no edge); when
>   false, it only updates `currentState`/projection and records a distinct
>   history event (e.g. `event_bypass`), never `event_external` (reserved
>   for Task 8's non-workflow-engine writes).
>
> **Action-scope clarification (per review):** per this change's own EE
> scoping (actions-on-**transition**, edge-level, vs. actions-on-**status**,
> state-level onEnter/onExit — both already distinguished in this project's
> product notes), bypass mode has no edge, so it can only ever run
> state-level actions-on-status (onEnter of the target state, onExit of the
> current state). It never runs edge-specific actions-on-transition, since
> those are only defined for a specific transition edge that bypass mode, by
> definition, does not traverse. State this explicitly in the UI copy/tooltip
> so admins aren't surprised that transition-specific automations don't fire.

> Before implementing, re-run `writing-plans` scoped to this task after
> reading `WorkflowTransitions.tsx` and the entity-view action bar
> components in full — only partially explored during this planning pass.

**Files:**
- Modify: `opencti-platform/opencti-front/src/private/components/common/workflow/WorkflowTransitions.tsx`
- Create: bypass-update popover component alongside it
- Modify: `opencti-platform/opencti-graphql/src/modules/workflow/domain/workflow-domain.ts` (new `setWorkflowStatus` function, separate from `triggerWorkflowEvent`)
- Modify: workflow `.graphql` schema (new `setWorkflowStatus` mutation, distinct from `triggerWorkflowEvent`)
- Test: `WorkflowTransitions.test.tsx`, backend resolver tests

- [ ] **Step 1: Add apply-transition action** to the entity view with pending/error UI states, reusing `WorkflowTransitions.tsx` patterns from `DraftWorkspace`, calling the existing `triggerWorkflowEvent`.
- [ ] **Step 2: Ensure `WorkflowInstance` is created on first transition apply** if only legacy `Status` exists (reuses Task 3's `ensureWorkflowInstance`).
- [ ] **Step 3: Add bypass-update popover** with the two modes (status-only vs. status+transition actions), calling the new `setWorkflowStatus` mutation.
- [ ] **Step 4: Implement `setWorkflowStatus`** in `workflow-domain.ts` per the frozen contract above (no `allowedTransitions` check; `applyTransitionActions` toggles onExit/onEnter; `event_bypass` history entries). **RBAC (frozen per review):** gate the new `setWorkflowStatus` mutation with `@auth(for: [KNOWLEDGE_KNUPDATE])`, matching the existing `triggerWorkflowEvent` mutation \u2014 this is a knowledge-edit action available to any user who can already edit the entity, not an admin-only operation.
- [ ] **Step 5: Frontend + backend tests** for pending/error states and both update modes, including a test that `setWorkflowStatus` does not require an allowed transition edge.
- [ ] **Step 6: Commit**
  ```bash
  git add opencti-platform/opencti-front/src/private/components/common/workflow/ opencti-platform/opencti-graphql/src/modules/workflow/
  git commit -m "feat(workflow): add apply-transition action and bypass-update modes"
  ```

---

## Task 10: Mass operations

**Capability:** `workflow-transition-actions` (tasks.md group 10)

> Before implementing, re-run `writing-plans` scoped to this task after
> reading the existing background-task and playbook status-action
> implementations in full.

**Files:**
- Modify: mass-operation background task handler (locate existing bulk status-update task type)
- Modify: `opencti-platform/opencti-graphql/src/modules/playbook/components/manipulate-knowledge-component.ts` (existing status-writing component)
- Test: relevant unit/integration suites for background tasks and playbook components

- [ ] **Step 1: Add the two update modes to the mass-operation background task** (reusing the `applyTransitionActions` parameter from Task 9).
- [ ] **Step 2: Add the two update modes to the playbook status action** in `manipulate-knowledge-component.ts`.
- [ ] **Step 3: Unit/integration tests** for mass operation and playbook mode selection.
- [ ] **Step 4: Commit**
  ```bash
  git add opencti-platform/opencti-graphql/src/modules/playbook/ opencti-platform/opencti-graphql/tests/
  git commit -m "feat(workflow): support bypass update modes in mass operations and playbooks"
  ```

---

## Task 11: Closing reason

**Capability:** `workflow-closing-reason` (tasks.md group 11)

> Before implementing, re-run `writing-plans` scoped to this task after
> reading the existing comments backend/UI implementation in full to mirror
> its exact storage pattern.

**Files:**
- Create: closing-reason backend module modeled on the comments implementation
- Create: closing-reason UI component, separate from comments UI
- Test: unit/frontend tests for setting and displaying a closing reason

- [ ] **Step 1: Implement closing-reason backend storage**, modeled on the existing comments implementation (same relationship/attachment pattern).
- [ ] **Step 2: Add dedicated closing-reason UI**, separate from the comments section.
- [ ] **Step 3: Wire closing-reason capture into the closing transition flow** (entities transitioning into a closing state can supply a reason).
- [ ] **Step 4: Unit/frontend tests** for setting and displaying a closing reason.
- [ ] **Step 5: Commit**
  ```bash
  git commit -m "feat(workflow): add closing reason field with dedicated UI"
  ```

---

## Task 12: Frontend status unification

**Capability:** `workflow-entity-extension` (tasks.md group 12) — depends on Tasks 1-5 being live

**Files:**
- Modify: `opencti-platform/opencti-front/src/components/dataTableUtils.tsx`
- Modify: `opencti-platform/opencti-front/src/components/dataTableUtils.test.tsx`
- Modify: corresponding Status filter definition files

> Before implementing, re-run `writing-plans` scoped to this task after
> reading the current dual-column implementation in `dataTableUtils.tsx`
> in full.

- [ ] **Step 1: Merge the `workflowInstance` and `x_opencti_workflow_id` Status columns** into a single column definition.
- [ ] **Step 2: Keep the `initial-` id fallback check only as a transitional safety net**, documented as such in a one-line comment.
- [ ] **Step 3: Merge the corresponding Status filter definitions** into a single UI filter option.
- [ ] **Step 4: Update `dataTableUtils.test.tsx` and related filter tests** for the merged column/filter.
- [ ] **Step 5: Commit**
  ```bash
  git add opencti-platform/opencti-front/src/components/dataTableUtils.tsx opencti-platform/opencti-front/src/components/dataTableUtils.test.tsx
  git commit -m "feat(workflow): unify Status column and filter across workflowInstance and legacy status"
  ```

---

## Task 13: Non-regression & rollout verification

**Depends on:** all previous tasks

- [ ] **Step 1: Run the migration preview query** (Task 6) against production-like/staging data; share results with the PO for validation.
- [ ] **Step 2: Run full non-regression suite** confirming sorting/filtering/widgets are unchanged for entity types without a configured workflow.
- [ ] **Step 3: Verify stream/history/notification event shapes** are unchanged after projection writes (compare event payloads before/after Task 2).
- [ ] **Step 4: Verify EE gating**: RBAC transition restriction and on-transition/on-status actions are rejected/hidden without an Enterprise Edition license, matching `checkEnterpriseEdition` usage already present for `DraftWorkspace`.
- [ ] **Step 5: Accept explicit event-cardinality criteria** (process note from review): a workflow transition now emits at least two update events (instance update, projected status update) instead of one. Document this as an accepted, intentional change in cardinality/ordering (instance event before projection event, per the fixed write order), and validate against any known downstream stream consumers that assume one-update-per-transition before enabling `ENTITIES_WORKFLOW` broadly.
- [ ] **Step 5.1: Event-type semantic compatibility check** (per review): cardinality is not the only change \u2014 this plan introduces new history/event categories (`event_external` from Task 8, `event_bypass` from Task 9) alongside the existing engine-driven transition events. Verify with known downstream consumers that they either ignore unrecognized event/history-type values gracefully, or explicitly extend their parsing to recognize `event_external`/`event_bypass` \u2014 a consumer that switches on a closed enum of event types could misclassify or drop these before this is validated.
- [ ] **Step 6: Commit** (if any fixes were needed during verification)
  ```bash
  git commit -m "test(workflow): non-regression and EE-gating verification for workflow engine rollout"
  ```
