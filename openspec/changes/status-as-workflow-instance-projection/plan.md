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
widget/stream consumers keep working unchanged, with no bulk entity
migration.

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

- Single feature flag `ENTITIES_WORKFLOW` gates all backend wiring + UI for
  entity types other than `DraftWorkspace`, until every phase is
  production-ready.
- No mass entity-document migration: `WorkflowInstance` is created eagerly
  on new entities and lazily backfilled on first read for existing ones.
- Projection writes MUST use the normal attribute-patch flow
  (`updateAttribute`/equivalent), never a direct ES write, so stream/
  history/notifications are unaffected.
- Fixed write order: `WorkflowInstance.currentState` persisted before the
  projected `x_opencti_workflow_id` is updated.
- Statuses referenced by a published `WorkflowDefinition` cannot be
  deleted; orphaned ones are deleted on republish once unreferenced by any
  entity or state.
- EE gating: RBAC transition restriction and automated on-transition/
  on-status actions require Enterprise Edition, matching `DraftWorkspace`
  precedent; core enforced-ordering mechanics are Community Edition.
- Phase 1.1 (state ordering + full mapping invariant) is blocking for all
  later phases.

---

## Task 1: Workflow state ordering & full mapping invariant (blocking)

**Capability:** `workflow-status-projection` (tasks.md group 1)

**Files:**
- Modify: `opencti-platform/opencti-graphql/src/modules/workflow/types/workflow-types.ts` (add `order` to state type)
- Modify: `opencti-platform/opencti-graphql/src/modules/workflow/domain/workflow-domain.ts` (publish/republish flow — see `publishWorkflowDefinition` and `getDefinitionData` already in this file)
- Modify: `opencti-platform/opencti-graphql/src/modules/workflow/workflow-validation.ts` (deletion guard for `Status`/`StatusTemplate`)
- Create: `opencti-platform/opencti-graphql/src/modules/workflow/domain/workflow-ordering.ts` (topological + manual-order computation)
- Test: `opencti-platform/opencti-graphql/tests/01-unit/modules/workflow-ordering-test.ts`
- Test: `opencti-platform/opencti-graphql/tests/01-unit/modules/workflow-domain-test.ts` (publish invariant + deletion guard cases)

**Interfaces:**
- Produces: `computeStateOrder(definitionData): Map<stateId, order>` — used by Task 2's projection function and by frontend sort display.
- Produces: `ensureFullStatusMapping(context, user, entitySetting, definitionData): Promise<void>` — called from `publishWorkflowDefinition`.
- Consumes: existing `getWorkflowConfig`, `getDefinitionData`, `publishWorkflowDefinition` from `workflow-domain.ts`.

- [ ] **Step 1.1: Add `order` field to workflow state schema/types**
  - Add `order?: number` to the state definition type in `workflow-types.ts`.
  - Add a GraphQL schema field `order: Int` on the workflow state type in the workflow `.graphql` file.
- [ ] **Step 1.2: Write failing unit tests for topological ordering**
  - In `workflow-ordering-test.ts`, test that a linear chain `open → in_progress → resolved → closed` yields orders `0,1,2,3`.
  - Test a branching-but-convergent graph still yields a valid unambiguous order.
  - Test a graph with ambiguous parallel branches returns `null`/needs-manual-order signal.
- [ ] **Step 1.3: Run tests to verify failure** — `yarn workspace opencti-graphql vitest run tests/01-unit/modules/workflow-ordering-test.ts`
- [ ] **Step 1.4: Implement `computeStateOrder`** in `workflow-ordering.ts`: BFS/topological sort from `definitionData.initialState` counting minimum transitions; return `null` when ambiguous.
- [ ] **Step 1.5: Run tests to verify pass**
- [ ] **Step 2.1: Write failing test for manual-order fallback**
  - When `computeStateOrder` returns `null`, verify the system falls back to a manually supplied `order` field per state.
- [ ] **Step 2.2: Implement fallback**: in the publish path, if topological ordering is ambiguous, require/read the manual `order` values already stored on each state.
- [ ] **Step 2.3: Run tests to verify pass**
- [ ] **Step 3.1: Write failing test for full-mapping creation on publish**
  - Given a `WorkflowDefinition` with 3 states and an attached entity type with only 1 existing `Status`, publishing creates the 2 missing `Status` records (one per missing state).
- [ ] **Step 3.2: Implement `ensureFullStatusMapping`**: for each attached entity type, diff states vs. existing `Status` records (by template/state id), create missing ones via existing `createEntity`-based `Status` creation path.
- [ ] **Step 3.3: Wire `ensureFullStatusMapping` into `publishWorkflowDefinition`** (before it marks the definition published).
- [ ] **Step 3.4: Run tests to verify pass**
- [ ] **Step 4.1: Write failing test for orphan deletion on republish**
  - A state removed from a new published version whose mapped `Status` has no entity referencing it and no other state mapping to it gets deleted.
- [ ] **Step 4.2: Implement orphan detection + deletion** in the republish path: unreferenced = no entity `x_opencti_workflow_id` points to it AND no state in the new definition maps to it.
- [ ] **Step 4.3: Run tests to verify pass**
- [ ] **Step 5.1: Write failing test — no Status changes on draft save**
  - Saving an unpublished draft version of a `WorkflowDefinition` must not call `ensureFullStatusMapping` or the deletion path.
- [ ] **Step 5.2: Verify/guard**: confirm the draft-save code path (`setWorkflowDefinition` with draft target) does not invoke the publish-only functions above.
- [ ] **Step 5.3: Run tests to verify pass**
- [ ] **Step 6.1: Write failing test for deletion guard**
  - Attempting to delete a `Status`/`StatusTemplate` referenced by a published `WorkflowDefinition` throws a `FunctionalError`.
- [ ] **Step 6.2: Implement guard** in `workflow-validation.ts` (or the Status/StatusTemplate delete domain function): check for references before allowing deletion.
- [ ] **Step 6.3: Run tests to verify pass**
- [ ] **Step 7: Commit**
  ```bash
  git add opencti-platform/opencti-graphql/src/modules/workflow/
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
- Consumes: `computeStateOrder`/state→`Status` mapping built in Task 1.
- Produces: `projectWorkflowState(context, user, entity, stateId): Promise<void>` — called from both the sync transition path (`triggerWorkflowEvent`) and the async completion path.

- [ ] **Step 1.1: Write failing unit test for projection function**
  - `projectWorkflowState` given an entity and a target state id calls `updateAttribute` with `x_opencti_workflow_id` set to the mapped `Status` id.
- [ ] **Step 1.2: Implement `projectWorkflowState`** in `workflow-projection.ts` using the existing `updateAttribute` middleware (same one used elsewhere in `workflow-domain.ts`).
- [ ] **Step 1.3: Run test to verify pass**
- [ ] **Step 2.1: Write failing test — sync transition calls projection after instance update**
  - Assert `updateAttribute` (instance) is called, then `projectWorkflowState`, in that order, using a mock/spy.
- [ ] **Step 2.2: Wire `projectWorkflowState` into `triggerWorkflowEvent`** immediately after `history` is updated (existing code around `{ key: 'history', value: [...] }` update in `workflow-domain.ts`).
- [ ] **Step 2.3: Run test to verify pass**
- [ ] **Step 3.1: Write failing test — async completion calls projection**
- [ ] **Step 3.2: Wire `projectWorkflowState` into the async completion handler** (`workflow-async-completion.ts`).
- [ ] **Step 3.3: Run test to verify pass**
- [ ] **Step 4.1: Write failing test for read-repair**
  - `getWorkflowInstance` given an entity whose `x_opencti_workflow_id` doesn't match the `Status` mapped to `currentState` triggers a projection correction before returning.
- [ ] **Step 4.2: Implement read-repair** inside `getWorkflowInstance` (existing function in `workflow-domain.ts`), calling `projectWorkflowState` when divergence detected.
- [ ] **Step 4.3: Run test to verify pass**
- [ ] **Step 5.1: Write integration test** — extend `tests/03-integration/02-resolvers/workflow-test.ts`: trigger a real workflow event and assert both `workflowInstance.currentState` and the entity's `status`/`x_opencti_workflow_id` reflect the new state, and a stream update event is emitted.
- [ ] **Step 5.2: Run integration tests** — `yarn workspace opencti-graphql test:integration -- workflow-test`
- [ ] **Step 6: Commit**
  ```bash
  git add opencti-platform/opencti-graphql/src/modules/workflow/
  git commit -m "feat(workflow): project WorkflowInstance state onto legacy Status field"
  ```

---

## Task 3: Eager instance creation & lazy backfill

**Capability:** `workflow-entity-extension` (tasks.md group 3)

**Files:**
- Modify: `opencti-platform/opencti-graphql/src/modules/workflow/domain/workflow-domain.ts` (`initializeEntityWorkflow`, `getWorkflowInstance`, `ensureWorkflowInstance` already exist here)
- Modify: generic entity-creation path — locate the shared `createEntity`/domain "add" pipeline that currently stamps legacy status (likely `database/middleware.ts` or a shared `domain/` helper); wire `initializeEntityWorkflow` there instead of per-module (as done today only in `draftWorkspace-resolvers.ts`)
- Test: `opencti-platform/opencti-graphql/tests/01-unit/modules/workflow-domain-test.ts`

**Interfaces:**
- Consumes: existing `initializeEntityWorkflow(context, user, entity)`, `getWorkflowInstance`, `ensureWorkflowInstance` (all already implemented in `workflow-domain.ts` for `DraftWorkspace` today).
- Produces: no new public interface — behavior change only (generalizes existing functions to run for all entity types).

- [ ] **Step 1.1: Write failing test — eager creation on generic entity add**
  - Create an entity of a type with a published workflow through the generic creation path (not `draftWorkspaceAdd`); assert a real `WorkflowInstance` exists immediately (not an `initial-...` id).
- [ ] **Step 1.2: Locate the single shared entity-creation call site** where legacy status is stamped (search for where `x_opencti_workflow_id` default/`Status` default is set at creation).
- [ ] **Step 1.3: Wire `initializeEntityWorkflow(context, user, createdEntity)`** into that shared call site, removing the need for each module (e.g. `draftWorkspace-resolvers.ts`) to call it individually — keep the draft-workspace call for backward compatibility during rollout if the shared path isn't reached for drafts.
- [ ] **Step 1.4: Run test to verify pass**
- [ ] **Step 2.1: Write failing test — lazy backfill on first read**
  - `getWorkflowInstance` for a pre-existing entity (created before this change, no `WorkflowInstance` row) with a published workflow persists a real instance and returns it.
- [ ] **Step 2.2: Modify `getWorkflowInstance`** to call `ensureWorkflowInstance` (already defined in this file, currently only used by `triggerWorkflowEvent`) instead of only computing `id: \`initial-${effectiveEntityId}\`` in memory.
- [ ] **Step 2.3: Run test to verify pass**
- [ ] **Step 3.1: Write failing test — idempotent backfill**
  - Calling `getWorkflowInstance` twice in a row for the same entity creates exactly one `WorkflowInstance`.
- [ ] **Step 3.2: Verify** `ensureWorkflowInstance`'s existing `findWorkflowInstanceEntity` early-return handles this (it already does per current code); add regression test only.
- [ ] **Step 3.3: Run test to verify pass**
- [ ] **Step 4: Commit**
  ```bash
  git add opencti-platform/opencti-graphql/src/modules/workflow/
  git commit -m "feat(workflow): generalize eager creation and lazy backfill to all entity types"
  ```

---

## Task 4: Generalized filtering

**Capability:** `workflow-entity-extension` (tasks.md group 4)

**Files:**
- Modify: `opencti-platform/opencti-graphql/src/utils/filtering/filtering-completeSpecialFilterKeys.ts`
- Modify: `opencti-platform/opencti-graphql/src/modules/draftWorkspace/draftWorkspace-domain.ts` (remove/redirect `resolveWorkflowInstanceStatusFilter`, currently defined here)
- Test: `opencti-platform/opencti-graphql/tests/01-unit/domain/draft-workspace-test.ts` (existing suite covers current filter — extend/relocate)
- Test: `opencti-platform/opencti-graphql/tests/01-unit/utils/filtering-completeSpecialFilterKeys-test.ts`

**Interfaces:**
- Consumes: `WORKFLOW_INSTANCE_STATUS_FILTER` constant (`filtering-constants.ts`), `ENTITY_TYPE_WORKFLOW_INSTANCE`, `fullEntitiesList`.
- Produces: a generalized resolver function in `filtering-completeSpecialFilterKeys.ts` alongside the existing legacy-status resolver, registered for any entity type with a configured workflow (not just `DraftWorkspace`).

- [ ] **Step 1.1: Write failing test** for the generalized filter resolving a non-draft entity type by workflow status to an id-list filter, mirroring the existing `resolveWorkflowInstanceStatusFilter` behavior in `draftWorkspace-domain.ts`.
- [ ] **Step 1.2: Extract the logic** from `resolveWorkflowInstanceStatusFilter` in `draftWorkspace-domain.ts` into `filtering-completeSpecialFilterKeys.ts`, generalized to accept any entity type (remove the draft-specific assumptions).
- [ ] **Step 1.3: Register the generalized resolver** for all entity types with a `workflow_id` configured in their `EntitySetting` (reuse `getWorkflowConfig`-style lookup).
- [ ] **Step 1.4: Update `draftWorkspace-domain.ts`** to call into the shared resolver instead of its own copy (or remove it if the shared special-filter-key pipeline already covers `DraftWorkspace` queries).
- [ ] **Step 1.5: Run tests to verify pass**
- [ ] **Step 2.1: Write test — legacy entity types unaffected** (no workflow configured → filter still resolves via legacy `Status`).
- [ ] **Step 2.2: Run test to verify pass**
- [ ] **Step 3.1: Manual check — bounded query, not full scan**: confirm the generalized resolver still uses `first: 5000`/bounded `fullEntitiesList` calls as the current draft implementation does, not an unbounded scan.
- [ ] **Step 4: Commit**
  ```bash
  git add opencti-platform/opencti-graphql/src/utils/filtering/ opencti-platform/opencti-graphql/src/modules/draftWorkspace/
  git commit -m "feat(workflow): generalize workflow-status filtering to all entity types"
  ```

---

## Task 5: Feature flag & new workflow UI

**Capability:** `workflow-entity-extension` (tasks.md group 5)

**Files:**
- Modify: feature-flag registry (locate existing flag pattern, e.g. `opencti-platform/opencti-graphql/src/config/` and frontend `opencti-platform/opencti-front/src/utils/` flag helpers)
- Modify: `opencti-platform/opencti-front/src/private/components/common/workflow/` (reuse `WorkflowStatus.tsx`, `WorkflowTransitions.tsx` components already built for `DraftWorkspace`)
- Test: existing `WorkflowStatus.test.tsx`, `WorkflowTransitions.test.tsx` (extend for non-draft entity types)

> Before implementing this task, re-run `writing-plans` scoped to this task
> after reading the current feature-flag registration pattern and the full
> `WorkflowStatus.tsx`/`WorkflowTransitions.tsx` components — not yet read in
> full during this planning pass.

- [ ] **Step 1: Add `ENTITIES_WORKFLOW` flag** following the existing feature-flag registration pattern used elsewhere in the codebase (locate one similar flag as a template).
- [ ] **Step 2: Gate workflow UI rendering** on entity views behind the flag for non-`DraftWorkspace` types, reusing `WorkflowStatus`/`WorkflowTransitions` components.
- [ ] **Step 3: Hide validate-draft action and skip its validation** for non-`DraftWorkspace` types (locate validate-draft action component and its validation check).
- [ ] **Step 4: Hide Authorized Members actions for Container entities** and add the corresponding validation check.
- [ ] **Step 5: Frontend tests** for flagged behavior per entity type category (draft, container, other).
- [ ] **Step 6: Commit**
  ```bash
  git add opencti-platform/opencti-front/src/private/components/common/workflow/
  git commit -m "feat(workflow): gate extended workflow UI behind ENTITIES_WORKFLOW flag"
  ```

---

## Task 6: Definition migration

**Capability:** `workflow-definition-migration` (tasks.md group 6)

**Files:**
- Create: `opencti-platform/opencti-graphql/src/modules/workflow/migration/status-to-definition-converter.ts` (pure function + diagnostics types)
- Modify: `opencti-platform/opencti-graphql/src/modules/workflow/api/workflow-resolvers.ts` (add preview query resolver)
- Modify: workflow `.graphql` schema (add `workflowMigrationPreview(entityType: String!): WorkflowMigrationPreview` query type)
- Create: `opencti-platform/opencti-graphql/src/migrations/<timestamp>-workflow-definition-migration.js` (follow existing migration file pattern in `src/migrations/`, see `1651939301056-workflow_rename.js` for format)
- Test: `opencti-platform/opencti-graphql/tests/01-unit/modules/status-to-definition-converter-test.ts`

**Interfaces:**
- Produces: `convertStatusToDefinition(statuses: StatusTemplate[]): { definition: WorkflowDefinitionInput; diagnostics: Diagnostic[] }` — pure, no I/O; used by both the preview query and the migration script.

- [ ] **Step 1.1: Write failing tests for the pure conversion function** covering: well-formed ordered statuses → valid definition with empty diagnostics; missing order → diagnostic + best-effort definition; name conflicts → diagnostic.
- [ ] **Step 1.2: Implement `convertStatusToDefinition`** as a pure function (no context/user/store access) in `status-to-definition-converter.ts`.
- [ ] **Step 1.3: Run tests to verify pass**
- [ ] **Step 2.1: Add GraphQL preview query** `workflowMigrationPreview(entityType)` calling `convertStatusToDefinition` on the entity type's current `Status` set, read-only.
- [ ] **Step 2.2: Integration test**: query preview for a sample entity type, assert no persisted changes occur.
- [ ] **Step 3.1: Implement the versioned migration** reusing `convertStatusToDefinition`, following the existing migration file format (`params`, `up`/`next` function shape as in `1651939301056-workflow_rename.js`), creating `WorkflowDefinition` entities and setting `EntitySetting.workflow_id`.
- [ ] **Step 3.2: Integration test**: run migration against seeded status data, assert preview output matches actual created definition.
- [ ] **Step 4: Commit**
  ```bash
  git add opencti-platform/opencti-graphql/src/modules/workflow/migration/ opencti-platform/opencti-graphql/src/migrations/
  git commit -m "feat(workflow): add Status-to-WorkflowDefinition conversion, preview query, and migration"
  ```

---

## Task 7: Request access dual workflows

**Capability:** `workflow-request-access` (tasks.md group 7)

**Files:**
- Modify: `opencti-platform/opencti-graphql/src/modules/requestAccess/requestAccess-domain.ts` (existing `x_opencti_workflow_id`/status-setting code around line 426)
- Modify: `opencti-platform/opencti-graphql/src/modules/entitySetting/` (entity setting schema — add second `workflow_id`-style field, e.g. `request_access_workflow_id`)
- Modify: `opencti-platform/opencti-graphql/src/modules/workflow/domain/workflow-domain.ts` (`getWorkflowConfig`/`getDefinitionData` to accept a scope parameter)
- Test: `opencti-platform/opencti-graphql/tests/01-unit/modules/workflow-domain-test.ts`

**Interfaces:**
- Consumes: existing `getWorkflowConfig(context, user, targetType)`.
- Produces: `getWorkflowConfig(context, user, targetType, { scope: 'request_access' | 'standard' })` — extends the existing signature with an optional scope parameter, defaulting to `'standard'`.

- [ ] **Step 1.1: Write failing test** — entity type with both a standard and `request_access` workflow definition; creating an entity within `request_access` scope initializes against the `request_access` definition.
- [ ] **Step 1.2: Add `request_access_workflow_id`** to the `EntitySetting` schema (mirrors existing `workflow_id`).
- [ ] **Step 1.3: Extend `getWorkflowConfig`/`getDefinitionData`** to accept a scope and look up the corresponding field.
- [ ] **Step 1.4: Wire scope detection** at entity-creation time in `requestAccess-domain.ts` into `initializeEntityWorkflow`'s call to `getWorkflowConfig`.
- [ ] **Step 1.5: Run test to verify pass**
- [ ] **Step 2.1: Write failing test — fallback to standard definition** when no `request_access_workflow_id` is configured.
- [ ] **Step 2.2: Implement fallback** in `getWorkflowConfig`.
- [ ] **Step 2.3: Run test to verify pass**
- [ ] **Step 3: Commit**
  ```bash
  git add opencti-platform/opencti-graphql/src/modules/requestAccess/ opencti-platform/opencti-graphql/src/modules/workflow/
  git commit -m "feat(workflow): support dual workflow definitions for request_access scope"
  ```

---

## Task 8: Concurrent/direct status writers

**Capability:** `workflow-concurrent-writers` (tasks.md group 8)

**Files:**
- Modify: `opencti-platform/opencti-graphql/src/modules/workflow/domain/workflow-domain.ts` (add external-sync hook near projection code from Task 2)
- Modify: `opencti-platform/opencti-graphql/src/database/middleware.ts` (existing `x_opencti_workflow_id` special-case around line 932 — hook in the sync call)
- Test: `opencti-platform/opencti-graphql/tests/01-unit/modules/workflow-domain-test.ts`

**Interfaces:**
- Produces: `syncWorkflowInstanceFromExternalWrite(context, user, entity, newStatusId): Promise<void>` — called wherever `x_opencti_workflow_id` is set outside the workflow engine (playbooks' `manipulate-knowledge-component.ts`, `requestAccess-domain.ts`, public API attribute update path, sync manager).

- [ ] **Step 1.1: Write failing test** — a direct write of `x_opencti_workflow_id` to a `Status` mapped to a different state than the current `WorkflowInstance.currentState` updates the instance and appends an `event_external` history entry.
- [ ] **Step 1.2: Implement `syncWorkflowInstanceFromExternalWrite`** in `workflow-domain.ts`, reusing the state↔status mapping from Task 1/2.
- [ ] **Step 1.3: Hook the sync call** into the generic attribute-update path in `middleware.ts` where `x_opencti_workflow_id` writes are already special-cased.
- [ ] **Step 1.4: Run test to verify pass**
- [ ] **Step 2.1: Write failing test — no-op when status unchanged** (direct write to the already-current mapped status records no new history entry).
- [ ] **Step 2.2: Implement the no-op guard** in `syncWorkflowInstanceFromExternalWrite`.
- [ ] **Step 2.3: Run test to verify pass**
- [ ] **Step 3: Commit**
  ```bash
  git add opencti-platform/opencti-graphql/src/modules/workflow/ opencti-platform/opencti-graphql/src/database/middleware.ts
  git commit -m "feat(workflow): sync WorkflowInstance state on direct Status writes"
  ```

---

## Task 9: Transition & bypass UI

**Capability:** `workflow-transition-actions` (tasks.md group 9)

> Before implementing, re-run `writing-plans` scoped to this task after
> reading `WorkflowTransitions.tsx` and the entity-view action bar
> components in full — only partially explored during this planning pass.

**Files:**
- Modify: `opencti-platform/opencti-front/src/private/components/common/workflow/WorkflowTransitions.tsx`
- Create: bypass-update popover component alongside it
- Modify: workflow GraphQL mutations (`triggerWorkflowEvent`) to support a "status-only" mode parameter
- Test: `WorkflowTransitions.test.tsx`, backend resolver tests

- [ ] **Step 1: Add apply-transition action** to the entity view with pending/error UI states, reusing `WorkflowTransitions.tsx` patterns from `DraftWorkspace`.
- [ ] **Step 2: Ensure `WorkflowInstance` is created on first transition apply** if only legacy `Status` exists (reuses Task 3's `ensureWorkflowInstance`).
- [ ] **Step 3: Add bypass-update popover** with the two modes (status-only vs. status+transition actions).
- [ ] **Step 4: Add a `applyTransitionActions: boolean` parameter** to the status-update mutation so the resolver can skip onExit/onEnter when status-only mode is selected.
- [ ] **Step 5: Frontend + backend tests** for pending/error states and both update modes.
- [ ] **Step 6: Commit**
  ```bash
  git add opencti-platform/opencti-front/src/private/components/common/workflow/
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
  git add opencti-platform/opencti-graphql/src/modules/playbook/
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
- [ ] **Step 5: Commit** (if any fixes were needed during verification)
  ```bash
  git commit -m "test(workflow): non-regression and EE-gating verification for workflow engine rollout"
  ```
