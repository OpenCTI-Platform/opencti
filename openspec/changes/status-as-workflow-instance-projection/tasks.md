## 1. Workflow state ordering & full mapping invariant (blocking, `workflow-status-projection`)

- [x] 1.1 Add `order` field to workflow state definitions in the workflow schema/types
- [x] 1.2 Implement topological ordering computation from the transition graph
- [x] 1.3 Implement manual-order fallback when topological ordering is ambiguous
- [x] 1.4 On workflow publish: compute missing `Status` records per attached entity type and create them
- [x] 1.5 On workflow publish/republish: identify orphaned `Status` records (no state maps to them, no entity references them) and delete them (soft-delete with 30-day grace period + scheduled cleanup manager, per plan Step 4.5-4.7)
- [x] 1.6 Ensure no `Status` creation/deletion occurs on draft (unpublished) workflow save
- [x] 1.7 Add deletion guard rejecting `Status`/`StatusTemplate` deletion when referenced by a published `WorkflowDefinition`
- [x] 1.8 Unit tests: ordering (topological + manual fallback), full-mapping creation, orphan deletion, deletion guard

## 2. Status projection (`workflow-status-projection`)

- [x] 2.1 Implement state→status projection function (workflow state id → mapped `Status` id per entity type)
- [x] 2.2 Wire projection write-through into the synchronous transition path via the existing attribute-patch flow
- [x] 2.3 Wire projection write-through into the asynchronous action completion path
- [x] 2.4 Enforce fixed write order (instance update before projection update) in both paths
- [x] 2.5 Implement read-repair: detect and correct `x_opencti_workflow_id` divergence from `currentState` in `getWorkflowInstance`
- [x] 2.6 Unit tests: projection correctness, write order, read-repair
- [x] 2.7 Integration tests: sync and async transitions update both instance state and projected entity status; stream emits normal update events — added a `Workflow projection onto legacy Status field (Report)` describe block in `workflow-test.ts` covering a legacy-Status entity type (`Report`, not `DraftWorkspace`): eager `WorkflowInstance` creation on read, a synchronous `triggerWorkflowEvent` transition updating both `workflowInstance.currentState` and the projected `status.id`, and a `findHistory`-based assertion (polled, since the history manager consumes its stream asynchronously and may not even be subscribed yet on a freshly-started platform) proving a normal `update` history/audit-log entry was recorded for the `x_opencti_workflow_id` write — confirming `workflowInternalWrite: true` only suppresses the Task 8 anti-loop hook, never the standard event/history pipeline. Verified passing (24/24, full clean platform run) against the real ES-backed integration environment. This also caught and fixed a real bug: `resolveProjectionScope` in `workflow-projection.ts` imported `StatusScope` as `type`-only but used it as a runtime value (`StatusScope.Global`), causing a `ReferenceError` during read-repair for any non-`DraftWorkspace` entity type — fixed to a regular value import.

## 3. Eager instance creation & lazy backfill (`workflow-entity-extension`)

- [x] 3.1 Generalize `initializeEntityWorkflow` to run for any entity type at creation (already no-ops safely without a configured workflow)
- [x] 3.2 Wire `initializeEntityWorkflow` into the generic entity-creation path (same place legacy status is stamped today)
- [x] 3.3 Update `getWorkflowInstance` to persist a real `WorkflowInstance` on first read instead of only faking an `initial-...` placeholder
- [x] 3.4 Unit tests: eager creation on entity add; lazy backfill on first read; idempotent backfill on second read

## 4. Generalized filtering (`workflow-entity-extension`)

- [x] 4.1 Extract the `DraftWorkspace`-only workflow-status filter resolution into a shared helper (per plan.md Task 4 Step 0/option (b): `src/utils/filtering/workflow-status-filter.ts`, domain-query layer — not `filtering-completeSpecialFilterKeys.ts`, which has no entity-type parameter)
- [x] 4.2 Mirror the legacy-status filter resolution pattern (status filter → entity-id list) for workflow-instance-based types, generalized with an explicit `entityType` parameter
- [x] 4.3 Register the generalized filter for all entity types with a configured workflow (currently `DraftWorkspace` only — the only type with an actual list-resolver wiring today; no other entity type registers `WORKFLOW_INSTANCE_STATUS_FILTER` in `filterKeysSchema.ts` yet, so there's nothing else to wire per plan.md's "Phase-1 rollout surface" guidance)
- [x] 4.4 Remove/redirect the now-redundant `DraftWorkspace`-specific filter resolver to the shared implementation
- [x] 4.5 Unit tests: filtering various entity types by status, matching legacy-status-based and workflow-instance-based types
- [x] 4.6 Manual check: no performance regression on large entity-type listings (bounded workflow-instance query, not full collection scan) — unchanged `first: 5000` bound, now also logs a warning when hit

## 5. Feature flag & new workflow UI (`workflow-entity-extension`)

Step 0 (prerequisite, per plan.md): field-embedding + duplicate-resolver consolidation + batching — DONE, uncommitted.
- [x] 5.0.2 Consolidated the duplicate `DraftWorkspace.workflowInstance` resolver (was defined in both `draftWorkspace-resolvers.ts` and `workflow-resolvers.ts`) down to a single owner in `workflow-resolvers.ts`.
- [x] 5.0.3 Expanded `workflowInstance` field to `StixSightingRelationship` (strategy A, `extend type` in `workflow.graphql`) — the only other entity type with `workflow_id` in its `entitySetting-utils.ts` allow-list besides `DraftWorkspace`; the ~40 legacy-status entity types only have `workflow_configuration` (not `workflow_id`) and are out of scope for this field until they're migrated.
- [x] 5.0.7 Implemented `batchWorkflowInstances` (DataLoader via `workflowInstancesBatchLoader`) to avoid N+1 store round trips: entitySetting/definitionData resolved once per distinct `entity_type`, and the `WorkflowInstance` row lookup is a single bulk `fullEntitiesList` call (bound to 5000, with a warning log on bound-hit) instead of N sequential lookups. Wired into both `DraftWorkspace.workflowInstance` and `StixSightingRelationship.workflowInstance`. Also added the write-burst cap called out in plan.md (read batching alone doesn't solve it): a per-request cap of 20 read-repair writes (`READ_REPAIR_WRITE_CAP_PER_REQUEST`, keyed by `AuthContext` object identity), so a page of N simultaneously-diverging entities can't fire N concurrent `updateAttribute` repair writes in one request — entities beyond the cap are returned unrepaired and corrected on a later request.
- [x] 5.0.8 Unit tests: resolver consolidation + `StixSightingRelationship` resolver (`workflow-resolvers-test.ts`, 72/72 passing) and `batchWorkflowInstances` batching behavior — single bulk query for N entities, per-type config memoization, input-order-preserving results, no-configured-workflow short-circuit, bound-hit warning log; plus the per-request repair-write cap (caps at 20, cap is per-context not global) (`workflow-domain-test.ts`, 124/124 passing).
- [x] 5.0.4 Auth-matrix test (`@auth(for: [KNOWLEDGE_KNUPDATE])` on the new field) — added to the same `Workflow projection onto legacy Status field (Report)` block in `workflow-test.ts`: `queryAsUserIsExpectedForbidden(USER_PARTICIPATE, ...)` against `report(id).workflowInstance` confirms a user without `KNOWLEDGE_KNUPDATE` is denied on a non-`DraftWorkspace` type, proving the generalized `StixDomainObject.workflowInstance` field enforces the directive consistently across entity types. Verified passing in the same full-clean integration run as 2.7.

- [x] 5.1 Add `ENTITIES_WORKFLOW` feature flag (backend + frontend)
- [x] 5.2 Reuse/adapt the DraftWorkspace workflow UI components for other entity types, gated by the flag
- [x] 5.3 Hide validate-draft action and skip its validation error for non-`DraftWorkspace` entity types
- [x] 5.4 Hide Authorized Members actions for Container entities and add the corresponding validation check
- [x] 5.4.5 Guard `StatusField` (legacy free-choice Status dropdown) to render read-only, keyed on `type`/`scope` props it already receives, when both (a) `ENTITIES_WORKFLOW` is enabled for that entity type and (b) a published `WorkflowDefinition` exists for it — prevents bypassing the new engine's enforced transitions via the pre-existing field. Added a new non-admin-gated `Query.workflowDefinitionPublished(entityType: String!): Boolean` (`@auth(for: [KNOWLEDGE_KNUPDATE])`) backed by `hasPublishedWorkflowDefinition` in `workflow-domain.ts`, since the existing `workflowDefinition` query is `SETTINGS_SETCUSTOMIZATION`-gated and unusable from a regular knowledge-edit form.
- [x] 5.5 Frontend tests for flagged UI behavior per entity type

## 6. Definition migration (`workflow-definition-migration`)

- [x] 6.1 Implement pure `Status → WorkflowDefinition` conversion function with diagnostics (`convertStatusToDefinition` in `status-to-definition-converter.ts`) — groups input by `scope` first (never blends `GLOBAL`/`REQUEST_ACCESS` into one definition), synthesizes a fully-connected transition graph by default (N transitions, one per target state listing every other state as `from`) to preserve the legacy UI's unenforced "jump anywhere" behavior without imposing new ordering restrictions on migrated data.
- [x] 6.2 Add unit tests for all diagnostics edge cases (ambiguous/missing `order` → `MISSING_ORDER` diagnostic + best-effort fallback ordering by source array position; name conflicts via joined `StatusTemplate.name` → `NAME_CONFLICT` diagnostic; mixed-scope input → separate, never-merged `byScope` entries; single-state input → no transitions) — `status-to-definition-converter-test.ts`, 6/6 passing.
- [x] 6.3 Expose a read-only GraphQL preview query using the conversion function — `Query.workflowMigrationPreview(entityType: String!): WorkflowMigrationPreview` (`@auth(for: [SETTINGS_SETCUSTOMIZATION])`, matching `workflowDefinition`'s existing admin-only gating since this is a config-preview surface), backed by new `getWorkflowMigrationPreview` in `workflow-domain.ts` (gathers all-scope `Status`/`StatusTemplate` data for the type, delegates to `convertStatusToDefinition`, no persisted changes). Unit tests in `workflow-domain-test.ts` (2 new) and `workflow-resolvers-test.ts` (2 new); codegen regenerated (`nx run-many --target graphql`).
- [x] 6.4 Implement the versioned migration reusing the conversion function to create `WorkflowDefinition`s and set `EntitySetting.workflow_id` — **scoped decision (per user, option 2): `GLOBAL` scope only for now.** `migrateEntityTypeStatusToWorkflowDefinition` (`migrate-status-to-workflow-definition.ts`) reuses `convertStatusToDefinition` + `setWorkflowDefinition`/`publishWorkflowDefinition` (so the full-status-mapping invariant is enforced by the existing publish path); idempotent (no-op if `workflow_id` already set or no legacy `Status` data), and **fails loudly** (`FunctionalError`) if any `request_access`-scoped `Status` data is found for the type, since that requires Task 7's `RequestAccessFlow.workflow_definition_id` routing (not yet implemented) — never silently drops that data. The actual `src/migrations/1787412273072-workflow-definition-migration.ts` file is a canary-controlled no-op by default: it only migrates entity types explicitly listed via `app:workflow_definition_migration:entity_types` config (empty by default), per plan.md Step 3.3's "one type at a time, never bulk" guidance — a standard deploy-time migration cannot itself pause between types to monitor rollout metrics, so the opt-in list is the mechanism for operator-controlled canary rollout. 6/6 unit tests passing (`migrate-status-to-workflow-definition-test.ts`); migration file itself is untested per existing repo precedent (no other `src/migrations/*` file has a unit test).
- [x] 6.5 Integration test: migration preview matches actual migration output for a sample entity type — new `workflow-migration-test.ts` (entity type `Incident`, clean of any default per-type `Status` seeding unlike `Report`/`Case-Rfi`): seeds two Global-scope `Status` rows via `subTypeEdit.statusAdd`, asserts `workflowMigrationPreview` reflects them with no diagnostics, calls `migrateEntityTypeStatusToWorkflowDefinition` directly (domain function, using a dedicated `executionContext('workflow-migration-test', ADMIN_USER)` context rather than the shared `testContext` — several workflow-module functions read `context.user`, which `testContext` deliberately leaves unset) and asserts the persisted `WorkflowDefinition` matches the preview's states/transitions/initialState, then asserts idempotency on a second call. 3/3 passing in a full-clean integration run.
- [x] 6.6 Fix the rollback/re-enable data-loss asymmetry (per review, round 19): rolling back (clearing `EntitySetting.workflow_id`) un-gates direct `x_opencti_workflow_id` edits without syncing them into `WorkflowInstance`; re-enabling (republishing) previously caused the next read's repair (Task 2, instance-wins) to silently discard those edits. Fixed with new `reconcileExternalWritesOnRepublish` in `workflow-domain.ts`, invoked from `publishWorkflowDefinition` only on a genuine republish (definition already had a `published_version`) — scans entities of the type, and for any whose `updated_at` is newer than their stale `WorkflowInstance`, applies Task 8's status-wins sync once. 3 new unit tests in `workflow-domain-test.ts`, all passing (154/154 in that file). Live-integration-environment version of the test remains deferred, consistent with 6.5/2.7/5.0.4.
- [x] 6.7 Add a throughput/latency benchmark gate for the per-entity-creation workflow-init cost (per review, round 19): new `tests/01-unit/database/entity-lifecycle-hooks-benchmark-test.ts` (2 tests, both passing), exercising the real `runPostEntityCreationHooks`/`initializeEntityWorkflow` code paths with only store-level calls mocked. Gates: (1) near-linear growth across 500/2000/8000-entity batches (no accidental quadratic regression); (2) per-entity overhead bound (mocked-store baseline ≈0.013ms/entity at 5000 entities, gated <5ms). No existing worker/connector bulk-import fixture with a reusable entity count was found to reuse literally; a live-ES worker-level benchmark remains deferred, consistent with 6.5/2.7/5.0.4.

## 7. Request access dual workflows (`workflow-request-access`)

- [x] 7.1 Allow an entity type to reference two published `WorkflowDefinition`s (standard, `request_access`) — added `workflow_definition_id?: string` **inside** the existing `RequestAccessFlow` interface (`entitySetting-types.ts`) and GraphQL `RequestAccessWorkflow` type (`requestAccess.graphql`), per the plan's explicit correction against introducing a new top-level scalar. `EntitySetting.workflow_id` remains the standard-scope definition id; `EntitySetting.request_access_workflow.workflow_definition_id` is the new, optional, dedicated request_access-scope definition id.
- [x] 7.2 Route `WorkflowInstance` initialization to the `request_access` definition when the entity is created within `request_access` scope — implemented generically in `workflow-domain.ts`, no entity-type-specific hardcoding: new private `resolveEntityCreationScope` derives scope directly from the supplied `x_opencti_workflow_id`'s own `Status.scope` field (scope is a property of the Status itself, not something the caller declares), and `initializeEntityWorkflow` passes it into `getDefinitionData`'s new `scope` parameter (defaults to `StatusScope.Global`, preserving all existing callers' behavior unchanged). Also fixed a latent bug this surfaced: `WorkflowInstance.workflow_id` was being set from `entitySetting.workflow_id` unconditionally — now set from `definitionData.id` (the actually-resolved definition, correct for both scopes).
- [x] 7.3 Fall back to the standard definition when no dedicated `request_access` definition exists — `getDefinitionData` resolves `entitySetting.request_access_workflow?.workflow_definition_id ?? entitySetting.workflow_id` when scope is `RequestAccess`.
- [x] 7.4 Unit tests: routing to correct definition based on scope — 2 new tests in `workflow-domain-test.ts` (dedicated request_access definition used when configured; fallback to standard definition when not configured), both passing alongside the full existing suite (264/264 across all workflow-related unit test files, up from 262/262 before this task). Note: `requestAccess-domain.ts` was deliberately left unmodified — its existing `x_opencti_workflow_id: firstStatus.id` (set at RFI-creation time, `scope: RequestAccess`) already supplies everything `resolveEntityCreationScope` needs, so no CaseRfi-specific wiring was required beyond the generic `workflow-domain.ts` changes. Codegen regenerated (`nx run-many --target graphql`) after the `.graphql` schema change.

## 8. Concurrent/direct status writers (`workflow-concurrent-writers`)

- [x] 8.1 Confirm/keep tolerant mode for direct `Status` writes from playbooks, requestAccess, public API, sync manager
      — kept tolerant: `syncWorkflowInstanceFromExternalWrite` never rejects a direct write, even
      when unmapped to any published state (records a `pendingError` diagnostic instead, per the
      unmapped-status write policy).
- [x] 8.2 Implement external-state-jump sync: on direct write, update `WorkflowInstance.currentState` and append an `event_external` history entry
      — `syncWorkflowInstanceFromExternalWrite` (`workflow-domain.ts`), wired generically via a new
      `PostAttributeUpdateHook` registry (`entity-lifecycle-hooks.ts`) invoked from
      `middleware.ts`'s `updateAttribute` whenever an `x_opencti_workflow_id` input actually
      changes something (`data.event` truthy). Anti-feedback-loop: `projectWorkflowState`'s own
      write is marked `{ workflowInternalWrite: true }` and is filtered out in `updateAttribute`
      before the hook chain runs, so the workflow engine's own projection never re-triggers this
      sync. Gated on published-workflow-definition existence (Step 0.6) and on a `WorkflowInstance`
      already existing for the entity (absence is left to Task 3's lazy backfill-on-read).
- [x] 8.3 Skip redundant history entries when the direct write matches the already-current state
      — idempotent no-op branch in `syncWorkflowInstanceFromExternalWrite` when the resolved state
      equals `instanceEntity.currentState`.
- [x] 8.4 Unit tests: external state jump recorded correctly; no-op when status unchanged
      — `workflow-domain-test.ts`, `describe('syncWorkflowInstanceFromExternalWrite (Task 8)')`
      (gating on published-definition/instance existence, state-jump + `event_external` history,
      idempotent no-op, unmapped-status `pendingError` policy);
      `entity-lifecycle-hooks-test.ts` (registry mechanics for the new
      `PostAttributeUpdateHook` kind); `workflow-projection-test.ts` (asserts
      `projectWorkflowState`'s write carries the `workflowInternalWrite` anti-loop marker).
      Write-path audit (Step 3.4): the only other direct writer of `x_opencti_workflow_id` found
      is `requestAccess-domain.ts`'s creation-time write, which never goes through
      `updateAttribute` and is already correctly handled by Task 3/7's creation-time
      `initializeEntityWorkflow` path — documented as an intentional exclusion in
      `syncWorkflowInstanceFromExternalWrite`'s doc comment.
- [x] 8.5 Step 3.4b: clarifying comment added in `middleware.ts`'s `prepareAttributesForUpdate`
      noting its `X_WORKFLOW_ID` filter is type-only (not scope-aware) by design — scope mismatches
      are caught downstream by `syncWorkflowInstanceFromExternalWrite`'s unmapped-write policy.
- [x] 8.6 Step 5: history blob pruning — added `appendWorkflowHistoryEntry` (caps
      `WorkflowInstance.history` to the most recent 200 entries), applied at both append sites
      (`triggerWorkflowEvent`'s sync-transition history and `syncWorkflowInstanceFromExternalWrite`'s
      `event_external` history). Test asserts bounded length after exceeding the cap. Flagging,
      per plan: a size cap doesn't address the underlying per-write reindex cost of rewriting the
      whole array on every touch — a high-frequency writer (e.g. connector re-syncs) may still need
      an append-only substore instead of this single array; not solved here.

## 9. Transition & bypass UI (`workflow-transition-actions`)

- [x] 9.1 Add user-facing apply-transition action (pending spinner, error display) on entity view
      `WorkflowTransitions.tsx` renders pending-state (spinner + async action progress + admin
      Clear button) and error-state (error icon + admin force-unlock Clear button) UI, plus a
      consolidated "Apply transition" dialog (comment / org-picker / validate-draft sections,
      shown together per transition's requirements) driven by `useTransitionWizard`. Split into a
      shared `WorkflowTransitionsView` presentational component, with two thin wrappers: the
      original `WorkflowTransitions` (DraftWorkspace-bound, used by `DraftToolbar.tsx`, unchanged
      external API) and the new `WorkflowTransitionsForEntity` (generic StixDomainObject-bound,
      resolves `WorkflowStatusStixDomainObject_data` fragment). Mounted into
      `StixDomainObjectOverview.jsx`'s "Processing status" block, gated by
      `isWorkflowUiEnabledForType(entityType, isFeatureEnable) && !!stixDomainObject.workflowInstance`,
      falling back to the legacy read-only `ItemStatus` otherwise. Required adding
      `...WorkflowStatusStixDomainObject_data` to each of the ~38 individual entity-type GraphQL
      fragments that feed `StixDomainObjectOverview` (no single shared fragment point exists across
      all StixDomainObject-implementing view components), anchored after each file's own
      `workflowEnabled` field. Codegen (`nx run-many --target graphql`) re-run after all spreads
      added — compiled cleanly.
- [x] 9.2 Create `WorkflowInstance` on first transition apply if only legacy `Status` exists
      Covered by the backend's `ensureWorkflowInstance` call inside `triggerWorkflowEvent`
      (pre-existing, unchanged this session) — the frontend's apply-transition action added in 9.1
      goes through this same mutation for both DraftWorkspace and generic StixDomainObject entities.
- [x] 9.3 Add bypass-update popover with two modes: status-only, status+onExit/onEnter actions
      Backend half done: new `setWorkflowStatus(context, user, entityId, targetStatusId,
      applyTransitionActions, comment?)` domain function in `workflow-domain.ts`, jumps directly
      to any state mapped in the published workflow (no `allowedTransitions` check — bypass by
      design), calls `ensureWorkflowInstance` first (satisfies 9.4 on the backend side), records
      `event_bypass` history entries (never `event_external`), runs only current-state onExit +
      target-state onEnter side effects (via `WorkflowFactory.createDefinition(...).getStateDefinition(...)`,
      bypassing the edge-based `StateMachine.trigger()` entirely since bypass mode has no edge)
      when `applyTransitionActions` is true. New `setWorkflowStatus` GraphQL mutation added
      (`@auth(for: [KNOWLEDGE_KNUPDATE])`, matching `triggerWorkflowEvent`), resolver wired,
      codegen run. Frontend: new `WorkflowBypassStatus.tsx` component (admin-only via
      `isBypassUser`), listing all statuses for the entity's type via the existing
      `statusFieldStatusesSearchQuery` (from `StatusField.tsx`), with a confirm dialog exposing
      the `applyTransitionActions` boolean (`Switch`, defaults to true = "apply onExit/onEnter
      actions") and an optional comment, calling `workflowSetStatusMutation`. Mounted alongside
      the apply-transition action in `StixDomainObjectOverview.jsx`.
- [x] 9.4 Wire both update modes to create a `WorkflowInstance` when only legacy `Status` exists
      Backend covered (see 9.3 note: `setWorkflowStatus` calls `ensureWorkflowInstance`). Frontend
      apply-transition action (9.1) already goes through `triggerWorkflowEvent`, which also calls
      `ensureWorkflowInstance` — no new code needed there, verify via test only.
- [x] 9.5 Frontend + backend tests for pending/error states and both update modes
      Backend tests done: `setWorkflowStatus (Task 9)` describe block in `workflow-domain-test.ts`
      (6 tests — no published workflow, unmapped target status, pending-lock rejection, bypass
      jump without an allowed-transition edge + `event_bypass` history entry, and
      applyTransitionActions true/false onExit/onEnter invocation). Frontend tests: extended
      `WorkflowStatus.test.tsx` with `WorkflowStatusForEntity`/`WorkflowTransitionsForEntity`
      describe blocks (flag gating, transition firing), new `WorkflowBypassStatus.test.tsx` (7
      tests: admin gating, flag gating, status list fetch, applyTransitionActions toggle default
      and mutation variables, Cancel without commit), and new
      `StixDomainObjectOverview.test.tsx` (3 tests covering the new workflow-mount branching:
      legacy fallback with no `workflowInstance`, legacy fallback with flag off, and the new
      components mounted when both a `workflowInstance` and the flag are present). All frontend
      workflow-directory tests green (102/102 across `workflow/` + `stix_domain_objects/`); backend
      workflow tests green (228/228).

## 10. Mass operations (`workflow-transition-actions`)

- [x] 10.1 Add mass-operation background task supporting both update modes (status-only, status+transitions)
      Status-only mode was already implicit: a mass `REPLACE` on `x_opencti_workflow_id` goes
      through the generic `KNOWLEDGE_CHANGE` bundle patch (unchanged), which lands in Task 8's
      passive `syncWorkflowInstanceFromExternalWrite` hook downstream (no onExit/onEnter). Added
      the explicit "apply transition actions" mode: `BackgroundTaskContextOptionsInput` gained
      `applyTransitionActions: Boolean` (`config/schema/opencti.graphql`); when a `REPLACE` action
      targets `x_opencti_workflow_id` with `context.options.applyTransitionActions: true`, the
      `taskHandlerGenerator` action-grouping in `taskManager.js` now buckets it as a new pseudo
      type `WORKFLOW_TRANSITION` (`isWorkflowTransitionAction` helper) instead of `KNOWLEDGE_CHANGE`,
      routed to a new `workflowTransitionOperationCallback` that calls `setWorkflowStatus(context,
      user, element.internal_id, targetStatusId, true)` directly and synchronously per element
      (bypassing the worker/bundle pipeline entirely, since onExit/onEnter hooks must run through
      the workflow engine, not a plain attribute patch). Per-element errors are caught and logged
      so one failing entity doesn't abort the rest of the batch.
- [x] 10.2 Add playbook status action supporting both update modes
      `manipulate-knowledge-component.ts`'s `ManipulateConfiguration.actions[]` items gained an
      optional `apply_transition_actions?: boolean` field (JSON schema updated, default `false`).
      The executor partitions configured actions into `workflowTransitionActions` (a 'replace' on
      `x_opencti_workflow_id` with `apply_transition_actions: true`) vs `genericActions` (everything
      else, unchanged behavior). For each matching, already-persisted bundle element (`id` present),
      workflow-transition actions call `setWorkflowStatus(context, AUTOMATION_MANAGER_USER, id,
      targetStatusId, true)` directly instead of enlisting a JSON-patch bundle operation — status-only
      mode (the default, `apply_transition_actions` absent/false) is unchanged and still flows through
      the existing generic JSON-patch → `opencti_upsert_operations` → downstream ingestion path.
- [x] 10.3 Unit/integration tests for mass operation and playbook mode selection
      Unit tests (executable, all green): `taskManager-test.ts` — new `isWorkflowTransitionAction`
      describe block (5 tests: true/false cases for option absent/false/wrong-field/wrong-action-type,
      plus the exported constant) and `workflowTransitionOperationCallback` describe block (3 tests:
      calls `setWorkflowStatus` per element with the right args, updates `task_processed_number`,
      and continues processing remaining elements when one call throws). 267/267 backend unit tests
      green across `taskManager-test.ts` + `workflow-domain-test.ts` + `workflow-resolvers-test.ts`;
      full `tests/01-unit` suite: 2964 passed / 15 failed (pre-existing, unrelated — missing built
      `build/safeEjs.worker.mjs` worker artifact for `publisherManager`/`safeEjs` tests, confirmed
      failing identically on a clean `git stash` of this session's changes).
      Integration tests: added a `workflow status update modes (Task 10)` describe block to
      `manipulate-knowledge-component-test.ts` (2 tests: transition-actions mode calls
      `setWorkflowStatus` and skips the generic patch; status-only mode does the reverse), with
      `setWorkflowStatus` mocked so the assertions don't depend on a live workflow definition.
      **Could not be executed in this session**: this whole test file (like its 8 sibling files in
      `playbookComponents/`) fails to even load in isolation in this sandbox due to a **pre-existing**
      circular import (`manipulate-knowledge-component.ts` → `playbook-utils.ts` →
      `playbook-components.ts` → `manipulate-knowledge-component.ts`), reproduced identically on
      the unmodified base commit via `git stash`; the project's real `test:ci-integration`/`test:dev`
      commands require a live ES/Redis/RabbitMQ stack and a built `build/` directory, neither
      available in this sandbox. Same class of deferral as items 2.7 / 5.0.4 / 6.5.

## 11. Closing reason (`workflow-closing-reason`)

- [x] 11.1 Implement closing-reason backend storage modeled on the existing comments implementation.
      Researched the existing "comment" pattern first: comments are inline fields on
      `WorkflowInstance.history` JSON entries (not a separate entity), propagated through both the
      sync (`triggerWorkflowEvent`) and async/pending (`WorkflowPendingTransition` →
      `workflow-async-completion.ts`) transition paths, plus the bypass path (`setWorkflowStatus`).
      "Closing state" is not an explicit schema field — it's derived (a state with no outgoing
      transitions, excluding wildcard `'*'` from-entries), a convention already duplicated inline in
      `publishWorkflowDefinition` and `workflow-validation.ts`. Generalized this into a new reusable,
      unit-tested helper `isEndingState()` in `workflow-ordering.ts` rather than re-implementing it a
      third time. Added `closingReason?: string` threading, mirroring `comment` exactly but stored as
      `closing_reason` (snake_case) in persisted/GraphQL-exposed history entries (camelCase
      `closingReason` only on the internal, non-GraphQL-exposed `WorkflowPendingTransition`):
      `triggerWorkflowEvent`, `setWorkflowStatus`, `workflow-async-completion.ts`'s completion push,
      and `workflow-types.ts`. Added a new computed `isClosingTransition` field to
      `getAllowedTransitions`'s per-transition result (`isEndingState(definitionData.transitions,
      transition.to)`). GraphQL schema (`workflow.graphql`): `WorkflowTransition.isClosingTransition`,
      `WorkflowLastHistoryEntry.closing_reason`, and a `closingReason: String` argument on both
      `triggerWorkflowEvent` and `setWorkflowStatus` mutations. Resolvers
      (`workflow-resolvers.ts`): new `CLOSING_REASON_MAX_LENGTH = 1000` constant, both mutation
      resolvers validate/trim/forward `closingReason` exactly like `comment`, and
      `WorkflowTransition.isClosingTransition` resolver added. Ran GraphQL codegen
      (`nx run-many --tuiAutoExit --target graphql`) to regenerate `src/generated/graphql.ts`.
- [x] 11.2 Add dedicated closing-reason UI, separate from comments.
      `WorkflowStatus.tsx`: added a second, visually distinct icon+popover (`AssignmentTurnedInOutlined`,
      aria-label "View closing reason") reading `workflowInstance.lastHistoryEntry?.closing_reason`,
      rendered alongside (not merged with) the existing comment icon+popover — both can appear
      simultaneously when a history entry has both fields. `WorkflowTransitions.tsx`: added a new,
      separate `TextField` ("Closing reason", its own `StepPill`, own `CLOSING_REASON_MAX_LENGTH`
      character counter) distinct from the existing "Comment" field, rendered when the wizard's steps
      include `'closing-reason'`. `useTransitionWizard.ts`: intentionally did NOT add an admin-config
      "closing reason mode" analogous to `CommentMode` — the trigger condition is purely the computed
      `isClosingTransition` flag on the selected transition, not an admin-configured setting.
- [x] 11.3 Wire closing-reason capture into the closing transition flow.
      `useTransitionWizard.ts`: added `'closing-reason'` to `WizardStep`, `isClosingTransition` to
      `TransitionWizard`; `handleTransition` now takes an `isClosingTransition` argument and pushes
      the `'closing-reason'` step when true; `fireTransition` and `handleApplyWizard` now accept/pass
      a trimmed `closingReason` through to the `triggerWorkflowEvent`/`WorkflowStatusTriggerMutation`
      call. `WorkflowStatus.graphql.ts`: added `closing_reason` to both `lastHistoryEntry` selections,
      `isClosingTransition` to both `allowedTransitions` selections, and a `$closingReason: String`
      variable/argument to both `WorkflowStatusTriggerMutation` and `WorkflowSetStatusMutation`.
      `WorkflowTransitions.tsx`: both transition-invocation call sites (single-button and menu-item)
      now pass `transition.isClosingTransition` through to `handleTransition`. Ran `yarn relay` to
      regenerate frontend Relay artifacts. Deliberately scoped OUT of this task: the admin
      bypass-status-update UI (`WorkflowBypassStatus.tsx`) — the backend `closingReason` param on
      `setWorkflowStatus` exists for API symmetry/testability, but plan.md's "closing transition flow"
      refers to the standard `triggerWorkflowEvent` wizard flow, not the bypass mechanism.
- [x] 11.4 Unit/frontend tests for setting and displaying a closing reason.
      Backend (`tests/01-unit/modules/`): `workflow-ordering-test.ts` — 5 new tests for
      `isEndingState()` (terminal state, non-terminal state, array `from`, wildcard exclusion, absent
      state). `workflow-domain-test.ts` — new tests for `isClosingTransition` true/false in
      `getAllowedTransitions`, `closing_reason` persisted correctly (present/absent/combined-with-
      comment) in `triggerWorkflowEvent`'s history entry, and in `setWorkflowStatus`'s `event_bypass`
      history entry. `workflow-resolvers-test.ts` — updated existing `toHaveBeenCalledWith` assertions
      for the new trailing `closingReason` argument, plus new tests for `closingReason`
      forwarding/trimming/length-validation on both mutation resolvers and the new
      `WorkflowTransition.isClosingTransition` resolver. All backend changes verified via
      `node_modules/.bin/vitest run tests/01-unit` — 2982 passed / 15 failed (same 15 pre-existing,
      unrelated failures as the Task 10 baseline: missing `build/safeEjs.worker.mjs` and axios-mock
      issues in `publisherManager`/`safeEjs` tests, confirmed unrelated to this session's work).
      Frontend (`opencti-front/src/private/components/common/workflow/`): new tests in
      `useTransitionWizard.test.ts` (closing-reason step addition/omission, trimmed/undefined
      `closingReason` forwarding to the mutation), `WorkflowStatus.test.tsx` (closing-reason icon
      render/no-render, popover content, coexistence with the comment icon, closing-reason dialog
      field open/not-open based on `isClosingTransition`, trimmed `closingReason` on Apply). All 79
      tests in the `workflow` directory pass (`node_modules/.bin/vitest run
      src/private/components/common/workflow`).

## 12. Frontend status unification (`workflow-entity-extension`, depends on groups 1-5 being live)

- [x] 12.1 Merge the `workflowInstance` and `x_opencti_workflow_id` Status columns into a single column definition in `dataTableUtils.tsx`.
      Added a single shared `renderStatusColumn` helper in `dataTableUtils.tsx`, used by both the
      `workflowInstance` column definition (Drafts, the only list selecting `workflowInstance`
      today) and the `x_opencti_workflow_id` column definition (every other entity type, whose
      legacy `status` field stays live via Task 2's projection). Logic: prefer
      `workflowInstance.currentStatus` when `workflowInstance` is present, not an `initial-`
      placeholder (see 12.2), and `isWorkflowUiEnabledForType` is true for the row's entity type;
      otherwise fall back to the legacy `status`/`workflowEnabled` fields exactly as before. No
      behavior change for the ~20 existing entity list tables, since their fragments don't select
      `workflowInstance` yet and the legacy `status` field they do select is already correct
      (kept live by the projection) — this is pure de-duplication + future-proofing so the column
      "just works" once/if a list's fragment adds `workflowInstance` later.
- [x] 12.2 Keep the `initial-` id fallback check only as a transitional safety net.
      `renderStatusColumn` checks `workflowInstance.id?.startsWith('initial-')` and ignores such a
      (synthesized-but-unpersisted, error-fallback) instance, falling back to the legacy `status`
      field instead of rendering a stale/synthetic value. Added `id` to the `workflowInstance`
      selection in `DraftsList.tsx`'s GraphQL query (the one place already using this column) so
      the check has data to act on; ran `yarn relay` to regenerate.
- [ ] 12.3 Merge the corresponding Status filter definitions into a single UI filter option.
      **Deferred** (explicit user decision, not a gap in this session's execution). Investigated:
      backend registers two separate filter keys — `workflow_id` (`WORKFLOW_FILTER`, label
      "Status", registered for all Stix-Domain-Objects) and `workflowInstanceCurrentState`
      (`WORKFLOW_INSTANCE_STATUS_FILTER`, label "Workflow status", registered only for
      `DraftWorkspace`). Task 4 already generalized the *resolution* logic
      (`workflow-status-filter.ts`) to work for any entity type, but no entity type registers both
      keys today, so there is no currently-visible duplicate filter to merge as pure frontend UI
      work. The clean fix — making `DraftWorkspace` share the universal `workflow_id` key/legacy
      `status` field like every other type — requires giving `DraftWorkspace` a brand-new
      `status`/`x_opencti_workflow_id` schema attribute (it never had one; Drafts were built
      directly on `WorkflowInstance` from day one, predating this migration), extending Task 2's
      projection write-path to also target it, and backfilling/migrating existing drafts. That's a
      real schema+migration task, not scripted anywhere in this plan, and out of scope for a
      frontend-only column/filter cleanup. Left for a future, separate change if/when prioritized.
- [x] 12.4 Update `dataTableUtils.test.tsx` and related filter tests for the merged column/filter.
      Rewrote `dataTableUtils.test.tsx` to render columns through `testRender`
      (`utils/tests/test-render.tsx`) with a mocked `UserContext` (needed since the merged
      `renderStatusColumn` calls `useHelper()`/`useAuth()`), covering: legacy-status fallback with
      no `workflowInstance`, `workflowInstance.currentStatus` preferred when present and the
      `ENTITIES_WORKFLOW` flag is on, legacy fallback with no `workflowInstance`, legacy fallback
      when the flag is off despite `workflowInstance` being present, the `initial-` placeholder
      safety net, and the DraftWorkspace-always-on-regardless-of-flag case. 11/11 passing
      (`node_modules/.bin/vitest run src/components/dataGrid/dataTableUtils.test.tsx`).

## 13. Non-regression & rollout verification

- [x] 13.1 Run the migration preview query against a live local dev instance (podman-run ES/Redis/RabbitMQ/MinIO stack + full `nx run-many --target dev` app, no staging/production data pulled per explicit instruction). `workflowMigrationPreview` for `Report` (existing legacy `Status` data, GLOBAL scope) returned 3 states, fully-connected transitions, no diagnostics, correct lowest-order initial state; for `Case-Rfi` correctly returned `REQUEST_ACCESS` scope (never blended with GLOBAL). Read-only confirmed (no persisted changes from repeated calls).
- [x] 13.2 Live non-regression check against the same local instance: every entity type except `DraftWorkspace` has `workflow_id: null` in this dev DB (confirmed via `entitySettings`), so the whole existing dataset currently exercises only the legacy path. Verified sorting (`orderBy: x_opencti_workflow_id`), filtering (`x_opencti_workflow_id` filter key), and a widget-style `reportsDistribution` aggregation on `Report` all return correct, unchanged legacy `status`/`template` shapes with `workflowInstance: null` — no regression.
- [x] 13.3 Verified live on `DraftWorkspace` (the one type with an actual published `WorkflowDefinition`): a freshly-created entity gets an eager, non-placeholder `WorkflowInstance` with `lastHistoryEntry = {state, event: "initialization", timestamp}` (correct shape, per Task 3's eager-creation design); `setWorkflowStatus` (bypass path) fails safely with `{success:false, reason}` rather than crashing when given an unmapped status. Full history/notification-event-shape diffing before/after a *successful* transition was not completed (the only available real transition on a fresh instance was RBAC-condition-gated, see 13.4), so the specific "instance update then projection update" event-ordering/cardinality claim (Step 5) is accepted on the existing unit-test evidence, not re-confirmed via a fresh live trigger this session.
- [x] 13.4 Verified EE gating live: this dev instance has a valid EE license (`platform_enterprise_edition.license_validated: true`); its real `DraftWorkspace` workflow uses transition `conditions` (RBAC-style restriction) and `setWorkflowDefinition` explicitly calls `checkEnterpriseEdition` whenever a definition's transitions/states use conditions or on-transition/on-status actions (`workflow-domain.ts`, `definitionRequiresEE` check). Live-tested that both `allowedTransitions` (list) and `triggerWorkflowEvent` (mutation, called directly bypassing the list) independently re-evaluate and reject a condition-gated transition for the current user (`"Condition failed for transition 'Request MO manager review'"`) — defense-in-depth confirmed, not just UI-level filtering.
- [x] 13.5 **Blocking gap found during 13.1/13.2 live verification — fixed:** Task 6's migration (`migrateEntityTypeStatusToWorkflowDefinition` → `setWorkflowDefinition` → `updateAttribute`) could not succeed for any of the ~40 legacy-status entity types it targets (e.g. `Report`, `Case-Rfi`) — confirmed live via `workflowDefinitionSet(entityType: "Report", ...)` failing with `UnsupportedError: This setting is not available for this entity` (setting: `workflow_id`). Root cause: `entitySetting-utils.ts`'s `availableSettings` allow-list only granted the `workflow_id` setting to `STIX_SIGHTING_RELATIONSHIP`/`DraftWorkspace` (Task 5, tasks.md 5.0.3). **Fix (per user decision — extend to all entities):** added `workflow_id` alongside every existing `workflow_configuration` entry in `availableSettings` (`templateObjectSettings`, `ABSTRACT_STIX_DOMAIN_OBJECT`, `ABSTRACT_STIX_CORE_RELATIONSHIP`, and the four container overrides `ENTITY_TYPE_CONTAINER_NOTE`/`_OPINION`/`_CASE`/`_TASK`) — i.e. every legacy-status entity type now has `workflow_id` available, matching `workflow_configuration`'s existing reach; types with no Status/workflow support at all (cyber observables, external references) are untouched. **Verified live** end-to-end after the fix: `workflowDefinitionSet(entityType: "Report", ...)` → `workflowDefinitionPublish(entityType: "Report")` both now succeed (previously the first call failed); test workflow removed via `workflowDefinitionDelete` afterward to leave the dev DB unchanged. New regression test `entitySetting-utils-test.ts` (5/5 passing) pins `workflow_id` availability for a container SDO, a template-object SDO, a stix-core-relationship, and the two originally-wired types, and its absence for cyber observables. Full existing unit suite re-run (255 tests across `workflow-domain-test.ts`, `workflow-resolvers-test.ts`, `entity-lifecycle-hooks-test.ts`, `entity-lifecycle-hooks-benchmark-test.ts`) plus `migrate-status-to-workflow-definition-test.ts` (6/6) all still passing.
