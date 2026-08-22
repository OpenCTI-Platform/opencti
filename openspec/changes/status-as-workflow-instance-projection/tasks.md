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
- [ ] 2.7 Integration tests: sync and async transitions update both instance state and projected entity status; stream emits normal update events

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
- [ ] 5.0.4 Auth-matrix test (`@auth(for: [KNOWLEDGE_KNUPDATE])` on the new field) — **deliberately deferred**: `@auth` directive enforcement is only verifiable via live GraphQL execution against the schema (Apollo directive layer), which this repo only exercises in `tests/03-integration/**` (e.g. `draftWorkspace-test.ts`'s `@auth(forDraft: ...)` / `@auth(for: [KNOWLEDGE])` coverage), not in the `tests/01-unit/**` resolver-map-direct-call style used for `workflow-resolvers-test.ts`. Consistent with precedent of leaving genuine integration-test items unchecked (see 2.7). A follow-up integration test in `stixSightingRelationship-test.js` mirroring `draftWorkspace-test.ts`'s pattern would close this gap.

- [x] 5.1 Add `ENTITIES_WORKFLOW` feature flag (backend + frontend)
- [x] 5.2 Reuse/adapt the DraftWorkspace workflow UI components for other entity types, gated by the flag
- [x] 5.3 Hide validate-draft action and skip its validation error for non-`DraftWorkspace` entity types
- [x] 5.4 Hide Authorized Members actions for Container entities and add the corresponding validation check
- [x] 5.4.5 Guard `StatusField` (legacy free-choice Status dropdown) to render read-only, keyed on `type`/`scope` props it already receives, when both (a) `ENTITIES_WORKFLOW` is enabled for that entity type and (b) a published `WorkflowDefinition` exists for it — prevents bypassing the new engine's enforced transitions via the pre-existing field. Added a new non-admin-gated `Query.workflowDefinitionPublished(entityType: String!): Boolean` (`@auth(for: [KNOWLEDGE_KNUPDATE])`) backed by `hasPublishedWorkflowDefinition` in `workflow-domain.ts`, since the existing `workflowDefinition` query is `SETTINGS_SETCUSTOMIZATION`-gated and unusable from a regular knowledge-edit form.
- [x] 5.5 Frontend tests for flagged UI behavior per entity type

## 6. Definition migration (`workflow-definition-migration`)

- [ ] 6.1 Implement pure `Status → WorkflowDefinition` conversion function with diagnostics
- [ ] 6.2 Add unit tests for all diagnostics edge cases (ambiguous ordering, name conflicts, missing data)
- [ ] 6.3 Expose a read-only GraphQL preview query using the conversion function
- [ ] 6.4 Implement the versioned migration reusing the conversion function to create `WorkflowDefinition`s and set `EntitySetting.workflow_id`
- [ ] 6.5 Integration test: migration preview matches actual migration output for a sample entity type

## 7. Request access dual workflows (`workflow-request-access`)

- [ ] 7.1 Allow an entity type to reference two published `WorkflowDefinition`s (standard, `request_access`)
- [ ] 7.2 Route `WorkflowInstance` initialization to the `request_access` definition when the entity is created within `request_access` scope
- [ ] 7.3 Fall back to the standard definition when no dedicated `request_access` definition exists
- [ ] 7.4 Unit tests: routing to correct definition based on scope

## 8. Concurrent/direct status writers (`workflow-concurrent-writers`)

- [ ] 8.1 Confirm/keep tolerant mode for direct `Status` writes from playbooks, requestAccess, public API, sync manager
- [ ] 8.2 Implement external-state-jump sync: on direct write, update `WorkflowInstance.currentState` and append an `event_external` history entry
- [ ] 8.3 Skip redundant history entries when the direct write matches the already-current state
- [ ] 8.4 Unit tests: external state jump recorded correctly; no-op when status unchanged

## 9. Transition & bypass UI (`workflow-transition-actions`)

- [ ] 9.1 Add user-facing apply-transition action (pending spinner, error display) on entity view
- [ ] 9.2 Create `WorkflowInstance` on first transition apply if only legacy `Status` exists
- [ ] 9.3 Add bypass-update popover with two modes: status-only, status+onExit/onEnter actions
- [ ] 9.4 Wire both update modes to create a `WorkflowInstance` when only legacy `Status` exists
- [ ] 9.5 Frontend + backend tests for pending/error states and both update modes

## 10. Mass operations (`workflow-transition-actions`)

- [ ] 10.1 Add mass-operation background task supporting both update modes (status-only, status+transitions)
- [ ] 10.2 Add playbook status action supporting both update modes
- [ ] 10.3 Unit/integration tests for mass operation and playbook mode selection

## 11. Closing reason (`workflow-closing-reason`)

- [ ] 11.1 Implement closing-reason backend storage modeled on the existing comments implementation
- [ ] 11.2 Add dedicated closing-reason UI, separate from comments
- [ ] 11.3 Wire closing-reason capture into the closing transition flow
- [ ] 11.4 Unit/frontend tests for setting and displaying a closing reason

## 12. Frontend status unification (`workflow-entity-extension`, depends on groups 1-5 being live)

- [ ] 12.1 Merge the `workflowInstance` and `x_opencti_workflow_id` Status columns into a single column definition in `dataTableUtils.tsx`
- [ ] 12.2 Keep the `initial-` id fallback check only as a transitional safety net
- [ ] 12.3 Merge the corresponding Status filter definitions into a single UI filter option
- [ ] 12.4 Update `dataTableUtils.test.tsx` and related filter tests for the merged column/filter

## 13. Non-regression & rollout verification

- [ ] 13.1 Manual/PO validation: run the migration preview query on production-like data
- [ ] 13.2 Non-regression check: sorting, filtering, widgets unchanged for entity types without a workflow
- [ ] 13.3 Verify stream/history/notification events remain unchanged in shape after projection writes
- [ ] 13.4 Verify EE gating: RBAC transition restriction and on-transition/on-status actions require Enterprise Edition
