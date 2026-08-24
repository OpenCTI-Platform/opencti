## 1. Workflow editor routing generalization

- [x] 1.1 In `Root.tsx`, replace the `isDraftWorkspaceType` branch on the
      Workflow tab route with `isWorkflowUiEnabledForType(subTypeId, isFeatureEnable)`,
      keeping `GlobalWorkflowSettingsCard` as the fallback.
- [x] 1.2 In `SubTypeWorkflow.tsx`, replace the hardcoded
      `entityType: 'DraftWorkspace'` query variables with the actual `subTypeId`,
      and pass `entityType` through as a prop to `<Workflow>`.
- [ ] 1.3 In `Workflow.tsx`, keep `allowDraft` conditioned on
      `entityType === 'DraftWorkspace'` only, verifying no other draft-specific
      behavior leaks to other entity types.
- [ ] 1.4 Add/update frontend tests covering the Workflow tab rendering the
      graph editor for a non-DraftWorkspace type when the feature is enabled,
      and the legacy card when it is disabled.

## 2. Global/RequestAccess scope switcher

- [x] 2.1 Add a `scope: StatusScope.Global | StatusScope.RequestAccess`
      prop/selector to `Workflow.tsx`, defaulting to `GLOBAL`.
- [x] 2.2 Gate the `RequestAccess` scope option on `hasRequestAccessConfig`
      (EE + `request_access_workflow` in `availableSettings`), matching the
      existing check in `GlobalWorkflowSettingsCard.tsx`.
- [x] 2.3 Update the `workflowDefinition` query/loader in `SubTypeWorkflow.tsx`
      to accept and pass through the selected `scope`.
- [x] 2.4 Add frontend tests for scope switching (RequestAccess hidden/shown
      per gating, switching reloads the correct definition).

## 3. Legacy status migration entry point

- [x] 3.1 Add a GraphQL mutation (e.g. `migrateEntityTypeStatusToWorkflowDefinition(entityType: String!, scope: StatusScope!)`)
      in `workflow-resolvers.ts`/`workflow.graphql` wrapping the domain
      migration function, auth-gated the same as `workflowMigrationPreview`
      (`SETTINGS_SETCUSTOMIZATION`).
- [x] 3.2 In the frontend editor, when opening a type/scope with no
      `workflow_id` configured, call the existing `workflowMigrationPreview`
      query and render a confirmation dialog with its diagnostics.
- [x] 3.3 Wire the dialog's confirm action to the new mutation from 3.1; on
      success, reload the editor with the newly published definition.
- [x] 3.4 Add tests: preview diagnostics render correctly, migration mutation
      is only called after explicit confirm, subsequent visits skip the
      confirmation once `workflow_id` is set.

## 4. RequestAccess-scope migration support

- [ ] 4.1 Generalize `resolveEntityCreationScope` into a shared
      `resolveStatusScope(context, user, statusId?)` helper, and use it \u2014
      instead of the hardcoded `StatusScope.Global` default \u2014 in
      `syncWorkflowInstanceFromExternalWrite`, `getWorkflowInstance`,
      `getAllowedTransitions`, `triggerWorkflowEvent`, `setWorkflowStatus`,
      and `batchWorkflowInstances` (keyed by `(entityType, scope)`). This is
      the confirmed prerequisite for RequestAccess migration: without it, no
      runtime function can ever resolve a `RequestAccess`-scope
      `WorkflowDefinition` for a real entity, so `requestAccess-domain.ts`'s
      approve/decline writes would silently fail to sync the
      `WorkflowInstance` projection (see design.md D4b).
- [ ] 4.2 In `migrate-status-to-workflow-definition.ts`, remove the
      `FunctionalError` thrown for `RequestAccess`-scoped Status data, and
      persist `byScope[StatusScope.RequestAccess]`'s conversion output via
      `setWorkflowDefinition`/`publishWorkflowDefinition`, scoped correctly
      alongside the existing `GLOBAL` handling.
- [ ] 4.3 Add/update backend tests for migrating `RequestAccess`-scoped
      legacy Status data (success case, no-data no-op case, idempotency when
      `workflow_id` already set).
- [ ] 4.4 Add backend tests for 4.1 covering `RequestAccess` scope in each
      updated function, and an integration-style test confirming
      `approveRequestAccess`/`declineRequestAccess` correctly sync the
      `WorkflowInstance` once a `RequestAccess`-scope definition exists (no
      change needed to `requestAccess-domain.ts` itself).

## 5. Cycle-scoped state ordering

- [ ] 5.1 Rewrite `computeStateOrder` in `workflow-ordering.ts` to compute,
      per state, the longest simple path length from `initialState` via DFS
      with a path-scoped (not global) visited set.
- [ ] 5.2 Add a bounded work cap (constant, informed by realistic max
      state/transition counts) with graceful per-state fallback to `null`
      when exceeded, rather than an unbounded computation.
- [ ] 5.3 Update `workflow-validation.ts`'s `MISSING_MANUAL_ORDER` handling
      to consume the new per-state result shape (only affected states
      require manual `order`, not the whole graph).
- [ ] 5.4 Add unit tests for `computeStateOrder`: acyclic graphs unchanged,
      a cycle isolated from an unrelated branch still allows that branch to
      auto-order, states on/entangled with a cycle still require manual
      order, and the bounded-cap fallback path.

## 6. Mass real-transition apply (backend + frontend)

- [ ] 6.1 In `taskManager.js`, add a new mass-op action type that calls
      `triggerWorkflowEvent` per selected element for a given `eventName`,
      reusing the existing per-element try/catch error-tolerance pattern
      from `workflowTransitionOperationCallback`.
- [ ] 6.2 Ensure the new action type is authorized the same as the
      single-entity `triggerWorkflowEvent` mutation (`KNOWLEDGE_KNUPDATE`).
- [ ] 6.3 In `DataTableToolBar.jsx`, add a mass-edit UI mode to pick a
      workflow transition (by `event`) for the current bulk selection's
      entity type, submitting via the new action type.
- [ ] 6.4 Add backend tests for the new mass-op action (eligible elements
      transition, ineligible elements are skipped/error-counted, unauthorized
      users rejected).
- [ ] 6.5 Add frontend tests for the new mass transition UI option.

## 7. Mass bypass forced status update (frontend only)

- [ ] 7.1 Create a bulk-selection variant of `WorkflowBypassStatus.tsx`
      (target status + apply-actions toggle + comment) for use from
      `DataTableToolBar.jsx`, gated on `isBypassUser`.
- [ ] 7.2 Wire it to the existing `applyTransitionActions` mass-op backend
      path (already implemented, calls `setWorkflowStatus` per element) —
      no backend changes needed for this task.
- [ ] 7.3 Add frontend tests for the bypass mass-update UI (visibility gated
      to bypass users, correct mutation variables submitted).

## 8. Rollout

- [ ] 8.1 Confirm all four areas (1-3, 4, 5, 6-7) are independently
      functional behind `ENTITIES_WORKFLOW` before enabling the flag broadly,
      per design.md's Migration Plan.
- [ ] 8.2 Enable `ENTITIES_WORKFLOW` for all entity types (single flag, no
      per-type canary) and manually verify the full editor + migration +
      mass-ops flow end to end for at least one non-DraftWorkspace type in
      each of GLOBAL and RequestAccess scope.
