## Why

The backend/UI plumbing from `status-as-workflow-instance-projection` (per-type
`WorkflowInstance`, `workflow_id`, mass-op task hooks) was built generically,
but three integration gaps leave it unreachable in practice: the Workflow
settings tab still hardcodes the legacy card for every type except
`DraftWorkspace`, the state-ordering algorithm forces manual ordering on
entire graphs the moment any cycle exists anywhere in them (common in
real-world Status data with "reopen" transitions), and there is no UI (and,
for real-transition mass-apply, no backend path either) for bulk workflow
operations. Fixing these three gaps is what makes the parent change actually
usable beyond `DraftWorkspace`.

## What Changes

**Workflow editor routing**
- From: `Root.tsx` always renders `GlobalWorkflowSettingsCard` (legacy Status
  toggle) for every entity type except the literal `DraftWorkspace`.
- To: the tab renders the generalized graph editor (`Workflow.tsx`) for any
  type where `isWorkflowUiEnabledForType` is true, with a `Global`/
  `RequestAccess` scope switcher in the same canvas.
- Reason: the graph editor and its scope-aware backend plumbing already exist
  and are unit-tested generically; only the routing/wiring was missing.
- Impact: non-breaking for `DraftWorkspace` (unchanged); for every other type,
  the Workflow tab's content changes once `ENTITIES_WORKFLOW` is enabled.

**Legacy-status-to-workflow migration entry point**
- From: `migrateEntityTypeStatusToWorkflowDefinition` is only reachable via a
  canary-gated deploy-time migration file or direct test calls, and throws on
  any `RequestAccess`-scoped Status data.
- To: a one-time, confirm-gated migration step (showing
  `workflowMigrationPreview` diagnostics) runs the first time the new editor
  is opened for a type/scope with no `WorkflowDefinition` yet; the migration
  function is extended to support `RequestAccess` scope.
- Reason: opening the new editor is the natural point to convert legacy data,
  but doing so silently would be an invisible, enforcement-activating side
  effect.
- Impact: non-breaking; only triggered by an explicit admin action inside the
  new editor.

**Cycle-tolerant status ordering**
- From: `computeStateOrder` returns `null` for the whole reachable subgraph
  if any cycle exists anywhere in it, forcing every state to need a manual
  `order`.
- To: per-state longest-simple-path DFS (path-scoped visited set, bounded work
  cap with graceful fallback) so only states actually entangled in a cycle
  need a manual `order`.
- Reason: real Status graphs commonly have cycles (e.g. reopen transitions);
  the current behavior makes migration/authoring needlessly painful.
- Impact: non-breaking; strictly reduces how often manual `order` is required.

**Mass workflow operations**
- From: `DataTableToolBar.jsx`'s "Status" mass-edit is a plain free-choice
  Status autocomplete with no transition/bypass concept; the backend's
  `applyTransitionActions` mass mode only supports the bypass path
  (`setWorkflowStatus`), not real allowed-transition following.
- To: two distinct mass actions — (1) a new real-transition mass-apply backed
  by `triggerWorkflowEvent` per element (server-side tolerant of elements not
  currently in the transition's required `from` state), available to any
  `KNOWLEDGE_KNUPDATE` user; (2) a bypass forced mass-update UI (frontend
  only — backend already exists) mirroring `WorkflowBypassStatus.tsx`,
  restricted to bypass/admin users.
- Reason: bulk workflow actions were designed for the single-entity case only;
  extending to bulk requires both new backend support (real-transition mode)
  and new frontend UI (both modes).
- Impact: non-breaking addition; existing plain Status mass-edit continues to
  work for types without a published `WorkflowDefinition`.

## Capabilities

### New Capabilities
- `workflow-editor-rollout`: generalizing the graph-editor UI, routing, and
  scope switcher to any entity type with a configured workflow, including the
  confirm-gated legacy-status migration entry point.
- `workflow-state-ordering`: the cycle-tolerant, per-state longest-simple-path
  ordering computation used during workflow authoring/validation.
- `workflow-mass-operations`: bulk real-transition apply and bulk bypass
  forced status update, both UI and (for real-transition) backend support.

### Modified Capabilities
- None — `openspec/specs/` has no existing capability specs yet (the parent
  change `status-as-workflow-instance-projection` has not been archived), so
  there is nothing to modify at the spec level; this proposal introduces new
  capability specs only.

## Impact

- **Frontend**: `Root.tsx`, `SubTypeWorkflow.tsx`, `Workflow.tsx` (scope prop
  + entityType threading), `DataTableToolBar.jsx` (new mass-op UI), new
  bulk-bypass component mirroring `WorkflowBypassStatus.tsx`.
- **Backend**: `workflow-ordering.ts` (`computeStateOrder` rewrite),
  `migrate-status-to-workflow-definition.ts` (RequestAccess scope support),
  a new/extended GraphQL mutation to trigger migration from the frontend,
  `taskManager.js` (new real-transition mass-apply action type calling
  `triggerWorkflowEvent`).
- **GraphQL schema**: new mutation for triggering the legacy-status migration;
  possible new task action-type/input for real-transition mass-apply.
- **Dependencies**: builds directly on `status-as-workflow-instance-projection`
  (workflow engine, `WorkflowInstance`, `workflow_id` projection, existing
  mass-op task hooks) — no new external dependencies.
