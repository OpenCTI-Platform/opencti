## Design Summary

Follow-up to `status-as-workflow-instance-projection`: the new workflow engine's
graph editor, per-type `WorkflowInstance`/`workflow_id` plumbing, and mass-op
backend hooks were all built generically, but three integration gaps mean none
of it is actually reachable/usable for entity types other than `DraftWorkspace`:

1. **Routing gap**: `Root.tsx`'s "Workflow" settings tab hardcodes
   `isDraftWorkspaceType ? <SubTypeWorkflow /> : <GlobalWorkflowSettingsCard />`
   — every other entity type always renders the old legacy Status
   enable/disable card, regardless of the `ENTITIES_WORKFLOW` flag.
   `SubTypeWorkflow.tsx` also hardcodes `entityType: 'DraftWorkspace'` in its
   GraphQL query variables and never threads an `entityType` prop to
   `<Workflow>`, even though `Workflow.tsx` itself already accepts a generic
   `entityType` prop and is unit-tested for other types.
2. **Ordering-algorithm gap**: `computeStateOrder` (`workflow-ordering.ts`)
   returns `null` for the *entire* reachable subgraph the moment **any** cycle
   exists anywhere in it, forcing every state (even ones unrelated to the
   cycle) to require a manually supplied `order`. This makes the migration UI
   painful for real-world Status graphs, which routinely have cycles (e.g.
   "reopen" transitions back to an earlier state).
3. **Mass-ops gap**: `DataTableToolBar.jsx`'s existing "Status" mass-edit
   option is the old free-choice Status autocomplete — it has no concept of
   the new engine's allowed-transitions graph or the bypass-with-actions mode.
   Backend-wise, Task 10's `applyTransitionActions` mass mode only ever wired
   the **bypass** path (`setWorkflowStatus`, no edge/condition checks); there
   is no mass path that follows `triggerWorkflowEvent`'s real allowed-transition
   graph at all.

## Alternatives Considered

### Alternative A: Fully unified, silent, dual-scope routing/migration
- **Approach**: Generalize routing/editor to any `entityType` + a
  `Global`/`RequestAccess` scope switcher, with the legacy-Status-to-workflow
  migration triggered silently and automatically the first time the tab is
  opened for a type/scope that has no `WorkflowDefinition` yet.
- **Pros**: Simplest end-user flow — no extra click, ever.
- **Cons**: Migration is a real, side-effecting backend action (creates +
  publishes a `WorkflowDefinition`, which per the parent change's Global
  Constraints immediately activates backend enforcement for that type
  regardless of the UI flag). Doing this invisibly just because an admin
  opened a settings tab is a real safety concern — no chance to review
  `workflowMigrationPreview` diagnostics (missing order, name conflicts,
  orphan statuses) before they're baked into a published definition.
- **Why not chosen**: the blast radius of a fully silent, mutating,
  enforcement-activating side effect is too high for a page visit.

### Alternative B: Defer RequestAccess scope entirely (Global-only)
- **Approach**: Same routing/generalization work, but only ever expose the
  `Global`-scope definition in the new editor; `RequestAccessSettings` (the
  existing EE card) stays as the only way to manage request-access workflows,
  matching the parent change's original Task 6 GLOBAL-only migration scoping.
- **Pros**: Smallest blast radius; avoids touching
  `migrateEntityTypeStatusToWorkflowDefinition`'s existing fail-loud guard for
  `RequestAccess`-scoped Status data.
- **Cons**: Leaves request-access workflows on the old UI indefinitely, which
  directly contradicts the goal of unifying the workflow-editing experience.
- **Why not chosen**: explicitly de-scoped by the user in favor of full
  dual-scope support now.

### Alternative C: Dual-scope routing with a one-time migration confirm (chosen)
- **Approach**: Same generalized routing/scope-switcher as A, but the
  legacy-Status-to-workflow migration is not fully silent: the *first*,
  actually-mutating visit to a type/scope with no `WorkflowDefinition` yet
  shows a lightweight confirm step with `workflowMigrationPreview` diagnostics
  inline; accepting performs the migration once. Every subsequent visit opens
  the editor directly (feels "auto" outside of that one first-time gate).
- **Pros**: Keeps the single coherent dual-scope editor experience requested,
  without an admin unknowingly triggering a persisted, published,
  enforcement-activating side effect merely by clicking a settings tab.
- **Cons**: One extra step compared to a fully silent flow, but only the very
  first time per type/scope.
- **Why not chosen**: N/A — this is the agreed approach.

## Agreed Approach

**1. Routing generalization (Alternative C)**
- `Root.tsx`: replace the literal `isDraftWorkspaceType` branch with
  `isWorkflowUiEnabledForType(subTypeId, isFeatureEnable)` to decide between
  the new graph editor and the legacy `GlobalWorkflowSettingsCard`.
- `SubTypeWorkflow.tsx` / `Workflow.tsx`: thread the actual `subTypeId` through
  as `entityType` (default remains `'DraftWorkspace'` for existing callers),
  plus a `scope: Global | RequestAccess` prop/switcher. `allowDraft` stays
  `DraftWorkspace`-specific.
- `migrateEntityTypeStatusToWorkflowDefinition`: extend to actually implement
  `RequestAccess`-scope migration (currently throws `FunctionalError` on any
  `RequestAccess`-scoped Status data) — needed since RequestAccess is now in
  scope for the editor.
- New (or reused) GraphQL mutation to trigger the one-time migration from the
  frontend (today `migrateEntityTypeStatusToWorkflowDefinition` is only
  invoked from the canary-gated deploy-time migration file / tests, not from
  any live mutation).
- Tab eligibility stays the current set (everything with `workflow_configuration`
  available, i.e. everything except cyber observables/external references).

**2. Cycle-tolerant status ordering**
- Replace `computeStateOrder`'s all-or-nothing behavior with a per-state
  longest-*simple*-path computation: DFS from `initialState`, using a
  "visited" set scoped to the *current* path only (not global), so revisiting
  a node via a different branch is still explored, but a true cycle back to an
  already-on-this-path node stops that branch instead of looping forever. A
  state's order = the longest simple-path length found to it.
- This is a strictly better-scoped fix than today's "any cycle anywhere ⇒
  every state needs manual order": only states actually entangled in a cycle
  (i.e., where the longest-simple-path search is genuinely ambiguous/unbounded
  for that specific state) still require a manual order fallback.
- Add a bounded work cap on the DFS (workflow graphs are small — tens of
  states) with a graceful fallback to today's existing "manual order required"
  path if the cap is ever exceeded, rather than hanging.

**3. Mass operations UI — two distinct actions**
- **Real transition mass-apply** (new backend + frontend): admin picks a
  transition (by `event`) for the selection's entity type; a new task
  action type applies it via `triggerWorkflowEvent` per selected element.
  Elements not currently in that transition's required `from` state are
  skipped and error-counted server-side (matching the existing tolerant
  per-element error handling already used by the bypass mass-op callback) —
  the frontend does **not** need to know every selected row's current status
  up front (this also has to work with "select all matching filter", where
  per-row state isn't available client-side at all). Available to any
  `KNOWLEDGE_KNUPDATE` user, same gating as the single-entity "Apply
  transition" action.
- **Bypass forced mass update** (frontend-only, backend already exists via
  `applyTransitionActions` + `setWorkflowStatus`): admin/bypass-users only,
  mirrors `WorkflowBypassStatus.tsx`'s single-entity UX (target status +
  "apply onExit/onEnter actions" toggle + comment) applied to the current
  bulk selection.
- Both replace/extend the existing plain "Status" `x_opencti_workflow_id`
  mass-edit option in `DataTableToolBar.jsx`, gated by
  `isWorkflowUiEnabledForType`.

## Key Decisions

- Rollout is a single `ENTITIES_WORKFLOW` flag for all types at once — no
  per-type allow-list (unlike Task 6's migration canary).
- RequestAccess-scope editing is in scope, exposed via a scope switcher in the
  same graph canvas (not a separate tab/route).
- Legacy-to-workflow migration is confirm-gated on the first mutating visit
  per type/scope, not fully silent, because it's a real persisted/published
  side effect that activates backend enforcement immediately.
- Status ordering: fix at the algorithm level (per-state longest-simple-path
  DFS) rather than just improving the manual-order UX around the existing
  all-or-nothing cycle check.
- Mass "real transition" apply tolerates a heterogeneous/unknown-state
  selection server-side rather than requiring the frontend to pre-validate
  every row's current status.

## Open Questions

- Exact DFS work cap for the longest-simple-path ordering computation (needs a
  concrete number, informed by realistic max state/transition counts) —
  deferred to design.md.
- Exact shape of the new "trigger the migration" mutation (dedicated mutation
  vs. reusing/extending an existing one) — deferred to design.md.
- Whether the real-transition mass-apply needs the same EE/condition
  re-evaluation as the single-entity `triggerWorkflowEvent` path (conditions,
  EE gating) — almost certainly yes since it calls the same function, but
  worth confirming no mass-specific bypass of conditions is expected.
