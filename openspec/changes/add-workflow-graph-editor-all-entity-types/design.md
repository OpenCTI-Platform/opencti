## Context

`status-as-workflow-instance-projection` built the new workflow engine end to
end (`WorkflowDefinition`, `WorkflowInstance` projection, `workflow_id`,
`triggerWorkflowEvent`, `setWorkflowStatus`, `workflowMigrationPreview`,
`Workflow.tsx` graph editor, mass-op task hooks) but wired the live UI to only
`DraftWorkspace`. Three concrete integration gaps block using any of this for
other entity types:

- `Root.tsx` (`opencti-front/src/private/components/settings/sub_types/Root.tsx`)
  routes the Workflow settings tab based on a literal
  `subTypeId === 'DraftWorkspace'` check, not the `ENTITIES_WORKFLOW` feature
  flag or `isWorkflowUiEnabledForType`. `SubTypeWorkflow.tsx` hardcodes
  `entityType: 'DraftWorkspace'` in its query variables.
- `computeStateOrder` (`workflow-ordering.ts`) does whole-graph BFS + a
  separate white/gray/black DFS cycle check; if `hasCycle` is true anywhere in
  the reachable subgraph, it returns `null` for the *entire* graph, which
  `workflow-validation.ts` turns into a `MISSING_MANUAL_ORDER` error for every
  state, even ones with no involvement in the cycle.
- `migrateEntityTypeStatusToWorkflowDefinition` is GLOBAL-scope only by
  explicit prior product decision (throws `FunctionalError` on
  `RequestAccess`-scoped Status data) and is only invoked from a canary-gated
  deploy-time migration path — there is no live mutation an admin can trigger
  from the UI.
- `taskManager.js`'s `workflowTransitionOperationCallback` (mass-op backend)
  only calls `setWorkflowStatus` (bypass path); nothing in the mass-op path
  calls `triggerWorkflowEvent` (real allowed-transition path). The frontend
  `DataTableToolBar.jsx` "Status" mass-edit option is a plain Status
  autocomplete with no transition/bypass distinction at all.
- **Confirmed via code reading (not just assumption): every entity-scoped
  runtime function in `workflow-domain.ts`** (`getWorkflowInstance`,
  `getAllowedTransitions`, `triggerWorkflowEvent`, `setWorkflowStatus`,
  `batchWorkflowInstances`, `syncWorkflowInstanceFromExternalWrite`) resolves
  `getDefinitionData` with a hardcoded `StatusScope.Global` default — only
  entity *creation* (`initializeEntityWorkflow` via `resolveEntityCreationScope`)
  actually derives scope from the entity's own assigned `Status.scope`. This
  means `requestAccess-domain.ts`'s `approveRequestAccess`/`declineRequestAccess`
  (which patch `x_opencti_workflow_id` via a plain `updateAttribute` call,
  relying on the generic post-attribute-update hook —
  `syncWorkflowInstanceFromExternalWrite` — to keep the `WorkflowInstance`
  projection in sync) will silently fail to sync for any entity type whose
  only configured `WorkflowDefinition` is `RequestAccess`-scoped: the hook
  looks up the `Global`-scope definition (absent), returns early, and the
  `WorkflowInstance` never reflects the RFI's real approve/decline state. No
  changes to `requestAccess-domain.ts` itself are needed once this is fixed —
  it already goes through the generic hook mechanism by design.

Constraints carried over from the parent change (do not re-litigate):
publishing a `WorkflowDefinition` for a type immediately activates backend
enforcement for that type regardless of any frontend flag state; the
`ENTITIES_WORKFLOW` flag only gates *UI visibility* of the new editor, not
backend enforcement.

## Goals / Non-Goals

**Goals:**
- Make the graph editor (`Workflow.tsx`) reachable and functional for every
  entity type with `workflow_configuration` available, in both `Global` and
  `RequestAccess` scope, gated by `isWorkflowUiEnabledForType`.
- Provide a safe, explicit (not silent) one-time entry point to convert
  legacy `Status` data to a `WorkflowDefinition` per type/scope, including
  extending the migration function to support `RequestAccess` scope.
- Reduce how often `computeStateOrder` forces a manual `order`: only states
  actually entangled in a cycle should need one, not the whole graph.
- Add bulk (mass) workflow operations: a real-transition mass-apply (new
  backend support) and a bypass forced mass-update (frontend only).

**Non-Goals:**
- No changes to the single-entity `triggerWorkflowEvent`/`setWorkflowStatus`
  semantics themselves (conditions, EE gating, history recording) — mass
  operations reuse them as-is per element.
- No change to which entity types are eligible for workflow configuration
  (`workflow_configuration` in `availableSettings` stays the existing gate).
- No redesign of `Workflow.tsx`'s canvas/editing UX itself — it is already
  generic; this change is about reaching it and feeding it the right scope.
- Not building a generic "undo migration" / down-migration path.

## Decisions

**D1 — Routing: branch on `isWorkflowUiEnabledForType`, not a literal type check**
`Root.tsx`'s `<Route path={SUBTYPE_TAB_WORKFLOW} ...>` switches on
`isWorkflowUiEnabledForType(subTypeId, isFeatureEnable)` instead of
`isDraftWorkspaceType`. `SubTypeWorkflow.tsx` takes `entityType` from
`subTypeId` (falling back to `'DraftWorkspace'` only for its existing
call sites) instead of a literal string, and passes it through to
`<Workflow entityType={entityType} />`. `allowDraft` remains conditioned on
`entityType === 'DraftWorkspace'` since draft-object behavior is genuinely
type-specific.
- Alternative rejected: adding a second parallel route/component instead of
  generalizing the existing one — rejected because `Workflow.tsx` is already
  parameterized and unit-tested generically; duplicating it would just
  reintroduce the same kind of drift that caused this bug.

**D2 — Scope switcher lives inside the existing editor, not a separate tab**
Add a `scope: StatusScope.Global | StatusScope.RequestAccess` prop/selector
inside `Workflow.tsx`'s existing canvas (e.g., a segmented control above the
graph), rather than a second Workflow-like tab. `RequestAccess` scope is only
offered when `hasRequestAccessConfig` (EE + `request_access_workflow` in
`availableSettings`) is true — same gate `GlobalWorkflowSettingsCard` uses
today for `RequestAccessSettings`.
- Alternative rejected: keep `RequestAccessSettings` as a fully separate EE
  card alongside the new editor (Alternative B from brainstorm.md) — rejected
  because it perpetuates two different editing UIs for what is conceptually
  one workflow-configuration surface.

**D3 — Legacy migration: confirm-gated mutation using existing preview data**
Add a mutation, e.g. `migrateEntityTypeStatusToWorkflowDefinition(entityType: String!, scope: StatusScope!)`,
that wraps the existing `migrateEntityTypeStatusToWorkflowDefinition` domain
function (extended for `RequestAccess`, see D4). The frontend calls the
already-existing `workflowMigrationPreview` query first to render diagnostics
(missing order, unmapped statuses, etc.) in a confirm dialog; only on explicit
confirm does it call the new mutation. After that one-time run, subsequent
visits find `entitySetting.workflow_id` already set and go straight to the
editor.
- Alternative rejected: fully silent auto-migration on first visit
  (brainstorm Alternative A) — rejected due to the enforcement-activation
  side effect described in Context.
- Alternative rejected: defer RequestAccess migration entirely (brainstorm
  Alternative B) — rejected per explicit user requirement to support both
  scopes now.

**D4 — Extend `migrateEntityTypeStatusToWorkflowDefinition` to support `RequestAccess`**
Remove the current hard `FunctionalError` throw on `RequestAccess`-scoped
Status data; instead, run `convertStatusToDefinition`'s existing
per-scope (`byScope[StatusScope.RequestAccess]`) conversion output through
the same `setWorkflowDefinition`/`publishWorkflowDefinition` persistence path
already used for `Global`, keyed by scope. `RequestAccessFlow` routing to the
resulting `workflow_definition_id` (previously blocked on "Task 7 not
implemented") must be confirmed as landed/land alongside this — flagged as an
open question below since brainstorm.md's context says this was blocked on
prior Task 7 work.

**D4b — Resolve workflow scope per-entity from its own assigned Status, not a hardcoded default**
Generalize the existing `resolveEntityCreationScope` helper (today only used
at entity-creation time) into a shared `resolveStatusScope(context, user,
statusId?: string): Promise<StatusScope>` that looks up a given `Status`
entity's own `scope` field (defaulting to `Global` when the id is absent or
unresolvable). Use it — instead of the hardcoded `StatusScope.Global`
default — everywhere a runtime function resolves `getDefinitionData` for a
*specific entity* (as opposed to Task 3's CRUD-authoring functions, which
correctly take an explicit, UI-selected `scope` argument):
`syncWorkflowInstanceFromExternalWrite` (resolve from the `newStatusId` being
written — the fix that makes RFI approve/decline sync correctly, since it
already receives that id as a parameter), `getWorkflowInstance`,
`getAllowedTransitions`, `triggerWorkflowEvent`, `setWorkflowStatus` (resolve
from the loaded entity's current `x_opencti_workflow_id`), and
`batchWorkflowInstances` (key its per-type `definitionData` cache by
`(entityType, scope)` instead of `entityType` alone, since two entities of
the same type could in principle carry statuses of different scopes). This
is a prerequisite for D4 — extending the migration function to persist a
`RequestAccess`-scope definition is pointless if nothing at runtime can ever
resolve it for a real entity.
- Alternative rejected: have `requestAccess-domain.ts` call
  `triggerWorkflowEvent`/`setWorkflowStatus` directly instead of its current
  raw `updateAttribute` patch — rejected because the generic
  `syncWorkflowInstanceFromExternalWrite` hook mechanism already exists
  specifically to handle direct writers like this one; fixing scope
  resolution once, centrally, is smaller and lower-risk than changing
  `requestAccess-domain.ts`'s approve/decline semantics (which today are a
  direct forced write, not a validated transition, and should stay that way).

**D5 — Ordering: per-state longest-simple-path DFS, path-scoped visited set**
Rewrite `computeStateOrder` to, for each state reachable from `initialState`,
compute the length of the longest *simple* path from `initialState` to it via
DFS, where the "visited" set used to prevent infinite loops is scoped to the
*current call stack / path* (passed down through recursion), not global. A
back-edge to a node already on the current path stops that branch (cycle
avoidance) without preventing other branches through that node from being
explored. The state's order is the max path length found across all
DFS explorations reaching it. Add a bounded step counter (e.g. a constant
cap on total DFS visits, since production workflow graphs are on the order of
tens of states/transitions); if the cap is hit, fall back to returning `null`
for just the affected states (not the whole graph) so
`workflow-validation.ts`'s existing `MISSING_MANUAL_ORDER` path still
degrades gracefully for pathological inputs.
- Alternative rejected: keep BFS depth but simply suppress the global cycle
  bail-out — rejected because BFS depth does not have a well-defined meaning
  once cycles exist (a node's BFS depth doesn't reflect "how far through the
  workflow" a cyclic state actually is); longest-simple-path is the metric
  the user explicitly asked for and matches intuitive state progression.
- Alternative rejected: memoized/topological approach — not applicable
  directly since the graph isn't a DAG by assumption (that's the whole
  problem); DFS with path-scoped visited handles the general case directly.

**D6 — Mass real-transition apply: new task action type, server-side tolerant**
Add a new mass-op action recognized by `taskManager.js` (parallel to the
existing `ACTION_TYPE_WORKFLOW_TRANSITION`/bypass path) that calls
`triggerWorkflowEvent` per selected element, given a fixed `eventName`. Errors
from elements not currently in an eligible `from` state for that event are
caught and counted per-element (same tolerant pattern already used by
`workflowTransitionOperationCallback` for the bypass path), so a
heterogeneous or "select all matching filter" selection doesn't abort the
whole task. Available to any `KNOWLEDGE_KNUPDATE` user, matching
`triggerWorkflowEvent`'s existing single-entity auth.

**D7 — Mass bypass forced update: frontend-only, backend reused as-is**
`DataTableToolBar.jsx` gets a new mass-edit UI variant (modeled on
`WorkflowBypassStatus.tsx`: target status + "apply onEnter/onExit actions"
toggle + comment) that, on submit, uses the *existing* `applyTransitionActions`
mass-op backend path (bypass path already implemented, calls
`setWorkflowStatus`). No backend change needed for this mode. Gated to
bypass/admin users, mirroring `WorkflowBypassStatus.tsx`'s existing
`isBypassUser` gate.

## Risks / Trade-offs

- **[Risk]** Enabling `ENTITIES_WORKFLOW` surfaces the confirm-gated migration
  step for every eligible type at once (no per-type canary, per Key Decisions
  in brainstorm.md) → **Mitigation**: migration is per-type/scope and
  opt-in-per-visit (admin must open that type's tab and explicitly confirm);
  nothing is migrated in bulk automatically.
- **[Risk]** Extending `migrateEntityTypeStatusToWorkflowDefinition` for
  `RequestAccess` would resurface the exact gap it was guarding against,
  **confirmed** via code reading: `syncWorkflowInstanceFromExternalWrite` and
  every other entity-scoped runtime function default to `StatusScope.Global`
  and never resolve `RequestAccess` scope for a real entity →
  **Mitigation**: D4b lands as an explicit prerequisite task (Task 7 in
  plan.md) before D4/D3's `RequestAccess` migration path is enabled in the UI.
- **[Risk]** Longest-simple-path DFS is exponential in the worst case (dense
  graphs with many alternate routes) → **Mitigation**: bounded step cap with
  per-state graceful fallback to manual order, not an unbounded computation;
  real workflow graphs are small (tens of states).
- **[Risk]** Mass real-transition apply calling `triggerWorkflowEvent` per
  element in a large bulk selection could be slow / hit rate limits →
  **Mitigation**: reuse the existing mass-op task infrastructure's batching
  and per-element error tolerance, same as today's bypass mass-op path — no
  new concurrency model needed.
- **[Trade-off]** Confirm-gated migration is one extra step vs. a fully
  silent flow — accepted deliberately (see D3) given the side effect's
  severity (immediate backend enforcement activation).
- **[Risk]** If an admin later removes/unsets `entitySetting.request_access_workflow`
  after a `RequestAccess`-scope `WorkflowDefinition` was published, the
  `RequestAccess`-scope `Status` records created by `ensureFullStatusMapping`
  become orphaned with no config pointing at their definition →
  **Mitigation**: the existing cleanup manager's `isStatusOrphaned` check
  (extended in Task 3 to use `status.scope`) already re-verifies orphan
  status against the *current* config before hard-deleting, so this
  self-heals via the existing grace-period mechanism — no new rollback code
  needed, but worth calling out explicitly since it wasn't previously
  exercised for a non-`Global` scope.

## Migration Plan

1. Land D1/D2 (routing + scope switcher) behind the existing `ENTITIES_WORKFLOW`
   flag — no behavior change until the flag is enabled, `DraftWorkspace`
   unaffected.
2. Land D5 (ordering fix) independently — pure function change, strictly
   relaxes today's `MISSING_MANUAL_ORDER` behavior, safe to ship ungated.
3. Land D4b first (per-entity scope resolution in runtime functions — pure
   additive fix, safe to ship ungated since it only changes behavior for
   entity types that have a `RequestAccess`-scope definition, none of which
   exist yet pre-migration), then D4 (migration function RequestAccess
   support) plus D3 (mutation + confirm UI).
4. Land D6 (backend real-transition mass-op) and D7 (frontend bypass mass-op
   UI) independently of 1-3 — both are additive to `DataTableToolBar.jsx` and
   `taskManager.js`.
5. Enable `ENTITIES_WORKFLOW` for all types (single flag, no per-type
   canary, per brainstorm.md's Key Decisions).
- **Rollback**: each of the 4 areas is independently revertible (flag-gated
  routing, pure-function ordering change, additive mutation, additive mass-op
  action type) — no destructive migrations of existing data are introduced;
  the legacy `Status` migration only ever creates a new `WorkflowDefinition`
  when none exists, never mutates/deletes legacy `Status` records.

## Open Questions

- ~~Does `RequestAccessFlow` already route via `workflow_definition_id`?~~
  **Resolved during plan.md research**: no — confirmed by reading
  `requestAccess-domain.ts` (approve/decline patch `x_opencti_workflow_id`
  via a raw `updateAttribute`, relying on the generic
  `syncWorkflowInstanceFromExternalWrite` hook) and `workflow-domain.ts`
  (every entity-scoped runtime function defaults to `StatusScope.Global`).
  Resolved by landing D4b as an explicit prerequisite task.
- Concrete DFS step cap value for D5 — needs a number derived from realistic
  max state/transition counts across existing entity types (spec/tasks phase
  can pick a concrete constant, e.g. based on largest current Status set).
- Does the real-transition mass-apply (D6) need a dry-run/preview step
  (showing how many selected elements are actually eligible for the chosen
  transition) before execution, or is post-hoc error-count reporting
  sufficient? Deferred to specs/tasks.
