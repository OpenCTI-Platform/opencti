## Why

Legacy `Status` and the new `WorkflowInstance` engine are disconnected: only
`DraftWorkspace` uses real workflow instances, everything else fakes a
placeholder state. Enterprises need enforced state transitions and RBAC
across all entity types, but a full data migration to bootstrap this is
too risky. A CQRS projection lets `WorkflowInstance` become the source of
truth for every entity type while legacy `Status` fields keep working
unchanged for sort, filter, and widgets.

## What Changes

**Source of truth**
- From: Legacy `Status` (`x_opencti_workflow_id`) is stamped directly on
  entity creation and is the only reliable status data for most entity
  types; `WorkflowInstance` only exists for `DraftWorkspace` and is faked
  (`initial-...` placeholder) elsewhere.
- To: `WorkflowInstance.currentState` becomes the source of truth for any
  entity type with a published `WorkflowDefinition`. `Status`
  (`x_opencti_workflow_id`) becomes a deterministic, write-through
  projection of that state, updated via the normal attribute-patch flow.
- Reason: Enables enforced transitions/RBAC platform-wide without a mass
  entity migration.
- Impact: Non-breaking for entity types without a configured workflow
  (unchanged legacy behavior); breaking internally for how status is
  written for workflow-enabled types (now derived, not directly settable
  except through workflow transitions or the tolerant direct-write path).

**Workflow instance creation**
- From: `WorkflowInstance` created only for `DraftWorkspace`, and only
  lazily faked (never persisted) for any other type via
  `getWorkflowInstance`.
- To: `initializeEntityWorkflow` runs for all entity types at creation
  time (no-op if no workflow configured); `getWorkflowInstance` persists a
  real instance on first read for pre-existing entities instead of only
  faking one in memory.
- Reason: Avoids bulk backfill while guaranteeing a real record exists as
  soon as it's needed.
- Impact: Non-breaking; internal lazy-write behavior change only.

**Filtering**
- From: Workflow-status filtering resolved only for `DraftWorkspace` via a
  dedicated resolver in `draftWorkspace-domain.ts`.
- To: Generalized into the shared special-filter-key resolution
  (`filtering-completeSpecialFilterKeys.ts`), mirroring the existing
  legacy-status filter pattern, registered for all entity types with a
  configured workflow.
- Reason: Consistent filter behavior regardless of which system an entity
  type resolves through.
- Impact: Non-breaking; extends existing filter capability to more types.

**Migration path**
- From: Two separate planned migration endpoints (workflow definition
  migration, then entity status migration).
- To: A single pure `Status → WorkflowDefinition` conversion function with
  diagnostics, a read-only preview query, and one versioned migration that
  creates definitions/sets `workflow_id` references. No entity-level
  migration is needed — the projection mechanism handles individual
  entities lazily.
- Reason: The CQRS projection removes the need for a second, riskier
  entity-status migration.
- Impact: Non-breaking; replaces one of the two originally planned
  endpoints.

**Frontend unification**
- From: Two parallel Status display columns/filters (`workflowInstance`
  and `x_opencti_workflow_id`), with fallback logic checking for
  `initial-` placeholder ids.
- To: Single unified Status column/filter in `dataTableUtils.tsx` once an
  entity type consistently resolves through one system; placeholder
  fallback kept only as a transitional safety net.
- Reason: Removes user-facing confusion between two status concepts.
- Impact: Non-breaking, purely additive/simplifying once workflows are
  live for a type.

## Capabilities

### New Capabilities
- `workflow-status-projection`: CQRS projection making `WorkflowInstance`
  the source of truth and `Status`/`x_opencti_workflow_id` a deterministic,
  write-through projection, including state ordering, full mapping
  guarantees on publish, and deletion protection for referenced statuses.
- `workflow-entity-extension`: Extending eager workflow-instance creation,
  lazy backfill on read, generalized filtering, and the new workflow UI to
  all entity types behind a single feature flag, with the CE/EE mechanic
  boundary.
- `workflow-definition-migration`: Pure `Status → WorkflowDefinition`
  conversion with diagnostics, a read-only preview query, and a versioned
  migration to create definitions and set entity-setting workflow
  references.
- `workflow-request-access`: Supporting two workflow definitions per
  entity type so `request_access`-scoped cases use a separate definition
  from the standard one.
- `workflow-concurrent-writers`: Tolerant handling of direct `Status`
  writes from playbooks, requestAccess, the public API, and the sync
  manager, synchronizing `WorkflowInstance.currentState` as an external
  state jump.
- `workflow-transition-actions`: User-facing apply-transition action,
  bypass-update popover (status-only vs. status+transition), and the same
  update modes for mass background-task/playbook status operations.
- `workflow-closing-reason`: A closing-reason field on entities, modeled
  on the existing comments implementation with dedicated UI.

### Modified Capabilities
- None. No existing `openspec/specs/` capabilities exist yet in this repo
  to modify.

## Impact

- **Backend** (`opencti-platform/opencti-graphql`): `modules/workflow/`
  (domain, engine, registry, storage), `modules/draftWorkspace/` (filter
  logic to be generalized/removed), `modules/requestAccess/` (direct
  status writes, dual definitions), `modules/playbook/` (status-writing
  component), `utils/filtering/filtering-completeSpecialFilterKeys.ts`,
  generic entity-creation path (wherever legacy status is stamped today),
  a new versioned migration, stix converters/sync manager touching
  `x_opencti_workflow_id`.
- **Frontend** (`opencti-platform/opencti-front`): workflow UI components
  (reused from DraftWorkspace customization), `dataTableUtils.tsx` column
  and filter definitions, entity view transition/status actions, mass
  operation dialogs, `ENTITIES_WORKFLOW` feature flag wiring.
- **APIs**: GraphQL schema additions for `workflowInstance` on all
  relevant entity types, new/updated mutations for transitions and
  closing reason, a new migration-preview query.
- **Enterprise Edition**: role-based transition restriction and
  automated on-transition/on-status actions remain EE-gated, consistent
  with current `DraftWorkspace` behavior.
