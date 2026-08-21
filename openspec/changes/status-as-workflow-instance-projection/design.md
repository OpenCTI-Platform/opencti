## Design Summary

OpenCTI has two disconnected status mechanisms: legacy `Status` (stamped on
every entity at creation, instantly filterable/sortable) and the new
state-machine `WorkflowInstance` (currently wired only for `DraftWorkspace`,
lazily faked via an `initial-...` placeholder until a real transition
happens). The goal is to extend the workflow engine to all entity types
while making `WorkflowInstance.currentState` the single source of truth,
without a mass data migration — achieved via a CQRS-style projection where
legacy `Status` (`x_opencti_workflow_id`) becomes a derived, continuously
projected view of the workflow instance, preserving all existing
sort/filter/widget/stream behavior.

## Alternatives Considered

### Alternative A: Full backfill migration
- **Approach**: Write a migration that creates a real `WorkflowInstance` for
  every existing entity of a workflow-enabled type, converting legacy
  `Status` history into workflow history directly.
- **Pros**: Conceptually simple; no dual-write/projection logic; a single
  clean source of truth from day one.
- **Cons**: Requires a heavy, long-running, riskier data migration across
  every entity type and index; legacy status history reconstruction is
  lossy/ambiguous; harder to roll back; blocks incremental per-entity-type
  rollout.
- **Why not chosen**: Explicitly rejected due to migration risk/cost vs. the
  CQRS alternative, which achieves the same end state without touching
  entity documents in bulk.

### Alternative B: Dual system, no unification
- **Approach**: Extend `WorkflowInstance` to more entity types but keep
  `Status`/`x_opencti_workflow_id` and `WorkflowInstance.currentState` as
  two independent, unsynchronized fields; let the UI pick whichever exists.
- **Pros**: Least backend work; no projection/consistency logic needed.
- **Cons**: Filtering/sorting/widgets keep needing per-entity-type
  fallback logic (the exact "confusing mix" problem the plan aims to
  remove); direct writers (playbooks, requestAccess, public API, sync
  manager) could silently diverge from workflow state indefinitely.
- **Why not chosen**: Doesn't solve the stated goal of one consistent status
  concept; only defers the inconsistency problem.

### Alternative C: CQRS projection (chosen)
- **Approach**: `WorkflowInstance.currentState` is the source of truth;
  `Status`/`x_opencti_workflow_id` becomes a generated, write-through
  projection maintained via the normal attribute-patch flow after every
  state change (sync transition, async completion, and external/direct
  writes reconciled via a tolerant "external state jump" sync).
- **Pros**: No mass entity migration; existing sort/filter/widget/stream
  consumers keep working unchanged; incremental rollout entity-type by
  entity-type behind one flag; direct-write flows (playbooks, requestAccess,
  sync manager, public API) keep working in a tolerant mode instead of all
  needing simultaneous rerouting.
- **Cons**: More upfront design/invariant work (state↔status mapping
  guarantees, ordering, deletion protection, read-repair) than a naive
  backfill; requires careful write-order and consistency handling for
  concurrent writers.
- **Why not chosen**: N/A — this is the agreed approach.

## Agreed Approach

Adopt **Alternative C (CQRS projection)**. `WorkflowInstance.currentState` is
the single source of truth for any entity type with a published
`WorkflowDefinition`; `x_opencti_workflow_id` (`Status`) remains the
queryable field, generated deterministically from workflow state and kept in
sync via normal attribute-patch writes (never raw ES writes) so stream,
history, and notifications stay intact.

### Core principles
1. Single source of truth: `WorkflowInstance.currentState`.
2. Deterministic projection: `x_opencti_workflow_id` is derived from
   `WorkflowInstance.currentState` via generated `Status` records.
3. Fixed write order: update instance first, project to entity second.
4. Full mapping guarantee: every published workflow state maps to a
   `Status` for each attached entity type.
5. Statuses referenced by a published workflow cannot be deleted.

### Phase plan (merges the original product chunks 0-9 with the CQRS phases)

| Phase | Content | Source |
|---|---|---|
| **1.1 — Invariant (blocking)** | Add `order` to workflow states (topological, manual fallback). On publish: ensure every attached entity type has a `Status` per state (create missing; delete orphaned/unreferenced ones on republish — unreferenced means no entity currently has `x_opencti_workflow_id` pointing at it and no `WorkflowDefinition` state maps to it). Block deletion of `Status`/`StatusTemplate` referenced by a published workflow. No `Status` creation on draft save. | CQRS Phase 1.1 |
| **1.2 — Extend + new UI (flag)** | `initializeEntityWorkflow` generalized to all entity types at creation. New workflow UI (from DraftWorkspace) reused, gated by a single `ENTITIES_WORKFLOW` flag. Hide draft-only actions (validate draft, Authorized Members actions) for non-draft/non-container entities. Filters/sort/widgets untouched (still query `x_opencti_workflow_id`). | Chunks 2, 4, 5 + CQRS 1.2 |
| **2.1 — Projection** | Implement state→status projection function; run after sync transition and async completion paths; read-repair on `getWorkflowInstance` divergence. | CQRS 2.1 |
| **2.2 — Legacy-aware fallback** | No `WorkflowInstance` → behave exactly as legacy `Status` today. Missing/invalid mapping → fall back to `initialState`. | CQRS 2.2 |
| **2.3 — Definition migration** | Pure `Status → WorkflowDefinition` conversion function + diagnostics; read-only preview query for PO validation; versioned migration reusing the same function to create definitions/set `workflow_id` refs. Replaces the separate migration-endpoint chunks — no bulk entity-status migration needed since projection handles individual entities lazily. | Chunks 1, 3 → CQRS 2.3 |
| **2.4 — Request access** | Two workflow definitions allowed per entity type; `request_access`-scoped cases use the second definition. | Chunk 0 + CQRS 2.4 |
| **3 — Concurrent writers** | Tolerant mode: direct `Status` writes (playbooks, requestAccess, public API, sync manager) remain allowed; each direct write triggers a `WorkflowInstance.currentState` sync recorded as an `event_external` history entry. | CQRS Phase 3 |
| **4 — UX: apply transition** | User-facing transition action on entity view (pending spinner, error display); creates a `WorkflowInstance` on first use if only legacy `Status` existed. | Chunk 6 |
| **5 — UX: bypass update** | Popover: "update status only" vs. "update status + apply onExit/onEnter transitions". | Chunk 7 |
| **6 — UX: mass operations** | Same two update modes for bulk background-task status updates and playbook status actions. | Chunk 8 |
| **7 — Closing reason field** | New field, backend modeled like comments, dedicated UI. | Chunk 9 |

### EE gating
- Core state-machine mechanics (enforced ordering, no-skip transitions) are
  Community Edition, matching draft-workspace precedent.
- Role-based transition restriction and automated actions on
  transition/status (Apply/Remove Authorized Members, share, comment,
  validate) are Enterprise Edition, matching draft-workspace precedent.

### Deployment strategy
- Single `ENTITIES_WORKFLOW` flag gates the entire feature (backend wiring +
  frontend UI) until all phases are production-ready; only `DraftWorkspace`
  stays on its current dedicated path until then.
- Phases 1.1 → 3 are backend-only and can ship dark (flag off)
  incrementally; UI phases (1.2, 4-7) require the flag enabled.
- Rollout respects the dependency order in the phase table; Phase 1.1 is
  blocking for everything else.

### Draft entities and workflow
- Entities *inside* a Draft (DraftWorkspace content, not the DraftWorkspace
  itself) keep using legacy `Status` while in draft; they only get a real
  `WorkflowInstance` once validated into the live index. Deferred, not
  in scope for this plan.

## Key Decisions

- CQRS projection (Alternative C) over full backfill or dual-system.
- Stale/orphaned `Status` records are deleted once unreferenced by any
  entity's `x_opencti_workflow_id` and by any `WorkflowDefinition` state.
- Ordering of workflow states: topological when possible, manual fallback
  otherwise.
- `request_access` gets its own separate `WorkflowDefinition` per entity
  type rather than branching within one definition.
- Legacy status history reconstruction into workflow history is not
  required (accepted gap).
- Single feature flag (`ENTITIES_WORKFLOW`) for the whole rollout, not
  per-entity-type flags.
- Draft-contained entities (not DraftWorkspace itself) do not get a
  `WorkflowInstance`; deferred.
- Scope includes all 10 original chunks (0-9), not just the CQRS core.

## Open Questions

- Exact mechanism for reconciling concurrent direct writes with in-flight
  async transitions (ordering guarantees when both happen close together).
- Whether the EE/CE boundary for the extended (non-draft) engine needs
  product sign-off beyond the draft-workspace precedent assumed here.
