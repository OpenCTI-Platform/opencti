import { StatusScope } from '../../../generated/graphql';
import type { BasicWorkflowStatus, BasicWorkflowTemplateEntity } from '../../../types/store';
import type { WorkflowSerializedTransition } from '../types/workflow-types';

export interface WorkflowMigrationDiagnostic {
  type: string;
  message: string;
  statusId?: string;
}

// A migrated state carries a fully-computed, sequential `order` (its final rank in the migrated
// sequence, 0-based) — unlike the real `WorkflowSerializedState`, which has no ordering concept at
// all (a real workflow's order is inferred from its transition graph). Exposing this rank is only
// meaningful in the context of a legacy-Status migration, so it lives in its own type rather than
// polluting the shared `WorkflowSerializedState` used by real, persisted workflow definitions.
export interface WorkflowMigrationState {
  statusId: string;
  order: number;
}

export interface WorkflowMigrationDefinitionData {
  initialState: string;
  states: WorkflowMigrationState[];
  transitions: WorkflowSerializedTransition[];
}

export interface WorkflowMigrationConversionResult {
  definition: WorkflowMigrationDefinitionData;
  diagnostics: WorkflowMigrationDiagnostic[];
}

export type WorkflowMigrationByScope = Partial<Record<StatusScope, WorkflowMigrationConversionResult>>;

export interface ConvertStatusToDefinitionResult {
  byScope: WorkflowMigrationByScope;
}

// Turns a display name into a valid, human-readable event segment (`In Progress` -> `IN_PROGRESS`),
// falling back to the raw id if the name is missing/empty so the event is never blank.
const toEventSegment = (value: string): string => {
  const segment = value.trim().toUpperCase().replace(/[^A-Z0-9]+/g, '_').replace(/^_+|_+$/g, '');
  return segment || value;
};

/**
 * Synthesizes a fully-connected transition graph over `states`: legacy `Status` data has no
 * edge/transition concept, only a flat `order`, and today's `StatusField` UI lets users jump to
 * any status in any order. To introduce zero new ordering restrictions on migrated data, every
 * state must be able to transition to every other state. One transition is synthesized per target
 * state, with `from` listing every other state, rather than one transition per ordered pair
 * (N transitions instead of N*(N-1)). The event name uses the target status's display name (e.g.
 * `MOVE_TO_APPROVED`) rather than its id, to match the naming convention of hand-authored
 * transitions (e.g. `NEW_EVENT`).
 */
const synthesizeFullyConnectedTransitions = (
  states: WorkflowMigrationState[],
  templatesById: Map<string, BasicWorkflowTemplateEntity>,
): WorkflowSerializedTransition[] => {
  const stateIds = states.map((state) => state.statusId);
  if (stateIds.length < 2) return [];
  return stateIds.map((to) => {
    const name = templatesById.get(to)?.name ?? to;
    return {
      from: stateIds.filter((id) => id !== to),
      to,
      event: `MOVE_TO_${toEventSegment(name)}`,
    };
  });
};

const hasOrder = (status: BasicWorkflowStatus): boolean => status.order !== undefined && status.order !== null;

const convertScopeGroup = (
  statuses: BasicWorkflowStatus[],
  templatesById: Map<string, BasicWorkflowTemplateEntity>,
): WorkflowMigrationConversionResult => {
  const diagnostics: WorkflowMigrationDiagnostic[] = [];

  // One state per distinct StatusTemplate, keeping the first occurrence's ordering info.
  const seenTemplateIds = new Set<string>();
  const uniqueStatuses: BasicWorkflowStatus[] = [];
  statuses.forEach((status) => {
    if (!seenTemplateIds.has(status.template_id)) {
      seenTemplateIds.add(status.template_id);
      uniqueStatuses.push(status);
    }
  });

  uniqueStatuses.forEach((status) => {
    if (!hasOrder(status)) {
      diagnostics.push({
        type: 'MISSING_ORDER',
        message: `Status ${status.id} (template ${status.template_id}) has no order value; falling back to source order.`,
        statusId: status.id,
      });
    }
  });

  // Statuses with a defined order sort by that value; statuses missing order keep their original
  // (source array) relative order, appended after the ordered ones — a deterministic best-effort
  // fallback rather than a hard failure.
  const ordered = uniqueStatuses
    .map((status, index) => ({ status, index }))
    .sort((a, b) => {
      if (hasOrder(a.status) && hasOrder(b.status)) return a.status.order - b.status.order;
      if (hasOrder(a.status)) return -1;
      if (hasOrder(b.status)) return 1;
      return a.index - b.index;
    })
    .map((entry) => entry.status);

  // Name-conflict diagnostic: two distinct states (different template_id) resolving to the same
  // display name would be indistinguishable to a human reviewing the migrated definition.
  const nameCounts = new Map<string, number>();
  ordered.forEach((status) => {
    const name = templatesById.get(status.template_id)?.name ?? status.template_id;
    nameCounts.set(name, (nameCounts.get(name) ?? 0) + 1);
  });
  ordered.forEach((status) => {
    const name = templatesById.get(status.template_id)?.name ?? status.template_id;
    if ((nameCounts.get(name) ?? 0) > 1) {
      diagnostics.push({
        type: 'NAME_CONFLICT',
        message: `Multiple statuses resolve to the same display name "${name}" (status ${status.id}, template ${status.template_id}).`,
        statusId: status.id,
      });
    }
  });

  // `order` is always the state's final 0-based rank in `ordered` (not the raw legacy value):
  // statuses without a legacy order were already appended after the ordered ones above, so their
  // rank here is well-defined and reflects the actual migrated sequence, not a gap.
  const states: WorkflowMigrationState[] = ordered.map((status, order) => ({
    statusId: status.template_id,
    order,
  }));

  return {
    definition: {
      initialState: states[0]?.statusId ?? '',
      states,
      transitions: synthesizeFullyConnectedTransitions(states, templatesById),
    },
    diagnostics,
  };
};

/**
 * Pure conversion of legacy `Status[]` (for a given entity type) into a `WorkflowDefinitionData`
 * per `scope`, with diagnostics. No context/user/store access: this function only shapes data
 * that is already in memory, so it can be reused for both the read-only preview and the actual
 * migration without any side effects of its own.
 *
 * Groups `statuses` by `scope` and converts each group independently — an entity type can have
 * both `GLOBAL` and `REQUEST_ACCESS`-scoped `Status` sets coexisting, and since the mapping key
 * established elsewhere in this module is (entity type, scope, state), a single merged
 * definition would be ambiguous or silently wrong. `templates` supplies display names via
 * `template_id`, used both for diagnostics and for synthesized transition event names; state
 * identity is always `template_id`, never the name.
 */
export const convertStatusToDefinition = (
  statuses: BasicWorkflowStatus[],
  templates: BasicWorkflowTemplateEntity[],
): ConvertStatusToDefinitionResult => {
  const templatesById = new Map(templates.map((template) => [template.id, template]));

  const byScopeStatuses = new Map<StatusScope, BasicWorkflowStatus[]>();
  statuses.forEach((status) => {
    const scope = status.scope ?? StatusScope.Global;
    const group = byScopeStatuses.get(scope) ?? [];
    group.push(status);
    byScopeStatuses.set(scope, group);
  });

  const byScope: WorkflowMigrationByScope = {};
  byScopeStatuses.forEach((group, scope) => {
    byScope[scope] = convertScopeGroup(group, templatesById);
  });

  return { byScope };
};
