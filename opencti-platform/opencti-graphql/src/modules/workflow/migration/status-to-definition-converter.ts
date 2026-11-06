import { FunctionalError } from '../../../config/errors';
import { StatusScope } from '../../../generated/graphql';
import type { BasicWorkflowStatus, BasicWorkflowTemplateEntity } from '../../../types/store';
import type { WorkflowSerializedState, WorkflowSerializedTransition } from '../types/workflow-types';

export type WorkflowMigrationDiagnosticType = 'MISSING_ORDER' | 'DUPLICATE_ORDER' | 'DUPLICATE_TEMPLATE' | 'NAME_CONFLICT' | 'MISSING_TEMPLATE' | 'EXISTING_WORKFLOW';

export interface WorkflowMigrationDiagnostic {
  type: WorkflowMigrationDiagnosticType;
  message: string;
  // Id of the legacy `Status` entity the diagnostic is about.
  legacyStatusId?: string;
  // `StatusTemplate` id of that status, i.e. the `statusId` of the matching migrated state.
  templateId?: string;
}

// A migrated state is a plain `WorkflowSerializedState` whose optional legacy `order` is always set:
// its final 0-based rank in the migrated sequence.
export type WorkflowMigrationState = WorkflowSerializedState & { order: number };

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

// Events are capped at 255 characters by validation: `MOVE_TO_` (8) + segment + a `_N` uniqueness
// suffix must fit, so the segment itself is capped well below that.
const MAX_EVENT_SEGMENT_LENGTH = 200;

// Turns a display name into a valid, human-readable event segment (`In Progress` -> `IN_PROGRESS`),
// falling back to the trimmed raw value when nothing ASCII is left (e.g. a non-Latin name) so the
// event is never blank.
const toEventSegment = (value: string): string => {
  const segment = value.trim().toUpperCase().replace(/[^A-Z0-9]+/g, '_').replace(/^_+|_+$/g, '');
  return (segment || value.trim()).slice(0, MAX_EVENT_SEGMENT_LENGTH);
};

// A blank/whitespace-only template name is treated the same as a missing one everywhere in this
// module (falls back to the template id), so both the transition-naming and name-conflict checks
// agree on what counts as "blank".
const resolveDisplayName = (templateId: string, templatesById: Map<string, BasicWorkflowTemplateEntity>): string => {
  const rawName = templatesById.get(templateId)?.name;
  return rawName && rawName.trim().length > 0 ? rawName : templateId;
};

/**
 * Synthesizes a fully-connected transition graph over `states`: legacy `Status` data has no
 * edge/transition concept, only a flat `order`, and today's `StatusField` UI lets users jump to
 * any status in any order. To introduce zero new ordering restrictions on migrated data, every
 * state must be able to transition to every other state. One transition is emitted per ordered
 * (from, to) pair, with a single-string `from`, like the front editor does: the engine matches a
 * transition on `from === currentState`. All transitions into the same state share one event
 * name, built from its display name (e.g. `MOVE_TO_APPROVED`) rather than its id, to match the
 * naming convention of hand-authored transitions; duplicates are only checked per (from, event).
 */
const synthesizeFullyConnectedTransitions = (
  states: WorkflowMigrationState[],
  templatesById: Map<string, BasicWorkflowTemplateEntity>,
): WorkflowSerializedTransition[] => {
  const stateIds = states.map((state) => state.statusId);
  if (stateIds.length < 2) return [];
  // Different names can normalize to the same segment ("In Progress" / "in-progress"), which would
  // fail validation with DUPLICATE_TRANSITION_EVENT. The first state keeps the natural segment; a
  // later one gets the first free `_2`, `_3`... suffix, skipping segments other states use naturally.
  const segments = stateIds.map((id) => toEventSegment(resolveDisplayName(id, templatesById)));
  const taken = new Set(segments);
  const claimed = new Set<string>();
  const uniqueSegments = segments.map((segment) => {
    if (!claimed.has(segment)) {
      claimed.add(segment);
      return segment;
    }
    let suffix = 2;
    while (taken.has(`${segment}_${suffix}`)) suffix += 1;
    const unique = `${segment}_${suffix}`;
    taken.add(unique);
    return unique;
  });
  return stateIds.flatMap((to, index) => stateIds
    .filter((from) => from !== to)
    .map((from) => ({ from, to, event: `MOVE_TO_${uniqueSegments[index]}` })));
};

const hasOrder = (status: BasicWorkflowStatus): boolean => status.order !== undefined && status.order !== null;

const convertScopeGroup = (
  statuses: BasicWorkflowStatus[],
  templatesById: Map<string, BasicWorkflowTemplateEntity>,
): WorkflowMigrationConversionResult => {
  const diagnostics: WorkflowMigrationDiagnostic[] = [];

  // Statuses with a defined order sort by that value; statuses missing order are appended after the
  // ordered ones. Ties (equal or missing order) break on the status id, never on store return order,
  // so the preview and the migration always produce the same sequence.
  const sorted = [...statuses].sort((a, b) => {
    if (hasOrder(a) && hasOrder(b) && a.order !== b.order) return a.order - b.order;
    if (hasOrder(a) !== hasOrder(b)) return hasOrder(a) ? -1 : 1;
    return a.id.localeCompare(b.id);
  });

  // One state per distinct StatusTemplate, ranked by the occurrence with the lowest order. States
  // are keyed by template, so every Status sharing it maps to that one state: entities on a dropped
  // duplicate keep their status and land in the same state, and their next transition moves them
  // onto whichever Status the workflow projects for that template.
  const keptByTemplateId = new Map<string, BasicWorkflowStatus>();
  const ordered: BasicWorkflowStatus[] = [];
  sorted.forEach((status) => {
    const kept = keptByTemplateId.get(status.template_id);
    if (kept) {
      diagnostics.push({
        type: 'DUPLICATE_TEMPLATE',
        message: `Status ${status.id} uses template ${status.template_id}, like status ${kept.id}; both become one state, ranked by the order of ${kept.id}. Entities on either status stay in that state.`,
        legacyStatusId: status.id,
        templateId: status.template_id,
      });
      return;
    }
    keptByTemplateId.set(status.template_id, status);
    ordered.push(status);
  });

  ordered.forEach((status) => {
    if (!hasOrder(status)) {
      diagnostics.push({
        type: 'MISSING_ORDER',
        message: `Status ${status.id} (template ${status.template_id}) has no order value; it is placed after the ordered statuses, by status id.`,
        legacyStatusId: status.id,
        templateId: status.template_id,
      });
    }
    if (!templatesById.has(status.template_id)) {
      diagnostics.push({
        type: 'MISSING_TEMPLATE',
        message: `Status ${status.id} references template ${status.template_id}, which no longer exists; falling back to the template id as its display name.`,
        legacyStatusId: status.id,
        templateId: status.template_id,
      });
    }
  });

  // Duplicate-order diagnostic: statuses sharing the same legacy `order` within a scope group are
  // ordered by status id, which a reviewer may not expect.
  const orderCounts = new Map<number, number>();
  ordered.forEach((status) => {
    if (hasOrder(status)) {
      orderCounts.set(status.order, (orderCounts.get(status.order) ?? 0) + 1);
    }
  });
  ordered.forEach((status) => {
    if (hasOrder(status) && (orderCounts.get(status.order) ?? 0) > 1) {
      diagnostics.push({
        type: 'DUPLICATE_ORDER',
        message: `Multiple statuses share order ${status.order} (status ${status.id}, template ${status.template_id}); the tie is broken by status id.`,
        legacyStatusId: status.id,
        templateId: status.template_id,
      });
    }
  });

  // Name-conflict diagnostic: two distinct states (different template_id) resolving to the same
  // display name would be indistinguishable to a human reviewing the migrated definition.
  const nameCounts = new Map<string, number>();
  ordered.forEach((status) => {
    const name = resolveDisplayName(status.template_id, templatesById);
    nameCounts.set(name, (nameCounts.get(name) ?? 0) + 1);
  });
  ordered.forEach((status) => {
    const name = resolveDisplayName(status.template_id, templatesById);
    if ((nameCounts.get(name) ?? 0) > 1) {
      diagnostics.push({
        type: 'NAME_CONFLICT',
        message: `Multiple statuses resolve to the same display name "${name}" (status ${status.id}, template ${status.template_id}).`,
        legacyStatusId: status.id,
        templateId: status.template_id,
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

/**
 * Turns the converted REQUEST_ACCESS group of Case-Rfi into a request access definition that passes
 * publish validation: the states of the legacy approved / declined statuses (identified by their
 * template) are marked as outcomes, the Approved one shares the requested entities with the
 * requesting organization on enter, transitions into them are named `Accept` / `Reject`, and every
 * transition leaving them is dropped. The other states keep their jump-anywhere transitions.
 */
export const convertRequestAccessGroup = (
  result: WorkflowMigrationConversionResult,
  approvedTemplateId: string,
  declinedTemplateId: string,
): WorkflowMigrationConversionResult => {
  const { definition } = result;
  if (approvedTemplateId === declinedTemplateId) {
    throw FunctionalError('Cannot migrate request access: the approved and declined statuses must use different status templates', { approvedTemplateId, declinedTemplateId });
  }
  const stateIds = new Set(definition.states.map((state) => state.statusId));
  const missingTemplateIds = [approvedTemplateId, declinedTemplateId].filter((templateId) => !stateIds.has(templateId));
  if (missingTemplateIds.length > 0) {
    throw FunctionalError('Cannot migrate request access: the approved or declined status is not one of the request access statuses', { missingTemplateIds });
  }
  if (definition.initialState === approvedTemplateId || definition.initialState === declinedTemplateId) {
    throw FunctionalError('Cannot migrate request access: the approved or declined status cannot be the initial state, it must not be the first request access status by order', { initialState: definition.initialState });
  }
  const outcomeIds = new Set([approvedTemplateId, declinedTemplateId]);
  const states: WorkflowMigrationState[] = definition.states.map((state) => {
    if (state.statusId === approvedTemplateId) {
      return { ...state, requestAccessOutcome: 'APPROVED', onEnter: [...(state.onEnter ?? []), { type: 'shareRequestedEntities', params: { organizations: ['AUTHOR'] } }] };
    }
    if (state.statusId === declinedTemplateId) {
      return { ...state, requestAccessOutcome: 'DECLINED' };
    }
    return state;
  });
  const transitions = definition.transitions
    .filter((transition) => !(Array.isArray(transition.from) ? transition.from : [transition.from]).some((from) => outcomeIds.has(from)))
    .map((transition) => {
      if (transition.to === approvedTemplateId) return { ...transition, event: 'Accept' };
      if (transition.to === declinedTemplateId) return { ...transition, event: 'Reject' };
      return transition;
    });
  return {
    definition: { ...definition, states, transitions },
    diagnostics: result.diagnostics,
  };
};

// GraphQL-ready shape for a single scope's preview result, distinct from `WorkflowMigrationConversionResult`
// because it also carries the `hasPublishedVersion` field expected by the `WorkflowMigrationScopeResult`
// schema type.
export interface WorkflowMigrationScopeResult {
  scope: StatusScope;
  initialState: string;
  hasPublishedVersion: boolean;
  states: WorkflowMigrationState[];
  transitions: WorkflowSerializedTransition[];
  diagnostics: WorkflowMigrationDiagnostic[];
}

export interface WorkflowMigrationPreviewResult {
  entityType: string;
  results: WorkflowMigrationScopeResult[];
}

// GLOBAL first, then any other scope by name, so the output does not depend on store ordering.
const compareScopes = (a: string, b: string): number => {
  if (a === b) return 0;
  if (a === StatusScope.Global) return -1;
  if (b === StatusScope.Global) return 1;
  return a.localeCompare(b);
};

/**
 * Pure reshaping of `byScope` (keyed by `StatusScope`) into the flat `results` array expected by
 * the `WorkflowMigrationPreview` GraphQL type. Kept here, next to `convertStatusToDefinition`,
 * rather than in the resolver, so it stays unit-testable without a resolver/context and the
 * resolver stays a thin bridge to domain logic. `hasPublishedVersion` tells whether the entity
 * type's existing workflow has a published version; it only applies to the GLOBAL scope, the only
 * one a workflow covers.
 */
export const buildWorkflowMigrationPreviewResult = (
  entityType: string,
  byScope: WorkflowMigrationByScope,
  hasPublishedVersion = false,
): WorkflowMigrationPreviewResult => ({
  entityType,
  results: Object.entries(byScope)
    .filter((entry): entry is [string, WorkflowMigrationConversionResult] => entry[1] !== undefined)
    .sort(([a], [b]) => compareScopes(a, b))
    .map(([scope, result]) => ({
      scope: scope as StatusScope,
      initialState: result.definition.initialState,
      hasPublishedVersion: hasPublishedVersion && scope === StatusScope.Global,
      states: result.definition.states,
      transitions: result.definition.transitions,
      diagnostics: result.diagnostics,
    })),
});

// Diagnostics that make a migrated definition unsafe to publish straight away: a state whose
// template no longer exists, or two states a human cannot tell apart. Ordering and duplicate
// diagnostics (MISSING_ORDER / DUPLICATE_ORDER / DUPLICATE_TEMPLATE) are only warnings, the
// converter resolves them deterministically. EXISTING_WORKFLOW is gated by `overwrite` instead.
const PUBLISH_BLOCKING_DIAGNOSTIC_TYPES: WorkflowMigrationDiagnosticType[] = ['NAME_CONFLICT', 'MISSING_TEMPLATE'];

export const getPublishBlockingDiagnostics = (diagnostics: WorkflowMigrationDiagnostic[]): WorkflowMigrationDiagnostic[] => {
  return diagnostics.filter((diagnostic) => PUBLISH_BLOCKING_DIAGNOSTIC_TYPES.includes(diagnostic.type));
};

/**
 * Picks the result of one scope out of a conversion result, and throws when that scope has no
 * statuses to migrate. GLOBAL is an entity type's workflow; REQUEST_ACCESS is the request access
 * workflow of Case-Rfi, finished by `convertRequestAccessGroup`.
 */
export const pickMigrationScope = (
  entityType: string,
  byScope: WorkflowMigrationByScope,
  scope: StatusScope = StatusScope.Global,
): WorkflowMigrationConversionResult => {
  const result = byScope[scope];
  if (!result || result.definition.states.length === 0) {
    throw FunctionalError('No legacy statuses to migrate', { entityType, scope });
  }
  return result;
};
