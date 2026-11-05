import { BadUserInputError, UnsupportedError } from '../../config/errors';
import { fullEntitiesList } from '../../database/middleware-loader';
import { FilterMode, FilterOperator } from '../../generated/graphql';
import { getWorkflowDefaultState } from '../../modules/workflow/domain/workflow-domain';
import { ENTITY_TYPE_WORKFLOW_INSTANCE } from '../../modules/workflow/types/workflow-types';
import type { AuthContext } from '../../types/user';
import { bypassDraftContext } from '../draftContext';
import { WORKFLOW_INSTANCE_STATUS_FILTER } from './filtering-constants';

// Page size only: fullEntitiesList keeps paginating until every match is loaded.
const WORKFLOW_INSTANCE_PAGE_SIZE = 5000;

// Each status filter can cost a full WorkflowInstance scan, so one filter tree may only hold a few.
export const MAX_WORKFLOW_STATUS_FILTERS = 10;

const isWorkflowStatusFilter = (f: any) => f.key?.includes(WORKFLOW_INSTANCE_STATUS_FILTER);
const countWorkflowStatusFilters = (group: any): number => (group.filters ?? []).filter(isWorkflowStatusFilter).length
  + (group.filterGroups ?? []).reduce((count: number, g: any) => count + countWorkflowStatusFilters(g), 0);

const POSITIVE_OPERATORS: string[] = [FilterOperator.Eq, FilterOperator.OnlyEqTo, FilterOperator.NotNil];
const NEGATIVE_OPERATORS: string[] = [FilterOperator.NotEq, FilterOperator.NotOnlyEqTo, FilterOperator.Nil];

type WorkflowDefaultState = { initialState: string | null } | null;

// With no ids, keeping matches nothing and excluding matches everything.
const idFilter = (entityIds: string[], keep: boolean) => ({
  key: ['id'],
  values: entityIds.length > 0 ? entityIds : ['<no-match>'],
  operator: keep ? FilterOperator.Eq : FilterOperator.NotEq,
  mode: keep ? FilterMode.Or : FilterMode.And,
});

// Identical lookups of one filter tree share a single scan: the key ignores the order of the states.
type InstanceLookupCache = Map<string, Promise<string[]>>;

const findInstanceEntityIds = (executionCtx: AuthContext, cache: InstanceLookupCache, stateFilters: any[]) => {
  const cacheKey = JSON.stringify(stateFilters.map((f) => ({ ...f, values: [...f.values].sort() })));
  let entityIds = cache.get(cacheKey);
  if (!entityIds) {
    entityIds = fullEntitiesList(executionCtx, executionCtx.user!, [ENTITY_TYPE_WORKFLOW_INSTANCE], {
      first: WORKFLOW_INSTANCE_PAGE_SIZE,
      filters: { mode: FilterMode.And, filters: stateFilters, filterGroups: [] },
    }).then((workflowInstances) => workflowInstances.map((wi: any) => wi.entity_id as string).filter(Boolean));
    cache.set(cacheKey, entityIds);
  }
  return entityIds;
};

// An entity is in exactly one state, so the values match "in any of them" (eq) or "in none of them" (not_eq).
// The filter's own mode is not read: 'and' over several states would only match nothing (eq) or everything (not_eq).
// Like getWorkflowInstance, an entity without a WorkflowInstance (or without a currentState) is in the
// initial state, and no entity has a status when its type has no published workflow.
const resolveFilter = async (executionCtx: AuthContext, cache: InstanceLookupCache, filter: any, defaultState: WorkflowDefaultState) => {
  const operator = filter.operator ?? FilterOperator.Eq;
  const isNegative = NEGATIVE_OPERATORS.includes(operator);
  if (!isNegative && !POSITIVE_OPERATORS.includes(operator)) {
    throw UnsupportedError('Workflow status filter only supports equality and empty operators', { operator });
  }
  if (!defaultState) return idFilter([], !isNegative);
  const isPresence = operator === FilterOperator.Nil || operator === FilterOperator.NotNil;
  const { initialState } = defaultState;
  const initialStateMatches = !!initialState && (isPresence || filter.values.includes(initialState));
  // Filter values are StatusTemplate ids, as stored in WorkflowInstance.currentState.
  const hasState = { key: ['currentState'], values: [], operator: FilterOperator.NotNil, mode: FilterMode.Or };
  let entityIds: string[];
  if (!initialStateMatches) {
    // Only entities whose instance is in a matching state match.
    const matchingState = isPresence ? hasState : { key: ['currentState'], values: filter.values, operator: FilterOperator.Eq, mode: FilterMode.Or };
    entityIds = await findInstanceEntityIds(executionCtx, cache, [matchingState]);
  } else if (isPresence) {
    // Every entity has a state, so none is left out.
    entityIds = [];
  } else {
    // Every entity matches except those whose instance is in another state.
    entityIds = await findInstanceEntityIds(executionCtx, cache, [
      hasState,
      { key: ['currentState'], values: filter.values, operator: FilterOperator.NotEq, mode: FilterMode.And },
    ]);
  }
  // The ids are the matching entities, or with a matching initial state the non-matching ones.
  return idFilter(entityIds, isNegative === initialStateMatches);
};

// Each filter is replaced where it stands, so the caller's modes and nesting keep their meaning.
const resolveGroup = async (executionCtx: AuthContext, cache: InstanceLookupCache, group: any, defaultState: WorkflowDefaultState): Promise<any> => ({
  ...group,
  filters: await Promise.all((group.filters ?? []).map((f: any) => (isWorkflowStatusFilter(f) ? resolveFilter(executionCtx, cache, f, defaultState) : f))),
  filterGroups: await Promise.all((group.filterGroups ?? []).map((g: any) => resolveGroup(executionCtx, cache, g, defaultState))),
});

// WorkflowInstance.currentState lives outside the tracked entity, so a workflow status filter
// cannot be applied natively: it is rewritten into an id filter on the matching entities.
// The caller's query must already be scoped to entityType.
export const resolveWorkflowStatusFilter = async (context: AuthContext, args: any, entityType: string): Promise<any> => {
  const { filters } = args;
  const statusFilterCount = filters ? countWorkflowStatusFilters(filters) : 0;
  if (statusFilterCount === 0) return args;
  if (statusFilterCount > MAX_WORKFLOW_STATUS_FILTERS) {
    throw BadUserInputError('Too many workflow status filters', { count: statusFilterCount, max: MAX_WORKFLOW_STATUS_FILTERS });
  }
  const executionCtx = bypassDraftContext(context);
  const defaultState = await getWorkflowDefaultState(executionCtx, executionCtx.user!, entityType);
  return { ...args, filters: await resolveGroup(executionCtx, new Map(), filters, defaultState) };
};
