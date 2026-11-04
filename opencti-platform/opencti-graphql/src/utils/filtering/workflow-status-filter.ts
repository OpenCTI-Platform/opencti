import { UnsupportedError } from '../../config/errors';
import { fullEntitiesList } from '../../database/middleware-loader';
import { FilterMode, FilterOperator } from '../../generated/graphql';
import { getWorkflowDefaultState } from '../../modules/workflow/domain/workflow-domain';
import { ENTITY_TYPE_WORKFLOW_INSTANCE } from '../../modules/workflow/types/workflow-types';
import type { AuthContext } from '../../types/user';
import { bypassDraftContext } from '../draftContext';
import { WORKFLOW_INSTANCE_STATUS_FILTER } from './filtering-constants';

// Page size only: fullEntitiesList keeps paginating until every match is loaded.
const WORKFLOW_INSTANCE_PAGE_SIZE = 5000;

const isWorkflowStatusFilter = (f: any) => f.key?.includes(WORKFLOW_INSTANCE_STATUS_FILTER);
const hasWorkflowStatusFilter = (group: any): boolean => (group.filters ?? []).some(isWorkflowStatusFilter)
  || (group.filterGroups ?? []).some(hasWorkflowStatusFilter);

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

const findInstanceEntityIds = async (executionCtx: AuthContext, stateFilters: any[]) => {
  const workflowInstances = await fullEntitiesList(executionCtx, executionCtx.user!, [ENTITY_TYPE_WORKFLOW_INSTANCE], {
    first: WORKFLOW_INSTANCE_PAGE_SIZE,
    filters: { mode: FilterMode.And, filters: stateFilters, filterGroups: [] },
  });
  return workflowInstances.map((wi: any) => wi.entity_id as string).filter(Boolean);
};

// An entity is in exactly one state, so the values match "in any of them" (eq) or "in none of them" (not_eq).
// The filter's own mode is not read: 'and' over several states would only match nothing (eq) or everything (not_eq).
// Like getWorkflowInstance, an entity without a WorkflowInstance (or without a currentState) is in the
// initial state, and no entity has a status when its type has no published workflow.
const resolveFilter = async (executionCtx: AuthContext, filter: any, defaultState: WorkflowDefaultState) => {
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
    entityIds = await findInstanceEntityIds(executionCtx, [matchingState]);
  } else if (isPresence) {
    // Every entity has a state, so none is left out.
    entityIds = [];
  } else {
    // Every entity matches except those whose instance is in another state.
    entityIds = await findInstanceEntityIds(executionCtx, [
      hasState,
      { key: ['currentState'], values: filter.values, operator: FilterOperator.NotEq, mode: FilterMode.And },
    ]);
  }
  // The ids are the matching entities, or with a matching initial state the non-matching ones.
  return idFilter(entityIds, isNegative === initialStateMatches);
};

// Each filter is replaced where it stands, so the caller's modes and nesting keep their meaning.
const resolveGroup = async (executionCtx: AuthContext, group: any, defaultState: WorkflowDefaultState): Promise<any> => ({
  ...group,
  filters: await Promise.all((group.filters ?? []).map((f: any) => (isWorkflowStatusFilter(f) ? resolveFilter(executionCtx, f, defaultState) : f))),
  filterGroups: await Promise.all((group.filterGroups ?? []).map((g: any) => resolveGroup(executionCtx, g, defaultState))),
});

// WorkflowInstance.currentState lives outside the tracked entity, so a workflow status filter
// cannot be applied natively: it is rewritten into an id filter on the matching entities.
// The caller's query must already be scoped to entityType.
export const resolveWorkflowStatusFilter = async (context: AuthContext, args: any, entityType: string): Promise<any> => {
  const { filters } = args;
  if (!filters || !hasWorkflowStatusFilter(filters)) return args;
  const executionCtx = bypassDraftContext(context);
  const defaultState = await getWorkflowDefaultState(executionCtx, executionCtx.user!, entityType);
  return { ...args, filters: await resolveGroup(executionCtx, filters, defaultState) };
};
