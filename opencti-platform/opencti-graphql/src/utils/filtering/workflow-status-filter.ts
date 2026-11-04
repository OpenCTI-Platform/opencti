import { UnsupportedError } from '../../config/errors';
import { fullEntitiesList } from '../../database/middleware-loader';
import { FilterMode, FilterOperator } from '../../generated/graphql';
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

// An entity is in exactly one state, so the values match "in any of them" (eq) or "in none of them" (not_eq).
// The filter's own mode is not read: 'and' over several states would only match nothing (eq) or everything (not_eq).
// An entity without a WorkflowInstance has no status, so nil excludes and not_nil keeps every entity that has one.
const resolveFilter = async (executionCtx: AuthContext, filter: any) => {
  const operator = filter.operator ?? FilterOperator.Eq;
  const isNegative = NEGATIVE_OPERATORS.includes(operator);
  if (!isNegative && !POSITIVE_OPERATORS.includes(operator)) {
    throw UnsupportedError('Workflow status filter only supports equality and empty operators', { operator });
  }
  const isPresence = operator === FilterOperator.Nil || operator === FilterOperator.NotNil;
  // Filter values are StatusTemplate ids, as stored in WorkflowInstance.currentState.
  const stateFilter = isPresence
    ? { key: ['currentState'], values: [], operator: FilterOperator.NotNil, mode: FilterMode.Or }
    : { key: ['currentState'], values: filter.values, operator: FilterOperator.Eq, mode: FilterMode.Or };
  const workflowInstances = await fullEntitiesList(executionCtx, executionCtx.user!, [ENTITY_TYPE_WORKFLOW_INSTANCE], {
    first: WORKFLOW_INSTANCE_PAGE_SIZE,
    filters: { mode: FilterMode.And, filters: [stateFilter], filterGroups: [] },
  });
  const entityIds = workflowInstances.map((wi: any) => wi.entity_id as string).filter(Boolean);
  return {
    key: ['id'],
    values: entityIds.length > 0 ? entityIds : ['<no-match>'],
    operator: isNegative ? FilterOperator.NotEq : FilterOperator.Eq,
    mode: isNegative ? FilterMode.And : FilterMode.Or,
  };
};

// Each filter is replaced where it stands, so the caller's modes and nesting keep their meaning.
const resolveGroup = async (executionCtx: AuthContext, group: any): Promise<any> => ({
  ...group,
  filters: await Promise.all((group.filters ?? []).map((f: any) => (isWorkflowStatusFilter(f) ? resolveFilter(executionCtx, f) : f))),
  filterGroups: await Promise.all((group.filterGroups ?? []).map((g: any) => resolveGroup(executionCtx, g))),
});

// WorkflowInstance.currentState lives outside the tracked entity, so a workflow status filter
// cannot be applied natively: it is rewritten into an id filter on the matching entities.
// The caller's query must already be scoped to the tracked entity type.
export const resolveWorkflowStatusFilter = async (context: AuthContext, args: any): Promise<any> => {
  const { filters } = args;
  if (!filters || !hasWorkflowStatusFilter(filters)) return args;
  return { ...args, filters: await resolveGroup(bypassDraftContext(context), filters) };
};
