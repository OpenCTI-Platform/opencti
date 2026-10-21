import { fullEntitiesList } from '../../database/middleware-loader';
import { FilterMode, FilterOperator } from '../../generated/graphql';
import { ENTITY_TYPE_WORKFLOW_INSTANCE } from '../../modules/workflow/types/workflow-types';
import type { AuthContext } from '../../types/user';
import { bypassDraftContext } from '../draftContext';
import { WORKFLOW_INSTANCE_STATUS_FILTER } from './filtering-constants';

// Page size only: fullEntitiesList keeps paginating until every match is loaded.
const WORKFLOW_INSTANCE_PAGE_SIZE = 5000;

// WorkflowInstance.currentState lives outside the tracked entity, so a workflow status filter
// cannot be applied natively: it is rewritten into an id filter on the matching entities.
// The caller's query must already be scoped to the tracked entity type.
export const resolveWorkflowStatusFilter = async (context: AuthContext, args: any): Promise<any> => {
  const { filters } = args;
  if (!filters) return args;

  const workflowStatusFilters = filters.filters?.filter((f: any) => f.key?.includes(WORKFLOW_INSTANCE_STATUS_FILTER)) ?? [];
  if (workflowStatusFilters.length === 0) return args;

  // Filter values are StatusTemplate ids, as stored in WorkflowInstance.currentState.
  const statusTemplateIds: string[] = workflowStatusFilters.flatMap((f: any) => f.values as string[]);
  const executionCtx = bypassDraftContext(context);

  const workflowInstances = await fullEntitiesList(executionCtx, executionCtx.user!, [ENTITY_TYPE_WORKFLOW_INSTANCE], {
    first: WORKFLOW_INSTANCE_PAGE_SIZE,
    filters: {
      mode: FilterMode.And,
      filters: [{ key: ['currentState'], values: statusTemplateIds, operator: FilterOperator.Eq, mode: FilterMode.Or }],
      filterGroups: [],
    },
  });

  const entityIds = workflowInstances
    .map((wi: any) => wi.entity_id as string)
    .filter(Boolean);

  const remainingFilters = filters.filters.filter((f: any) => !f.key?.includes(WORKFLOW_INSTANCE_STATUS_FILTER));
  const idFilter = { key: ['id'], values: entityIds.length > 0 ? entityIds : ['<no-match>'], operator: FilterOperator.Eq, mode: FilterMode.Or };

  return {
    ...args,
    filters: {
      ...filters,
      filters: [...remainingFilters, idFilter],
    },
  };
};
