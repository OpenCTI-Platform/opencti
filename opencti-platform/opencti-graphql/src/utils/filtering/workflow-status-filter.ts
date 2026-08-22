import { logApp } from '../../config/conf';
import { fullEntitiesList } from '../../database/middleware-loader';
import { FilterMode, FilterOperator } from '../../generated/graphql';
import { ENTITY_TYPE_WORKFLOW_INSTANCE } from '../../modules/workflow/types/workflow-types';
import type { AuthContext, AuthUser } from '../../types/user';
import { bypassDraftContext } from '../draftContext';
import { WORKFLOW_INSTANCE_STATUS_FILTER } from './filtering-constants';

const WORKFLOW_INSTANCE_QUERY_BOUND = 5000;

/**
 * Resolves a `WORKFLOW_INSTANCE_STATUS_FILTER` filter (workflow state / `StatusTemplate` ids) on
 * `args.filters` into an `id` filter listing the matching `entityType` entities. Necessary
 * because `WorkflowInstance.currentState` lives on a separate document from the entity it
 * tracks, so the match can't be expressed as a native field filter on the entity itself.
 * No-op (returns `args` unchanged) when no such filter is present.
 *
 * This is the shared, entity-type-parameterized generalization of the `DraftWorkspace`-only
 * `resolveWorkflowInstanceStatusFilter` (per plan.md Task 4, option (b): resolved explicitly at
 * the domain-query layer, not injected into `completeSpecialFilterKeys`). `entityType` isn't used
 * to scope the underlying `WorkflowInstance` query below — it has no `entity_type` attribute (see
 * workflow-instance-entity.ts) — the resulting id-list is only ever combined into a query already
 * scoped to `entityType`'s own index, so ids belonging to other entity types are harmlessly
 * dropped downstream. It's still required explicitly so callers are unambiguous about which
 * entity type they're filtering, and it's used below to flag the pre-existing `first: 5000` bound
 * (same limitation `draftWorkspace-domain.ts` already has today — see plan.md Task 4 Step 3.2)
 * when it's actually hit for a given type, rather than silently truncating matches.
 */
export const resolveWorkflowStatusFilter = async (
  context: AuthContext,
  user: AuthUser,
  entityType: string,
  args: any,
): Promise<any> => {
  const { filters } = args;
  if (!filters) return args;

  const workflowStatusFilters = filters.filters?.filter((f: any) => f.key?.includes(WORKFLOW_INSTANCE_STATUS_FILTER)) ?? [];
  if (workflowStatusFilters.length === 0) return args;

  // Filter values are StatusTemplate IDs — WorkflowInstance.currentState stores them directly.
  const statusTemplateIds: string[] = workflowStatusFilters.flatMap((f: any) => f.values as string[]);
  const executionCtx = bypassDraftContext(context);
  const executionUser = executionCtx.user!;

  const workflowInstances = await fullEntitiesList(executionCtx, executionUser, [ENTITY_TYPE_WORKFLOW_INSTANCE], {
    first: WORKFLOW_INSTANCE_QUERY_BOUND,
    filters: {
      mode: FilterMode.And,
      filters: [{ key: ['currentState'], values: statusTemplateIds, operator: FilterOperator.Eq, mode: FilterMode.Or }],
      filterGroups: [],
    },
  });

  if (workflowInstances.length === WORKFLOW_INSTANCE_QUERY_BOUND) {
    logApp.warn('[OPENCTI-MODULE] Workflow status filter hit the WorkflowInstance query bound, matches may be truncated', { entityType, bound: WORKFLOW_INSTANCE_QUERY_BOUND });
  }

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
