import { logApp } from '../../../config/conf';
import { updateAttribute } from '../../../database/middleware';
import { fullEntitiesList } from '../../../database/middleware-loader';
import { FilterMode, type StatusScope } from '../../../generated/graphql';
import { ENTITY_TYPE_STATUS } from '../../../schema/internalObject';
import type { BasicStoreEntity, BasicWorkflowStatus } from '../../../types/store';
import type { AuthContext } from '../../../types/user';
import { bypassDraftContext } from '../../../utils/draftContext';

/**
 * Projects a workflow state onto the legacy `x_opencti_workflow_id` field of an entity, by
 * resolving the `Status` mapped to (entity type, scope, state) and writing its id. `scope` is an
 * explicit parameter — callers already have it on hand (from the `WorkflowInstance` they're
 * acting on) and must never re-derive it ad hoc, since the mapping key includes scope.
 *
 * A missing mapping (e.g. transient eventual-consistency window right after publish) is logged
 * and skipped rather than thrown — this is a projection best-effort write, not a hard invariant
 * check; callers (sync/async transition paths, read-repair) must not fail on it.
 */
export const projectWorkflowState = async (
  context: AuthContext,
  entity: BasicStoreEntity & { id?: string; internal_id?: string; entity_type: string },
  stateId: string,
  scope: StatusScope,
): Promise<void> => {
  const executionContext = bypassDraftContext(context);
  const executionUser = executionContext.user!;
  const entityType = entity.entity_type;
  const entityId = entity.internal_id || entity.id;

  try {
    const matchingStatuses = await fullEntitiesList<BasicWorkflowStatus>(executionContext, executionUser, [ENTITY_TYPE_STATUS], {
      filters: {
        mode: FilterMode.And,
        filters: [
          { key: ['type'], values: [entityType] },
          { key: ['scope'], values: [scope] },
          { key: ['template_id'], values: [stateId] },
        ],
        filterGroups: [],
      },
    });
    const status = matchingStatuses[0];
    if (!status) {
      logApp.warn('[OPENCTI-MODULE] No Status mapped for workflow state, skipping projection', { entityType, scope, stateId });
      return;
    }

    await updateAttribute(executionContext, executionUser, entityId, entityType, [
      { key: 'x_opencti_workflow_id', value: [status.id] },
    ]);
  } catch (error) {
    logApp.warn('[OPENCTI-MODULE] Failed to project workflow state onto entity', { cause: error, entityType, scope, stateId, entityId });
  }
};
