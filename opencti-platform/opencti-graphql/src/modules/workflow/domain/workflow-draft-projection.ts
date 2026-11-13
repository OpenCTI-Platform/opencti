import { fullEntitiesList } from '../../../database/middleware-loader';
import { FilterMode } from '../../../generated/graphql';
import { ENTITY_TYPE_DRAFT_WORKSPACE } from '../../draftWorkspace/draftWorkspace-types';
import { ENTITY_TYPE_WORKFLOW_INSTANCE } from '../types/workflow-types';
import { ENTITY_TYPE_STATUS } from '../../../schema/internalObject';
import type { BasicWorkflowStatus } from '../../../types/store';
import type { AuthContext, AuthUser } from '../../../types/user';
import { resolveProjectionScope } from './workflow-projection';

/**
 * Projects the workflow state of every draft onto `x_opencti_workflow_id`: the Status of the current
 * state of its instance, or of the initial state for a draft without instance (or without state).
 * Drafts hold a status only once something projected it, so this runs when the DraftWorkspace
 * workflow is published (existing drafts are in its initial state) and from the migration that
 * introduced the projection. Only the drafts that hold another status are updated.
 *
 * `update` runs the update by query, so that the migration can wait for its task and a publication
 * can not. Returns the number of drafts updated.
 */
export const projectDraftWorkflowStatuses = async (
  context: AuthContext,
  user: AuthUser,
  initialState: string | null | undefined,
  update: (body: object) => Promise<unknown>,
): Promise<{ updated: number; total: number }> => {
  const statuses = await fullEntitiesList<BasicWorkflowStatus>(context, user, [ENTITY_TYPE_STATUS], {
    filters: { mode: FilterMode.And, filters: [{ key: ['type'], values: [ENTITY_TYPE_DRAFT_WORKSPACE] }], filterGroups: [] },
  });
  const statusIdOf = new Map(statuses.map((status) => [`${status.scope}|${status.template_id}`, status.id]));
  const drafts = await fullEntitiesList<any>(context, user, [ENTITY_TYPE_DRAFT_WORKSPACE]);
  const instances = drafts.length === 0 ? [] : await fullEntitiesList<any>(context, user, [ENTITY_TYPE_WORKFLOW_INSTANCE], {
    filters: { mode: FilterMode.And, filters: [{ key: ['entity_id'], values: drafts.map((draft) => draft.internal_id) }], filterGroups: [] },
  });
  const instanceOf = new Map(instances.map((instance) => [instance.entity_id as string, instance]));

  const statusIdByDraftId: Record<string, string> = {};
  for (let i = 0; i < drafts.length; i += 1) {
    const draft = drafts[i];
    const instance = instanceOf.get(draft.internal_id);
    const state = instance?.currentState ?? initialState;
    const statusId = state ? statusIdOf.get(`${resolveProjectionScope(instance?.scope)}|${state}`) : undefined;
    if (statusId && draft.x_opencti_workflow_id !== statusId) {
      statusIdByDraftId[draft.internal_id] = statusId;
    }
  }
  const draftIds = Object.keys(statusIdByDraftId);
  if (draftIds.length > 0) {
    await update({
      script: {
        params: { statusIdByDraftId },
        source: 'ctx._source.x_opencti_workflow_id = params.statusIdByDraftId[ctx._source.internal_id]',
      },
      query: {
        bool: {
          must: [
            { term: { 'entity_type.keyword': { value: ENTITY_TYPE_DRAFT_WORKSPACE } } },
            { terms: { 'internal_id.keyword': draftIds } },
          ],
        },
      },
    });
  }
  return { updated: draftIds.length, total: drafts.length };
};
