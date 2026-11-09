import { logMigration } from '../config/conf';
import { elUpdateByQueryForMigration } from '../database/engine';
import { fullEntitiesList } from '../database/middleware-loader';
import { FilterMode } from '../generated/graphql';
import { READ_INDEX_INTERNAL_OBJECTS } from '../database/utils';
import { ENTITY_TYPE_DRAFT_WORKSPACE } from '../modules/draftWorkspace/draftWorkspace-types';
import { getWorkflowDefaultState } from '../modules/workflow/domain/workflow-domain';
import { resolveProjectionScope } from '../modules/workflow/domain/workflow-projection';
import { ENTITY_TYPE_WORKFLOW_INSTANCE } from '../modules/workflow/types/workflow-types';
import { ENTITY_TYPE_STATUS } from '../schema/internalObject';
import type { BasicWorkflowStatus } from '../types/store';
import { executionContext, SYSTEM_USER } from '../utils/access';

const message = '[MIGRATION] Project the workflow state of drafts onto x_opencti_workflow_id';

// Drafts only just registered x_opencti_workflow_id: every transition projects it from now on,
// existing drafts get the Status of their current state, or of the initial state without an instance.
export const up = async (next: () => void) => {
  logMigration.info(`${message} > started`);
  const context = executionContext('migration');
  const defaultState = await getWorkflowDefaultState(context, SYSTEM_USER, ENTITY_TYPE_DRAFT_WORKSPACE);
  if (!defaultState) {
    logMigration.info(`${message} > done, DraftWorkspace has no published workflow`);
    next();
    return;
  }
  const statuses = await fullEntitiesList<BasicWorkflowStatus>(context, SYSTEM_USER, [ENTITY_TYPE_STATUS], {
    filters: { mode: FilterMode.And, filters: [{ key: ['type'], values: [ENTITY_TYPE_DRAFT_WORKSPACE] }], filterGroups: [] },
  });
  const statusIdOf = new Map(statuses.map((status) => [`${status.scope}|${status.template_id}`, status.id]));
  const drafts = await fullEntitiesList<any>(context, SYSTEM_USER, [ENTITY_TYPE_DRAFT_WORKSPACE]);
  const instances = drafts.length === 0 ? [] : await fullEntitiesList<any>(context, SYSTEM_USER, [ENTITY_TYPE_WORKFLOW_INSTANCE], {
    filters: { mode: FilterMode.And, filters: [{ key: ['entity_id'], values: drafts.map((draft) => draft.internal_id) }], filterGroups: [] },
  });
  const instanceOf = new Map(instances.map((instance) => [instance.entity_id as string, instance]));

  const statusIdByDraftId: Record<string, string> = {};
  for (let i = 0; i < drafts.length; i += 1) {
    const draft = drafts[i];
    const instance = instanceOf.get(draft.internal_id);
    const state = instance?.currentState ?? defaultState.initialState;
    const statusId = state ? statusIdOf.get(`${resolveProjectionScope(instance?.scope)}|${state}`) : undefined;
    if (statusId && draft.x_opencti_workflow_id !== statusId) {
      statusIdByDraftId[draft.internal_id] = statusId;
    }
  }
  const draftIds = Object.keys(statusIdByDraftId);
  logMigration.info(`${message} > ${draftIds.length} of ${drafts.length} drafts to update`);
  if (draftIds.length > 0) {
    await elUpdateByQueryForMigration(message, READ_INDEX_INTERNAL_OBJECTS, {
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
  logMigration.info(`${message} > done`);
  next();
};

export const down = async (next: () => void) => {
  next();
};
