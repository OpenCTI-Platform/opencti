import { logMigration } from '../config/conf';
import { elUpdateByQueryForMigration } from '../database/engine';
import { READ_INDEX_INTERNAL_OBJECTS } from '../database/utils';
import { ENTITY_TYPE_DRAFT_WORKSPACE } from '../modules/draftWorkspace/draftWorkspace-types';
import { getWorkflowDefaultState } from '../modules/workflow/domain/workflow-domain';
import { projectDraftWorkflowStatuses } from '../modules/workflow/domain/workflow-draft-projection';
import { executionContext, SYSTEM_USER } from '../utils/access';

const message = '[MIGRATION] Project the workflow state of drafts onto x_opencti_workflow_id';

// Drafts only just registered x_opencti_workflow_id: every transition projects it from now on,
// existing drafts get the Status of their current state, or of the initial state without an instance.
// Publishing the DraftWorkspace workflow projects the drafts too, for a workflow published later.
export const up = async (next: () => void) => {
  logMigration.info(`${message} > started`);
  const context = executionContext('migration');
  const defaultState = await getWorkflowDefaultState(context, SYSTEM_USER, ENTITY_TYPE_DRAFT_WORKSPACE);
  if (!defaultState) {
    logMigration.info(`${message} > done, DraftWorkspace has no published workflow`);
    next();
    return;
  }
  const { updated, total } = await projectDraftWorkflowStatuses(
    context,
    SYSTEM_USER,
    defaultState.initialState,
    (body) => elUpdateByQueryForMigration(message, READ_INDEX_INTERNAL_OBJECTS, body),
  );
  logMigration.info(`${message} > done, ${updated} of ${total} drafts updated`);
  next();
};

export const down = async (next: () => void) => {
  next();
};
