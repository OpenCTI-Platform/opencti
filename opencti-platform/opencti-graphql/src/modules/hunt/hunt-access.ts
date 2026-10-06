import type { AuthContext, AuthUser } from '../../types/user';
import { ForbiddenAccess } from '../../config/errors';
import { storeLoadById } from '../../database/middleware-loader';
import { AccessOperation, validateUserAccessOperation } from '../../utils/access';
import { getDraftContext } from '../../utils/draftContext';
import { type BasicStoreEntityDraftWorkspace, ENTITY_TYPE_DRAFT_WORKSPACE } from '../draftWorkspace/draftWorkspace-types';
import type { BasicStoreEntityHunt } from './hunt-types';

const loadCurrentDraft = async (context: AuthContext, user: AuthUser) => {
  const draftId = getDraftContext(context, user);
  return draftId ? storeLoadById<BasicStoreEntityDraftWorkspace>(context, user, draftId, ENTITY_TYPE_DRAFT_WORKSPACE) : null;
};

/**
 * The hunts the user can change, as an update of a hunt requires: in a draft, the edit access to the draft. Starting the
 * runs of a hunt, retrying, triaging them and setting their verdicts (which opens an incident) change the hunt, while
 * the hunt manager writes the runs: the access of the user is checked here, the writes do not check it.
 */
export const filterEditableHunts = async <T extends BasicStoreEntityHunt>(context: AuthContext, user: AuthUser, hunts: T[]) => {
  if (hunts.length === 0) {
    return hunts;
  }
  const draft = await loadCurrentDraft(context, user);
  return hunts.filter((hunt) => validateUserAccessOperation(user, hunt, AccessOperation.EDIT, draft));
};

export const checkHuntEditAccess = async (context: AuthContext, user: AuthUser, hunt: BasicStoreEntityHunt) => {
  const [editable] = await filterEditableHunts(context, user, [hunt]);
  if (!editable) {
    throw ForbiddenAccess('You can read this hunt but not change it or its runs', { huntId: hunt.internal_id });
  }
};
