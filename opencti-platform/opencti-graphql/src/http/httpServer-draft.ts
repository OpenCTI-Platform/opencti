import type { AuthContext } from '../types/user';
import { findById as findDraftById } from '../modules/draftWorkspace/draftWorkspace-domain';
import { DraftLockedError, FunctionalError } from '../config/errors';
import { DRAFT_STATUS_OPEN } from '../modules/draftWorkspace/draftStatuses';
import { userEditField } from '../domain/user';

export const checkDraftInContext = async (executeContext: AuthContext) => {
  // When context is in draft, we need to check draft status: if draft is not in an open status, it means that it is no longer possible to execute requests in this draft
  if (executeContext.draft_context) {
    if (executeContext.user) {
      // const draftWorkspace = await checkAndReturnDraft(executeContext, executeContext.user, executeContext.draft_context);
      const draftWorkspace = await findDraftById(executeContext, executeContext.user, executeContext.draft_context);
      // const draftWorkspaces = await getEntitiesMapFromCache(executeContext, SYSTEM_USER, ENTITY_TYPE_DRAFT_WORKSPACE);
      // const draftWorkspace = draftWorkspaces.get(executeContext.draft_context);
      if (!draftWorkspace) {
        if (executeContext.user.draft_context === executeContext.draft_context) {
          // If user is stuck in an invalid draft, remove draft context from user
          await userEditField(executeContext, executeContext.user, executeContext.user.id, [{
            key: 'draft_context',
            value: '',
          }]);
        }
        throw DraftLockedError('Could not find draft workspace');
      }
      if (draftWorkspace.draft_status !== DRAFT_STATUS_OPEN) {
        if (executeContext.user.draft_context === executeContext.draft_context) {
          // If user is stuck in an invalid draft, remove draft context from user
          await userEditField(executeContext, executeContext.user, executeContext.user.id, [{
            key: 'draft_context',
            value: '',
          }]);
        }
        throw DraftLockedError('Can not execute request in a draft not in an open state');
      }
    } else {
      throw FunctionalError('User cannot be found');
    }
  }
};
