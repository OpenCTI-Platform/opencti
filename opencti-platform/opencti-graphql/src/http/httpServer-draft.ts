import type { AuthContext } from '../types/user';
import { DraftLockedError, FunctionalError } from '../config/errors';
import { DRAFT_STATUS_OPEN } from '../modules/draftWorkspace/draftStatuses';
import { userEditField } from '../domain/user';
import { ENTITY_TYPE_DRAFT_WORKSPACE, type BasicStoreEntityDraftWorkspace } from '../modules/draftWorkspace/draftWorkspace-types';
import { getEntitiesMapFromCache } from '../database/cache';
import { isUserCanAccessStoreElement, SYSTEM_USER } from '../utils/access';

export const checkDraftInContext = async (executeContext: AuthContext) => {
  // When context is in draft, we need to check draft status: if draft is not in an open status, it means that it is no longer possible to execute requests in this draft
  if (executeContext.draft_context) {
    if (executeContext.user) {
      const draftWorkspaces = await getEntitiesMapFromCache(executeContext, SYSTEM_USER, ENTITY_TYPE_DRAFT_WORKSPACE);
      const draftWorkspace: BasicStoreEntityDraftWorkspace = draftWorkspaces.get(executeContext.draft_context) as BasicStoreEntityDraftWorkspace;

      const isUserCanAccess = await isUserCanAccessStoreElement(executeContext, executeContext.user, draftWorkspace);
      if (!isUserCanAccess) {
        throw FunctionalError(`Draft ${executeContext.draft_context} cannot be found`);
      }

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
