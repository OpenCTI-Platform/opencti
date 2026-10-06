import type { AuthContext } from '../types/user';
import { DraftLockedError, FunctionalError } from '../config/errors';
import { logApp } from '../config/conf';
import { DRAFT_STATUS_OPEN } from '../modules/draftWorkspace/draftStatuses';
import { enterDraft } from '../modules/draftWorkspace/draftWorkspace-closure';
import { userEditField } from '../modules/user/user-domain';
import { ENTITY_TYPE_DRAFT_WORKSPACE, type BasicStoreEntityDraftWorkspace } from '../modules/draftWorkspace/draftWorkspace-types';
import { getEntitiesMapFromCache } from '../database/cache';
import { isUserCanAccessStoreElement, SYSTEM_USER } from '../utils/access';

interface RequestResponse {
  closed: boolean;
  destroyed: boolean;
  once: (event: 'close', listener: () => void) => unknown;
}

/**
 * Draft of an API request, once its user is known: work queued or routed into a draft closed meanwhile goes to the
 * draft that took over from it, or is refused (see enterDraft). The lease on a draft of a forwarding chain is released
 * when the response ends, so a closure of that draft waits for the request.
 */
export const enterRequestDraft = async (executeContext: AuthContext, res: RequestResponse) => {
  if (!executeContext.draft_context) {
    return;
  }
  const entry = await enterDraft(executeContext.draft_context);
  executeContext.draft_context = entry.draftId;
  executeContext.draft_forward_closed = entry.closed;
  executeContext.draft_writer_id = entry.writerId;
  if (entry.writerId) {
    const release = () => {
      entry.release().catch((cause) => logApp.error('[OPENCTI] Draft lease of a request could not be released', { cause, draftId: entry.draftId }));
    };
    if (res.closed || res.destroyed) {
      release();
    } else {
      res.once('close', release);
    }
  }
};

export const checkDraftInContext = async (executeContext: AuthContext) => {
  // When context is in draft, we need to check draft status: if draft is not in an open status, it means that it is no longer possible to execute requests in this draft
  if (executeContext.draft_context) {
    if (executeContext.user) {
      if (executeContext.draft_forward_closed) {
        throw DraftLockedError('Cannot execute request in a draft that was closed with no draft taking over from it');
      }
      const draftWorkspaces = await getEntitiesMapFromCache(executeContext, SYSTEM_USER, ENTITY_TYPE_DRAFT_WORKSPACE);
      const draftWorkspace: BasicStoreEntityDraftWorkspace = draftWorkspaces.get(executeContext.draft_context) as BasicStoreEntityDraftWorkspace;

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

      const isUserCanAccess = await isUserCanAccessStoreElement(executeContext, executeContext.user, draftWorkspace);
      if (!isUserCanAccess) {
        if (executeContext.user.draft_context === executeContext.draft_context) {
          // If user is stuck in a draft they cannot access, remove draft context from user so they are not trapped
          await userEditField(executeContext, executeContext.user, executeContext.user.id, [{
            key: 'draft_context',
            value: '',
          }]);
        }
        const serviceAccountHint = executeContext.user.user_service_account === true
          ? ''
          : ', consider switching the user associated to your connector to a service account (instead of a user)';
        throw FunctionalError(`Draft ${executeContext.draft_context} cannot be found${serviceAccountHint}`);
      }

      if (draftWorkspace.draft_status !== DRAFT_STATUS_OPEN) {
        if (executeContext.user.draft_context === executeContext.draft_context) {
          // If user is stuck in an invalid draft, remove draft context from user
          await userEditField(executeContext, executeContext.user, executeContext.user.id, [{
            key: 'draft_context',
            value: '',
          }]);
        }
        throw DraftLockedError('Cannot execute request in a draft that is not in an open state');
      }
    } else {
      throw FunctionalError('User cannot be found');
    }
  }
};
