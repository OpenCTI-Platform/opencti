import type { AuthContext } from '../types/user';
import { DraftLockedError, FunctionalError } from '../config/errors';
import { logApp } from '../config/conf';
import { DRAFT_STATUS_OPEN } from '../modules/draftWorkspace/draftStatuses';
import { enterDraft } from '../modules/draftWorkspace/draftWorkspace-closure';
import { resolveQueuedFeedQuarantineDraftId } from '../modules/sourceIntelligence/sourceIntelligence-quarantine';
import { userEditField } from '../modules/user/user-domain';
import { ENTITY_TYPE_DRAFT_WORKSPACE, type BasicStoreEntityDraftWorkspace } from '../modules/draftWorkspace/draftWorkspace-types';
import { getEntitiesMapFromCache } from '../database/cache';
import { isUserCanAccessStoreElement, SYSTEM_USER } from '../utils/access';

// Requests holding a lease on their draft, by response, until their handler settled (see settleRequestDraft)
const leasedRequests = new WeakMap<object, AuthContext>();

/**
 * Draft of an API request, once its user is known: a feed bundle queued before its source was quarantined goes to the
 * quarantine draft (see resolveQueuedFeedQuarantineDraftId), and work queued or routed into a draft closed meanwhile
 * goes to the draft that took over from it, or is refused (see enterDraft). The lease on a draft of a forwarding chain
 * lasts until the request settled (see settleRequestDraft), so a closure of that draft waits for it.
 */
export const enterRequestDraft = async (executeContext: AuthContext, res: object) => {
  const quarantineDraftId = await resolveQueuedFeedQuarantineDraftId(executeContext);
  if (quarantineDraftId) {
    executeContext.draft_context = quarantineDraftId;
  }
  if (!executeContext.draft_context) {
    return;
  }
  const entry = await enterDraft(executeContext.draft_context);
  executeContext.draft_context = entry.draftId;
  executeContext.draft_forward_closed = entry.closed;
  executeContext.draft_writer_id = entry.writerId;
  if (entry.writerId) {
    executeContext.draft_writer_release = entry.release;
    leasedRequests.set(res, executeContext);
  }
};

export const releaseRequestDraft = async (executeContext: AuthContext) => {
  const release = executeContext.draft_writer_release;
  if (release) {
    executeContext.draft_writer_release = undefined;
    await release().catch((cause) => logApp.error('[OPENCTI] Draft lease of a request could not be released', { cause, draftId: executeContext.draft_context }));
  }
};

/**
 * GraphQL request handler releasing the draft lease of its request once it settled. The handler must return the promise
 * of the execution of the request, as the Express 5 integration of Apollo Server does although its declared type (the
 * Express `RequestHandler`) returns `unknown`: it settles only after the execution and its writes settled, also when the
 * client disconnected meanwhile (the execution is not aborted, whatever the HTTP timeout), or after it refused the
 * context or the body of the request.
 */
export const settleRequestDraft = <Req, Res extends object, Rest extends unknown[]>(handler: (req: Req, res: Res, ...rest: Rest) => unknown) => {
  return async (req: Req, res: Res, ...rest: Rest) => {
    try {
      await handler(req, res, ...rest);
    } finally {
      const executeContext = leasedRequests.get(res);
      if (executeContext) {
        leasedRequests.delete(res);
        await releaseRequestDraft(executeContext);
      }
    }
  };
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
