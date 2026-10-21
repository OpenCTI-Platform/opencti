import type { AuthContext, AuthUser } from '../types/user';
import { DraftLockedError } from '../config/errors';

export const getDraftContext = (context: AuthContext, user?: AuthUser | undefined) => {
  return context?.draft_context ?? user?.draft_context;
};

export const bypassDraftContext = (context: AuthContext): AuthContext => {
  return {
    ...context,
    draft_context: undefined,
    user: context.user ? { ...context.user, draft_context: undefined } : undefined,
  };
};

/** Records on the request a draft it closes (validation, deletion), from the moment the closure starts. */
export const recordDraftClosedByRequest = (context: AuthContext, draftId: string) => {
  context.draft_closed_ids = [...(context.draft_closed_ids ?? []), draftId];
};

/**
 * A request runs no mutation in a draft it closed, as a request started after the closure is refused: the closure read
 * the content of the draft (validation) or removed it (deletion), so what a later mutation would write there is lost.
 */
export const checkDraftNotClosedByRequest = (context: AuthContext) => {
  const draftId = getDraftContext(context, context.user);
  if (draftId && context.draft_closed_ids?.includes(draftId)) {
    throw DraftLockedError('Cannot execute a mutation in a draft that this request closed');
  }
};
