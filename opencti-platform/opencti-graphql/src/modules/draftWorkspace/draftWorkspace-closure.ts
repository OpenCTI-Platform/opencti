import type { AuthContext } from '../../types/user';

/**
 * Called when a draft is about to be validated or deleted, before its content is read or removed and before the users
 * working in it are moved back to the live context: a module routing users into a draft (Source Intelligence
 * quarantine) moves them to another draft first, so nothing they write lands in a draft that is being closed.
 */
export type DraftClosureHandler = (context: AuthContext, draftId: string) => Promise<void>;

const draftClosureHandlers: DraftClosureHandler[] = [];

export const registerDraftClosureHandler = (handler: DraftClosureHandler) => {
  draftClosureHandlers.push(handler);
};

export const runDraftClosureHandlers = async (context: AuthContext, draftId: string) => {
  for (let i = 0; i < draftClosureHandlers.length; i += 1) {
    await draftClosureHandlers[i](context, draftId);
  }
};
