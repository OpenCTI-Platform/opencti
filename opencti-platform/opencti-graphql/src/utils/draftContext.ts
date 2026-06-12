import type { AuthContext, AuthUser } from '../types/user';

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
