import type { AuthContext, AuthUser } from '../types/user';

export const getDraftContext = (context: AuthContext, user?: AuthUser | undefined) => {
  return context?.draft_context ?? user?.draft_context;
};
