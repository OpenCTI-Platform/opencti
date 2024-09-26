import type { AuthContext, AuthUser } from '../types/user';

export const inDraftContext = (context: AuthContext, user: AuthUser) => {
  return context?.workspace_context ?? user?.workspace_context;
};
