import type { AuthUser } from '../types/user';

export const inDraftContext = (user: AuthUser) => {
  return user.workspace_context;
};
