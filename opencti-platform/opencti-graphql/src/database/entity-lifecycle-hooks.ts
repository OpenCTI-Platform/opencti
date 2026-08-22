import type { AuthContext, AuthUser } from '../types/user';

type PostEntityCreationHook = (context: AuthContext, user: AuthUser, entity: Record<string, any>) => Promise<void>;

let postEntityCreationHooks: PostEntityCreationHook[] = [];

/**
 * Tiny decoupled registry so `middleware.ts` (the single centralized entity-creation function)
 * never has to import feature modules directly (which would create circular dependencies).
 * Feature modules register their own post-creation side effects here instead.
 */
export const registerPostEntityCreationHook = (hook: PostEntityCreationHook): void => {
  if (postEntityCreationHooks.includes(hook)) {
    return;
  }
  postEntityCreationHooks.push(hook);
};

export const runPostEntityCreationHooks = async (
  context: AuthContext,
  user: AuthUser,
  entity: Record<string, any>,
): Promise<void> => {
  for (const hook of postEntityCreationHooks) {
    await hook(context, user, entity);
  }
};

/** Test-only: clears all registered hooks between test cases. */
export const __resetPostEntityCreationHooksForTest = (): void => {
  postEntityCreationHooks = [];
};
