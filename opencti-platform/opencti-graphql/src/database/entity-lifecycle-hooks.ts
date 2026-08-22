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

type PostAttributeUpdateHook = (
  context: AuthContext,
  user: AuthUser,
  entity: Record<string, any>,
  field: string,
  newValue: any,
) => Promise<void>;

let postAttributeUpdateHooks: PostAttributeUpdateHook[] = [];

/**
 * Task 8: same decoupled-registry property as `registerPostEntityCreationHook` above, for
 * post-attribute-update side effects (e.g. `workflow-domain.ts`'s
 * `syncWorkflowInstanceFromExternalWrite`). Kept as an independent list — a separate concern
 * from entity creation, with its own registration/reset lifecycle.
 */
export const registerPostAttributeUpdateHook = (hook: PostAttributeUpdateHook): void => {
  if (postAttributeUpdateHooks.includes(hook)) {
    return;
  }
  postAttributeUpdateHooks.push(hook);
};

export const runPostAttributeUpdateHooks = async (
  context: AuthContext,
  user: AuthUser,
  entity: Record<string, any>,
  field: string,
  newValue: any,
): Promise<void> => {
  for (const hook of postAttributeUpdateHooks) {
    await hook(context, user, entity, field, newValue);
  }
};

/** Test-only: clears all registered hooks between test cases. */
export const __resetPostAttributeUpdateHooksForTest = (): void => {
  postAttributeUpdateHooks = [];
};
