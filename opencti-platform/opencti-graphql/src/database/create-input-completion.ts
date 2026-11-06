import type { AuthContext, AuthUser } from '../types/user';

// The completion of a create input from its resolved references, per entity type: the indicator's
// validity and decay read its author, labels and markings. It runs inside the creation, once the
// references are resolved, so the sequencer orders the references it needs like any other: a
// producer of the same batch is seen as the direct path sees a committed one. Registered by the
// entity's module; the registry lives outside the middleware (no import cycle, and the middleware
// mocks of the unit tests stay as they are). Inferred creations (fromRule) are not completed.
type CreateInputCompletion = (context: AuthContext, user: AuthUser, resolvedInput: Record<string, any>) => Promise<Record<string, any>>;
const createInputCompletions = new Map<string, CreateInputCompletion>();
export const registerCreateInputCompletion = (type: string, completion: CreateInputCompletion) => {
  createInputCompletions.set(type, completion);
};
export const createInputCompletionOf = (type: string) => createInputCompletions.get(type);
