import { GraphQLError, type GraphQLErrorExtensions } from 'graphql';
import { LOCK_ERROR, LockTimeoutError } from '../config/errors';

// The child locking process sends its errors to the parent over IPC, with the default json serialization.
// An error does not survive it: a GraphQLError is reduced to the output of its toJSON() and an Error loses its message.
// The child sends this shape instead, and the parent rebuilds a real error from it.
export interface ChildLockError {
  name?: string;
  message?: string;
  extensions?: GraphQLErrorExtensions;
}

const UNKNOWN_CHILD_LOCK_ERROR = 'Unknown error from the child locking process';

export const serializeChildLockError = (err: unknown): ChildLockError => {
  if (err instanceof Error) {
    const { extensions } = err as Partial<GraphQLError>;
    return { name: err.name, message: err.message, extensions };
  }
  return { message: String(err) };
};

export const rebuildChildLockError = (sent: ChildLockError | undefined): Error => {
  const message = sent?.message ?? UNKNOWN_CHILD_LOCK_ERROR;
  const extensions = sent?.extensions;
  if (extensions?.code === LOCK_ERROR) {
    return LockTimeoutError(extensions.data, message);
  }
  if (extensions) {
    return new GraphQLError(message, { extensions });
  }
  const rebuilt = new Error(message);
  // Keep the name: the callers convert an error named TYPE_LOCK_ERROR (lock acquisition failure) into a LockTimeoutError
  if (sent?.name) {
    rebuilt.name = sent.name;
  }
  return rebuilt;
};
