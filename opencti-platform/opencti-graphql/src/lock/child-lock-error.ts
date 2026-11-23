import { GraphQLError, type GraphQLErrorExtensions } from 'graphql';
import { LOCK_ERROR, LockTimeoutError } from '../config/errors';

// The child locking process sends its errors to the parent over IPC, with the default json serialization.
// An error does not survive it: a GraphQLError is reduced to the output of its toJSON() and an Error loses its message.
// The child sends this shape instead, and the parent rebuilds a real error from it.
export interface ChildLockError {
  name?: string;
  message?: string;
  stack?: string;
  extensions?: GraphQLErrorExtensions;
}

const UNKNOWN_CHILD_LOCK_ERROR = 'Unknown error from the child locking process';
const CALLER_STACK_SEPARATOR = '    --- lock operation requested by ---';

export const serializeChildLockError = (err: unknown): ChildLockError => {
  if (err instanceof Error) {
    const { extensions } = err as Partial<GraphQLError>;
    return { name: err.name, message: err.message, stack: err.stack, extensions };
  }
  return { message: String(err) };
};

// The parent rebuilds the error in the IPC message listener, where the stack shows neither the failure nor the caller.
// Capture the caller frames when the operation is sent to the child, to append them to the rebuilt stack.
export const captureCallerStack = (): string => {
  const holder: { stack?: string } = {};
  Error.captureStackTrace(holder, captureCallerStack);
  // Drop the "Error" header line, keep the frames only
  return (holder.stack ?? '').split('\n').slice(1).join('\n');
};

const buildChildLockError = (sent: ChildLockError | undefined): Error => {
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

// The rebuilt stack is the one of the child (where the lock failed), followed by the caller frames in the parent.
export const rebuildChildLockError = (sent: ChildLockError | undefined, callerStack?: string): Error => {
  const rebuilt = buildChildLockError(sent);
  if (sent?.stack || callerStack) {
    const childStack = sent?.stack ?? `${rebuilt.name}: ${rebuilt.message}`;
    rebuilt.stack = callerStack ? `${childStack}\n${CALLER_STACK_SEPARATOR}\n${callerStack}` : childStack;
  }
  return rebuilt;
};
