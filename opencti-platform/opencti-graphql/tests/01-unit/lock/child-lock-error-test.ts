import { describe, expect, it } from 'vitest';
import { GraphQLError } from 'graphql';
import { ExecutionError } from '@sesamecare-oss/redlock';
import { DATABASE_ERROR, DatabaseError, LOCK_ERROR, LockTimeoutError, TYPE_LOCK_ERROR } from '../../../src/config/errors';
import { type ChildLockError, rebuildChildLockError, serializeChildLockError } from '../../../src/lock/child-lock-error';

// The child locking process talks to its parent over IPC with the default json serialization
const sendOverIpc = (err: unknown): ChildLockError => JSON.parse(JSON.stringify(serializeChildLockError(err)));

describe('child lock error', () => {
  it('should rebuild a LockTimeoutError sent by the child', () => {
    const sent = LockTimeoutError({ participantIds: ['synthetic-id-1', 'synthetic-id-2'] });

    const rebuilt = rebuildChildLockError(sendOverIpc(sent));

    expect(rebuilt).toBeInstanceOf(GraphQLError);
    expect(rebuilt.message).toBe(sent.message);
    expect((rebuilt as GraphQLError).extensions.code).toBe(LOCK_ERROR);
    expect((rebuilt as GraphQLError).extensions.data).toEqual(sent.extensions.data);
  });

  it('should rebuild an error keeping the name of a lock acquisition failure', () => {
    // The callers convert an error named TYPE_LOCK_ERROR into a LockTimeoutError
    const sent = new ExecutionError('The operation was unable to achieve a quorum during its retry window.', []);

    const rebuilt = rebuildChildLockError(sendOverIpc(sent));

    expect(rebuilt).toBeInstanceOf(Error);
    expect(rebuilt.name).toBe(TYPE_LOCK_ERROR);
    expect(rebuilt.message).toBe(sent.message);
  });

  it('should rebuild an error with another code, keeping its message and extensions', () => {
    const sent = DatabaseError('Synthetic database failure', { synthetic: true });

    const rebuilt = rebuildChildLockError(sendOverIpc(sent));

    expect(rebuilt).toBeInstanceOf(GraphQLError);
    expect(rebuilt.message).toBe('Synthetic database failure');
    expect((rebuilt as GraphQLError).extensions).toEqual(sent.extensions);
    expect((rebuilt as GraphQLError).extensions.code).toBe(DATABASE_ERROR);
  });

  it('should rebuild a plain error keeping its message and name', () => {
    // Sent as is, a plain Error would arrive as an empty object
    const sent = new TypeError('Child lock manager is shutting down');

    const rebuilt = rebuildChildLockError(sendOverIpc(sent));

    expect(rebuilt).toBeInstanceOf(Error);
    expect(rebuilt.name).toBe('TypeError');
    expect(rebuilt.message).toBe('Child lock manager is shutting down');
  });

  it('should rebuild an error from a thrown value that is not an error', () => {
    const rebuilt = rebuildChildLockError(sendOverIpc('synthetic failure'));

    expect(rebuilt).toBeInstanceOf(Error);
    expect(rebuilt.message).toBe('synthetic failure');
  });

  it('should rebuild an error when the child sent nothing', () => {
    const rebuilt = rebuildChildLockError(undefined);

    expect(rebuilt).toBeInstanceOf(Error);
    expect(rebuilt.message).toBe('Unknown error from the child locking process');
  });
});
