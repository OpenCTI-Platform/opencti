import { beforeEach, describe, expect, it, vi } from 'vitest';
import { EventEmitter } from 'events';
import { GraphQLError } from 'graphql';
import { LOCK_ERROR, LockTimeoutError, TYPE_LOCK_ERROR } from '../../../src/config/errors';
import { serializeChildLockError } from '../../../src/lock/child-lock-error';

class FakeForkedProcess extends EventEmitter {
  send = vi.fn();
}

// Start master-lock with the child locking process enabled, on a fake forked process
const initChildLock = async () => {
  const fakeForkedProcess = new FakeForkedProcess();
  const warn = vi.fn();

  vi.doMock('child_process', () => ({
    fork: vi.fn(() => fakeForkedProcess),
  }));

  vi.doMock('../../../src/database/redis', () => ({
    lockResource: vi.fn(),
  }));

  vi.doMock('../../../src/config/conf', async (importOriginal) => {
    const actual = await importOriginal<typeof import('../../../src/config/conf')>();
    return {
      ...actual,
      default: { get: vi.fn(() => '256') },
      booleanConf: vi.fn(() => true),
      logApp: {
        ...actual.logApp,
        info: vi.fn(),
        warn,
      },
    };
  });

  const masterLock = await import('../../../src/lock/master-lock');
  masterLock.initLockFork();
  return { fakeForkedProcess, warn, lockResources: masterLock.lockResources };
};

// The child answers over IPC with the default json serialization
const answerFromChild = (fakeForkedProcess: FakeForkedProcess, message: object) => {
  fakeForkedProcess.emit('message', JSON.parse(JSON.stringify(message)));
};

describe('master-lock', () => {
  beforeEach(() => {
    vi.resetModules();
    vi.clearAllMocks();
  });

  it('should warn when receiving malformed child message', async () => {
    const { fakeForkedProcess, warn } = await initChildLock();

    fakeForkedProcess.emit('message', { type: 'lock' });

    expect(warn).toHaveBeenCalledWith(
      '[LOCKING] Ignoring malformed message from child lock process',
      {
        type: 'lock',
        keys: ['type'],
      },
    );
  });

  it('should reject with a LockTimeoutError when the child fails to lock with a lock error', async () => {
    const { fakeForkedProcess, lockResources } = await initChildLock();

    const lockPromise = lockResources(['synthetic-id']);
    const { operation } = fakeForkedProcess.send.mock.calls[0][0];
    const childError = LockTimeoutError({ participantIds: ['synthetic-id'] });
    answerFromChild(fakeForkedProcess, { operation, type: 'lock', success: false, error: serializeChildLockError(childError) });

    const rejection = await lockPromise.catch((err: unknown) => err);
    expect(rejection).toBeInstanceOf(GraphQLError);
    expect((rejection as GraphQLError).message).toBe(childError.message);
    expect((rejection as GraphQLError).extensions.code).toBe(LOCK_ERROR);
  });

  it('should reject with an error keeping its name when the child fails to acquire the lock', async () => {
    const { fakeForkedProcess, lockResources } = await initChildLock();

    const lockPromise = lockResources(['synthetic-id']);
    const { operation } = fakeForkedProcess.send.mock.calls[0][0];
    const childError = { name: TYPE_LOCK_ERROR, message: 'The operation was unable to achieve a quorum during its retry window.' };
    answerFromChild(fakeForkedProcess, { operation, type: 'lock', success: false, error: childError });

    const rejection = await lockPromise.catch((err: unknown) => err);
    expect(rejection).toBeInstanceOf(Error);
    expect((rejection as Error).name).toBe(TYPE_LOCK_ERROR);
    expect((rejection as Error).message).toBe(childError.message);
  });

  it('should reject with an error when the child fails to unlock', async () => {
    const { fakeForkedProcess, lockResources } = await initChildLock();

    const lockPromise = lockResources(['synthetic-id']);
    const { operation } = fakeForkedProcess.send.mock.calls[0][0];
    answerFromChild(fakeForkedProcess, { operation, type: 'lock', success: true });
    const lock = await lockPromise;

    const unlockPromise = lock.unlock();
    answerFromChild(fakeForkedProcess, { operation, type: 'unlock', success: false, error: serializeChildLockError(new Error('Synthetic unlock failure')) });

    const rejection = await unlockPromise.catch((err: unknown) => err);
    expect(rejection).toBeInstanceOf(Error);
    expect((rejection as Error).message).toBe('Synthetic unlock failure');
  });
});
