import { beforeEach, describe, expect, it, vi } from 'vitest';
import { runFunctionAsLongRunning } from '../../../src/database/utils';
import { lockResources } from '../../../src/lock/master-lock';
import { redisFinishAsyncCall, redisGetAsyncCall } from '../../../src/database/redis';
import { ADMIN_USER, testContext } from '../../utils/testQuery';

const unlock = vi.fn(async () => {});

vi.mock('../../../src/lock/master-lock', async (importOriginal) => {
  const actual: object = await importOriginal();
  return { ...actual, lockResources: vi.fn(async () => ({ unlock })) };
});

vi.mock('../../../src/database/redis', async (importOriginal) => {
  const actual: object = await importOriginal();
  return {
    ...actual,
    redisGetAsyncCall: vi.fn(async () => null),
    redisInitializeAsyncCall: vi.fn(async () => {}),
    redisFinishAsyncCall: vi.fn(async () => {}),
  };
});

describe('runFunctionAsLongRunning lock release', () => {
  beforeEach(() => {
    unlock.mockClear();
    vi.mocked(lockResources).mockClear();
    vi.mocked(redisFinishAsyncCall).mockReset().mockImplementation(async () => {});
  });

  it('should release the lock once when the function fails', async () => {
    const failing = async () => {
      throw new Error('function failure');
    };
    await expect(runFunctionAsLongRunning(testContext, ADMIN_USER, failing, 'execution-a', 'lock-a')).resolves.toBe(true);
    expect(vi.mocked(lockResources)).toHaveBeenCalledWith(['lock-a'], expect.anything());
    expect(unlock).toHaveBeenCalledTimes(1);
  });

  it('should release the lock once when the end of the call cannot be recorded', async () => {
    // A second unlock of the same handle never gets an answer from the child lock process
    vi.mocked(redisFinishAsyncCall).mockImplementation(async () => {
      throw new Error('redis failure');
    });
    await expect(runFunctionAsLongRunning(testContext, ADMIN_USER, async () => {}, 'execution-b', 'lock-b')).rejects.toThrow('redis failure');
    expect(unlock).toHaveBeenCalledTimes(1);
  });

  it('should release the lock once when the end of the call cannot be recorded after the call returned', async () => {
    // The call returns false after 10 s and the function goes on: the lock must still be released when it ends
    vi.useFakeTimers();
    try {
      let release: () => void = () => {};
      const pending = () => new Promise<void>((resolve) => {
        release = resolve;
      });
      vi.mocked(redisFinishAsyncCall).mockImplementation(async () => {
        throw new Error('redis failure');
      });
      const call = runFunctionAsLongRunning(testContext, ADMIN_USER, pending, 'execution-c', 'lock-c');
      await vi.advanceTimersByTimeAsync(10001);
      await expect(call).resolves.toBe(false);
      expect(unlock).toHaveBeenCalledTimes(0);
      release();
      await vi.advanceTimersByTimeAsync(0);
      expect(unlock).toHaveBeenCalledTimes(1);
    } finally {
      vi.useRealTimers();
    }
  });

  it('should release the lock once when the call is already finished, even if that release fails', async () => {
    vi.mocked(redisGetAsyncCall).mockImplementationOnce(async () => '1');
    unlock.mockImplementationOnce(async () => {
      throw new Error('unlock failure');
    });
    await expect(runFunctionAsLongRunning(testContext, ADMIN_USER, async () => {}, 'execution-d', 'lock-d')).rejects.toThrow('unlock failure');
    expect(unlock).toHaveBeenCalledTimes(1);
  });
});
