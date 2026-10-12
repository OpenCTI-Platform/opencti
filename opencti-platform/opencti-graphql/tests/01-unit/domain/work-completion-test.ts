import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import * as redis from '../../../src/database/redis';
import * as engine from '../../../src/database/engine';
import { logApp } from '../../../src/config/conf';
import { registerWorkCompletionHook, runWorkCompletion, unregisterWorkCompletionHook, type WorkCompletionHook } from '../../../src/domain/work-completion';

vi.mock('../../../src/database/redis', async (importOriginal) => {
  const actual: object = await importOriginal();
  return { ...actual, redisAcquireWorkCompletionHooksFlag: vi.fn(), redisDeleteWorkTouchedElements: vi.fn() };
});
vi.mock('../../../src/database/engine', async (importOriginal) => {
  const actual: object = await importOriginal();
  return { ...actual, elLoadById: vi.fn() };
});

describe('work completion hooks', () => {
  let errorSpy: ReturnType<typeof vi.spyOn> | undefined;

  /**
   * Silence logApp.error for the current test and keep the spy to assert on it.
   */
  const spyOnLogError = () => {
    errorSpy = vi.spyOn(logApp, 'error').mockImplementation(() => logApp);
    return errorSpy;
  };

  beforeEach(() => {
    vi.mocked(redis.redisAcquireWorkCompletionHooksFlag).mockReset().mockResolvedValue(true);
    vi.mocked(redis.redisDeleteWorkTouchedElements).mockReset().mockResolvedValue(undefined);
    vi.mocked(engine.elLoadById).mockReset().mockResolvedValue({ internal_id: 'work_1', event_type: 'INTERNAL_ENRICHMENT', touched_ids: ['a'] } as any);
  });
  afterEach(() => {
    unregisterWorkCompletionHook('hook-a');
    unregisterWorkCompletionHook('hook-b');
    errorSpy?.mockRestore();
    errorSpy = undefined;
  });

  it('should reject a duplicate hook id', () => {
    registerWorkCompletionHook({ id: 'hook-a', eventTypes: ['INTERNAL_ENRICHMENT'], handler: async () => {} });
    expect(() => registerWorkCompletionHook({ id: 'hook-a', eventTypes: [], handler: async () => {} })).toThrow();
  });

  it('should always clean the touched set, and skip the flag when no hook matches', async () => {
    registerWorkCompletionHook({ id: 'hook-a', eventTypes: ['EXTERNAL_IMPORT'], handler: vi.fn() });
    await runWorkCompletion('work_1', 'INTERNAL_ENRICHMENT');
    expect(redis.redisDeleteWorkTouchedElements).toHaveBeenCalledWith(['work_1']);
    expect(redis.redisAcquireWorkCompletionHooksFlag).not.toHaveBeenCalled();
  });

  it('should run matching hooks with the reloaded work', async () => {
    const handler = vi.fn<WorkCompletionHook['handler']>(async () => {});
    registerWorkCompletionHook({ id: 'hook-a', eventTypes: ['INTERNAL_ENRICHMENT'], handler });
    await runWorkCompletion('work_1', 'INTERNAL_ENRICHMENT');
    expect(handler).toHaveBeenCalledTimes(1);
    expect(handler.mock.calls[0][1]).toMatchObject({ id: 'work_1', touched_ids: ['a'] });
    expect(redis.redisAcquireWorkCompletionHooksFlag).toHaveBeenCalledWith('work_1');
  });

  it('should not take the flag when the work cannot be reloaded', async () => {
    vi.mocked(engine.elLoadById).mockRejectedValue(new Error('es down'));
    const handler = vi.fn(async () => {});
    registerWorkCompletionHook({ id: 'hook-a', eventTypes: ['INTERNAL_ENRICHMENT'], handler });
    await expect(runWorkCompletion('work_1', 'INTERNAL_ENRICHMENT')).rejects.toThrow('es down');
    expect(handler).not.toHaveBeenCalled();
    expect(redis.redisAcquireWorkCompletionHooksFlag).not.toHaveBeenCalled();
  });

  it('should not take the flag when the work no longer exists', async () => {
    vi.mocked(engine.elLoadById).mockResolvedValue(undefined as any);
    const handler = vi.fn(async () => {});
    registerWorkCompletionHook({ id: 'hook-a', eventTypes: ['INTERNAL_ENRICHMENT'], handler });
    await expect(runWorkCompletion('work_1', 'INTERNAL_ENRICHMENT')).resolves.toBeUndefined();
    expect(handler).not.toHaveBeenCalled();
    expect(redis.redisAcquireWorkCompletionHooksFlag).not.toHaveBeenCalled();
  });

  it('should not run hooks when another caller owns the dispatch', async () => {
    vi.mocked(redis.redisAcquireWorkCompletionHooksFlag).mockResolvedValue(false);
    const handler = vi.fn(async () => {});
    registerWorkCompletionHook({ id: 'hook-a', eventTypes: ['INTERNAL_ENRICHMENT'], handler });
    await runWorkCompletion('work_1', 'INTERNAL_ENRICHMENT');
    expect(handler).not.toHaveBeenCalled();
  });

  it('should still run matching hooks when the touched set cleanup fails', async () => {
    vi.mocked(redis.redisDeleteWorkTouchedElements).mockRejectedValue(new Error('redis down'));
    const warnSpy = vi.spyOn(logApp, 'warn').mockImplementation(() => logApp);
    const handler = vi.fn(async () => {});
    registerWorkCompletionHook({ id: 'hook-a', eventTypes: ['INTERNAL_ENRICHMENT'], handler });
    try {
      await expect(runWorkCompletion('work_1', 'INTERNAL_ENRICHMENT')).resolves.toBeUndefined();
      expect(handler).toHaveBeenCalledTimes(1);
      expect(warnSpy).toHaveBeenCalledWith('[WORK] Unable to clean the touched elements of a completed work', expect.objectContaining({ workId: 'work_1' }));
    } finally {
      warnSpy.mockRestore();
    }
  });

  it('should isolate a failing hook', async () => {
    const failing = vi.fn(async () => {
      throw new Error('boom');
    });
    const other = vi.fn(async () => {});
    registerWorkCompletionHook({ id: 'hook-a', eventTypes: ['INTERNAL_ENRICHMENT'], handler: failing });
    registerWorkCompletionHook({ id: 'hook-b', eventTypes: ['INTERNAL_ENRICHMENT'], handler: other });
    const spy = spyOnLogError();
    await expect(runWorkCompletion('work_1', 'INTERNAL_ENRICHMENT')).resolves.toBeUndefined();
    expect(other).toHaveBeenCalledTimes(1);
    expect(spy).toHaveBeenCalledWith('[WORK] Completion hook failed', expect.objectContaining({ hookId: 'hook-a', workId: 'work_1' }));
  });
});
