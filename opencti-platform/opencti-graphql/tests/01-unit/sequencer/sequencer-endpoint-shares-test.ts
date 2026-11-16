import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../../src/database/redis', () => ({
  bumpLockStamps: vi.fn(async () => {}),
  redisEndpointShareHolders: vi.fn(async () => []),
  redisMarkMergeSources: vi.fn(async () => {}),
  redisReleaseEndpointShares: vi.fn(async () => {}),
  redisRenewEndpointShares: vi.fn(async () => {}),
  redisShareEndpoints: vi.fn(async () => []),
  redisUnmarkMergeSources: vi.fn(async () => {}),
}));

import * as redis from '../../../src/database/redis';
import {
  markMergeSources,
  mergedSourceKeys,
  newEndpointShares,
  preShareEndpoints,
  releaseEndpointShares,
  shareRelationEndpoints,
  stampWrittenRelations,
  startEndpointShareRenewal,
  unmarkMergeSources,
} from '../../../src/database/sequencer/sequencer-endpoint-shares';
import { setCurrentBatchLock } from '../../../src/database/sequencer/sequencer-batch-lock';
import { SEQUENCER_CONFIG } from '../../../src/database/sequencer/sequencer-config';
import { isLockError, lockErrorKeys } from '../../../src/database/sequencer/sequencer-multi-writer';
import type { AuthContext } from '../../../src/types/user';

const mocked = vi.mocked(redis);
const applying = { sequencer: { scope: 'applying' } } as unknown as AuthContext;
const plain = {} as AuthContext;
const signal = new AbortController().signal;

describe('sequencer endpoint shares (task 0040 defect 1)', () => {
  const saved = SEQUENCER_CONFIG.multiWriter;
  beforeEach(() => {
    SEQUENCER_CONFIG.multiWriter = true;
    vi.clearAllMocks();
  });
  afterEach(() => {
    SEQUENCER_CONFIG.multiWriter = saved;
    setCurrentBatchLock(null);
    vi.useRealTimers();
  });

  it('should do nothing on a single writer', async () => {
    SEQUENCER_CONFIG.multiWriter = false;
    const shares = newEndpointShares();
    setCurrentBatchLock({ heldKeys: new Set(), signal, shares });
    await shareRelationEndpoints(applying, ['a']);
    expect(await markMergeSources(applying, ['s'])).toBeNull();
    await stampWrittenRelations(plain, [{ type: 'uses', fromId: 'f', toId: 't' }]);
    expect(mocked.redisShareEndpoints).not.toHaveBeenCalled();
    expect(mocked.redisMarkMergeSources).not.toHaveBeenCalled();
    expect(mocked.bumpLockStamps).not.toHaveBeenCalled();
  });

  it('should share once per batch and refuse a merged endpoint without making it a lock key', async () => {
    const shares = newEndpointShares();
    setCurrentBatchLock({ heldKeys: new Set(), signal, shares });
    mocked.redisShareEndpoints.mockResolvedValueOnce([]);
    await preShareEndpoints(shares, ['a', 'b', 'a']);
    expect(mocked.redisShareEndpoints).toHaveBeenLastCalledWith(shares.holder, ['a', 'b'], expect.any(Number));
    expect([...shares.ids]).toEqual(['a', 'b']);
    mocked.redisShareEndpoints.mockResolvedValueOnce(['s']);
    const error = await shareRelationEndpoints(applying, ['a', 's']).catch((err) => err);
    // only the id not shared yet went to Redis
    expect(mocked.redisShareEndpoints).toHaveBeenLastCalledWith(shares.holder, ['s'], expect.any(Number));
    expect(isLockError(error)).toBe(true);
    expect(mergedSourceKeys(error)).toEqual(['s']);
    expect(lockErrorKeys(error)).toEqual([]);
    expect(shares.ids.has('s')).toBe(false);
  });

  it('should not share outside an applying batch', async () => {
    setCurrentBatchLock({ heldKeys: new Set(), signal, shares: newEndpointShares() });
    await shareRelationEndpoints(plain, ['a']);
    setCurrentBatchLock({ heldKeys: new Set(), signal });
    await shareRelationEndpoints(applying, ['a']);
    expect(mocked.redisShareEndpoints).not.toHaveBeenCalled();
  });

  it('should renew the shares while the batch runs, until stopped, and release them', async () => {
    vi.useFakeTimers();
    const shares = newEndpointShares();
    shares.ids.add('a');
    const stop = startEndpointShareRenewal(shares);
    await vi.advanceTimersByTimeAsync(60000);
    const renewals = mocked.redisRenewEndpointShares.mock.calls.length;
    expect(renewals).toBeGreaterThanOrEqual(2);
    expect(mocked.redisRenewEndpointShares).toHaveBeenLastCalledWith(shares.holder, ['a'], expect.any(Number));
    stop();
    await vi.advanceTimersByTimeAsync(60000);
    expect(mocked.redisRenewEndpointShares.mock.calls.length).toBe(renewals);
    await releaseEndpointShares(shares);
    expect(mocked.redisReleaseEndpointShares).toHaveBeenCalledWith(shares.holder, ['a']);
  });

  it('should mark the sources and wait, ignoring its own batch shares', async () => {
    const shares = newEndpointShares();
    setCurrentBatchLock({ heldKeys: new Set(), signal, shares });
    mocked.redisEndpointShareHolders.mockResolvedValueOnce(['other']).mockResolvedValueOnce([]);
    const mark = await markMergeSources(applying, ['s']);
    expect(mark?.ids).toEqual(['s']);
    expect(mocked.redisMarkMergeSources).toHaveBeenCalledWith(['s'], mark?.token, expect.any(Number));
    expect(mocked.redisEndpointShareHolders).toHaveBeenCalledWith(['s'], shares.holder);
    expect(mocked.redisEndpointShareHolders).toHaveBeenCalledTimes(2);
    expect(mocked.redisUnmarkMergeSources).not.toHaveBeenCalled();
    await unmarkMergeSources(mark);
    expect(mocked.redisUnmarkMergeSources).toHaveBeenCalledWith(['s'], mark?.token);
  });

  it('should give up quickly under an applying batch, unmark and fail with a lock error on the sources', async () => {
    vi.useFakeTimers();
    setCurrentBatchLock({ heldKeys: new Set(), signal, shares: newEndpointShares() });
    mocked.redisEndpointShareHolders.mockResolvedValue(['other']);
    const pending = markMergeSources(applying, ['s']).catch((err) => err);
    await vi.advanceTimersByTimeAsync(3000);
    const error = await pending;
    expect(isLockError(error)).toBe(true);
    expect(lockErrorKeys(error)).toEqual(['s']);
    expect(mocked.redisUnmarkMergeSources).toHaveBeenCalledWith(['s'], expect.any(String));
  });

  it('should wait longer than a share lives outside a batch', async () => {
    vi.useFakeTimers();
    mocked.redisEndpointShareHolders.mockResolvedValue(['other']);
    let settled = false;
    const pending = markMergeSources(plain, ['s']).catch((err) => err).finally(() => {
      settled = true;
    });
    await vi.advanceTimersByTimeAsync(60000);
    expect(settled).toBe(false);
    await vi.advanceTimersByTimeAsync(10000);
    expect(isLockError(await pending)).toBe(true);
    expect(mocked.redisEndpointShareHolders).toHaveBeenCalledWith(['s'], undefined);
  });

  it('should unmark when Redis fails during the wait', async () => {
    mocked.redisEndpointShareHolders.mockRejectedValueOnce(new Error('redis down'));
    await expect(markMergeSources(plain, ['s'])).rejects.toThrow('redis down');
    expect(mocked.redisUnmarkMergeSources).toHaveBeenCalledWith(['s'], expect.any(String));
  });

  it('should stamp a written relation now outside a batch, after the flush under one', async () => {
    await stampWrittenRelations(plain, [{ type: 'uses', fromId: 'f', toId: 't' }]);
    expect(mocked.bumpLockStamps).toHaveBeenCalledWith(['relation-dedup:uses:f:t'], expect.any(Number));
    vi.clearAllMocks();
    const writtenDedupKeys = new Set<string>();
    setCurrentBatchLock({ heldKeys: new Set(), signal, writtenDedupKeys });
    await stampWrittenRelations(applying, [{ type: 'uses', fromId: 'f', toId: 't' }]);
    expect(mocked.bumpLockStamps).not.toHaveBeenCalled();
    expect([...writtenDedupKeys]).toEqual(['relation-dedup:uses:f:t']);
    // an applying context without a current batch stamps at once
    setCurrentBatchLock(null);
    await stampWrittenRelations(applying, [{ type: 'uses', fromId: 'f', toId: 't' }]);
    expect(mocked.bumpLockStamps).toHaveBeenCalledWith(['relation-dedup:uses:f:t'], expect.any(Number));
  });

  it('should unmark when setting the marks fails', async () => {
    mocked.redisMarkMergeSources.mockRejectedValueOnce(new Error('READONLY'));
    await expect(markMergeSources(plain, ['s'])).rejects.toThrow('READONLY');
    expect(mocked.redisUnmarkMergeSources).toHaveBeenCalledWith(['s'], expect.any(String));
  });
});
