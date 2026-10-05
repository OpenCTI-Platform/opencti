import { beforeEach, describe, expect, it, vi } from 'vitest';
import '../../../../src/modules/index';
import { RECOMPUTE_MAX_IDS, requestGraphAnalyticsRecompute } from '../../../../src/modules/graphAnalytics/graphAnalytics-domain';
import { elFindByIds } from '../../../../src/database/engine';
import { redisGraphAnalyticsMarkPriority } from '../../../../src/database/redis';
import { SYSTEM_USER } from '../../../../src/utils/access';
import type { AuthContext } from '../../../../src/types/user';

vi.mock('../../../../src/database/engine', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/engine')>()),
  elFindByIds: vi.fn(),
}));
vi.mock('../../../../src/database/redis', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/redis')>()),
  redisGraphAnalyticsMarkPriority: vi.fn(),
}));

const context = { source: 'test', otp_mandatory: false } as unknown as AuthContext;

describe('graph analytics recompute request', () => {
  beforeEach(() => {
    vi.mocked(elFindByIds).mockReset();
    vi.mocked(redisGraphAnalyticsMarkPriority).mockReset();
  });

  it('should refuse a request above the limit instead of queuing only part of it', async () => {
    const ids = Array.from({ length: RECOMPUTE_MAX_IDS + 1 }, (_, i) => `entity-${i}`);
    await expect(requestGraphAnalyticsRecompute(context, SYSTEM_USER, ids)).rejects.toThrow('Too many entities to recompute in one request');
    expect(elFindByIds).not.toHaveBeenCalled();
    expect(redisGraphAnalyticsMarkPriority).not.toHaveBeenCalled();
  });

  it('should queue every accessible entity of a request within the limit', async () => {
    vi.mocked(elFindByIds).mockResolvedValue({ a: { internal_id: 'a' }, b: { internal_id: 'b' } } as never);
    const queued = await requestGraphAnalyticsRecompute(context, SYSTEM_USER, ['a', 'b', 'hidden']);
    expect(queued).toBe(2);
    expect(redisGraphAnalyticsMarkPriority).toHaveBeenCalledWith(['a', 'b']);
  });
});
