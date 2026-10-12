import { beforeEach, describe, expect, it, vi } from 'vitest';
import '../../../src/modules/index';
import { processReadyEntities } from '../../../src/manager/graphAnalyticsManager';
import { processDirtyEntities, getGraphAnalyticsComputeConfig } from '../../../src/modules/graphAnalytics/graphAnalytics-compute';
import { redisGraphAnalyticsMarkDirty, redisGraphAnalyticsPopReady, redisGraphAnalyticsSetState } from '../../../src/database/redis';
import { GRAPH_ANALYTICS_MANAGER_USER } from '../../../src/utils/access';
import type { AuthContext } from '../../../src/types/user';

vi.mock('../../../src/database/redis', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../src/database/redis')>()),
  redisGraphAnalyticsPopReady: vi.fn(),
  redisGraphAnalyticsMarkDirty: vi.fn(),
  redisGraphAnalyticsSetState: vi.fn(),
}));

vi.mock('../../../src/modules/graphAnalytics/graphAnalytics-compute', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../src/modules/graphAnalytics/graphAnalytics-compute')>()),
  processDirtyEntities: vi.fn(),
}));

const context = { source: 'test', otp_mandatory: false } as unknown as AuthContext;
const user = GRAPH_ANALYTICS_MANAGER_USER;

describe('graph analytics manager batches', () => {
  beforeEach(() => {
    vi.mocked(redisGraphAnalyticsPopReady).mockReset();
    vi.mocked(redisGraphAnalyticsMarkDirty).mockReset();
    vi.mocked(redisGraphAnalyticsSetState).mockReset();
    vi.mocked(processDirtyEntities).mockReset();
  });

  it('should do nothing when no entity is ready', async () => {
    vi.mocked(redisGraphAnalyticsPopReady).mockResolvedValue([]);
    const result = await processReadyEntities(context, user, getGraphAnalyticsComputeConfig());
    expect(result).toEqual({ processed: 0, removed: 0, failed: [] });
    expect(processDirtyEntities).not.toHaveBeenCalled();
    expect(redisGraphAnalyticsSetState).not.toHaveBeenCalled();
  });

  it('should record the run of a processed batch', async () => {
    vi.mocked(redisGraphAnalyticsPopReady).mockResolvedValue(['a', 'b']);
    vi.mocked(processDirtyEntities).mockResolvedValue({ processed: 2, removed: 0, failed: [] });
    const result = await processReadyEntities(context, user, getGraphAnalyticsComputeConfig());
    expect(result).toEqual({ processed: 2, removed: 0, failed: [] });
    expect(processDirtyEntities).toHaveBeenCalledWith(context, user, ['a', 'b'], expect.any(Object));
    expect(redisGraphAnalyticsSetState).toHaveBeenCalledTimes(1);
    expect(redisGraphAnalyticsMarkDirty).not.toHaveBeenCalled();
  });

  it('should queue again the entities whose similarity failed', async () => {
    vi.mocked(redisGraphAnalyticsPopReady).mockResolvedValue(['a', 'b']);
    vi.mocked(processDirtyEntities).mockResolvedValue({ processed: 2, removed: 0, failed: ['b'] });
    const result = await processReadyEntities(context, user, getGraphAnalyticsComputeConfig());
    expect(result.failed).toEqual(['b']);
    expect(redisGraphAnalyticsMarkDirty).toHaveBeenCalledWith(['b']);
    expect(redisGraphAnalyticsSetState).toHaveBeenCalledTimes(1);
  });

  it('should queue a failing batch again so it is retried', async () => {
    vi.mocked(redisGraphAnalyticsPopReady).mockResolvedValue(['a', 'b']);
    vi.mocked(processDirtyEntities).mockRejectedValue(new Error('engine unavailable'));
    await expect(processReadyEntities(context, user, getGraphAnalyticsComputeConfig())).rejects.toThrow('engine unavailable');
    expect(redisGraphAnalyticsMarkDirty).toHaveBeenCalledWith(['a', 'b']);
    expect(redisGraphAnalyticsSetState).not.toHaveBeenCalled();
  });
});
