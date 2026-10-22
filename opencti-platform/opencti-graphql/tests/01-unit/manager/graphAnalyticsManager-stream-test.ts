import { beforeEach, describe, expect, it, vi } from 'vitest';
import '../../../src/modules/index';
import { resolveStreamStart } from '../../../src/manager/graphAnalyticsManager';
import { redisGetManagerEventState, redisSetManagerEventState } from '../../../src/database/redis';
import { fetchStreamInfo } from '../../../src/database/stream/stream-handler';
import { GRAPH_ANALYTICS_MANAGER_NAME } from '../../../src/modules/graphAnalytics/graphAnalytics-state';

vi.mock('../../../src/database/redis', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../src/database/redis')>()),
  redisGetManagerEventState: vi.fn(),
  redisSetManagerEventState: vi.fn(),
}));

vi.mock('../../../src/database/stream/stream-handler', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../src/database/stream/stream-handler')>()),
  fetchStreamInfo: vi.fn(),
}));

describe('graph analytics manager stream start', () => {
  beforeEach(() => {
    vi.mocked(redisGetManagerEventState).mockReset();
    vi.mocked(redisSetManagerEventState).mockReset();
    vi.mocked(fetchStreamInfo).mockReset();
  });

  it('should resume from the saved position', async () => {
    vi.mocked(redisGetManagerEventState).mockResolvedValue('1700000000000-0');
    expect(await resolveStreamStart()).toBe('1700000000000-0');
    expect(fetchStreamInfo).not.toHaveBeenCalled();
    expect(redisSetManagerEventState).not.toHaveBeenCalled();
  });

  it('should save the live position at the first start, so the events of the next ticks are not skipped', async () => {
    vi.mocked(redisGetManagerEventState).mockResolvedValue(null as unknown as string);
    vi.mocked(fetchStreamInfo).mockResolvedValue({ lastEventId: '1700000000123-0' } as Awaited<ReturnType<typeof fetchStreamInfo>>);
    expect(await resolveStreamStart()).toBe('1700000000123-0');
    expect(redisSetManagerEventState).toHaveBeenCalledWith(GRAPH_ANALYTICS_MANAGER_NAME, '1700000000123-0');
  });

  it('should start from the beginning when the stream does not exist yet', async () => {
    vi.mocked(redisGetManagerEventState).mockResolvedValue(null as unknown as string);
    vi.mocked(fetchStreamInfo).mockRejectedValue(new Error('no stream'));
    expect(await resolveStreamStart()).toBe('0-0');
    expect(redisSetManagerEventState).toHaveBeenCalledWith(GRAPH_ANALYTICS_MANAGER_NAME, '0-0');
  });
});
