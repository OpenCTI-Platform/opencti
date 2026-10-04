import { beforeEach, describe, expect, it, vi } from 'vitest';
import '../../../../src/modules/index';
import { getGraphAnalyticsComputeConfig, runInfrastructureClustering } from '../../../../src/modules/graphAnalytics/graphAnalytics-compute';
import { redisGraphAnalyticsAcquireRunLease, redisGraphAnalyticsGetState, redisGraphAnalyticsReleaseRunLease, redisGraphAnalyticsSetState } from '../../../../src/database/redis';
import { elList } from '../../../../src/database/engine';
import { finalizeClusteringRun, upsertGraphClusters } from '../../../../src/modules/graphAnalytics/graphAnalytics-store';
import { GRAPH_STATE_ANALYTICS_LAST_RUN_AT } from '../../../../src/modules/graphAnalytics/graphAnalytics-state';
import { GRAPH_ANALYTICS_MANAGER_USER } from '../../../../src/utils/access';
import type { AuthContext } from '../../../../src/types/user';

vi.mock('../../../../src/database/redis', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/redis')>()),
  redisGraphAnalyticsGetState: vi.fn(),
  redisGraphAnalyticsSetState: vi.fn(),
  redisGraphAnalyticsAcquireRunLease: vi.fn(),
  redisGraphAnalyticsReleaseRunLease: vi.fn(),
}));

vi.mock('../../../../src/database/engine', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/engine')>()),
  elList: vi.fn(),
}));

vi.mock('../../../../src/modules/graphAnalytics/graphAnalytics-store', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/modules/graphAnalytics/graphAnalytics-store')>()),
  upsertGraphClusters: vi.fn(),
  finalizeClusteringRun: vi.fn(),
}));

vi.mock('../../../../src/modules/graphAnalytics/graphAnalytics-notification', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/modules/graphAnalytics/graphAnalytics-notification')>()),
  notifyClusterMemberships: vi.fn(),
}));

const context = { source: 'test', otp_mandatory: false } as unknown as AuthContext;
const config = { ...getGraphAnalyticsComputeConfig(), clusteringEnabled: true };

describe('graph analytics platform clustering ownership', () => {
  beforeEach(() => {
    vi.mocked(redisGraphAnalyticsGetState).mockReset().mockResolvedValue({});
    vi.mocked(redisGraphAnalyticsSetState).mockReset();
    vi.mocked(redisGraphAnalyticsAcquireRunLease).mockReset().mockResolvedValue(true);
    vi.mocked(redisGraphAnalyticsReleaseRunLease).mockReset();
    vi.mocked(elList).mockReset().mockResolvedValue([]);
    vi.mocked(upsertGraphClusters).mockReset().mockResolvedValue(0);
    vi.mocked(finalizeClusteringRun).mockReset().mockResolvedValue({ publishedAt: new Date().toISOString(), removed: [] } as never);
  });

  it('should leave the clusters to an analytics run published while the population was computed', async () => {
    vi.mocked(redisGraphAnalyticsGetState)
      .mockResolvedValueOnce({})
      .mockResolvedValueOnce({ [GRAPH_STATE_ANALYTICS_LAST_RUN_AT]: new Date().toISOString() });
    const result = await runInfrastructureClustering(context, GRAPH_ANALYTICS_MANAGER_USER, config);
    expect(result.skipped).toBe(true);
    expect(redisGraphAnalyticsReleaseRunLease).toHaveBeenCalledTimes(1);
    expect(upsertGraphClusters).not.toHaveBeenCalled();
    expect(finalizeClusteringRun).not.toHaveBeenCalled();
  });

  it('should publish its run when the analytics process stayed inactive', async () => {
    const result = await runInfrastructureClustering(context, GRAPH_ANALYTICS_MANAGER_USER, config);
    expect(result.skipped).toBe(false);
    expect(finalizeClusteringRun).toHaveBeenCalledTimes(1);
    expect(redisGraphAnalyticsReleaseRunLease).toHaveBeenCalledTimes(1);
  });
});
