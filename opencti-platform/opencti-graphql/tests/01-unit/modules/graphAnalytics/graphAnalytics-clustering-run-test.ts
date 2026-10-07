import { beforeEach, describe, expect, it, vi } from 'vitest';
import '../../../../src/modules/index';
import {
  getGraphAnalyticsComputeConfig,
  GRAPH_RUN_LEASE_HEARTBEAT_MS,
  runInfrastructureClustering,
  withRunLeaseHeartbeat,
} from '../../../../src/modules/graphAnalytics/graphAnalytics-compute';
import {
  redisGraphAnalyticsAcquireRunLease,
  redisGraphAnalyticsGetState,
  redisGraphAnalyticsReleaseRunLease,
  redisGraphAnalyticsRenewRunLease,
  redisGraphAnalyticsSetState,
} from '../../../../src/database/redis';
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
  redisGraphAnalyticsRenewRunLease: vi.fn(),
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
    vi.mocked(redisGraphAnalyticsRenewRunLease).mockReset().mockResolvedValue(true);
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

  it('should stop before writing once its lease went to another run', async () => {
    vi.mocked(redisGraphAnalyticsRenewRunLease).mockResolvedValue(false);
    const run = runInfrastructureClustering(context, GRAPH_ANALYTICS_MANAGER_USER, config);
    await expect(run).rejects.toThrow('Graph analytics run lost its write lease to another run');
    expect(upsertGraphClusters).not.toHaveBeenCalled();
    expect(finalizeClusteringRun).not.toHaveBeenCalled();
    expect(redisGraphAnalyticsReleaseRunLease).toHaveBeenCalledTimes(1);
  });
});

describe('graph analytics run lease heartbeat', () => {
  beforeEach(() => {
    vi.mocked(redisGraphAnalyticsRenewRunLease).mockReset().mockResolvedValue(true);
  });

  it('should keep renewing the lease while a long write runs, and stop once it ends', async () => {
    vi.useFakeTimers();
    try {
      let finishWrite: () => void = () => {};
      const run = withRunLeaseHeartbeat('run-1', () => new Promise<void>((resolve) => {
        finishWrite = resolve;
      }));
      await vi.advanceTimersByTimeAsync(GRAPH_RUN_LEASE_HEARTBEAT_MS * 3);
      expect(redisGraphAnalyticsRenewRunLease).toHaveBeenCalledTimes(3);
      finishWrite();
      await run;
      await vi.advanceTimersByTimeAsync(GRAPH_RUN_LEASE_HEARTBEAT_MS * 2);
      expect(redisGraphAnalyticsRenewRunLease).toHaveBeenCalledTimes(3);
    } finally {
      vi.useRealTimers();
    }
  });

  it('should refuse every write after a renewal found the lease taken by another run', async () => {
    vi.useFakeTimers();
    try {
      vi.mocked(redisGraphAnalyticsRenewRunLease).mockResolvedValueOnce(false);
      const run = withRunLeaseHeartbeat('run-1', async (assertRunLease) => {
        await vi.advanceTimersByTimeAsync(GRAPH_RUN_LEASE_HEARTBEAT_MS);
        await assertRunLease();
      });
      await expect(run).rejects.toThrow('Graph analytics run lost its write lease to another run');
      // a lease lost once is never claimed back, even when the key is free again
      expect(redisGraphAnalyticsRenewRunLease).toHaveBeenCalledTimes(1);
    } finally {
      vi.useRealTimers();
    }
  });
});
