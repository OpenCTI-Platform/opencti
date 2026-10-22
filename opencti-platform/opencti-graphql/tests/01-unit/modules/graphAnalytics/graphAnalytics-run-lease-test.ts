import { beforeEach, describe, expect, it, vi } from 'vitest';
import '../../../../src/modules/index';
import { finalizeClusteringRun } from '../../../../src/modules/graphAnalytics/graphAnalytics-store';
import { elBulk, elList, elRawSearch, elRawUpdateByQuery } from '../../../../src/database/engine';
import { SYSTEM_USER } from '../../../../src/utils/access';
import type { AuthContext } from '../../../../src/types/user';

// The engine is canned: the lease checks around every publication write are under test.
vi.mock('../../../../src/database/engine', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/engine')>()),
  elBulk: vi.fn(),
  elList: vi.fn(),
  elRawSearch: vi.fn(),
  elRawUpdateByQuery: vi.fn(),
}));

const context = { source: 'test', otp_mandatory: false } as unknown as AuthContext;
const STALE_CLUSTERS = 1200;

// A lease that holds for `checks` checks, then is lost to another run
const leaseHeldFor = (checks: number) => {
  let done = 0;
  return vi.fn(async () => {
    done += 1;
    if (done > checks) throw new Error('lease lost');
  });
};

const writes = () => vi.mocked(elRawUpdateByQuery).mock.calls.length + vi.mocked(elBulk).mock.calls.length;

describe('graph analytics clustering run publication', () => {
  beforeEach(() => {
    vi.mocked(elBulk).mockReset().mockResolvedValue({} as never);
    vi.mocked(elRawUpdateByQuery).mockReset().mockResolvedValue({} as never);
    vi.mocked(elRawSearch).mockReset().mockResolvedValue({ aggregations: { pairs: { buckets: [] } } } as never);
    vi.mocked(elList).mockReset().mockResolvedValue(
      Array.from({ length: STALE_CLUSTERS }, (_, index) => ({ _index: 'opencti_internal_objects', internal_id: `cluster-${index}` })) as never,
    );
  });

  it('should check the lease before every write, each update by query and each bulk chunk', async () => {
    const assertRunLease = leaseHeldFor(Number.POSITIVE_INFINITY);
    await finalizeClusteringRun(context, SYSTEM_USER, 'run-1', assertRunLease);
    // 5 updates by query (publish, drop pending clusters, promote, drop pending metrics, clear) and 3 deletion chunks
    expect(elRawUpdateByQuery).toHaveBeenCalledTimes(5);
    expect(elBulk).toHaveBeenCalledTimes(3);
    // one more check opens the run, before its first read
    expect(assertRunLease).toHaveBeenCalledTimes(writes() + 1);
  });

  it('should stop between the two cluster publication writes when the lease is lost', async () => {
    const assertRunLease = leaseHeldFor(2);
    await expect(finalizeClusteringRun(context, SYSTEM_USER, 'run-1', assertRunLease)).rejects.toThrow('lease lost');
    expect(elRawUpdateByQuery).toHaveBeenCalledTimes(1);
    expect(elBulk).not.toHaveBeenCalled();
  });

  it('should stop between two stale cluster deletion chunks when the lease is lost', async () => {
    const assertRunLease = leaseHeldFor(6);
    await expect(finalizeClusteringRun(context, SYSTEM_USER, 'run-1', assertRunLease)).rejects.toThrow('lease lost');
    expect(elBulk).toHaveBeenCalledTimes(1);
    // the members of older runs are never detached by a run that lost its lease
    expect(elRawUpdateByQuery).toHaveBeenCalledTimes(4);
  });
});
