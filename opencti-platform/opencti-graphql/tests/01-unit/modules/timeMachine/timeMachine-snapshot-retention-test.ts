import { afterEach, describe, expect, it, vi } from 'vitest';

// The manager state, the retention rules and the snapshot store are canned: the schedule of the retention is under test.
const redisGetManagerEventStateMock = vi.fn();
const redisSetManagerEventStateMock = vi.fn();
vi.mock('../../../../src/database/redis', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/redis')>()),
  redisGetManagerEventState: (...args: unknown[]) => redisGetManagerEventStateMock(...args),
  redisSetManagerEventState: (...args: unknown[]) => redisSetManagerEventStateMock(...args),
}));
const listRulesMock = vi.fn();
vi.mock('../../../../src/modules/retentionRules/retentionRules-domain', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/modules/retentionRules/retentionRules-domain')>()),
  listRules: (...args: unknown[]) => listRulesMock(...args),
}));
const deleteSnapshotsBeforeMock = vi.fn();
vi.mock('../../../../src/modules/timeMachine/timeMachine-store', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/modules/timeMachine/timeMachine-store')>()),
  deleteSnapshotsBefore: (...args: unknown[]) => deleteSnapshotsBeforeMock(...args),
}));

import { snapshotHandler } from '../../../../src/manager/snapshotManager';

const DAY_MS = 24 * 3600 * 1000;

describe('Snapshot manager retention', () => {
  afterEach(() => {
    vi.clearAllMocks();
  });

  it('should purge the expired snapshots at every run, between two snapshot windows too', async () => {
    // The last window completed yesterday: the next one is days away
    redisGetManagerEventStateMock.mockResolvedValue(JSON.stringify({ cursor: new Date(Date.now() - DAY_MS).toISOString() }));
    listRulesMock.mockResolvedValue([{ scope: 'history', active: true, max_retention: 30, retention_unit: 'days' }]);
    deleteSnapshotsBeforeMock.mockResolvedValue(3);
    await snapshotHandler();
    expect(deleteSnapshotsBeforeMock).toHaveBeenCalledTimes(1);
    const horizon = new Date(deleteSnapshotsBeforeMock.mock.calls[0][0]).getTime();
    expect(Math.abs(horizon - (Date.now() - 30 * DAY_MS))).toBeLessThan(60000);
    // No snapshot window was opened
    expect(redisSetManagerEventStateMock).not.toHaveBeenCalled();
  });
});
