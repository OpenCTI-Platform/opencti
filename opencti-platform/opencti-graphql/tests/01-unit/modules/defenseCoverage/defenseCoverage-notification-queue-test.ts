import { beforeEach, describe, expect, it, vi } from 'vitest';
import { type DefenseCoverageChange, type DefenseDeliveryProgress, deliverPendingDefenseLevelChanges } from '../../../../src/modules/defenseCoverage/defenseCoverage-notification';
import { clearPendingLevelChanges, listPendingLevelChanges, queuePendingLevelChanges, savePendingLevelChange } from '../../../../src/modules/defenseCoverage/defenseCoverage-state';
import { redisGetDefensePendingLevelChanges, redisSetDefensePendingLevelChanges } from '../../../../src/database/redis';
import type { AuthContext } from '../../../../src/types/user';

vi.mock('../../../../src/database/redis', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/redis')>()),
  redisGetDefensePendingLevelChanges: vi.fn(async () => ({})),
  redisSetDefensePendingLevelChanges: vi.fn(async () => {}),
  redisDeleteDefensePendingLevelChanges: vi.fn(async () => {}),
}));

vi.mock('../../../../src/modules/defenseCoverage/defenseCoverage-state', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../../src/modules/defenseCoverage/defenseCoverage-state')>();
  return {
    ...actual,
    listPendingLevelChanges: vi.fn(actual.listPendingLevelChanges),
    savePendingLevelChange: vi.fn(async () => {}),
    clearPendingLevelChanges: vi.fn(async () => {}),
  };
});

const context = {} as AuthContext;
const coverage = (level: number) => ({ level, computed_at: `2026-10-0${level + 1}T00:00:00.000Z` }) as unknown as DefenseCoverageChange['coverage'];
const change = (attackPatternId: string, from = 1, to = 2): DefenseCoverageChange => ({ attack_pattern_id: attackPatternId, previous: coverage(from), coverage: coverage(to) });
// The coverages of the queued changes were stored
const storedAsQueued = async (_context: AuthContext, ids: string[]) => new Map(ids.map((id) => [id, coverage(2)]));

describe('Queued defense level changes', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should keep one entry per technique, with the first previous coverage and the latest coverage', async () => {
    vi.mocked(redisGetDefensePendingLevelChanges).mockResolvedValueOnce({
      'ap-1': JSON.stringify({ ...change('ap-1', 3, 2), delivered_trigger_ids: ['trigger-1'] }),
    });
    await queuePendingLevelChanges([change('ap-1', 2, 1), change('ap-2', 1, 2)]);
    expect(vi.mocked(redisGetDefensePendingLevelChanges)).toHaveBeenCalledWith(['ap-1', 'ap-2']);
    const written = vi.mocked(redisSetDefensePendingLevelChanges).mock.calls[0][0];
    // A change queued again is delivered again to every trigger
    expect(JSON.parse(written['ap-1'])).toEqual(change('ap-1', 3, 1));
    expect(JSON.parse(written['ap-2'])).toEqual(change('ap-2', 1, 2));
  });

  it('should clear the delivered changes and keep what a failed delivery did not handle', async () => {
    vi.mocked(listPendingLevelChanges).mockResolvedValueOnce({ changes: [change('ap-1'), change('ap-2'), change('ap-3')], unreadable: [] });
    const notify = vi.fn(async (_context: AuthContext, _changes: DefenseCoverageChange[], progress?: DefenseDeliveryProgress) => {
      // ap-1 is fully handled, ap-2 fails after its first trigger stored its notification
      if (progress) {
        progress.done = 1;
        progress.triggerIds = ['trigger-1'];
      }
      throw new Error('notification stream unavailable');
    });
    expect(await deliverPendingDefenseLevelChanges(context, notify, storedAsQueued)).toEqual(0);
    expect(vi.mocked(clearPendingLevelChanges).mock.calls).toEqual([[['ap-1']]]);
    expect(vi.mocked(savePendingLevelChange)).toHaveBeenCalledWith({ ...change('ap-2'), delivered_trigger_ids: ['trigger-1'] });
  });

  it('should clear every change once delivered and drop the unreadable entries', async () => {
    vi.mocked(listPendingLevelChanges).mockResolvedValueOnce({ changes: [change('ap-1'), change('ap-2')], unreadable: ['ap-9'] });
    const notify = vi.fn(async () => 2);
    expect(await deliverPendingDefenseLevelChanges(context, notify, storedAsQueued)).toEqual(2);
    expect(vi.mocked(clearPendingLevelChanges).mock.calls).toEqual([[['ap-9']], [['ap-1', 'ap-2']]]);
    expect(vi.mocked(savePendingLevelChange)).not.toHaveBeenCalled();
  });

  it('should deliver each change up to the stored coverage and drop the techniques without one', async () => {
    vi.mocked(listPendingLevelChanges).mockResolvedValueOnce({ changes: [change('ap-1', 1, 3), change('ap-2')], unreadable: [] });
    const notify = vi.fn(async (_context: AuthContext, _changes: DefenseCoverageChange[]) => 1);
    const storedPrevious = async () => new Map([['ap-1', coverage(1)]]);
    expect(await deliverPendingDefenseLevelChanges(context, notify, storedPrevious)).toEqual(1);
    // The new coverage of ap-1 was never stored: the change is told from its previous coverage to the stored one
    expect(notify.mock.calls[0][1]).toEqual([{ ...change('ap-1'), coverage: coverage(1) }]);
    expect(vi.mocked(clearPendingLevelChanges).mock.calls).toEqual([[['ap-2']], [['ap-1']]]);
  });

  it('should keep a change untouched when its delivery fails before the first trigger', async () => {
    vi.mocked(listPendingLevelChanges).mockResolvedValueOnce({ changes: [change('ap-1')], unreadable: [] });
    const notify = vi.fn(async () => {
      throw new Error('no live trigger could be read');
    });
    expect(await deliverPendingDefenseLevelChanges(context, notify, storedAsQueued)).toEqual(0);
    expect(vi.mocked(clearPendingLevelChanges).mock.calls).toEqual([[[]]]);
    expect(vi.mocked(savePendingLevelChange)).not.toHaveBeenCalled();
  });
});
