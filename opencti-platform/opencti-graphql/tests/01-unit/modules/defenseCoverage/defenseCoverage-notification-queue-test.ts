import { beforeEach, describe, expect, it, vi } from 'vitest';
import { type DefenseCoverageChange, type DefenseDeliveryProgress, deliverPendingDefenseLevelChanges } from '../../../../src/modules/defenseCoverage/defenseCoverage-notification';
import {
  clearPendingLevelChanges,
  listPendingLevelChanges,
  mergeQueuedLevelChange,
  queuePendingLevelChanges,
  savePendingLevelChange,
} from '../../../../src/modules/defenseCoverage/defenseCoverage-state';
import { redisGetDefensePendingLevelChanges, redisSetDefensePendingLevelChanges } from '../../../../src/database/redis';
import { logApp } from '../../../../src/config/conf';
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
      'ap-3': JSON.stringify(change('ap-3', 0, 1)),
    });
    await queuePendingLevelChanges([change('ap-1', 2, 1), change('ap-2', 1, 2), change('ap-3', 1, 2)]);
    expect(vi.mocked(redisGetDefensePendingLevelChanges)).toHaveBeenCalledWith(['ap-1', 'ap-2', 'ap-3']);
    const written = vi.mocked(redisSetDefensePendingLevelChanges).mock.calls[0][0];
    // trigger-1 was told the coverage stored when its delivery failed: it is told the new change from there
    expect(JSON.parse(written['ap-1'])).toEqual({ ...change('ap-1', 3, 1), trigger_baselines: [{ trigger_ids: ['trigger-1'], previous: coverage(2) }] });
    expect(JSON.parse(written['ap-2'])).toEqual(change('ap-2', 1, 2));
    // Nobody was told the earlier change of ap-3: every trigger is told the change from the first previous coverage
    expect(JSON.parse(written['ap-3'])).toEqual(change('ap-3', 0, 2));
  });

  it('should keep the baseline of every trigger over several failed deliveries', () => {
    // A delivery failed after trigger-1 and trigger-2; the next one, from a later coverage, failed after trigger-2 again
    const earlier: DefenseCoverageChange = {
      ...change('ap-1', 0, 2),
      delivered_trigger_ids: ['trigger-2'],
      trigger_baselines: [{ trigger_ids: ['trigger-1', 'trigger-2'], previous: coverage(1) }],
    };
    expect(mergeQueuedLevelChange(earlier, change('ap-1', 2, 3))).toEqual({
      ...change('ap-1', 0, 3),
      trigger_baselines: [{ trigger_ids: ['trigger-1'], previous: coverage(1) }, { trigger_ids: ['trigger-2'], previous: coverage(2) }],
    });
  });

  it('should drop a queued change whose trigger baselines cannot be read', async () => {
    vi.mocked(redisGetDefensePendingLevelChanges).mockResolvedValueOnce({
      'ap-1': JSON.stringify({ ...change('ap-1'), trigger_baselines: [{ previous: coverage(1) }] }),
      'ap-2': JSON.stringify({ ...change('ap-2'), trigger_baselines: [{ trigger_ids: ['trigger-1'], previous: coverage(1) }] }),
    });
    const { changes, unreadable } = await listPendingLevelChanges();
    expect(unreadable).toEqual(['ap-1']);
    expect(changes.map((pending) => pending.attack_pattern_id)).toEqual(['ap-2']);
  });

  it('should clear the delivered changes and keep what a failed delivery did not handle', async () => {
    const logAppErrorSpy = vi.spyOn(logApp, 'error');
    const logAppWarnSpy = vi.spyOn(logApp, 'warn');
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
    expect(logAppWarnSpy).toHaveBeenCalledTimes(1);
    expect(logAppWarnSpy.mock.calls[0][0]).toContain('kept for the next run');
    expect(logAppErrorSpy, 'A delivery retried at the next run is not an application error.').not.toHaveBeenCalled();
  });

  it('should clear every change once delivered and drop the unreadable entries', async () => {
    const logAppErrorSpy = vi.spyOn(logApp, 'error');
    vi.mocked(listPendingLevelChanges).mockResolvedValueOnce({ changes: [change('ap-1'), change('ap-2')], unreadable: ['ap-9'] });
    const notify = vi.fn(async () => 2);
    expect(await deliverPendingDefenseLevelChanges(context, notify, storedAsQueued)).toEqual(2);
    expect(vi.mocked(clearPendingLevelChanges).mock.calls).toEqual([[['ap-9']], [['ap-1', 'ap-2']]]);
    expect(vi.mocked(savePendingLevelChange)).not.toHaveBeenCalled();
    // A dropped entry is lost work
    expect(logAppErrorSpy).toHaveBeenCalledTimes(1);
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
