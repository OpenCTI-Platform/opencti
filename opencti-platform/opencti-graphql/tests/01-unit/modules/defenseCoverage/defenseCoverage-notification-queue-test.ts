import { beforeEach, describe, expect, it, vi } from 'vitest';
import {
  type DefenseCoverageChange,
  type DefenseDeliveryProgress,
  deliverPendingDefenseLevelChanges,
  remainingDefenseLevelChanges,
} from '../../../../src/modules/defenseCoverage/defenseCoverage-notification';
import { clearPendingLevelChanges, listPendingLevelChanges, replacePendingLevelChanges } from '../../../../src/modules/defenseCoverage/defenseCoverage-state';
import type { AuthContext } from '../../../../src/types/user';

vi.mock('../../../../src/modules/defenseCoverage/defenseCoverage-state', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/modules/defenseCoverage/defenseCoverage-state')>()),
  listPendingLevelChanges: vi.fn(),
  replacePendingLevelChanges: vi.fn(async () => {}),
  clearPendingLevelChanges: vi.fn(async () => {}),
}));

const context = {} as AuthContext;
const change = (attackPatternId: string) => ({ attack_pattern_id: attackPatternId } as unknown as DefenseCoverageChange);

describe('Queued defense level changes', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should clear the delivered batches and keep what a failed delivery did not handle', async () => {
    vi.mocked(listPendingLevelChanges).mockResolvedValue([
      { id: 'batch-1', changes: [change('ap-1'), change('ap-2')] },
      { id: 'batch-2', changes: [change('ap-3'), change('ap-4'), change('ap-5')] },
      { id: 'batch-3', changes: [change('ap-6')] },
    ]);
    const notify = vi.fn(async (_context: AuthContext, changes: DefenseCoverageChange[], progress?: DefenseDeliveryProgress) => {
      if (changes[0].attack_pattern_id === 'ap-3') {
        // ap-3 is fully handled, ap-4 fails after its first trigger stored its notification
        if (progress) {
          progress.done = 1;
          progress.triggerIds = ['trigger-1'];
        }
        throw new Error('notification stream unavailable');
      }
      if (progress) progress.done = changes.length;
      return changes.length;
    });
    const delivered = await deliverPendingDefenseLevelChanges(context, notify);
    expect(delivered).toEqual(2);
    expect(vi.mocked(clearPendingLevelChanges).mock.calls).toEqual([['batch-1']]);
    expect(vi.mocked(replacePendingLevelChanges)).toHaveBeenCalledWith('batch-2', [
      { attack_pattern_id: 'ap-4', delivered_trigger_ids: ['trigger-1'] },
      change('ap-5'),
    ]);
    // The next batches wait behind the failed one
    expect(notify).toHaveBeenCalledTimes(2);
  });

  it('should keep the triggers already handled when a change fails again', () => {
    const retried = { ...change('ap-1'), delivered_trigger_ids: ['trigger-1'] };
    expect(remainingDefenseLevelChanges([retried, change('ap-2')], { done: 0, triggerIds: ['trigger-1', 'trigger-2'] })).toEqual([
      { attack_pattern_id: 'ap-1', delivered_trigger_ids: ['trigger-1', 'trigger-2'] },
      change('ap-2'),
    ]);
    expect(remainingDefenseLevelChanges([change('ap-1'), change('ap-2')], { done: 1, triggerIds: [] })).toEqual([change('ap-2')]);
  });

  it('should keep a batch untouched when its delivery fails before the first change', async () => {
    vi.mocked(listPendingLevelChanges).mockResolvedValue([{ id: 'batch-1', changes: [change('ap-1')] }]);
    const notify = vi.fn(async () => {
      throw new Error('no live trigger could be read');
    });
    expect(await deliverPendingDefenseLevelChanges(context, notify)).toEqual(0);
    expect(vi.mocked(replacePendingLevelChanges)).not.toHaveBeenCalled();
    expect(vi.mocked(clearPendingLevelChanges)).not.toHaveBeenCalled();
  });

  it('should drop a batch that cannot be read', async () => {
    vi.mocked(listPendingLevelChanges).mockResolvedValue([{ id: 'batch-1' }, { id: 'batch-2', changes: [change('ap-1')] }]);
    const notify = vi.fn(async () => 1);
    expect(await deliverPendingDefenseLevelChanges(context, notify)).toEqual(1);
    expect(vi.mocked(clearPendingLevelChanges).mock.calls).toEqual([['batch-1'], ['batch-2']]);
  });
});
