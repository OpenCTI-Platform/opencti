import { beforeEach, describe, expect, it, vi } from 'vitest';
import { patchAttribute } from '../../../../src/database/middleware';
import { fullEntitiesList } from '../../../../src/database/middleware-loader';
import { offsetToCursor } from '../../../../src/database/utils';
import { FilterMode } from '../../../../src/generated/graphql';
import { resumeSettledHuntPlaybooks } from '../../../../src/modules/hunt/hunt-automation';
import { buildHuntPlaybookResume, executeHuntPlaybookResume, findPlaybookHuntRuns, isHuntRunGroupSettled } from '../../../../src/modules/hunt/hunt-playbook';
import { HUNT_CONFIG } from '../../../../src/modules/hunt/hunt-utils';
import type { AuthContext } from '../../../../src/types/user';

vi.mock('../../../../src/database/middleware', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/database/middleware')>(),
  patchAttribute: vi.fn(),
}));

vi.mock('../../../../src/database/middleware-loader', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/database/middleware-loader')>(),
  fullEntitiesList: vi.fn(),
}));

vi.mock('../../../../src/modules/hunt/hunt-playbook', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/modules/hunt/hunt-playbook')>(),
  findPlaybookHuntRuns: vi.fn(),
  isHuntRunGroupSettled: vi.fn(() => true),
  buildHuntPlaybookResume: vi.fn(async () => ({ playbook_id: 'playbook-1', step_id: 'hunt-step' })),
  executeHuntPlaybookResume: vi.fn(async () => true),
}));

const context = {} as AuthContext;
const leaderOf = (index: number) => ({
  internal_id: `run-${index}`,
  playbook_leader: true,
  playbook_id: 'playbook-1',
  playbook_execution_id: `execution-${index}`,
  playbook_instance_id: 'instance-1',
  playbook_step_id: 'hunt-step',
  playbook_context: JSON.stringify({ playbook_id: 'playbook-1', step_id: 'hunt-step' }),
  sort: [index, `run-${index}`],
});
const leader = leaderOf(1);
let leaders = [leader];
const patches = () => vi.mocked(patchAttribute).mock.calls.map((call) => call[4]);
const scanOptions = (call: number) => vi.mocked(fullEntitiesList).mock.calls[call][3] as { after?: string; filters: unknown };

describe('Hunt playbook continuation', () => {
  beforeEach(() => {
    leaders = [leader];
    vi.mocked(patchAttribute).mockReset();
    vi.mocked(patchAttribute).mockResolvedValue({ element: leader } as never);
    vi.mocked(fullEntitiesList).mockReset();
    vi.mocked(fullEntitiesList).mockImplementation((async (_context: unknown, _user: unknown, _types: unknown, opts: { callback: (elements: unknown[]) => Promise<boolean> }) => {
      await opts.callback(leaders);
      return [];
    }) as never);
    vi.mocked(findPlaybookHuntRuns).mockImplementation((async () => [leader]) as never);
    vi.mocked(buildHuntPlaybookResume).mockClear();
    vi.mocked(executeHuntPlaybookResume).mockReset();
    vi.mocked(executeHuntPlaybookResume).mockResolvedValue(true);
  });

  it('should hand the continuation over before the step executes', async () => {
    expect(await resumeSettledHuntPlaybooks(context)).toEqual(1);
    expect(scanOptions(0).filters).toEqual({ mode: FilterMode.And, filters: [{ key: ['playbook_leader'], values: ['true'] }], filterGroups: [] });
    expect(patches()).toEqual([{ playbook_leader: false, playbook_resumed_at: expect.any(String) }]);
    expect(executeHuntPlaybookResume).toHaveBeenCalledTimes(1);
    expect(vi.mocked(patchAttribute).mock.invocationCallOrder[0]).toBeLessThan(vi.mocked(executeHuntPlaybookResume).mock.invocationCallOrder[0]);
  });

  it('should not execute a step whose handover could not be recorded, and execute it once handed over at the next tick', async () => {
    vi.mocked(patchAttribute).mockRejectedValueOnce(new Error('engine unavailable'));
    expect(await resumeSettledHuntPlaybooks(context)).toEqual(0);
    expect(executeHuntPlaybookResume).not.toHaveBeenCalled();
    expect(await resumeSettledHuntPlaybooks(context)).toEqual(1);
    expect(executeHuntPlaybookResume).toHaveBeenCalledTimes(1);
  });

  it('should never execute again a step that failed once handed over', async () => {
    vi.mocked(executeHuntPlaybookResume).mockRejectedValueOnce(new Error('playbook step failed'));
    expect(await resumeSettledHuntPlaybooks(context)).toEqual(1);
    expect(patches()).toEqual([{ playbook_leader: false, playbook_resumed_at: expect.any(String) }]);
    expect(executeHuntPlaybookResume).toHaveBeenCalledTimes(1);
  });

  it('should keep the continuation of a step that could not be built, for the next tick', async () => {
    vi.mocked(buildHuntPlaybookResume).mockRejectedValueOnce(new Error('results unavailable'));
    expect(await resumeSettledHuntPlaybooks(context)).toEqual(0);
    expect(patchAttribute).not.toHaveBeenCalled();
    expect(executeHuntPlaybookResume).not.toHaveBeenCalled();
  });

  it('should leave a step whose runs are not settled', async () => {
    vi.mocked(isHuntRunGroupSettled).mockReturnValueOnce(false);
    expect(await resumeSettledHuntPlaybooks(context)).toEqual(0);
    expect(patchAttribute).not.toHaveBeenCalled();
    expect(executeHuntPlaybookResume).not.toHaveBeenCalled();
  });

  it('should resume at most the budget of a tick and start the next tick after the last continuation it read', async () => {
    leaders = Array.from({ length: HUNT_CONFIG.maxRunsPerTick + 1 }, (_, index) => leaderOf(index + 1));
    expect(await resumeSettledHuntPlaybooks(context)).toEqual(HUNT_CONFIG.maxRunsPerTick);
    leaders = leaders.slice(HUNT_CONFIG.maxRunsPerTick);
    expect(await resumeSettledHuntPlaybooks(context)).toEqual(1);
    expect(scanOptions(1).after).toEqual(offsetToCursor(leaderOf(HUNT_CONFIG.maxRunsPerTick).sort));
    expect(executeHuntPlaybookResume).toHaveBeenCalledTimes(HUNT_CONFIG.maxRunsPerTick + 1);
    // The last page was read: the scan starts over
    expect(await resumeSettledHuntPlaybooks(context)).toEqual(1);
    expect(scanOptions(2).after).toBeUndefined();
  });
});
