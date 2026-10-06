import { beforeEach, describe, expect, it, vi } from 'vitest';
import { patchAttribute } from '../../../../src/database/middleware';
import { topEntitiesList } from '../../../../src/database/middleware-loader';
import { FilterMode, FilterOperator } from '../../../../src/generated/graphql';
import { HUNT_PLAYBOOK_RESUME_LEASE_MINUTES, resumeSettledHuntPlaybooks } from '../../../../src/modules/hunt/hunt-automation';
import { findPlaybookHuntRuns, isHuntRunGroupSettled, resumeHuntPlaybookStep } from '../../../../src/modules/hunt/hunt-playbook';
import type { AuthContext } from '../../../../src/types/user';

vi.mock('../../../../src/database/middleware', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/database/middleware')>(),
  patchAttribute: vi.fn(),
}));

vi.mock('../../../../src/database/middleware-loader', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/database/middleware-loader')>(),
  topEntitiesList: vi.fn(),
}));

vi.mock('../../../../src/modules/hunt/hunt-playbook', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/modules/hunt/hunt-playbook')>(),
  findPlaybookHuntRuns: vi.fn(),
  isHuntRunGroupSettled: vi.fn(() => true),
  resumeHuntPlaybookStep: vi.fn(async () => true),
}));

const context = {} as AuthContext;
// Claimed by a tick that stopped with the platform, longer ago than the lease
const leader = {
  internal_id: 'run-1',
  playbook_leader: true,
  playbook_id: 'playbook-1',
  playbook_execution_id: 'execution-1',
  playbook_instance_id: 'instance-1',
  playbook_step_id: 'hunt-step',
  playbook_context: JSON.stringify({ playbook_id: 'playbook-1', step_id: 'hunt-step' }),
  playbook_resumed_at: new Date(Date.now() - (HUNT_PLAYBOOK_RESUME_LEASE_MINUTES + 5) * 60000).toISOString(),
};
const patches = () => vi.mocked(patchAttribute).mock.calls.map((call) => call[4]);

describe('Hunt playbook continuation', () => {
  beforeEach(() => {
    vi.mocked(patchAttribute).mockReset();
    vi.mocked(patchAttribute).mockResolvedValue({ element: leader } as never);
    vi.mocked(topEntitiesList).mockResolvedValue([leader] as never);
    vi.mocked(findPlaybookHuntRuns).mockResolvedValue([leader] as never);
    vi.mocked(resumeHuntPlaybookStep).mockClear();
  });

  it('should take over a claim older than its lease and end the leadership of the run once the step is handed over', async () => {
    expect(await resumeSettledHuntPlaybooks(context)).toEqual(1);
    const { filters } = vi.mocked(topEntitiesList).mock.calls[0][3] as { filters: { filters: unknown[]; filterGroups: unknown[] } };
    expect(filters.filters).toEqual([{ key: ['playbook_leader'], values: ['true'] }]);
    expect(filters.filterGroups).toEqual([expect.objectContaining({
      mode: FilterMode.Or,
      filters: [
        { key: ['playbook_resumed_at'], values: [], operator: FilterOperator.Nil },
        { key: ['playbook_resumed_at'], values: [expect.any(String)], operator: FilterOperator.Lte },
      ],
    })]);
    expect(resumeHuntPlaybookStep).toHaveBeenCalledTimes(1);
    expect(patches()).toEqual([{ playbook_resumed_at: expect.any(String) }, { playbook_leader: false }]);
  });

  it('should release the claim of a step that could not resume, for the next tick', async () => {
    vi.mocked(resumeHuntPlaybookStep).mockRejectedValueOnce(new Error('playbook unavailable'));
    expect(await resumeSettledHuntPlaybooks(context)).toEqual(0);
    expect(patches()).toEqual([{ playbook_resumed_at: expect.any(String) }, { playbook_resumed_at: null }]);
  });

  it('should keep the claim of a step handed over whose end of leadership could not be recorded', async () => {
    vi.mocked(patchAttribute)
      .mockResolvedValueOnce({ element: leader } as never)
      .mockRejectedValueOnce(new Error('engine unavailable'));
    expect(await resumeSettledHuntPlaybooks(context)).toEqual(1);
    expect(patches()).toEqual([{ playbook_resumed_at: expect.any(String) }, { playbook_leader: false }]);
  });

  it('should leave a step whose runs are not settled', async () => {
    vi.mocked(isHuntRunGroupSettled).mockReturnValueOnce(false);
    expect(await resumeSettledHuntPlaybooks(context)).toEqual(0);
    expect(patchAttribute).not.toHaveBeenCalled();
    expect(resumeHuntPlaybookStep).not.toHaveBeenCalled();
  });
});
