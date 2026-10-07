import { beforeEach, describe, expect, it, vi } from 'vitest';
import { topEntitiesList } from '../../../../src/database/middleware-loader';
import { runScheduledHunts } from '../../../../src/modules/hunt/hunt-automation';
import { updateHuntRunInformation } from '../../../../src/modules/hunt/hunt-stats';
import { createHuntRuns } from '../../../../src/modules/hunt/huntRun/huntRun-domain';
import { testContext } from '../../../utils/testQuery';

vi.mock('../../../../src/database/middleware-loader', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/database/middleware-loader')>(),
  topEntitiesList: vi.fn(),
}));

vi.mock('../../../../src/modules/hunt/huntRun/huntRun-domain', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/modules/hunt/huntRun/huntRun-domain')>(),
  createHuntRuns: vi.fn(),
}));

vi.mock('../../../../src/modules/hunt/hunt-stats', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/modules/hunt/hunt-stats')>(),
  updateHuntRunInformation: vi.fn(),
}));

const due = '2026-10-07T00:00:00.000Z';
const cronHunt = (references: Record<string, unknown> = {}) => ({ internal_id: 'hunt-1', hunt_schedule: '0 */6 * * *', next_run_at: due, ...references });
const plannedAgain = () => vi.mocked(updateHuntRunInformation).mock.calls.some(([, huntId, patch]) => huntId === 'hunt-1' && 'next_run_at' in (patch as object));

describe('Scheduled hunts of a manager tick', () => {
  beforeEach(() => {
    vi.mocked(updateHuntRunInformation).mockReset();
    vi.mocked(createHuntRuns).mockReset();
  });

  it('should plan the next occurrence of a due hunt once its runs started', async () => {
    vi.mocked(topEntitiesList).mockResolvedValue([cronHunt()] as never);
    vi.mocked(createHuntRuns).mockResolvedValue([{ internal_id: 'run-1' }] as never);
    expect(await runScheduledHunts(testContext)).toEqual(1);
    expect(plannedAgain()).toBe(true);
  });

  it('should keep the occurrence due when no hunt connector serves the scope yet', async () => {
    vi.mocked(topEntitiesList).mockResolvedValue([cronHunt()] as never);
    vi.mocked(createHuntRuns).mockResolvedValue([] as never);
    expect(await runScheduledHunts(testContext)).toEqual(0);
    expect(plannedAgain()).toBe(false);
  });

  it('should plan the first occurrence of a hunt, and the occurrences falling while its PIR activation is disarmed, without running', async () => {
    vi.mocked(topEntitiesList).mockResolvedValue([cronHunt({ next_run_at: null })] as never);
    await runScheduledHunts(testContext);
    expect(plannedAgain()).toBe(true);
    vi.mocked(updateHuntRunInformation).mockReset();
    vi.mocked(topEntitiesList).mockResolvedValue([cronHunt({ hunt_pir_activation: true, hunt_pir_armed: false })] as never);
    await runScheduledHunts(testContext);
    expect(plannedAgain()).toBe(true);
    expect(createHuntRuns).not.toHaveBeenCalled();
  });
});
