import { afterEach, describe, expect, it, vi } from 'vitest';
import { fullEntitiesList } from '../../../../src/database/middleware-loader';
import { reconcilePirActivatedHunts } from '../../../../src/modules/hunt/hunt-automation';
import { findByIds } from '../../../../src/modules/hunt/hunt-loaders';
import { updateHuntRunInformation } from '../../../../src/modules/hunt/hunt-stats';
import { type BasicStoreEntityHunt, HUNT_SCHEDULE_STANDING, HUNT_STATUS_ACTIVE, RELATION_HUNT_TARGETS } from '../../../../src/modules/hunt/hunt-types';
import { createHuntRuns } from '../../../../src/modules/hunt/huntRun/huntRun-domain';
import { RELATION_IN_PIR } from '../../../../src/schema/internalRelationship';
import { testContext } from '../../../utils/testQuery';

vi.mock('../../../../src/database/middleware-loader', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/database/middleware-loader')>(),
  fullEntitiesList: vi.fn(),
}));

vi.mock('../../../../src/modules/hunt/hunt-loaders', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/modules/hunt/hunt-loaders')>(),
  findByIds: vi.fn(),
}));

vi.mock('../../../../src/modules/hunt/hunt-stats', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/modules/hunt/hunt-stats')>(),
  updateHuntRunInformation: vi.fn(),
}));

vi.mock('../../../../src/modules/hunt/huntRun/huntRun-domain', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/modules/hunt/huntRun/huntRun-domain')>(),
  createHuntRuns: vi.fn(),
}));

const pirHunt = (id: string, schedule: string, index: number) => ({
  internal_id: id,
  hunt_status: HUNT_STATUS_ACTIVE,
  hunt_schedule: schedule,
  hunt_pir_activation: true,
  hunt_pir_armed: false,
  next_run_at: '2026-10-07T10:00:00.000Z',
  [RELATION_HUNT_TARGETS]: ['malware-1'],
  sort: [index],
}) as unknown as BasicStoreEntityHunt;

describe('PIR activation arming of a manager tick', () => {
  afterEach(() => {
    vi.mocked(fullEntitiesList).mockReset();
    vi.mocked(findByIds).mockReset();
    vi.mocked(updateHuntRunInformation).mockReset();
    vi.mocked(createHuntRuns).mockReset();
  });

  it('should let the arming run stand for the due occurrence of a cron hunt, and leave a standing trigger alone', async () => {
    const hunts = [pirHunt('hunt-cron', '0 */6 * * *', 0), pirHunt('hunt-standing', HUNT_SCHEDULE_STANDING, 1)];
    vi.mocked(fullEntitiesList).mockImplementation(async (_context, _user, _types, opts) => {
      await opts?.callback?.(hunts as never);
      return [];
    });
    vi.mocked(findByIds).mockResolvedValue([{ internal_id: 'malware-1', [RELATION_IN_PIR]: ['pir-1'] }] as never);
    vi.mocked(createHuntRuns).mockResolvedValue([{ internal_id: 'run-1' }] as never);
    const before = Date.now();
    expect(await reconcilePirActivatedHunts(testContext)).toBe(2);
    const patches = new Map(vi.mocked(updateHuntRunInformation).mock.calls.map(([, huntId, patch]) => [huntId, patch as Record<string, unknown>]));
    const cron = patches.get('hunt-cron') as Record<string, unknown>;
    expect(cron).toMatchObject({ hunt_pir_armed: true });
    expect(new Date(cron.next_run_at as string).getTime()).toBeGreaterThan(before);
    const standing = patches.get('hunt-standing') as Record<string, unknown>;
    expect(standing).toMatchObject({ hunt_pir_armed: true });
    expect(standing).not.toHaveProperty('next_run_at');
  });
});
