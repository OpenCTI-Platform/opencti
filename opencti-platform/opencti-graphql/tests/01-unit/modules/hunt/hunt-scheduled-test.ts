import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { fullEntitiesList } from '../../../../src/database/middleware-loader';
import { cursorToOffset } from '../../../../src/database/utils';
import { runScheduledHunts } from '../../../../src/modules/hunt/hunt-automation';
import { updateHuntRunInformation } from '../../../../src/modules/hunt/hunt-stats';
import type { BasicStoreEntityHunt } from '../../../../src/modules/hunt/hunt-types';
import { HUNT_CONFIG } from '../../../../src/modules/hunt/hunt-utils';
import { createHuntRuns } from '../../../../src/modules/hunt/huntRun/huntRun-domain';
import { testContext } from '../../../utils/testQuery';

vi.mock('../../../../src/database/middleware-loader', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/database/middleware-loader')>(),
  fullEntitiesList: vi.fn(),
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
const cronHunt = (id: string, index: number, references: Record<string, unknown> = {}) => ({ internal_id: id, sort: [index], hunt_schedule: '0 */6 * * *', next_run_at: due, ...references }) as unknown as BasicStoreEntityHunt;

// The due hunts the manager lists, page by page after the cursor of the scan
const serveHunts = (hunts: BasicStoreEntityHunt[]) => {
  vi.mocked(fullEntitiesList).mockImplementation(async (_context, _user, _types, opts) => {
    const start = opts?.after ? Number(cursorToOffset(opts.after)[0]) + 1 : 0;
    const first = opts?.first ?? hunts.length;
    for (let offset = start; offset < hunts.length; offset += first) {
      if (await opts?.callback?.(hunts.slice(offset, offset + first) as never) === false) {
        break;
      }
    }
    return [];
  });
};
// Only the hunts named ready have a hunt connector serving their scope
const connectorsServe = () => vi.mocked(createHuntRuns).mockImplementation(async (_context, hunt) => (
  hunt.internal_id.startsWith('ready') ? [{ internal_id: `run-of-${hunt.internal_id}` }] : []
) as never);
const planned = () => vi.mocked(updateHuntRunInformation).mock.calls.filter(([, , patch]) => 'next_run_at' in (patch as object)).map(([, huntId]) => huntId);

describe('Scheduled hunts of a manager tick', () => {
  const { automationPageSize, automationMaxPagesPerTick } = HUNT_CONFIG;

  beforeEach(() => {
    vi.mocked(updateHuntRunInformation).mockReset();
    vi.mocked(createHuntRuns).mockReset();
    connectorsServe();
  });

  afterEach(() => {
    HUNT_CONFIG.automationPageSize = automationPageSize;
    HUNT_CONFIG.automationMaxPagesPerTick = automationMaxPagesPerTick;
  });

  it('should plan the next occurrence of a due hunt once its runs started', async () => {
    serveHunts([cronHunt('ready-1', 0)]);
    expect(await runScheduledHunts(testContext)).toEqual(1);
    expect(planned()).toEqual(['ready-1']);
  });

  it('should keep the occurrence due when no hunt connector serves the scope yet', async () => {
    serveHunts([cronHunt('blocked-1', 0)]);
    expect(await runScheduledHunts(testContext)).toEqual(0);
    expect(planned()).toEqual([]);
  });

  it('should plan the first occurrence of a hunt, and the occurrences falling while its PIR activation is disarmed, without running', async () => {
    serveHunts([cronHunt('blocked-1', 0, { next_run_at: null }), cronHunt('ready-2', 1, { hunt_pir_activation: true, hunt_pir_armed: false })]);
    expect(await runScheduledHunts(testContext)).toEqual(0);
    expect(planned()).toEqual(['blocked-1', 'ready-2']);
    expect(createHuntRuns).not.toHaveBeenCalled();
  });

  it('should reach the due hunts behind the ones no connector serves, at the next ticks', async () => {
    HUNT_CONFIG.automationPageSize = 2;
    HUNT_CONFIG.automationMaxPagesPerTick = 1;
    serveHunts([cronHunt('blocked-1', 0), cronHunt('blocked-2', 1), cronHunt('ready-3', 2)]);
    expect(await runScheduledHunts(testContext)).toEqual(0);
    expect(await runScheduledHunts(testContext)).toEqual(1);
    expect(planned()).toEqual(['ready-3']);
  });
});
