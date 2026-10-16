import { afterEach, describe, expect, it, vi } from 'vitest';
import { fullEntitiesList } from '../../../../src/database/middleware-loader';
import { cursorToOffset } from '../../../../src/database/utils';
import { reconcilePirActivatedHunts } from '../../../../src/modules/hunt/hunt-automation';
import { HUNT_CONFIG } from '../../../../src/modules/hunt/hunt-utils';
import type { BasicStoreEntityHunt } from '../../../../src/modules/hunt/hunt-types';
import { testContext } from '../../../utils/testQuery';

vi.mock('../../../../src/database/middleware-loader', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/database/middleware-loader')>(),
  fullEntitiesList: vi.fn(),
}));

// PIR activated hunts without targets: nothing to arm, only the pages read are observed
const hunts = Array.from({ length: 5 }, (_, index) => ({ internal_id: `hunt-${index}`, sort: [index] }) as unknown as BasicStoreEntityHunt);

const visited: string[][] = [];
const serveHunts = () => {
  vi.mocked(fullEntitiesList).mockImplementation(async (_context, _user, _types, opts) => {
    const start = opts?.after ? Number(cursorToOffset(opts.after)[0]) + 1 : 0;
    const first = opts?.first ?? hunts.length;
    const read: string[] = [];
    for (let offset = start; offset < hunts.length; offset += first) {
      const page = hunts.slice(offset, offset + first);
      read.push(...page.map((hunt) => hunt.internal_id));
      if (await opts?.callback?.(page as never) === false) {
        break;
      }
    }
    visited.push(read);
    return [];
  });
};

describe('PIR activated hunts scan of a manager tick', () => {
  const { automationPageSize, automationMaxPagesPerTick } = HUNT_CONFIG;

  afterEach(() => {
    HUNT_CONFIG.automationPageSize = automationPageSize;
    HUNT_CONFIG.automationMaxPagesPerTick = automationMaxPagesPerTick;
    vi.mocked(fullEntitiesList).mockReset();
    visited.length = 0;
  });

  it('should read a bounded number of pages per tick and visit every hunt, then start over', async () => {
    HUNT_CONFIG.automationPageSize = 2;
    HUNT_CONFIG.automationMaxPagesPerTick = 1;
    serveHunts();
    for (let tick = 0; tick < 4; tick += 1) {
      await reconcilePirActivatedHunts(testContext);
    }
    expect(visited).toEqual([['hunt-0', 'hunt-1'], ['hunt-2', 'hunt-3'], ['hunt-4'], ['hunt-0', 'hunt-1']]);
  });
});
