import { beforeEach, describe, expect, it, vi } from 'vitest';
import '../../../../src/modules/index';
import { elAggregationCount, elCount } from '../../../../src/database/engine';
import { internalFindByIds, topEntitiesList } from '../../../../src/database/middleware-loader';
import { findByIds } from '../../../../src/modules/hunt/hunt-loaders';
import { annotateHuntRunHits, findHuntKnownHits, findHuntPlatformsWithEveryRunReadable } from '../../../../src/modules/hunt/huntHitRecord/huntHitRecord-domain';
import { ENTITY_TYPE_HUNT_HIT_RECORD } from '../../../../src/modules/hunt/huntHitRecord/huntHitRecord-types';
import type { BasicStoreEntityHuntRun } from '../../../../src/modules/hunt/huntRun/huntRun-types';
import type { AuthUser } from '../../../../src/types/user';
import { HUNT_MANAGER_USER } from '../../../../src/utils/access';
import { ADMIN_USER, testContext } from '../../../utils/testQuery';

vi.mock('../../../../src/database/engine', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/database/engine')>(),
  elAggregationCount: vi.fn(),
  elCount: vi.fn(async () => 0),
}));

vi.mock('../../../../src/database/middleware-loader', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/database/middleware-loader')>(),
  internalFindByIds: vi.fn(),
  topEntitiesList: vi.fn(async () => []),
}));

vi.mock('../../../../src/modules/hunt/hunt-loaders', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/modules/hunt/hunt-loaders')>(),
  findByIds: vi.fn(),
}));

type Buckets = { label: string; count: number }[];

// The runs of the hunt by platform for the hunt manager and for the reader, the hit records by platform
const counting = (runs: Buckets, readableRuns: Buckets, records: Buckets = []) => {
  vi.mocked(elAggregationCount).mockImplementation(async (_context, user, _index, options) => {
    if (options?.types?.includes(ENTITY_TYPE_HUNT_HIT_RECORD)) {
      return records as never;
    }
    return (user.id === HUNT_MANAGER_USER.id ? runs : readableRuns) as never;
  });
};

let readers = 0;
const reader = () => {
  readers += 1;
  return { ...ADMIN_USER, id: `reader-${readers}` } as AuthUser;
};

describe('Known hits told only over the runs the reader can read', () => {
  beforeEach(() => {
    vi.mocked(elAggregationCount).mockReset();
    vi.mocked(elCount).mockClear();
    vi.mocked(topEntitiesList).mockClear();
    vi.mocked(internalFindByIds).mockReset();
    vi.mocked(findByIds).mockReset();
  });

  it('should list the platforms on which the reader reads every execution run of the hunt', async () => {
    counting(
      [{ label: 'platform-1', count: 3 }, { label: 'platform-2', count: 2 }, { label: 'unknown', count: 1 }],
      [{ label: 'platform-1', count: 3 }, { label: 'platform-2', count: 1 }, { label: 'unknown', count: 1 }],
    );
    const platforms = await findHuntPlatformsWithEveryRunReadable(testContext, reader(), 'hunt-1');
    expect(Array.from(platforms)).toEqual(['platform-1', null]);
    const [options] = vi.mocked(elAggregationCount).mock.calls.map((call) => call[3]);
    expect(JSON.stringify(options?.filters)).toContain('"hunt_run_mode"');
  });

  it('should tell how often and since when a hit was found only to a reader of every run of the hunt on the platform', async () => {
    const run = {
      internal_id: 'run-2',
      hunt_id: 'hunt-1',
      security_platform_id: 'platform-1',
      hits_identified: true,
      hits_sample: [{ hit_key: 'hit-1' }, { hit_key: 'hit-2' }],
    } as unknown as BasicStoreEntityHuntRun;
    vi.mocked(internalFindByIds).mockResolvedValue([
      { hit_key: 'hit-1', first_run_id: 'run-1', times_seen: 4, first_seen: '2026-10-01T10:00:00.000Z' },
      { hit_key: 'hit-2', first_run_id: 'run-2', times_seen: 1, first_seen: '2026-10-07T10:00:00.000Z' },
    ] as never);
    // A run of the hunt on the platform is hidden from the reader
    counting([{ label: 'platform-1', count: 3 }], [{ label: 'platform-1', count: 2 }]);
    expect(await annotateHuntRunHits(testContext, reader(), run)).toEqual([
      { hit_key: 'hit-1', is_new: false, times_seen: null, known_since: null },
      { hit_key: 'hit-2', is_new: true, times_seen: null, known_since: null },
    ]);
    counting([{ label: 'platform-1', count: 3 }], [{ label: 'platform-1', count: 3 }]);
    expect(await annotateHuntRunHits(testContext, reader(), run)).toEqual([
      { hit_key: 'hit-1', is_new: false, times_seen: 4, known_since: '2026-10-01T10:00:00.000Z' },
      { hit_key: 'hit-2', is_new: true, times_seen: 1, known_since: '2026-10-07T10:00:00.000Z' },
    ]);
  });

  it('should summarize the known hits of a hunt over the platforms where the reader reads every run only', async () => {
    counting(
      [{ label: 'platform-1', count: 3 }, { label: 'platform-2', count: 1 }, { label: 'unknown', count: 2 }],
      [{ label: 'platform-1', count: 3 }, { label: 'unknown', count: 1 }],
      [{ label: 'platform-1', count: 10 }, { label: 'platform-2', count: 5 }, { label: 'unknown', count: 7 }],
    );
    vi.mocked(findByIds).mockResolvedValue([{ internal_id: 'platform-1' }] as never);
    vi.mocked(elCount).mockResolvedValue(10 as never);
    expect(await findHuntKnownHits(testContext, reader(), 'hunt-1')).toEqual({ distinct_count: 10, first_new_at: null, last_new_at: null });
    expect(vi.mocked(findByIds).mock.calls[0][2]).toEqual(['platform-1']);
    const scope = JSON.stringify(vi.mocked(elCount).mock.calls[0][3]);
    expect(scope).toContain('platform-1');
    expect(scope).not.toContain('platform-2');
    expect(scope).not.toContain('"nil"');
    // No platform with every run readable: nothing is told
    vi.mocked(elCount).mockClear();
    counting([{ label: 'platform-1', count: 3 }], [{ label: 'platform-1', count: 2 }], [{ label: 'platform-1', count: 10 }]);
    expect(await findHuntKnownHits(testContext, reader(), 'hunt-1')).toEqual({ distinct_count: 0, first_new_at: null, last_new_at: null });
    expect(elCount).not.toHaveBeenCalled();
  });
});
