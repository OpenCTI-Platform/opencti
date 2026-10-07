import { describe, expect, it, vi } from 'vitest';
import { computeHealthMetrics, createDuplicateEstimator, estimateDuplicates } from '../../../../src/modules/curation/curation-health';
import { fullEntitiesList } from '../../../../src/database/middleware-loader';
import { elFindByIds } from '../../../../src/database/engine';
import type { CurationSettings } from '../../../../src/modules/curation/curation-types';

vi.mock('../../../../src/database/middleware-loader', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/middleware-loader')>()),
  fullEntitiesList: vi.fn(),
}));
vi.mock('../../../../src/database/engine', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/engine')>()),
  elCount: vi.fn(async () => 0),
  elFindByIds: vi.fn(),
}));
vi.mock('../../../../src/database/redis', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/redis')>()),
  redisCurationGetCounters: vi.fn(async () => [0]),
}));

describe('Knowledge Health duplicate estimate', () => {
  it('counts, for each group of entities proposed for a merge, the entities that would disappear', () => {
    expect(estimateDuplicates([['a', 'b'], ['b', 'c'], ['d', 'e']])).toBe(3);
    expect(estimateDuplicates([])).toBe(0);
  });

  it('gives the same estimate when the groups are added page by page', () => {
    const estimator = createDuplicateEstimator();
    estimator.add(['a', 'b']);
    estimator.add(['d', 'e']);
    expect(estimator.estimate()).toBe(2);
    estimator.add(['c', 'b']);
    estimator.add(['e', 'a']);
    expect(estimator.estimate()).toBe(estimateDuplicates([['a', 'b'], ['d', 'e'], ['c', 'b'], ['e', 'a']]));
  });
});

describe('Knowledge Health metrics', () => {
  it('reads open proposals page by page, checks each page against the knowledge, and only counts what still exists', async () => {
    // "gone" was deleted or merged into another entity since its proposals were raised.
    const pages: Record<string, Array<Array<Record<string, unknown>>>> = {
      merge: [[{ subject_ids: ['a', 'b'] }, { subject_ids: ['b', 'gone'] }], [{ subject_ids: ['c', 'a'] }, { subject_ids: ['d', 'e'] }]],
      stale: [[{ subject_ids: ['s1'] }, { subject_ids: ['gone'] }], [{ subject_ids: ['s1'] }, { subject_ids: ['s2'] }]],
      contradiction: [[{ subject_ids: ['x'], target_id: 't1' }], [{ subject_ids: ['t2'] }, { subject_ids: ['y'], target_id: 'gone' }]],
    };
    vi.mocked(fullEntitiesList).mockImplementation(async (_context, _user, _types, args: any) => {
      const kindPages = pages[args.filters.filters[0].values[0]];
      for (let index = 0; index < kindPages.length; index += 1) {
        await args.callback(kindPages[index]);
      }
      return [];
    });
    vi.mocked(elFindByIds).mockImplementation(async (_context, _user, ids: any) => (ids as string[]).filter((id) => id !== 'gone').map((id) => ({ internal_id: id })) as never);
    const settings = { curated_entity_types: [], ambiguous_band_min: 0.5 } as unknown as CurationSettings;
    const metrics = await computeHealthMetrics({} as never, settings, '2026-10-01T00:00:00.000Z');
    // a, b and c are one group of duplicates (2 would disappear), d and e another (1).
    expect(metrics.duplicate_estimate).toBe(3);
    // s1 was found stale twice, on two pages: it counts once.
    expect(metrics.stale_count).toBe(2);
    expect(metrics.contradiction_count).toBe(2);
    expect(vi.mocked(fullEntitiesList).mock.calls).toHaveLength(3);
    expect(vi.mocked(elFindByIds).mock.calls.map(([, , ids]) => ids)).toEqual([
      ['a', 'b', 'gone'], ['c', 'a', 'd', 'e'], ['s1', 'gone'], ['s1', 's2'], ['t1'], ['t2', 'gone'],
    ]);
  });
});
