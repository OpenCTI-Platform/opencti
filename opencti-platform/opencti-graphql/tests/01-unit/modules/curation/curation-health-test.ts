import { beforeEach, describe, expect, it, vi } from 'vitest';
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

type ProposalPages = Record<string, Array<Array<Record<string, unknown>>>>;

// The open proposals of each kind, read page by page, and the subjects that still exist with their type.
const givenOpenProposals = (pages: ProposalPages, typeOf: (id: string) => string | null) => {
  vi.mocked(fullEntitiesList).mockImplementation(async (_context, _user, _types, args: any) => {
    const kindPages = pages[args.filters.filters[0].values[0]];
    for (let index = 0; index < kindPages.length; index += 1) {
      await args.callback(kindPages[index]);
    }
    return [];
  });
  vi.mocked(elFindByIds).mockImplementation(async (_context, _user, ids: any) => (ids as string[])
    .filter((id) => typeOf(id) !== null)
    .map((id) => ({ internal_id: id, entity_type: typeOf(id) })) as never);
};

const metricsFor = (curatedTypes: string[]) => {
  const settings = { curated_entity_types: curatedTypes, ambiguous_band_min: 0.5 } as unknown as CurationSettings;
  return computeHealthMetrics({} as never, settings, '2026-10-01T00:00:00.000Z');
};

describe('Knowledge Health metrics', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('reads open proposals page by page, checks each page against the knowledge, and only counts what still exists', async () => {
    // "gone" was deleted or merged into another entity since its proposals were raised.
    givenOpenProposals({
      merge: [[{ subject_ids: ['a', 'b'] }, { subject_ids: ['b', 'gone'] }], [{ subject_ids: ['c', 'a'] }, { subject_ids: ['d', 'e'] }]],
      stale: [[{ subject_ids: ['s1'] }, { subject_ids: ['gone'] }], [{ subject_ids: ['s1'] }, { subject_ids: ['s2'] }]],
      contradiction: [[{ subject_ids: ['x'], target_id: 't1' }], [{ subject_ids: ['t2'] }, { subject_ids: ['y'], target_id: 'gone' }]],
    }, (id) => (id === 'gone' ? null : 'Intrusion-Set'));
    const metrics = await metricsFor(['Intrusion-Set']);
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

  it('counts the duplicates and stale entities of the types the rates are measured over only', async () => {
    // Malware was removed from the curated types after its proposals were raised; r1 is a relationship.
    const types: Record<string, string> = { a: 'Intrusion-Set', b: 'Intrusion-Set', m1: 'Malware', m2: 'Malware', i1: 'Indicator', r1: 'uses' };
    givenOpenProposals({
      merge: [[{ subject_ids: ['a', 'b'] }, { subject_ids: ['m1', 'm2'] }]],
      stale: [[{ subject_ids: ['a'] }, { subject_ids: ['i1'] }, { subject_ids: ['m1'] }]],
      contradiction: [[{ subject_ids: ['m1'], target_id: 'm1' }, { subject_ids: ['r1'], target_id: 'r1' }]],
    }, (id) => types[id] ?? null);
    const curated = await metricsFor(['Intrusion-Set']);
    expect(curated.duplicate_estimate).toBe(1);
    // The staleness detector always examines Indicators.
    expect(curated.stale_count).toBe(2);
    // The contradiction detectors do not depend on the curated types.
    expect(curated.contradiction_count).toBe(2);
    const none = await metricsFor([]);
    expect(none.duplicate_estimate).toBe(0);
    expect(none.stale_count).toBe(1);
    expect(none.contradiction_count).toBe(2);
  });
});
