import { describe, expect, it, vi } from 'vitest';
import { READ_INDEX_STIX_SIGHTING_RELATIONSHIPS } from '../../../../src/database/utils';

const requested: string[][] = [];
const { rawSearch } = vi.hoisted(() => ({ rawSearch: vi.fn(async () => ({ aggregations: {} })) }));

vi.mock('../../../../src/database/engine', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/engine')>()),
  elRawSearch: rawSearch,
}));

vi.mock('../../../../src/database/middleware-loader', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/middleware-loader')>()),
  internalFindByIds: vi.fn(async (_context: unknown, _user: unknown, ids: string[]) => {
    requested.push(ids);
    return ids.map((id) => ({ internal_id: id, created_at: '2026-10-01T00:00:00.000Z', creator_id: ['user-1'] }));
  }),
}));

const { loadStoredDocuments } = await import('../../../../src/manager/sourceIntelligenceManager');
const { fetchPageLookups } = await import('../../../../src/modules/sourceIntelligence/sourceIntelligence-compute');

const ASOF = new Date('2026-09-20T23:59:59.999Z').getTime();
// The filters of the sightings query of a page, for a past day of the history backfill or for the live computation
const sightingFilters = async (historical: boolean) => {
  rawSearch.mockClear();
  const run = { asOf: ASOF, historical, falsePositiveLabelIds: new Set<string>(), pirRelevance: false };
  await fetchPageLookups({} as any, [{ internal_id: 'indicator-1', entity_type: 'Indicator' } as any], run);
  const call = rawSearch.mock.calls.find((args: any[]) => args[3].index.includes(READ_INDEX_STIX_SIGHTING_RELATIONSHIPS)) as any[];
  return call[3].body.query.bool.filter;
};

describe('Source intelligence sightings of a past day', () => {
  it('should leave out of a past day the sightings modified since, whose false positive flag may have changed', async () => {
    expect(await sightingFilters(true)).toContainEqual({
      bool: {
        should: [
          { range: { updated_at: { lte: '2026-09-20T23:59:59.999Z' } } },
          { bool: { must_not: [{ exists: { field: 'updated_at' } }] } },
        ],
        minimum_should_match: 1,
      },
    });
  });

  it('should count every sighting created by the end of the live computation, as it is now', async () => {
    const filters = await sightingFilters(false);
    expect(filters).toContainEqual({ range: { created_at: { lte: '2026-09-20T23:59:59.999Z' } } });
    expect(JSON.stringify(filters)).not.toContain('updated_at');
  });
});

describe('Source intelligence live lookups', () => {
  it('should load every signal object in bounded lookups, duplicates once', async () => {
    const ids = Array.from({ length: 12001 }, (_, i) => `object-${i}`);
    const documents = await loadStoredDocuments({} as any, [...ids, 'object-0']);
    expect(documents.size).toBe(12001);
    expect(requested.map((chunk) => chunk.length)).toEqual([5000, 5000, 2001]);
    expect(documents.get('object-12000')?.creator_id).toEqual(['user-1']);
  });
});
