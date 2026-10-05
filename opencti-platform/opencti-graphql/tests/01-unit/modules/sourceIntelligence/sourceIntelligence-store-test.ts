import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { AuthContext } from '../../../../src/types/user';

const { deleteByQuery, rawSearch } = vi.hoisted(() => ({ deleteByQuery: vi.fn(), rawSearch: vi.fn() }));

vi.mock('../../../../src/database/engine', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/engine')>()),
  elRawDeleteByQuery: deleteByQuery,
  elRawSearch: rawSearch,
}));

const {
  aggregateScorecardSnapshotsByDay,
  purgeScorecardSnapshots,
  searchScorecards,
  SNAPSHOT_PURGE_MAX_DOCS,
} = await import('../../../../src/modules/sourceIntelligence/sourceIntelligence-store');

describe('Source intelligence scorecard snapshots purge', () => {
  beforeEach(() => {
    deleteByQuery.mockReset();
  });

  it('should delete at most a bounded batch of expired snapshots per computation, never a live scorecard', async () => {
    deleteByQuery.mockResolvedValue({ deleted: SNAPSHOT_PURGE_MAX_DOCS });
    const now = new Date('2026-10-04T00:00:00.000Z').getTime();

    const deleted = await purgeScorecardSnapshots({} as AuthContext, 30, now);

    expect(deleted).toBe(SNAPSHOT_PURGE_MAX_DOCS);
    const [request] = deleteByQuery.mock.calls[0];
    expect(request.max_docs).toBe(SNAPSHOT_PURGE_MAX_DOCS);
    expect(request.body.query.bool.filter).toEqual([
      { term: { is_live: false } },
      { range: { 'snapshot_date.keyword': { lt: '2026-09-04' } } },
    ]);
  });
});

describe('Source intelligence scorecard snapshots date range', () => {
  beforeEach(() => {
    rawSearch.mockReset();
    rawSearch.mockResolvedValue({ hits: { hits: [] }, aggregations: { days: { buckets: [] } } });
  });

  it('should select the snapshots of the requested days, whenever the history backfill computed them', async () => {
    await searchScorecards({} as AuthContext, {
      sourceIds: ['source-1'],
      period: 'LAST_30_DAYS',
      live: false,
      startDate: '2026-09-01T22:30:00.000Z',
      endDate: '2026-09-30T08:00:00.000Z',
      orderMode: 'asc',
    });

    const [, , , request] = rawSearch.mock.calls[0];
    expect(request.body.query.bool.filter).toContainEqual({ range: { 'snapshot_date.keyword': { gte: '2026-09-01', lte: '2026-09-30' } } });
    expect(JSON.stringify(request.body.query.bool.filter)).not.toContain('computed_at');
    expect(request.body.sort).toEqual([{ 'snapshot_date.keyword': { order: 'asc' } }, { computed_at: { order: 'asc' } }]);
  });

  it('should bound the days of a time-series aggregation the same way', async () => {
    await aggregateScorecardSnapshotsByDay({} as AuthContext, {
      sourceIds: ['source-1'],
      period: 'LAST_30_DAYS',
      metric: 'value_score',
      aggregation: 'avg',
      startDate: '2026-09-15T00:00:00.000Z',
    });

    const [, , , request] = rawSearch.mock.calls[0];
    expect(request.body.query.bool.filter).toContainEqual({ range: { 'snapshot_date.keyword': { gte: '2026-09-15' } } });
  });

  it('should refuse a date that is not one', async () => {
    await expect(searchScorecards({} as AuthContext, { startDate: 'not a date' })).rejects.toThrow('Invalid date for the source scorecards');
    expect(rawSearch).not.toHaveBeenCalled();
  });
});
