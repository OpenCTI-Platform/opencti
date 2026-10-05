import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { AuthContext, AuthUser } from '../../../../src/types/user';

const { listSources, liveScorecards, aggregateByDay } = vi.hoisted(() => ({
  listSources: vi.fn(),
  liveScorecards: vi.fn(),
  aggregateByDay: vi.fn(),
}));

vi.mock('../../../../src/database/middleware-loader', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/middleware-loader')>()),
  fullEntitiesList: listSources,
}));

vi.mock('../../../../src/modules/sourceIntelligence/sourceIntelligence-store', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/modules/sourceIntelligence/sourceIntelligence-store')>()),
  findLiveScorecards: liveScorecards,
  aggregateScorecardSnapshotsByDay: aggregateByDay,
}));

vi.mock('../../../../src/modules/sourceIntelligence/sourceIntelligence-domain', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/modules/sourceIntelligence/sourceIntelligence-domain')>()),
  restrictSourceQueryToEdition: async (_: AuthContext, args: unknown) => args,
  maskRestrictedSources: async (_: AuthContext, __: AuthUser, sources: unknown[]) => sources,
}));

const { sourceScorecardsTimeSeries } = await import('../../../../src/modules/sourceIntelligence/sourceIntelligence-widgets');

const context = {} as AuthContext;
const user = {} as AuthUser;

describe('Source intelligence time-series widgets', () => {
  beforeEach(() => {
    listSources.mockReset();
    liveScorecards.mockReset();
    aggregateByDay.mockReset();
    aggregateByDay.mockResolvedValue([{ day: '2026-09-01', value: 42.123 }]);
  });

  it('should keep the history of a source that has no live scorecard any more', async () => {
    listSources.mockResolvedValue([
      { internal_id: 'scored', name: 'Scored', enabled: true },
      { internal_id: 'disabled', name: 'Disabled', enabled: false },
    ]);
    liveScorecards.mockResolvedValue([{ source_id: 'scored', cost_currency: null }]);

    const points = await sourceScorecardsTimeSeries(context, user, { metric: 'value_score' });

    expect(points).toEqual([{ date: '2026-09-01T00:00:00.000Z', value: 42.12, currency: null }]);
    expect(liveScorecards).not.toHaveBeenCalled();
    expect(aggregateByDay.mock.calls[0][1]).toMatchObject({ sourceIds: ['scored', 'disabled'], costCurrency: null, aggregation: 'avg' });
  });

  it('should aggregate a cost in the currency most sources use, the declared cost of a source without live scorecard included', async () => {
    listSources.mockResolvedValue([
      { internal_id: 'live-usd', name: 'Live USD', enabled: true },
      { internal_id: 'disabled-eur', name: 'Disabled EUR', enabled: false, source_cost: { currency: 'EUR' } },
      { internal_id: 'disabled-eur-2', name: 'Disabled EUR 2', enabled: false, source_cost: { currency: 'EUR' } },
    ]);
    liveScorecards.mockResolvedValue([{ source_id: 'live-usd', cost_currency: 'USD' }]);

    const points = await sourceScorecardsTimeSeries(context, user, { metric: 'cost_per_actionable_object' });

    expect(points[0].currency).toEqual('EUR');
    expect(aggregateByDay.mock.calls[0][1]).toMatchObject({ sourceIds: ['live-usd', 'disabled-eur', 'disabled-eur-2'], costCurrency: 'EUR' });
  });

  it('should return no point for a cost metric when no source has a cost', async () => {
    listSources.mockResolvedValue([{ internal_id: 'disabled', name: 'Disabled', enabled: false }]);
    liveScorecards.mockResolvedValue([]);

    await expect(sourceScorecardsTimeSeries(context, user, { metric: 'cost_per_actionable_object' })).resolves.toEqual([]);
    expect(aggregateByDay).not.toHaveBeenCalled();
  });
});
