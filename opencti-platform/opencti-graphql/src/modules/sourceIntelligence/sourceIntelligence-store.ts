import { elBulk, elIndexElements, elRawDeleteByQuery, elRawSearch } from '../../database/engine';
import { INDEX_SOURCE_SCORECARDS, READ_INDEX_SOURCE_SCORECARDS } from '../../database/utils';
import { SYSTEM_USER } from '../../utils/access';
import type { AuthContext } from '../../types/user';
import { DatabaseError } from '../../config/errors';
import { logApp } from '../../config/conf';
import { ENTITY_TYPE_SOURCE_SCORECARD, type ScorecardPeriodValue, type StoreSourceScorecard } from './sourceIntelligence-types';
import { scorecardDocumentId, toSnapshotDate } from './sourceIntelligence-scoring';

const MAX_SCORECARDS_PAGE = 1000;

const fromHit = (hit: { _id: string; _source: Record<string, any> }): StoreSourceScorecard => {
  const source = hit._source;
  return { ...source, id: source.internal_id ?? hit._id, overlap: source.overlap ?? [] } as StoreSourceScorecard;
};

export const writeScorecards = async (context: AuthContext, scorecards: StoreSourceScorecard[]) => {
  if (scorecards.length === 0) {
    return;
  }
  // `id` is a read-only alias of internal_id, never stored
  const documents = scorecards.map(({ id: _id, ...scorecard }) => ({ ...scorecard, _index: INDEX_SOURCE_SCORECARDS }));
  await elIndexElements(context, SYSTEM_USER, ENTITY_TYPE_SOURCE_SCORECARD, documents);
};

export interface ScorecardSearchOptions {
  sourceIds?: string[];
  period?: ScorecardPeriodValue;
  live?: boolean;
  startDate?: string | null;
  endDate?: string | null;
  first?: number;
  orderMode?: 'asc' | 'desc';
}

export const searchScorecards = async (context: AuthContext, options: ScorecardSearchOptions): Promise<StoreSourceScorecard[]> => {
  const filter: any[] = [{ term: { 'entity_type.keyword': ENTITY_TYPE_SOURCE_SCORECARD } }];
  if (options.sourceIds && options.sourceIds.length > 0) {
    filter.push({ terms: { 'source_id.keyword': options.sourceIds } });
  }
  if (options.period) {
    filter.push({ term: { 'scorecard_period.keyword': options.period } });
  }
  if (options.live !== undefined) {
    filter.push({ term: { is_live: options.live } });
  }
  if (options.startDate || options.endDate) {
    filter.push({ range: { computed_at: { ...(options.startDate ? { gte: options.startDate } : {}), ...(options.endDate ? { lte: options.endDate } : {}) } } });
  }
  const size = Math.min(Math.max(options.first ?? MAX_SCORECARDS_PAGE, 1), MAX_SCORECARDS_PAGE);
  const data = await elRawSearch(context, SYSTEM_USER, ENTITY_TYPE_SOURCE_SCORECARD, {
    index: [READ_INDEX_SOURCE_SCORECARDS],
    size,
    track_total_hits: false,
    body: {
      query: { bool: { filter } },
      sort: [{ computed_at: { order: options.orderMode ?? 'desc' } }],
    },
  }).catch((err: unknown) => {
    throw DatabaseError('Source scorecards search failed', { cause: err });
  });
  return (data.hits?.hits ?? []).map(fromHit);
};

/**
 * Latest scorecard of each source for a period: the live document, kept up to date by the streaming increments.
 */
export const findLiveScorecards = async (context: AuthContext, period: ScorecardPeriodValue, sourceIds?: string[]) => {
  const scorecards: StoreSourceScorecard[] = [];
  const ids = sourceIds ?? [];
  if (sourceIds && ids.length === 0) {
    return scorecards;
  }
  const chunks = ids.length > 0 ? Array.from({ length: Math.ceil(ids.length / MAX_SCORECARDS_PAGE) }, (_, i) => ids.slice(i * MAX_SCORECARDS_PAGE, (i + 1) * MAX_SCORECARDS_PAGE)) : [undefined];
  for (let i = 0; i < chunks.length; i += 1) {
    const page = await searchScorecards(context, { period, live: true, sourceIds: chunks[i], first: MAX_SCORECARDS_PAGE });
    scorecards.push(...page);
  }
  return scorecards;
};

export const deleteScorecardsOfSources = async (context: AuthContext, sourceIds: string[]) => {
  if (sourceIds.length === 0) {
    return;
  }
  await elRawDeleteByQuery({
    index: READ_INDEX_SOURCE_SCORECARDS,
    refresh: true,
    body: { query: { terms: { 'source_id.keyword': sourceIds } } },
  }).catch((err: unknown) => {
    throw DatabaseError('Source scorecards deletion failed', { cause: err, sourceIds });
  });
};

export const purgeScorecardSnapshots = async (context: AuthContext, retentionDays: number, now = Date.now()) => {
  const limit = toSnapshotDate(now - retentionDays * 24 * 3600 * 1000);
  const result = await elRawDeleteByQuery({
    index: READ_INDEX_SOURCE_SCORECARDS,
    refresh: true,
    body: {
      query: {
        bool: {
          filter: [
            { term: { is_live: false } },
            { range: { 'snapshot_date.keyword': { lt: limit } } },
          ],
        },
      },
    },
  }).catch((err: unknown) => {
    throw DatabaseError('Source scorecards purge failed', { cause: err });
  });
  logApp.debug('[OPENCTI-MODULE] Source intelligence scorecards purged', { deleted: result?.deleted, limit });
};

export interface LiveIncrement {
  volume_total?: number;
  new_objects?: number;
  volume_last_day?: number;
  volume_entities?: number;
  volume_relationships?: number;
  volume_indicators?: number;
  volume_observables?: number;
  sightings_count?: number;
  security_platform_sightings_count?: number;
  negative_sightings_count?: number;
  revoked_count?: number;
  pir_matched_count?: number;
  hunt_true_positives_count?: number;
  source_last_asserted_at?: number;
}

const LIVE_INCREMENT_SCRIPT = `
  for (entry in params.increments.entrySet()) {
    def current = ctx._source.containsKey(entry.getKey()) && ctx._source[entry.getKey()] != null ? ctx._source[entry.getKey()] : 0;
    ctx._source[entry.getKey()] = Math.max(0, current + entry.getValue());
  }
  if (params.last_asserted_at != null) {
    if (ctx._source.source_last_asserted_at == null || ctx._source.source_last_asserted_at.compareTo(params.last_asserted_at) < 0) {
      ctx._source.source_last_asserted_at = params.last_asserted_at;
      ctx._source.freshness_hours = 0;
    }
  }
  ctx._source.computed_at = params.now;
  ctx._source.updated_at = params.now;
`;

/**
 * Apply streaming increments on the live scorecards of every period. Counters only: ratios and medians stay as
 * computed by the last full recomputation, which also corrects any drift of the counters.
 */
export const applyLiveIncrements = async (
  context: AuthContext,
  increments: Map<string, LiveIncrement>,
  periods: readonly ScorecardPeriodValue[],
  now = Date.now(),
) => {
  if (increments.size === 0) {
    return;
  }
  const nowIso = new Date(now).toISOString();
  const body = Array.from(increments.entries()).flatMap(([sourceId, increment]) => {
    const { source_last_asserted_at, ...counters } = increment;
    const filteredCounters = Object.fromEntries(Object.entries(counters).filter(([, v]) => typeof v === 'number' && v !== 0));
    const lastAssertedAt = source_last_asserted_at ? new Date(source_last_asserted_at).toISOString() : null;
    return periods.flatMap((period) => [
      { update: { _index: INDEX_SOURCE_SCORECARDS, _id: scorecardDocumentId(sourceId, period, '', true), retry_on_conflict: 5 } },
      // Without upsert, a source with no live document yet is skipped: the next full computation creates it
      { script: { source: LIVE_INCREMENT_SCRIPT, lang: 'painless', params: { increments: filteredCounters, last_asserted_at: lastAssertedAt, now: nowIso } } },
    ]);
  });
  const result = await elBulk(context, { refresh: false, body });
  const notFound = (result?.items ?? []).filter((item: any) => item.update?.status === 404).length;
  if (notFound > 0) {
    logApp.debug('[OPENCTI-MODULE] Source intelligence live increments skipped for sources without scorecard yet', { count: notFound });
  }
};
