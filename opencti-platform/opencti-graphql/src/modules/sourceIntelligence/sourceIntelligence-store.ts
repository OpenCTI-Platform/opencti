import { elBulk, elIndexElements, elRawDeleteByQuery, elRawSearch } from '../../database/engine';
import { INDEX_SOURCE_SCORECARDS, READ_INDEX_SOURCE_SCORECARDS } from '../../database/utils';
import { SYSTEM_USER } from '../../utils/access';
import type { AuthContext } from '../../types/user';
import { DatabaseError, FunctionalError } from '../../config/errors';
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

// A snapshot describes the day of its `scorecard_date`, which the history backfill computes days later: a date range
// selects the days a chart shows, never the computation dates
const toSnapshotDayBound = (date: string) => {
  const time = new Date(date).getTime();
  if (Number.isNaN(time)) {
    throw FunctionalError('Invalid date for the source scorecards', { date });
  }
  return toSnapshotDate(time);
};

const buildScorecardFilter = (options: Omit<ScorecardSearchOptions, 'first' | 'orderMode'>) => {
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
    filter.push({
      range: {
        'scorecard_date.keyword': {
          ...(options.startDate ? { gte: toSnapshotDayBound(options.startDate) } : {}),
          ...(options.endDate ? { lte: toSnapshotDayBound(options.endDate) } : {}),
        },
      },
    });
  }
  return filter;
};

export const searchScorecards = async (context: AuthContext, options: ScorecardSearchOptions): Promise<StoreSourceScorecard[]> => {
  const filter = buildScorecardFilter(options);
  const size = Math.min(Math.max(options.first ?? MAX_SCORECARDS_PAGE, 1), MAX_SCORECARDS_PAGE);
  const data = await elRawSearch(context, SYSTEM_USER, ENTITY_TYPE_SOURCE_SCORECARD, {
    index: [READ_INDEX_SOURCE_SCORECARDS],
    size,
    track_total_hits: false,
    body: {
      query: { bool: { filter } },
      // By day first, as the range selects them: a page of the first days never skips one computed later
      sort: [{ 'scorecard_date.keyword': { order: options.orderMode ?? 'desc' } }, { computed_at: { order: options.orderMode ?? 'desc' } }],
    },
  }).catch((err: unknown) => {
    throw DatabaseError('Source scorecards search failed', { cause: err });
  });
  return (data.hits?.hits ?? []).map(fromHit);
};

/**
 * Every scorecard matching the options, page after page (`search_after` on a unique sort), never truncated.
 */
const searchAllScorecards = async (context: AuthContext, options: Omit<ScorecardSearchOptions, 'first' | 'orderMode'>) => {
  const filter = buildScorecardFilter(options);
  const scorecards: StoreSourceScorecard[] = [];
  let searchAfter: unknown[] | undefined;
  let hasMore = true;
  while (hasMore) {
    const data = await elRawSearch(context, SYSTEM_USER, ENTITY_TYPE_SOURCE_SCORECARD, {
      index: [READ_INDEX_SOURCE_SCORECARDS],
      size: MAX_SCORECARDS_PAGE,
      track_total_hits: false,
      body: {
        query: { bool: { filter } },
        sort: [{ 'internal_id.keyword': { order: 'asc' } }],
        ...(searchAfter ? { search_after: searchAfter } : {}),
      },
    }).catch((err: unknown) => {
      throw DatabaseError('Source scorecards search failed', { cause: err });
    });
    const hits = (data.hits?.hits ?? []) as Array<{ _id: string; _source: Record<string, any>; sort?: unknown[] }>;
    scorecards.push(...hits.map(fromHit));
    searchAfter = hits.length > 0 ? hits[hits.length - 1].sort : undefined;
    hasMore = hits.length === MAX_SCORECARDS_PAGE && searchAfter !== undefined;
  }
  return scorecards;
};

/**
 * Latest scorecard of each source for a period: the live document, kept up to date by the streaming increments.
 * Without source ids, the live scorecards of every source are returned.
 */
export const findLiveScorecards = async (context: AuthContext, period: ScorecardPeriodValue, sourceIds?: string[]) => {
  if (!sourceIds) {
    return searchAllScorecards(context, { period, live: true });
  }
  const scorecards: StoreSourceScorecard[] = [];
  // One live document per source and period: a chunk of ids never exceeds one page
  for (let i = 0; i < sourceIds.length; i += MAX_SCORECARDS_PAGE) {
    const page = await searchScorecards(context, { period, live: true, sourceIds: sourceIds.slice(i, i + MAX_SCORECARDS_PAGE), first: MAX_SCORECARDS_PAGE });
    scorecards.push(...page);
  }
  return scorecards;
};

/**
 * Daily snapshots of a source handed over to another one: the days the target has no snapshot of keep the history of
 * the source, the snapshots of the target are never overwritten. Returns the number of snapshots moved; the source's
 * own documents are left to the caller to delete.
 */
export const moveScorecardSnapshots = async (context: AuthContext, fromSourceId: string, toSourceId: string) => {
  const [moving, kept] = await Promise.all([
    searchAllScorecards(context, { sourceIds: [fromSourceId], live: false }),
    searchAllScorecards(context, { sourceIds: [toSourceId], live: false }),
  ]);
  const covered = new Set(kept.map((scorecard) => `${scorecard.scorecard_period}|${scorecard.scorecard_date}`));
  const moved = moving
    .filter((scorecard) => !covered.has(`${scorecard.scorecard_period}|${scorecard.scorecard_date}`))
    .map((scorecard) => {
      const internalId = scorecardDocumentId(toSourceId, scorecard.scorecard_period, scorecard.scorecard_date, false);
      return { ...scorecard, id: internalId, internal_id: internalId, standard_id: `source-scorecard--${internalId}`, source_id: toSourceId };
    });
  await writeScorecards(context, moved);
  return moved.length;
};

/**
 * Sources scored with knowledge: a live scorecard of at least one period counts an object. Every tracked source gets
 * live scorecards at each computation, so a scorecard alone does not tell that a source was scored.
 */
export const countScoredSources = async (context: AuthContext): Promise<number> => {
  const filter = [...buildScorecardFilter({ live: true }), { range: { volume_total: { gt: 0 } } }];
  const data = await elRawSearch(context, SYSTEM_USER, ENTITY_TYPE_SOURCE_SCORECARD, {
    index: [READ_INDEX_SOURCE_SCORECARDS],
    size: 0,
    track_total_hits: false,
    body: {
      query: { bool: { filter } },
      // Exact up to the threshold, far above the number of sources a platform tracks
      aggs: { sources: { cardinality: { field: 'source_id.keyword', precision_threshold: 40000 } } },
    },
  }).catch((err: unknown) => {
    throw DatabaseError('Source scorecards count failed', { cause: err });
  });
  return Number(data.aggregations?.sources?.value ?? 0);
};

export type ScorecardAggregation = 'sum' | 'avg' | 'min' | 'max';

/**
 * Daily aggregate of one metric over the snapshots of the given sources, computed by Elasticsearch and paginated
 * with a composite aggregation so that no day is dropped whatever the number of sources and the retention.
 * Days where no source has a value for the metric are omitted.
 */
export const aggregateScorecardSnapshotsByDay = async (
  context: AuthContext,
  options: {
    sourceIds: string[];
    period: ScorecardPeriodValue;
    metric: string;
    aggregation: ScorecardAggregation;
    startDate?: string | null;
    endDate?: string | null;
    // Cost metrics are aggregated in one currency only
    costCurrency?: string | null;
  },
) => {
  if (options.sourceIds.length === 0) {
    return [];
  }
  const filter = buildScorecardFilter({ sourceIds: options.sourceIds, period: options.period, live: false, startDate: options.startDate, endDate: options.endDate });
  if (options.costCurrency) {
    filter.push({ term: { 'cost_currency.keyword': options.costCurrency } });
  }
  const points: Array<{ day: string; value: number }> = [];
  let afterKey: Record<string, unknown> | undefined;
  let hasMore = true;
  while (hasMore) {
    const data = await elRawSearch(context, SYSTEM_USER, ENTITY_TYPE_SOURCE_SCORECARD, {
      index: [READ_INDEX_SOURCE_SCORECARDS],
      size: 0,
      track_total_hits: false,
      body: {
        query: { bool: { filter } },
        aggs: {
          days: {
            composite: {
              size: MAX_SCORECARDS_PAGE,
              sources: [{ day: { terms: { field: 'scorecard_date.keyword', order: 'asc' } } }],
              ...(afterKey ? { after: afterKey } : {}),
            },
            aggs: { metric: { [options.aggregation]: { field: options.metric } } },
          },
        },
      },
    }).catch((err: unknown) => {
      throw DatabaseError('Source scorecards aggregation failed', { cause: err, metric: options.metric });
    });
    const buckets = (data.aggregations?.days?.buckets ?? []) as Array<{ key: { day: string }; metric: { value: number | null } }>;
    buckets.forEach((bucket) => {
      if (typeof bucket.metric?.value === 'number' && Number.isFinite(bucket.metric.value)) {
        points.push({ day: bucket.key.day, value: bucket.metric.value });
      }
    });
    afterKey = data.aggregations?.days?.after_key;
    hasMore = buckets.length === MAX_SCORECARDS_PAGE && afterKey !== undefined;
  }
  return points;
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

/** Live scorecards only: the daily snapshots of the sources stay as their history. */
export const deleteLiveScorecardsOfSources = async (context: AuthContext, sourceIds: string[]) => {
  if (sourceIds.length === 0) {
    return;
  }
  await elRawDeleteByQuery({
    index: READ_INDEX_SOURCE_SCORECARDS,
    refresh: true,
    body: { query: { bool: { filter: [{ terms: { 'source_id.keyword': sourceIds } }, { term: { is_live: true } }] } } },
  }).catch((err: unknown) => {
    throw DatabaseError('Source live scorecards deletion failed', { cause: err, sourceIds });
  });
};

// Expired snapshots one daily computation deletes at most: after a retention cut on a long-lived platform, the next
// computations drain the rest instead of one massive deletion
export const SNAPSHOT_PURGE_MAX_DOCS = 100000;

export const purgeScorecardSnapshots = async (context: AuthContext, retentionDays: number, now = Date.now()) => {
  const limit = toSnapshotDate(now - retentionDays * 24 * 3600 * 1000);
  const result = await elRawDeleteByQuery({
    index: READ_INDEX_SOURCE_SCORECARDS,
    refresh: true,
    max_docs: SNAPSHOT_PURGE_MAX_DOCS,
    body: {
      query: {
        bool: {
          filter: [
            { term: { is_live: false } },
            { range: { 'scorecard_date.keyword': { lt: limit } } },
          ],
        },
      },
    },
  }).catch((err: unknown) => {
    throw DatabaseError('Source scorecards purge failed', { cause: err });
  });
  logApp.debug('[OPENCTI-MODULE] Source intelligence scorecards purged', { deleted: result?.deleted, limit, max_docs: SNAPSHOT_PURGE_MAX_DOCS });
  return result?.deleted ?? 0;
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

// Stream event ids are "<milliseconds>-<sequence>", both unbounded decimal numbers: compared by length, then digits.
// A scorecard that already applied the batch event id is left untouched, so a replayed batch is never counted twice.
const LIVE_INCREMENT_SCRIPT = `
  int compareNumbers(String a, String b) {
    if (a.length() != b.length()) {
      return a.length() < b.length() ? -1 : 1;
    }
    return a.compareTo(b);
  }
  int compareStreamIds(String a, String b) {
    int ia = a.indexOf('-');
    int ib = b.indexOf('-');
    int ms = compareNumbers(a.substring(0, ia), b.substring(0, ib));
    return ms != 0 ? ms : compareNumbers(a.substring(ia + 1), b.substring(ib + 1));
  }
  if (params.event_id != null && ctx._source.live_stream_event_id != null && compareStreamIds(ctx._source.live_stream_event_id, params.event_id) >= 0) {
    ctx.op = 'noop';
  } else {
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
    if (params.event_id != null) {
      ctx._source.live_stream_event_id = params.event_id;
    }
    ctx._source.updated_at = params.now;
  }
`;

// Cost fields of a live scorecard, from the actionable count the scorecard holds when it is updated (4 decimals)
const LIVE_COST_SCRIPT = `
  def count = ctx._source.actionable_count;
  ctx._source.cost_currency = params.currency;
  if (params.window_cost == null || count == null || count <= 0) {
    ctx._source.cost_per_actionable_object = null;
  } else {
    double windowCost = params.window_cost;
    ctx._source.cost_per_actionable_object = Math.round(windowCost / count * 10000.0) / 10000.0;
  }
`;

/**
 * Write a new cost on the live scorecards of a source as the only change of each scorecard, so that a stream batch or
 * a full computation updating the same scorecards meanwhile keeps its values. `windowCosts` is the cost normalized to
 * the window of each period; a source without a live scorecard yet gets it from the next full computation.
 */
export const applyLiveScorecardCost = async (
  context: AuthContext,
  sourceId: string,
  currency: string | null,
  windowCosts: Map<ScorecardPeriodValue, number | null>,
) => {
  const body = Array.from(windowCosts.entries()).flatMap(([period, windowCost]) => [
    { update: { _index: INDEX_SOURCE_SCORECARDS, _id: scorecardDocumentId(sourceId, period, '', true), retry_on_conflict: 5 } },
    { script: { source: LIVE_COST_SCRIPT, lang: 'painless', params: { currency, window_cost: windowCost } } },
  ]);
  if (body.length === 0) {
    return;
  }
  await elBulk(context, { refresh: true, body });
};

/**
 * Apply the streaming increments of one stream batch on the live scorecards, one update per source and period,
 * marked with the last event id of the batch. Volume and signal counters only: the counts depending on the whole
 * knowledge (noise, uniqueness, corroboration, accuracy, actionable objects), ratios, medians and `computed_at` stay as
 * set by the last full recomputation, which also corrects any drift of the counters; `updated_at` is the live update.
 */
export const applyLiveIncrements = async (
  context: AuthContext,
  incrementsByPeriod: Map<ScorecardPeriodValue, Map<string, LiveIncrement>>,
  eventId: string,
  now = Date.now(),
) => {
  const nowIso = new Date(now).toISOString();
  const body = Array.from(incrementsByPeriod.entries()).flatMap(([period, increments]) => Array.from(increments.entries()).flatMap(([sourceId, increment]) => {
    const { source_last_asserted_at, ...counters } = increment;
    const filteredCounters = Object.fromEntries(Object.entries(counters).filter(([, v]) => typeof v === 'number' && v !== 0));
    const lastAssertedAt = source_last_asserted_at ? new Date(source_last_asserted_at).toISOString() : null;
    return [
      { update: { _index: INDEX_SOURCE_SCORECARDS, _id: scorecardDocumentId(sourceId, period, '', true), retry_on_conflict: 5 } },
      // Without upsert, a source with no live document yet is skipped: the next full computation creates it
      { script: { source: LIVE_INCREMENT_SCRIPT, lang: 'painless', params: { increments: filteredCounters, last_asserted_at: lastAssertedAt, event_id: eventId, now: nowIso } } },
    ];
  }));
  if (body.length === 0) {
    return;
  }
  const result = await elBulk(context, { refresh: false, body });
  const notFound = (result?.items ?? []).filter((item: any) => item.update?.status === 404).length;
  if (notFound > 0) {
    logApp.debug('[OPENCTI-MODULE] Source intelligence live increments skipped for sources without scorecard yet', { count: notFound });
  }
};
