import { buildDataRestrictions, elRawSearch } from '../../database/engine';
import { elConvertHits } from '../../database/engine-data-converter';
import { READ_INDEX_HISTORY } from '../../database/utils';
import { ENTITY_TYPE_HISTORY } from '../../schema/internalObject';
import { DatabaseError } from '../../config/errors';
import { SYSTEM_USER } from '../../utils/access';
import { utcDate } from '../../utils/format';
import type { AuthContext, AuthUser } from '../../types/user';
import type { BasicStoreBase } from '../../types/store';
import type { HistoryChange, TimeMachineHistoryEvent } from './timeMachine-types';

// Maximum number of history events read per search request
const HISTORY_PAGE_SIZE = 1000;

const HISTORY_SOURCE_FIELDS = [
  'internal_id',
  'timestamp',
  'event_scope',
  'user_id',
  'context_data.id',
  'context_data.entity_type',
  'context_data.entity_name',
  'context_data.from_id',
  'context_data.to_id',
  'context_data.message',
  'context_data.history_changes',
];

export interface HistoryRange {
  // Exclusive lower bound
  from?: string | null;
  // Inclusive upper bound
  to?: string | null;
}

export interface HistoryQueryOptions extends HistoryRange {
  scopes?: string[];
  entityTypes?: string[];
  max: number;
  order?: 'asc' | 'desc';
}

const toArray = <T>(value: T | T[] | undefined | null): T[] => {
  if (value === undefined || value === null) return [];
  return Array.isArray(value) ? value : [value];
};

export const convertHistoryHit = (source: any): TimeMachineHistoryEvent => {
  const contextData = source.context_data ?? {};
  return {
    id: source.internal_id,
    timestamp: source.timestamp,
    event_scope: source.event_scope,
    user_id: source.user_id,
    context_id: contextData.id,
    context_entity_type: contextData.entity_type,
    context_entity_name: contextData.entity_name ?? '',
    from_id: contextData.from_id,
    to_id: contextData.to_id,
    message: contextData.message,
    changes: toArray<HistoryChange>(contextData.history_changes),
  };
};

/**
 * End date for a `created_at` listing of the engine, whose bounds are both exclusive: one millisecond later, so the
 * listing ends with `to` included like the history ranges below and an element created at `to` is in both.
 */
export const inclusiveEndDate = (to: string) => new Date(new Date(to).getTime() + 1).toISOString();

const buildRangeClause = (range: HistoryRange) => {
  const timestampRange: Record<string, string> = {};
  if (range.from) timestampRange.gt = range.from;
  if (range.to) timestampRange.lte = range.to;
  return Object.keys(timestampRange).length > 0 ? [{ range: { timestamp: timestampRange } }] : [];
};

/**
 * Search history events with the given element clause.
 * When `user` is not an internal user, the history access restrictions of the platform apply
 * (markings of the event, organization sharing, forbidden attributes).
 */
const searchHistoryEvents = async (
  context: AuthContext,
  user: AuthUser,
  elementClause: Record<string, unknown>,
  opts: HistoryQueryOptions,
): Promise<TimeMachineHistoryEvent[]> => {
  const restrictions = await buildDataRestrictions(context, user, { historyFiltering: true });
  const must: any[] = [
    { terms: { 'entity_type.keyword': [ENTITY_TYPE_HISTORY] } },
    elementClause,
    ...buildRangeClause(opts),
    ...restrictions.must,
  ];
  if (opts.scopes && opts.scopes.length > 0) {
    must.push({ terms: { 'event_scope.keyword': opts.scopes } });
  }
  if (opts.entityTypes && opts.entityTypes.length > 0) {
    must.push({ terms: { 'context_data.entity_type.keyword': opts.entityTypes } });
  }
  const order = opts.order ?? 'desc';
  const events: TimeMachineHistoryEvent[] = [];
  let searchAfter: any[] | undefined;
  let hasMore = true;
  while (hasMore && events.length < opts.max) {
    const size = Math.min(HISTORY_PAGE_SIZE, opts.max - events.length);
    const body: any = {
      size,
      query: { bool: { must, must_not: restrictions.must_not } },
      sort: [{ timestamp: order }, { 'internal_id.keyword': order }],
      _source: HISTORY_SOURCE_FIELDS,
    };
    if (searchAfter) body.search_after = searchAfter;
    const query = { index: READ_INDEX_HISTORY, track_total_hits: false, body };
    const data = await elRawSearch(context, user, ENTITY_TYPE_HISTORY, query).catch((err: unknown) => {
      throw DatabaseError('Time machine history search fail', { cause: err });
    });
    const hits = data.hits?.hits ?? [];
    // Conversion applies the inner hits of the history restrictions (forbidden attributes removed from changes)
    const converted = await elConvertHits<BasicStoreBase>(hits);
    for (let index = 0; index < converted.length; index += 1) {
      events.push(convertHistoryHit(converted[index]));
    }
    hasMore = hits.length === size;
    searchAfter = hits.length > 0 ? hits[hits.length - 1].sort : undefined;
  }
  return events;
};

// Events of the element itself (creation, updates, merges, deletion)
export const fetchElementHistoryEvents = async (
  context: AuthContext,
  user: AuthUser,
  elementId: string,
  opts: HistoryQueryOptions,
): Promise<TimeMachineHistoryEvent[]> => {
  return searchHistoryEvents(context, user, { term: { 'context_data.id.keyword': elementId } }, opts);
};

// Events of the element with a change of one of the given change fields (`<entity type>--<attribute>`)
export const fetchElementChangeFieldHistoryEvents = async (
  context: AuthContext,
  user: AuthUser,
  elementId: string,
  changeFields: string[],
  opts: HistoryQueryOptions,
): Promise<TimeMachineHistoryEvent[]> => {
  if (changeFields.length === 0) return [];
  const clause = {
    bool: {
      must: [
        { term: { 'context_data.id.keyword': elementId } },
        {
          nested: {
            path: 'context_data.history_changes',
            query: { terms: { 'context_data.history_changes.field.keyword': changeFields } },
          },
        },
      ],
    },
  };
  return searchHistoryEvents(context, user, clause, opts);
};

// Events of the elements themselves, for a batch of elements
export const fetchElementsHistoryEvents = async (
  context: AuthContext,
  user: AuthUser,
  elementIds: string[],
  opts: HistoryQueryOptions,
): Promise<TimeMachineHistoryEvent[]> => {
  if (elementIds.length === 0) return [];
  return searchHistoryEvents(context, user, { terms: { 'context_data.id.keyword': elementIds } }, opts);
};

// Events of the relationships having one of the elements as source or target
export const fetchRelationshipsHistoryEvents = async (
  context: AuthContext,
  user: AuthUser,
  elementIds: string[],
  opts: HistoryQueryOptions,
): Promise<TimeMachineHistoryEvent[]> => {
  if (elementIds.length === 0) return [];
  const clause = {
    bool: {
      should: [
        { terms: { 'context_data.from_id.keyword': elementIds } },
        { terms: { 'context_data.to_id.keyword': elementIds } },
      ],
      minimum_should_match: 1,
    },
  };
  return searchHistoryEvents(context, user, clause, opts);
};

// Date of the oldest history event still available for an element (history retention horizon)
export const fetchOldestHistoryDate = async (
  context: AuthContext,
  user: AuthUser,
  elementId: string,
): Promise<string | null> => {
  const events = await fetchElementHistoryEvents(context, user, elementId, { max: 1, order: 'asc' });
  return events.length > 0 ? events[0].timestamp : null;
};

// Overlap kept below the history watermark: one indexing batch of the history manager can become searchable in parts
export const HISTORY_INDEXING_MARGIN_MS = 60000;

/**
 * Newest history event searchable at or before `to`. The history manager indexes the stream in order and a history
 * timestamp is the time of its stream event, so every earlier event is searchable too (less one indexing batch).
 */
export const findHistoryWatermark = async (context: AuthContext, to: string): Promise<string | null> => {
  const body = {
    size: 0,
    query: { bool: { must: [{ terms: { 'entity_type.keyword': [ENTITY_TYPE_HISTORY] } }, { range: { timestamp: { lte: to } } }] } },
    aggs: { watermark: { max: { field: 'timestamp' } } },
  };
  const data = await elRawSearch(context, SYSTEM_USER, ENTITY_TYPE_HISTORY, { index: READ_INDEX_HISTORY, body }).catch((err: unknown) => {
    throw DatabaseError('Time machine history watermark fail', { cause: err });
  });
  const value = data.aggregations?.watermark?.value;
  return typeof value === 'number' ? new Date(value).toISOString() : null;
};

/**
 * Whether the history holds the change stamped `changedAt` on a document. The history manager indexes the stream
 * asynchronously and the stream event of a change is written after its document, so the change is searchable once an
 * event of the element stamped at or after it was read, or once the watermark is past it by the indexing margin (a
 * change written without any history event never gets one).
 */
export const isChangeInHistory = (changedAt: string | Date, eventDates: string[], watermark: string | null) => {
  const changed = utcDate(changedAt);
  if (eventDates.some((date) => !utcDate(date).isBefore(changed))) return true;
  return !!watermark && !utcDate(watermark).subtract(HISTORY_INDEXING_MARGIN_MS, 'milliseconds').isBefore(changed);
};
