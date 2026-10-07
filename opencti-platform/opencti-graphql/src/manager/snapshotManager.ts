import moment from 'moment';
import { type ManagerDefinition, registerManager } from './managerModule';
import conf, { booleanConf, logApp } from '../config/conf';
import { elRawSearch } from '../database/engine';
import { fullRelationsList, internalFindByIds } from '../database/middleware-loader';
import { redisGetManagerEventState, redisSetManagerEventState } from '../database/redis';
import { READ_INDEX_HISTORY, READ_RELATIONSHIPS_INDICES_WITHOUT_INFERRED, wait } from '../database/utils';
import { ABSTRACT_STIX_CORE_OBJECT, ABSTRACT_STIX_CORE_RELATIONSHIP } from '../schema/general';
import { ENTITY_TYPE_HISTORY } from '../schema/internalObject';
import { STIX_SIGHTING_RELATIONSHIP } from '../schema/stixSightingRelationship';
import { DatabaseError } from '../config/errors';
import { executionContext, SYSTEM_USER } from '../utils/access';
import { now, utcDate } from '../utils/format';
import { doYield } from '../utils/eventloop-utils';
import type { AuthContext } from '../types/user';
import type { BasicStoreEntity, BasicStoreRelation } from '../types/store';
import type { BasicStoreEntityRetentionRule } from '../modules/retentionRules/retentionRules-types';
import { listRules } from '../modules/retentionRules/retentionRules-domain';
import type { AttributeValues, CompactDocument, TimeMachineHistoryEvent } from '../modules/timeMachine/timeMachine-types';
import { extractAttributeValues, replayBackward } from '../modules/timeMachine/timeMachine-replay';
import { fetchElementsHistoryEvents, fetchRelationshipsHistoryEvents, findHistoryWatermark, HISTORY_INDEXING_MARGIN_MS } from '../modules/timeMachine/timeMachine-history';
import { deleteSnapshotsBefore, indexSnapshots, type SnapshotInput } from '../modules/timeMachine/timeMachine-store';
import { TIME_MACHINE_RELATIONSHIP_TYPES } from '../modules/timeMachine/timeMachine-relationships';
import { countRelationshipsByTypeForElements } from '../modules/timeMachine/timeMachine-counters';
const SNAPSHOT_MANAGER_ID = 'SNAPSHOT_MANAGER';
const SNAPSHOT_MANAGER_CONTEXT = 'snapshot_manager';
const SNAPSHOT_MANAGER_STATE = 'snapshot_manager';
const SNAPSHOT_MANAGER_ENABLED = booleanConf('snapshot_manager:enabled', true);
const SNAPSHOT_MANAGER_KEY = conf.get('snapshot_manager:lock_key') || 'snapshot_manager_lock';
const SCHEDULE_TIME = conf.get('snapshot_manager:interval') || 3600000;
const PERIOD_DAYS: number = conf.get('snapshot_manager:period_days') || 7;
const MIN_ENTITIES_PER_RUN = 100;
const MAX_ENTITIES_PER_RUN: number = Math.max(MIN_ENTITIES_PER_RUN, conf.get('snapshot_manager:max_entities_per_run') || 10000);
const BATCH_SIZE: number = conf.get('snapshot_manager:batch_size') || 100;
const MAX_RELATIONSHIP_IDS_PER_TYPE: number = conf.get('snapshot_manager:max_relationship_ids_per_type') || 500;
const RETENTION_DAYS: number = conf.get('snapshot_manager:retention_days') || 0;
const MAX_REWIND_EVENTS: number = conf.get('time_machine:max_replay_events') || 5000;
// Maximum number of history events read per batch to rewind the documents to the snapshot date
const MAX_REWIND_EVENTS_PER_BATCH = 20000;
// Maximum number of relationships read per batch of entities to build relationship id lists
const MAX_RELATIONSHIPS_PER_BATCH = 20000;
const COMPOSITE_PAGE_SIZE = 1000;
// A relationship bucket holds both of its sides: a budget always fits at least one relationship
const MIN_CHANGED_ELEMENTS_BUDGET = 2;
// Maximum number of entities kept in the state to retry a snapshot that could not be built exactly
const MAX_RETRY_IDS = 1000;
// The history manager indexes the stream in buffers of 5 seconds: a watermark that does not move for two buffers
// means that no event is waiting to be indexed
const HISTORY_QUIET_MS = 10000;
const HISTORY_POLL_MS = 1000;
// Still behind after this wait, the history manager is lagging: the batch is retried at the next window
const HISTORY_CATCH_UP_MAX_MS = 60000;

export interface SnapshotManagerState {
  // Lower bound of the next snapshot window (history cursor)
  cursor?: string;
  // End of the last completed snapshot window: the next one opens PERIOD_DAYS after it
  last_window_end?: string;
  // Window currently being processed, and the position in it when a run hit the per-run limit
  window_end?: string;
  // Newest history event searchable when the window in progress started (see nextWindowStart)
  window_watermark?: string | null;
  after_key?: Record<string, string> | null;
  // The position is in the relationship events of the window (the element events are done)
  relationships_phase?: boolean;
  // Entities whose snapshot could not be rewound exactly: their changes are behind the cursor, so they are retried explicitly
  retry_ids?: string[];
}

const readState = async (): Promise<SnapshotManagerState> => {
  const raw = await redisGetManagerEventState(SNAPSHOT_MANAGER_STATE);
  if (!raw) return {};
  try {
    return JSON.parse(raw) as SnapshotManagerState;
  } catch {
    return {};
  }
};

const writeState = async (state: SnapshotManagerState) => {
  await redisSetManagerEventState(SNAPSHOT_MANAGER_STATE, JSON.stringify(state));
};

/**
 * Wait until the history holds the events of every change made before `readDate`: the watermark reached that date
 * (the history manager indexes the stream in order), or it did not move for longer than the indexing buffer while
 * already past `lastChangeDate`, the latest change stamped on the documents read (an idle history holding every one of
 * them; a stalled one behind them is not taken for caught up). False when the history is still behind after the
 * maximum wait.
 */
export const waitForHistoryCatchUp = async (context: AuthContext, readDate: string, lastChangeDate: string): Promise<boolean> => {
  const startedAt = Date.now();
  let watermark = await findHistoryWatermark(context, now());
  let movedAt = startedAt;
  while (!watermark || utcDate(watermark).isBefore(utcDate(readDate))) {
    const checkedAt = Date.now();
    if (checkedAt - movedAt >= HISTORY_QUIET_MS) return !!watermark && !utcDate(watermark).isBefore(utcDate(lastChangeDate));
    if (checkedAt - startedAt >= HISTORY_CATCH_UP_MAX_MS) return false;
    await wait(HISTORY_POLL_MS);
    const next = await findHistoryWatermark(context, now());
    if (next !== watermark) {
      watermark = next;
      movedAt = Date.now();
    }
  }
  return true;
};

/**
 * Lower bound of the window after a completed one: the history watermark measured before the window was read, less the
 * indexing margin, and not the end of the window, so that an event of the window indexed after it was read is read by
 * the next window. It never moves back, and stays in place when no history event was searchable.
 */
export const nextWindowStart = (cursor: string, watermark: string | null | undefined): string => {
  if (!watermark) return cursor;
  const start = utcDate(watermark).subtract(HISTORY_INDEXING_MARGIN_MS, 'milliseconds');
  return start.isAfter(utcDate(cursor)) ? start.toISOString() : cursor;
};

export interface ChangedElementsCursor {
  relationships: boolean;
  afterKey: Record<string, string> | null;
}

const changedElementsQuery = (from: string, to: string, relationships: boolean) => {
  const window = [{ terms: { 'entity_type.keyword': [ENTITY_TYPE_HISTORY] } }, { range: { timestamp: { gt: from, lte: to } } }];
  const relationshipTypes = { terms: { 'context_data.entity_type.keyword': TIME_MACHINE_RELATIONSHIP_TYPES } };
  if (relationships) {
    return { bool: { must: [...window, { terms: { 'event_scope.keyword': ['create', 'update', 'delete'] } }, relationshipTypes] } };
  }
  return { bool: { must: [...window, { terms: { 'event_scope.keyword': ['create', 'update', 'merge'] } }], must_not: [relationshipTypes] } };
};

/**
 * Ids of the elements changed in the window, paginated with composite aggregations: first the elements with history
 * events (creation, update, merge), then both sides of the relationships created, updated or deleted, whose relationship
 * set changed. The returned cursor resumes the same window at the next run, null once both are read.
 * At most `max` ids are returned (at least two, the sides of one relationship): a page is only read when all of its
 * buckets fit in the budget left, so every bucket read is fully consumed and the cursor never skips an id.
 */
export const findChangedElementIds = async (
  context: AuthContext,
  from: string,
  to: string,
  cursor: ChangedElementsCursor | null,
  max: number,
) => {
  const budget = Math.max(MIN_CHANGED_ELEMENTS_BUDGET, max);
  const ids = new Set<string>();
  let relationships = cursor?.relationships ?? false;
  let currentAfter = cursor?.afterKey ?? null;
  let hasMore = true;
  while (hasMore) {
    const bucketWidth = relationships ? 2 : 1;
    const bucketsLeft = Math.floor((budget - ids.size) / bucketWidth);
    if (bucketsLeft === 0) break;
    const sources = relationships
      ? [{ from: { terms: { field: 'context_data.from_id.keyword' } } }, { to: { terms: { field: 'context_data.to_id.keyword' } } }]
      : [{ id: { terms: { field: 'context_data.id.keyword' } } }];
    const body: any = {
      size: 0,
      query: changedElementsQuery(from, to, relationships),
      aggs: {
        elements: {
          composite: {
            size: Math.min(COMPOSITE_PAGE_SIZE, bucketsLeft),
            sources,
            ...(currentAfter ? { after: currentAfter } : {}),
          },
        },
      },
    };
    const data = await elRawSearch(context, SYSTEM_USER, ENTITY_TYPE_HISTORY, { index: READ_INDEX_HISTORY, body }).catch((err: unknown) => {
      throw DatabaseError('Snapshot manager history aggregation fail', { cause: err });
    });
    const buckets: Array<{ key: Record<string, string | null> }> = data.aggregations?.elements?.buckets ?? [];
    buckets.forEach((bucket) => Object.values(bucket.key).forEach((id) => {
      if (id) ids.add(id);
    }));
    currentAfter = data.aggregations?.elements?.after_key ?? null;
    if (buckets.length === 0 || !currentAfter) {
      if (relationships) {
        hasMore = false;
      } else {
        relationships = true;
        currentAfter = null;
      }
    }
  }
  return { ids: [...ids], cursor: hasMore ? { relationships, afterKey: currentAfter } : null };
};

export interface RewoundElement {
  attributes: AttributeValues;
}

/**
 * Attributes of the entities at `snapshotDate`. The documents are read
 * after that date (a resumed window can be read hours later), so the changes made since are reverted with
 * their reverse patches. Entities that cannot be rewound exactly are left out and snapshotted at the next window.
 */
export const rewindAttributes = async (context: AuthContext, entities: BasicStoreEntity[], snapshotDate: string): Promise<Map<string, RewoundElement>> => {
  const rewound = new Map<string, RewoundElement>();
  if (entities.length === 0) return rewound;
  const ids = entities.map((entity) => entity.internal_id);
  const events = await fetchElementsHistoryEvents(context, SYSTEM_USER, ids, { from: snapshotDate, max: MAX_REWIND_EVENTS_PER_BATCH + 1 });
  if (events.length > MAX_REWIND_EVENTS_PER_BATCH) {
    logApp.warn('[TIME MACHINE] Too many changes since the snapshot date, the batch is snapshotted at the next window', { entities: ids.length });
    return rewound;
  }
  const eventsByElement = new Map<string, TimeMachineHistoryEvent[]>();
  events.forEach((event) => {
    const elementEvents = eventsByElement.get(event.context_id);
    if (elementEvents) {
      elementEvents.push(event);
    } else {
      eventsByElement.set(event.context_id, [event]);
    }
  });
  entities.forEach((entity) => {
    const attributes = extractAttributeValues(entity as any);
    const elementEvents = eventsByElement.get(entity.internal_id);
    if (!elementEvents) {
      rewound.set(entity.internal_id, { attributes });
      return;
    }
    const replay = replayBackward(attributes, entity.entity_type, elementEvents, snapshotDate, MAX_REWIND_EVENTS);
    if (replay.complete && replay.exists) {
      rewound.set(entity.internal_id, { attributes: replay.document });
    }
  });
  return rewound;
};

/**
 * Relationships of the entities deleted after `snapshotDate` that existed at that date (not created after it),
 * or null when there are too many relationship changes since that date to rewind them exactly.
 */
export const findRelationshipsDeletedSince = async (context: AuthContext, ids: string[], snapshotDate: string) => {
  const events = await fetchRelationshipsHistoryEvents(context, SYSTEM_USER, ids, {
    from: snapshotDate,
    scopes: ['create', 'delete'],
    entityTypes: TIME_MACHINE_RELATIONSHIP_TYPES,
    max: MAX_REWIND_EVENTS_PER_BATCH + 1,
  });
  if (events.length > MAX_REWIND_EVENTS_PER_BATCH) return null;
  const createdSince = new Set(events.filter((event) => event.event_scope === 'create').map((event) => event.context_id));
  return events.filter((event) => event.event_scope === 'delete' && !createdSince.has(event.context_id));
};

/**
 * Whether one of the entities changed after `snapshotDate`, read again after the knowledge reads of the batch. An update
 * moves `updated_at` and a relationship created or deleted moves `refreshed_at` of both sides (before the relationship
 * is removed), so their changes since are rewound from the history; a document without `refreshed_at` is assumed changed.
 */
const readChangeStamps = async (context: AuthContext, ids: string[]) => {
  const current = await internalFindByIds<BasicStoreEntity>(context, SYSTEM_USER, ids, {
    type: ABSTRACT_STIX_CORE_OBJECT,
    baseData: true,
    baseFields: ['updated_at', 'refreshed_at'],
  }) as BasicStoreEntity[];
  return new Map(current.map((entity) => [entity.internal_id, entity]));
};
const isChangedSince = (stamps: Map<string, BasicStoreEntity>, snapshotDate: string) => {
  const date = utcDate(snapshotDate);
  return [...stamps.values()].some((entity) => !entity.refreshed_at || utcDate(entity.refreshed_at).isAfter(date) || utcDate(entity.updated_at).isAfter(date));
};
// Latest change stamped on the documents: an update (`updated_at`) or a relationship created or deleted (`refreshed_at`)
const lastChangeOf = (stamps: Map<string, BasicStoreEntity>, fallback: string) => {
  const dates = [...stamps.values()].flatMap((entity) => [entity.updated_at, entity.refreshed_at]).filter((date) => !!date).map((date) => utcDate(date));
  return dates.length > 0 ? moment.max(dates).toISOString() : fallback;
};

/**
 * Compact documents at `snapshotDate`: raw attribute values, relationship ids by type (capped)
 * and exact relationship counts by type. The relationships are the ones
 * created up to that date and still present, plus the ones deleted since that existed at that date.
 * The history is indexed asynchronously: when an entity changed after that date, its changes are read from the history
 * once it holds every event older than the knowledge reads, and the batch is retried at the next window otherwise.
 */
export const buildCompactDocuments = async (context: AuthContext, entities: BasicStoreEntity[], snapshotDate: string): Promise<Map<string, CompactDocument>> => {
  const documents = new Map<string, CompactDocument>();
  if (entities.length === 0) return documents;
  const entityIds = entities.map((entity) => entity.internal_id);
  // One extra relationship is read to know whether the relationships of the batch were all read
  const relations = await fullRelationsList<BasicStoreRelation>(context, SYSTEM_USER, [ABSTRACT_STIX_CORE_RELATIONSHIP, STIX_SIGHTING_RELATIONSHIP], {
    fromOrToId: entityIds,
    indices: READ_RELATIONSHIPS_INDICES_WITHOUT_INFERRED,
    endDate: snapshotDate,
    dateAttribute: 'created_at',
    // The changes since the snapshot are read strictly after its date: one created at that date is listed here
    intervalInclude: true,
    baseData: true,
    maxSize: MAX_RELATIONSHIPS_PER_BATCH + 1,
  } as any);
  const readDate = now();
  const readStamps = await readChangeStamps(context, entityIds);
  if (isChangedSince(readStamps, snapshotDate) && !(await waitForHistoryCatchUp(context, readDate, lastChangeOf(readStamps, readDate)))) {
    logApp.warn('[TIME MACHINE] History indexing is behind the knowledge, the batch is snapshotted at the next window', { entities: entityIds.length });
    return documents;
  }
  const rewound = await rewindAttributes(context, entities, snapshotDate);
  rewound.forEach(({ attributes }, id) => {
    documents.set(id, { attributes, relationships: {}, relationships_count: {} });
  });
  if (documents.size === 0) return documents;
  const ids = [...documents.keys()];
  const allRead = relations.length <= MAX_RELATIONSHIPS_PER_BATCH;
  // Read after the present relationships: one deleted between the two reads is in both and counted once
  const deletedSince = await findRelationshipsDeletedSince(context, ids, snapshotDate);
  if (!deletedSince) {
    logApp.warn('[TIME MACHINE] Too many relationship changes since the snapshot date, the batch is snapshotted at the next window', { entities: ids.length });
    return new Map();
  }
  // An entity updated after its document was loaded has history events its document does not hold: it is retried
  const stamps = await readChangeStamps(context, ids);
  entities.forEach((entity) => {
    const stamp = stamps.get(entity.internal_id);
    if (stamp && String(stamp.updated_at) !== String(entity.updated_at)) documents.delete(entity.internal_id);
  });
  const listedIds = new Set(relations.slice(0, MAX_RELATIONSHIPS_PER_BATCH).map((relation) => relation.internal_id));
  const register = (entityId: string | undefined, relationshipId: string, type: string, counted: boolean) => {
    const document = entityId ? documents.get(entityId) : undefined;
    if (!document) return;
    if (counted) document.relationships_count[type] = (document.relationships_count[type] ?? 0) + 1;
    const typeIds = document.relationships[type] ?? [];
    if (typeIds.length < MAX_RELATIONSHIP_IDS_PER_TYPE) {
      typeIds.push(relationshipId);
      document.relationships[type] = typeIds;
    }
  };
  relations.slice(0, MAX_RELATIONSHIPS_PER_BATCH).forEach((relation) => {
    register(relation.fromId, relation.internal_id, relation.entity_type, allRead);
    if (relation.toId !== relation.fromId) register(relation.toId, relation.internal_id, relation.entity_type, allRead);
  });
  if (!allRead) {
    // Too many relationships to read them all: the exact counts come from one aggregation for the whole batch
    const countsById = await countRelationshipsByTypeForElements(context, SYSTEM_USER, ids, snapshotDate);
    countsById.forEach((counts, id) => {
      const document = documents.get(id);
      if (!document) return;
      counts.forEach((count, type) => {
        document.relationships_count[type] = count;
      });
    });
  }
  // Deleted relationships are no longer indexed: they are added on top of the counts of the present ones
  deletedSince.filter((event) => !listedIds.has(event.context_id)).forEach((event) => {
    register(event.from_id, event.context_id, event.context_entity_type, true);
    if (event.to_id !== event.from_id) register(event.to_id, event.context_id, event.context_entity_type, true);
  });
  return documents;
};

// Snapshots follow the history retention: the shortest active history retention rule, a filtered one included as it
// purges part of the history a reconstruction from an older snapshot would replay
export const computeSnapshotRetentionDate = (rules: BasicStoreEntityRetentionRule[], currentDate: string, retentionDays: number): string | null => {
  const horizons: moment.Moment[] = [];
  rules
    .filter((rule) => rule.scope === 'history' && rule.active !== false)
    .forEach((rule) => {
      horizons.push(utcDate(currentDate).subtract(rule.max_retention, (rule.retention_unit ?? 'days') as moment.unitOfTime.DurationConstructor));
    });
  if (retentionDays > 0) {
    horizons.push(utcDate(currentDate).subtract(retentionDays, 'days'));
  }
  if (horizons.length === 0) return null;
  return moment.max(horizons).toISOString();
};

// Last visit markers are purged by the retention manager, they do not depend on snapshots being enabled
export const applySnapshotRetention = async (context: AuthContext, currentDate: string) => {
  const rules = await listRules(context, SYSTEM_USER) as BasicStoreEntityRetentionRule[];
  const retentionDate = computeSnapshotRetentionDate(rules, currentDate, RETENTION_DAYS);
  const deletedSnapshots = retentionDate ? await deleteSnapshotsBefore(retentionDate) : 0;
  return { deletedSnapshots };
};

/**
 * Retries share the per-run budget with the discovery of the changed elements: they take at most half of it, so the
 * window keeps progressing, and the ones left over wait for the next run.
 */
export const splitRunBudget = (retryIds: string[], maxPerRun: number) => {
  const retried = retryIds.slice(0, Math.floor(maxPerRun / 2));
  return { retried, deferred: retryIds.slice(retried.length), discoveryBudget: maxPerRun - retried.length };
};

export const snapshotHandler = async () => {
  const context = executionContext(SNAPSHOT_MANAGER_CONTEXT);
  const state = await readState();
  const currentDate = now();
  const isWindowInProgress = !!state.window_end && (!!state.after_key || !!state.relationships_phase);
  const cursor = state.cursor ?? utcDate(currentDate).subtract(PERIOD_DAYS, 'days').toISOString();
  const lastWindowEnd = state.last_window_end ?? state.cursor;
  if (!isWindowInProgress && lastWindowEnd && utcDate(currentDate).diff(utcDate(lastWindowEnd), 'days', true) < PERIOD_DAYS) {
    // Next snapshot window not reached yet: the retention still follows the hourly schedule
    await applySnapshotRetention(context, currentDate);
    return;
  }
  const windowEnd = isWindowInProgress ? state.window_end as string : currentDate;
  // Measured before any read of the window, kept while the window is resumed
  const watermark = isWindowInProgress ? state.window_watermark ?? null : await findHistoryWatermark(context, windowEnd);
  logApp.info('[TIME MACHINE] Snapshot manager running', { from: cursor, to: windowEnd, watermark, resume: isWindowInProgress });
  const resumeFrom = isWindowInProgress ? { relationships: !!state.relationships_phase, afterKey: state.after_key ?? null } : null;
  const { retried, deferred, discoveryBudget } = splitRunBudget(state.retry_ids ?? [], MAX_ENTITIES_PER_RUN);
  const { ids: changedIds, cursor: nextCursor } = await findChangedElementIds(context, cursor, windowEnd, resumeFrom, discoveryBudget);
  const ids = [...new Set([...retried, ...changedIds])];
  const skippedIds: string[] = [];
  let snapshotsCount = 0;
  for (let index = 0; index < ids.length; index += BATCH_SIZE) {
    await doYield();
    const batchIds = ids.slice(index, index + BATCH_SIZE);
    // References are read from the denormalized fields (ids only)
    const entities = await internalFindByIds<BasicStoreEntity>(context, SYSTEM_USER, batchIds, { type: ABSTRACT_STIX_CORE_OBJECT, withoutRels: false }) as BasicStoreEntity[];
    if (entities.length > 0) {
      const documents = await buildCompactDocuments(context, entities, windowEnd);
      entities.filter((entity) => !documents.has(entity.internal_id)).forEach((entity) => skippedIds.push(entity.internal_id));
      const inputs: SnapshotInput[] = entities.filter((entity) => documents.has(entity.internal_id)).map((entity) => ({
        entityId: entity.internal_id,
        entityType: entity.entity_type,
        snapshotDate: windowEnd,
        historyCursor: windowEnd,
        document: documents.get(entity.internal_id) as CompactDocument,
      }));
      snapshotsCount += await indexSnapshots(inputs);
    }
  }
  const toRetry = [...new Set([...deferred, ...skippedIds])];
  if (toRetry.length > MAX_RETRY_IDS) {
    logApp.warn('[TIME MACHINE] Too many snapshots to retry, the others wait for the next change of their entity', { skipped: toRetry.length, retried: MAX_RETRY_IDS });
  }
  const retryIds = toRetry.slice(0, MAX_RETRY_IDS);
  if (nextCursor) {
    // Per run limit reached, the same window (same lower bound) is resumed at the next run
    await writeState({
      cursor,
      last_window_end: state.last_window_end,
      window_end: windowEnd,
      window_watermark: watermark,
      after_key: nextCursor.afterKey,
      relationships_phase: nextCursor.relationships,
      retry_ids: retryIds,
    });
  } else {
    await writeState({
      cursor: nextWindowStart(cursor, watermark),
      last_window_end: windowEnd,
      window_end: undefined,
      window_watermark: undefined,
      after_key: null,
      relationships_phase: false,
      retry_ids: retryIds,
    });
  }
  const retention = await applySnapshotRetention(context, currentDate);
  logApp.info('[TIME MACHINE] Snapshot manager done', { snapshots: snapshotsCount, retry: retryIds.length, ...retention, complete: !nextCursor });
};

const SNAPSHOT_MANAGER_DEFINITION: ManagerDefinition = {
  id: SNAPSHOT_MANAGER_ID,
  label: 'Knowledge snapshot manager',
  executionContext: SNAPSHOT_MANAGER_CONTEXT,
  cronSchedulerHandler: {
    handler: snapshotHandler,
    interval: SCHEDULE_TIME,
    lockKey: SNAPSHOT_MANAGER_KEY,
  },
  enabledByConfig: SNAPSHOT_MANAGER_ENABLED,
  enabledToStart(): boolean {
    return this.enabledByConfig;
  },
  enabled(): boolean {
    return this.enabledByConfig;
  },
};

registerManager(SNAPSHOT_MANAGER_DEFINITION);
