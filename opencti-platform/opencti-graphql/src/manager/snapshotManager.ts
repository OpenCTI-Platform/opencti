import moment from 'moment';
import { type ManagerDefinition, registerManager } from './managerModule';
import conf, { booleanConf, logApp } from '../config/conf';
import { elRawSearch } from '../database/engine';
import { fullRelationsList, internalFindByIds } from '../database/middleware-loader';
import { redisGetManagerEventState, redisSetManagerEventState } from '../database/redis';
import { READ_INDEX_HISTORY, READ_RELATIONSHIPS_INDICES_WITHOUT_INFERRED } from '../database/utils';
import { ABSTRACT_STIX_CORE_OBJECT, ABSTRACT_STIX_CORE_RELATIONSHIP } from '../schema/general';
import { ENTITY_TYPE_HISTORY } from '../schema/internalObject';
import { STIX_SIGHTING_RELATIONSHIP } from '../schema/stixSightingRelationship';
import { isStixDomainObjectContainer } from '../schema/stixDomainObject';
import { DatabaseError } from '../config/errors';
import { executionContext, SYSTEM_USER } from '../utils/access';
import { now, utcDate } from '../utils/format';
import { doYield } from '../utils/eventloop-utils';
import type { AuthContext } from '../types/user';
import type { BasicStoreEntity, BasicStoreRelation } from '../types/store';
import type { BasicStoreEntityRetentionRule } from '../modules/retentionRules/retentionRules-types';
import { listRules } from '../modules/retentionRules/retentionRules-domain';
import type { AttributeValues, CompactDocument, TimeMachineHistoryEvent } from '../modules/timeMachine/timeMachine-types';
import { containerObjectsCountAt, currentContainerObjectsCount, extractAttributeValues, replayBackward } from '../modules/timeMachine/timeMachine-replay';
import { fetchElementsHistoryEvents } from '../modules/timeMachine/timeMachine-history';
import { deleteSnapshotsBefore, indexSnapshots, type SnapshotInput } from '../modules/timeMachine/timeMachine-store';
import { TIME_MACHINE_RELATIONSHIP_TYPES } from '../modules/timeMachine/timeMachine-relationships';
import { countRelationshipsByType } from '../modules/timeMachine/timeMachine-domain';
import { isFilterGroupNotEmpty } from '../utils/filtering/filtering-utils';

const SNAPSHOT_MANAGER_ID = 'SNAPSHOT_MANAGER';
const SNAPSHOT_MANAGER_CONTEXT = 'snapshot_manager';
const SNAPSHOT_MANAGER_STATE = 'snapshot_manager';
const SNAPSHOT_MANAGER_ENABLED = booleanConf('snapshot_manager:enabled', true);
const SNAPSHOT_MANAGER_KEY = conf.get('snapshot_manager:lock_key') || 'snapshot_manager_lock';
const SCHEDULE_TIME = conf.get('snapshot_manager:interval') || 3600000;
const PERIOD_DAYS: number = conf.get('snapshot_manager:period_days') || 7;
const MAX_ENTITIES_PER_RUN: number = conf.get('snapshot_manager:max_entities_per_run') || 10000;
const BATCH_SIZE: number = conf.get('snapshot_manager:batch_size') || 100;
const MAX_RELATIONSHIP_IDS_PER_TYPE: number = conf.get('snapshot_manager:max_relationship_ids_per_type') || 500;
const RETENTION_DAYS: number = conf.get('snapshot_manager:retention_days') || 0;
const MAX_REWIND_EVENTS: number = conf.get('time_machine:max_replay_events') || 5000;
// Maximum number of history events read per batch to rewind the documents to the snapshot date
const MAX_REWIND_EVENTS_PER_BATCH = 20000;
// Maximum number of relationships read per batch of entities to build relationship id lists
const MAX_RELATIONSHIPS_PER_BATCH = 20000;
const COMPOSITE_PAGE_SIZE = 1000;
// Maximum number of entities kept in the state to retry a snapshot that could not be built exactly
const MAX_RETRY_IDS = 1000;

export interface SnapshotManagerState {
  // End of the last completed snapshot window (history cursor)
  cursor?: string;
  // Window currently being processed, and the position in it when a run hit the per-run limit
  window_end?: string;
  after_key?: Record<string, string> | null;
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

// Ids of the elements with history events (creation, update, merge) in the window, paginated with a composite aggregation
export const findChangedElementIds = async (
  context: AuthContext,
  from: string,
  to: string,
  afterKey: Record<string, string> | null | undefined,
  max: number,
) => {
  const ids: string[] = [];
  let currentAfter = afterKey ?? null;
  let hasMore = true;
  while (hasMore && ids.length < max) {
    const body: any = {
      size: 0,
      query: {
        bool: {
          must: [
            { terms: { 'entity_type.keyword': [ENTITY_TYPE_HISTORY] } },
            { terms: { 'event_scope.keyword': ['create', 'update', 'merge'] } },
            { range: { timestamp: { gt: from, lte: to } } },
          ],
          must_not: [{ terms: { 'context_data.entity_type.keyword': TIME_MACHINE_RELATIONSHIP_TYPES } }],
        },
      },
      aggs: {
        elements: {
          composite: {
            size: Math.min(COMPOSITE_PAGE_SIZE, max - ids.length),
            sources: [{ id: { terms: { field: 'context_data.id.keyword' } } }],
            ...(currentAfter ? { after: currentAfter } : {}),
          },
        },
      },
    };
    const data = await elRawSearch(context, SYSTEM_USER, ENTITY_TYPE_HISTORY, { index: READ_INDEX_HISTORY, body }).catch((err: unknown) => {
      throw DatabaseError('Snapshot manager history aggregation fail', { cause: err });
    });
    const buckets: Array<{ key: { id: string } }> = data.aggregations?.elements?.buckets ?? [];
    buckets.forEach((bucket) => ids.push(bucket.key.id));
    currentAfter = data.aggregations?.elements?.after_key ?? null;
    hasMore = buckets.length > 0 && !!currentAfter;
  }
  return { ids, afterKey: hasMore ? currentAfter : null };
};

export interface RewoundElement {
  attributes: AttributeValues;
  // Number of objects of a container at the snapshot date, null for other entities
  containerObjectsCount: number | null;
}

/**
 * Attributes (and number of objects of containers) of the entities at `snapshotDate`. The documents are read
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
    const isContainer = isStixDomainObjectContainer(entity.entity_type);
    const currentCount = isContainer ? currentContainerObjectsCount(entity as any) : null;
    const elementEvents = eventsByElement.get(entity.internal_id);
    if (!elementEvents) {
      rewound.set(entity.internal_id, { attributes, containerObjectsCount: currentCount });
      return;
    }
    const replay = replayBackward(attributes, entity.entity_type, elementEvents, snapshotDate, MAX_REWIND_EVENTS);
    if (replay.complete && replay.exists) {
      const containerObjectsCount = currentCount !== null ? containerObjectsCountAt(currentCount, elementEvents, 'backward') : null;
      rewound.set(entity.internal_id, { attributes: replay.document, containerObjectsCount });
    }
  });
  return rewound;
};

/**
 * Compact documents at `snapshotDate`: raw attribute values, number of objects of containers,
 * relationship ids by type (capped) and exact relationship counts by type.
 */
export const buildCompactDocuments = async (context: AuthContext, entities: BasicStoreEntity[], snapshotDate: string): Promise<Map<string, CompactDocument>> => {
  const documents = new Map<string, CompactDocument>();
  const rewound = await rewindAttributes(context, entities, snapshotDate);
  rewound.forEach(({ attributes, containerObjectsCount }, id) => {
    documents.set(id, {
      attributes,
      relationships: {},
      relationships_count: {},
      ...(containerObjectsCount !== null ? { container_objects_count: containerObjectsCount } : {}),
    });
  });
  if (documents.size === 0) return documents;
  const ids = [...documents.keys()];
  // One extra relationship is read to know whether the relationships of the batch were all read
  const relations = await fullRelationsList<BasicStoreRelation>(context, SYSTEM_USER, [ABSTRACT_STIX_CORE_RELATIONSHIP, STIX_SIGHTING_RELATIONSHIP], {
    fromOrToId: ids,
    indices: READ_RELATIONSHIPS_INDICES_WITHOUT_INFERRED,
    endDate: snapshotDate,
    dateAttribute: 'created_at',
    baseData: true,
    maxSize: MAX_RELATIONSHIPS_PER_BATCH + 1,
  } as any);
  const allRead = relations.length <= MAX_RELATIONSHIPS_PER_BATCH;
  const register = (entityId: string, relation: BasicStoreRelation) => {
    const document = documents.get(entityId);
    if (!document) return;
    const type = relation.entity_type;
    if (allRead) document.relationships_count[type] = (document.relationships_count[type] ?? 0) + 1;
    const typeIds = document.relationships[type] ?? [];
    if (typeIds.length < MAX_RELATIONSHIP_IDS_PER_TYPE) {
      typeIds.push(relation.internal_id);
      document.relationships[type] = typeIds;
    }
  };
  relations.slice(0, MAX_RELATIONSHIPS_PER_BATCH).forEach((relation) => {
    register(relation.fromId, relation);
    if (relation.toId !== relation.fromId) register(relation.toId, relation);
  });
  if (!allRead) {
    // Too many relationships to read them all: the exact counts come from an aggregation per entity
    for (let index = 0; index < ids.length; index += 1) {
      const counts = await countRelationshipsByType(context, SYSTEM_USER, ids[index], { endDate: snapshotDate });
      const document = documents.get(ids[index]) as CompactDocument;
      counts.forEach((count, type) => {
        document.relationships_count[type] = count;
      });
    }
  }
  return documents;
};

// Snapshots follow the history retention: the shortest active history retention rule applying to all the history
export const computeSnapshotRetentionDate = (rules: BasicStoreEntityRetentionRule[], currentDate: string, retentionDays: number): string | null => {
  const horizons: moment.Moment[] = [];
  rules
    .filter((rule) => rule.scope === 'history' && rule.active !== false)
    .filter((rule) => {
      if (!rule.filters) return true;
      try {
        return !isFilterGroupNotEmpty(JSON.parse(rule.filters));
      } catch {
        return false;
      }
    })
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

export const snapshotHandler = async () => {
  const context = executionContext(SNAPSHOT_MANAGER_CONTEXT);
  const state = await readState();
  const currentDate = now();
  const isWindowInProgress = !!state.window_end && !!state.after_key;
  const cursor = state.cursor ?? utcDate(currentDate).subtract(PERIOD_DAYS, 'days').toISOString();
  if (!isWindowInProgress && state.cursor && utcDate(currentDate).diff(utcDate(state.cursor), 'days', true) < PERIOD_DAYS) {
    // Next snapshot window not reached yet
    return;
  }
  const windowEnd = isWindowInProgress ? state.window_end as string : currentDate;
  logApp.info('[TIME MACHINE] Snapshot manager running', { from: cursor, to: windowEnd, resume: isWindowInProgress });
  const { ids: changedIds, afterKey } = await findChangedElementIds(context, cursor, windowEnd, state.after_key, MAX_ENTITIES_PER_RUN);
  const ids = [...new Set([...(state.retry_ids ?? []), ...changedIds])];
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
  if (skippedIds.length > MAX_RETRY_IDS) {
    logApp.warn('[TIME MACHINE] Too many snapshots to retry, the others wait for the next change of their entity', { skipped: skippedIds.length, retried: MAX_RETRY_IDS });
  }
  const retryIds = skippedIds.slice(0, MAX_RETRY_IDS);
  if (afterKey) {
    // Per run limit reached, the same window (same lower bound) is resumed at the next run
    await writeState({ cursor, window_end: windowEnd, after_key: afterKey, retry_ids: retryIds });
  } else {
    await writeState({ cursor: windowEnd, window_end: undefined, after_key: null, retry_ids: retryIds });
  }
  const retention = await applySnapshotRetention(context, currentDate);
  logApp.info('[TIME MACHINE] Snapshot manager done', { snapshots: snapshotsCount, retry: retryIds.length, ...retention, complete: !afterKey });
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
