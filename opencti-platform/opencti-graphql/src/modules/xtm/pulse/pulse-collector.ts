import { randomUUID } from 'node:crypto';
import type { AuthContext, AuthUser } from '../../../types/user';
import type { BasicStoreRelation } from '../../../types/store';
import { FilterMode, FilterOperator, type FilterGroup } from '../../../generated/graphql';
import { buildRelationsFilter, fullEntitiesList, fullRelationsList } from '../../../database/middleware-loader';
import { elCount, elFindByIds } from '../../../database/engine';
import { READ_RELATIONSHIPS_INDICES_WITHOUT_INFERRED, READ_INDEX_STIX_DOMAIN_OBJECTS } from '../../../database/utils';
import { STIX_SIGHTING_RELATIONSHIP } from '../../../schema/stixSightingRelationship';
import { RELATION_OBJECT } from '../../../schema/stixRefRelationship';
import { ABSTRACT_STIX_CORE_RELATIONSHIP } from '../../../schema/general';
import { ENTITY_TYPE_IDENTITY_SECURITY_PLATFORM } from '../../securityPlatform/securityPlatform-types';
import { computeStableKeys, computeTransportHash, isValidPulseHash } from './pulse-hashing';
import { isPulseContributable, type PulseMarkingPolicy } from './pulse-settings';
import type { PulseWindowSighting } from './pulse-cache';
import {
  PULSE_ENTITY_TYPE_BY_OBJECT_TYPE,
  PULSE_EVENT_KINDS,
  PULSE_MAX_RECORD_COUNT,
  PULSE_MAX_RECORDS_PER_BATCH,
  PULSE_OBJECT_TYPE_BY_ENTITY_TYPE,
  PULSE_REGION_BUCKETS,
  PULSE_SECTOR_BUCKETS,
  type BasicStorePulseEntity,
  type PulseBatch,
  type PulseOutboxItem,
  type PulseEventKind,
  type PulseObjectType,
  type PulseRecord,
  type PulseRegionBucketValue,
  type PulseSectorBucketValue,
} from './pulse-types';

export type PulseActivity = Map<string, Map<PulseEventKind, number>>;

const addActivity = (activity: PulseActivity, entityId: string, kind: PulseEventKind, count: number) => {
  const kinds = activity.get(entityId) ?? new Map<PulseEventKind, number>();
  kinds.set(kind, (kinds.get(kind) ?? 0) + Math.max(1, Math.floor(count)));
  activity.set(entityId, kinds);
};

const createdInWindowFilter = (since: Date, until: Date): FilterGroup => ({
  mode: FilterMode.And,
  filters: [
    { key: ['created_at'], values: [since.toISOString()], operator: FilterOperator.Gte },
    { key: ['created_at'], values: [until.toISOString()], operator: FilterOperator.Lt },
  ],
  filterGroups: [],
});

// The same scoped queries as collectPulseActivity: a window is sized by the activity it collects, never by the traffic
// of relationships between objects out of scope.
export const countPulseActivity = async (context: AuthContext, user: AuthUser, scopes: string[], since: Date, until: Date) => {
  if (scopes.length === 0) {
    return 0;
  }
  const filters = createdInWindowFilter(since, until);
  const countRelations = (type: string, sides: { fromTypes?: string[]; toTypes?: string[] }) => {
    return elCount(context, user, READ_RELATIONSHIPS_INDICES_WITHOUT_INFERRED, buildRelationsFilter(type, { ...sides, filters }));
  };
  const counts = await Promise.all([
    elCount(context, user, READ_INDEX_STIX_DOMAIN_OBJECTS, { types: scopes, filters }),
    countRelations(STIX_SIGHTING_RELATIONSHIP, { fromTypes: scopes }),
    countRelations(RELATION_OBJECT, { toTypes: scopes }),
    countRelations(ABSTRACT_STIX_CORE_RELATIONSHIP, { fromTypes: scopes }),
    countRelations(ABSTRACT_STIX_CORE_RELATIONSHIP, { toTypes: scopes }),
  ]);
  return counts.reduce((total, count) => total + count, 0);
};

// The end of a window starting at *since* that holds at most *maxEvents* events, counted again each time it narrows:
// the proportional span when it is shorter, at most half the window, so a burst near its start is bounded too. One
// millisecond is not narrowed further, as its events cannot be told apart: it may hold more, which its collection cuts
// at the budget (see collectPulseActivity).
export const boundPulseWindow = async (since: Date, until: Date, maxEvents: number, countUntil: (end: Date) => Promise<number>) => {
  let end = until;
  let events = await countUntil(end);
  while (events > maxEvents && end.getTime() - since.getTime() > 1) {
    const span = end.getTime() - since.getTime();
    const proportional = Math.floor((span * maxEvents) / events);
    end = new Date(since.getTime() + Math.max(1, Math.min(Math.floor(span / 2), proportional)));
    events = await countUntil(end);
  }
  return { end, events };
};

// What is left of the events one contribution may read, shared by the queries of its window.
export interface PulseCollectBudget {
  remaining: number;
}

// Local activity on in-scope objects during [since, until): creations, sightings (detections when sighted by a
// security platform), container references and new relationships. *sightings* receives each sighting read with the
// count read, for the commit of the window to add what an upsert raised meanwhile. At most *budget* events are read:
// each query stops once it is spent and the next ones are not run, so a millisecond holding more events than a run may
// read never loads them all.
export const collectPulseActivity = async (
  context: AuthContext,
  user: AuthUser,
  scopes: string[],
  since: Date,
  until: Date,
  sightings: PulseWindowSighting[] = [],
  budget: PulseCollectBudget = { remaining: Number.POSITIVE_INFINITY },
): Promise<PulseActivity> => {
  const activity: PulseActivity = new Map();
  if (scopes.length === 0) {
    return activity;
  }
  type ReadPage<T> = (callback: (elements: T[]) => Promise<boolean>) => Promise<unknown>;
  // Each page within what is left of the budget; a page that spends it stops the query.
  const collect = async <T>(read: ReadPage<T>, onElement: (element: T) => void) => {
    if (budget.remaining <= 0) {
      return;
    }
    await read(async (elements) => {
      const taken = elements.length > budget.remaining ? elements.slice(0, budget.remaining) : elements;
      budget.remaining -= taken.length;
      taken.forEach(onElement);
      return budget.remaining > 0;
    });
  };
  const filters = createdInWindowFilter(since, until);
  const entities: ReadPage<BasicStorePulseEntity> = (callback) => fullEntitiesList<BasicStorePulseEntity>(context, user, scopes, { filters, baseData: true, callback });
  await collect(entities, (entity) => {
    addActivity(activity, entity.internal_id, 'created', 1);
  });
  const relations = (type: string, sides: { fromTypes?: string[]; toTypes?: string[] }): ReadPage<BasicStoreRelation> => (callback) => {
    return fullRelationsList<BasicStoreRelation>(context, user, type, { ...sides, filters, indices: READ_RELATIONSHIPS_INDICES_WITHOUT_INFERRED, callback });
  };
  await collect(relations(STIX_SIGHTING_RELATIONSHIP, { fromTypes: scopes }), (relation) => {
    const kind = relation.toType === ENTITY_TYPE_IDENTITY_SECURITY_PLATFORM ? 'detected' : 'sighted';
    const count = Number(relation.attribute_count ?? 1);
    addActivity(activity, relation.fromId, kind, count);
    sightings.push({ id: relation.internal_id, count, entityId: relation.fromId, eventKind: kind });
  });
  await collect(relations(RELATION_OBJECT, { toTypes: scopes }), (relation) => {
    addActivity(activity, relation.toId, 'referenced', 1);
  });
  const coreRelationship = (side: 'from' | 'to') => (relation: BasicStoreRelation) => {
    const targetType = side === 'from' ? relation.fromType : relation.toType;
    if (scopes.includes(targetType)) {
      addActivity(activity, side === 'from' ? relation.fromId : relation.toId, 'referenced', 1);
    }
  };
  await collect(relations(ABSTRACT_STIX_CORE_RELATIONSHIP, { fromTypes: scopes }), coreRelationship('from'));
  await collect(relations(ABSTRACT_STIX_CORE_RELATIONSHIP, { toTypes: scopes }), coreRelationship('to'));
  return activity;
};

export const mergePulseActivity = (activity: PulseActivity, external: Array<{ entityId: string; eventKind: PulseEventKind; count: number }>) => {
  external.filter((entry) => PULSE_EVENT_KINDS.includes(entry.eventKind) && entry.count > 0)
    .forEach((entry) => addActivity(activity, entry.entityId, entry.eventKind, entry.count));
  return activity;
};

export interface PulseKeyedRecord {
  key: string;
  object_type: PulseObjectType;
  event_kind: PulseEventKind;
  count: number;
  // The object whose activity produced the record first: counted in the contribution statistics, never sent.
  entity_id?: string;
}

export interface PulseAggregation {
  records: PulseKeyedRecord[];
  contributedEntities: BasicStorePulseEntity[];
  excludedCount: number;
  recordsByEntityType: Record<string, number>;
}

const ENTITY_LOAD_CHUNK = 500;

export const loadPulseEntities = async (context: AuthContext, user: AuthUser, entityIds: string[]): Promise<BasicStorePulseEntity[]> => {
  const entities: BasicStorePulseEntity[] = [];
  for (let index = 0; index < entityIds.length; index += ENTITY_LOAD_CHUNK) {
    const chunk = entityIds.slice(index, index + ENTITY_LOAD_CHUNK);
    const loaded = await elFindByIds<BasicStorePulseEntity>(context, user, chunk, { indices: [READ_INDEX_STIX_DOMAIN_OBJECTS] }) as BasicStorePulseEntity[];
    entities.push(...loaded);
  }
  return entities;
};

// Turns local activity into keyed records. Objects whose markings or access restrictions exclude them never produce a
// record, whatever their activity.
export const aggregatePulseActivity = (
  activity: PulseActivity,
  entities: BasicStorePulseEntity[],
  policy: PulseMarkingPolicy,
  scopes: string[],
): PulseAggregation => {
  const totals = new Map<string, PulseKeyedRecord>();
  const contributedEntities: BasicStorePulseEntity[] = [];
  const recordsByEntityType: Record<string, number> = {};
  let excludedCount = 0;
  entities.forEach((entity) => {
    const kinds = activity.get(entity.internal_id);
    if (!kinds) {
      return;
    }
    if (!isPulseContributable(entity, policy, scopes)) {
      excludedCount += 1;
      return;
    }
    const objectType = PULSE_OBJECT_TYPE_BY_ENTITY_TYPE[entity.entity_type];
    const keys = computeStableKeys(entity);
    if (keys.length === 0) {
      return;
    }
    contributedEntities.push(entity);
    keys.forEach((key) => {
      kinds.forEach((count, kind) => {
        const recordId = `${key}|${kind}`;
        const current = totals.get(recordId);
        totals.set(recordId, {
          key,
          object_type: objectType,
          event_kind: kind,
          count: Math.min(PULSE_MAX_RECORD_COUNT, (current?.count ?? 0) + count),
          entity_id: current?.entity_id ?? entity.internal_id,
        });
        if (!current) {
          recordsByEntityType[entity.entity_type] = (recordsByEntityType[entity.entity_type] ?? 0) + 1;
        }
      });
    });
  });
  return { records: Array.from(totals.values()), contributedEntities, excludedCount, recordsByEntityType };
};

const RECORD_KEYS = ['count', 'event_kind', 'hash', 'object_type'];
const BATCH_KEYS = ['batch_id', 'day', 'records', 'region_bucket', 'sector_bucket'];
const BATCH_ID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const DAY_REGEX = /^\d{4}-\d{2}-\d{2}$/;

// The outbound payload schema: any field other than the batch header and the hash/count tuple is refused before it
// can leave the platform.
export const assertPulseBatch = (batch: PulseBatch) => {
  const batchKeys = Object.keys(batch).sort();
  if (batchKeys.join(',') !== BATCH_KEYS.join(',')) {
    throw new Error(`Threat Pulse batch refused: unexpected fields ${batchKeys.join(', ')}`);
  }
  if (!BATCH_ID_REGEX.test(batch.batch_id)
    || !DAY_REGEX.test(batch.day)
    || !PULSE_SECTOR_BUCKETS.includes(batch.sector_bucket)
    || !PULSE_REGION_BUCKETS.includes(batch.region_bucket)) {
    throw new Error('Threat Pulse batch refused: invalid header');
  }
  if (!Array.isArray(batch.records) || batch.records.length === 0 || batch.records.length > PULSE_MAX_RECORDS_PER_BATCH) {
    throw new Error('Threat Pulse batch refused: invalid number of records');
  }
  const objectTypes = Object.values(PULSE_OBJECT_TYPE_BY_ENTITY_TYPE);
  const seen = new Set<string>();
  batch.records.forEach((record) => {
    const recordKeys = Object.keys(record).sort();
    if (recordKeys.join(',') !== RECORD_KEYS.join(',')) {
      throw new Error(`Threat Pulse batch refused: unexpected record fields ${recordKeys.join(', ')}`);
    }
    if (!isValidPulseHash(record.hash)
      || !objectTypes.includes(record.object_type)
      || !PULSE_EVENT_KINDS.includes(record.event_kind)
      || !Number.isInteger(record.count) || record.count < 1 || record.count > PULSE_MAX_RECORD_COUNT) {
      throw new Error('Threat Pulse batch refused: invalid record');
    }
    const identity = `${record.hash}|${record.object_type}|${record.event_kind}`;
    if (seen.has(identity)) {
      throw new Error('Threat Pulse batch refused: duplicated record');
    }
    seen.add(identity);
  });
};

export const buildPulseBatches = (
  records: PulseKeyedRecord[],
  salt: string,
  day: string,
  buckets: { sector_bucket: PulseSectorBucketValue; region_bucket: PulseRegionBucketValue },
): PulseBatch[] => {
  const outbound: PulseRecord[] = records.map((record) => ({
    hash: computeTransportHash(salt, record.key),
    object_type: record.object_type,
    event_kind: record.event_kind,
    count: record.count,
  }));
  const batches: PulseBatch[] = [];
  for (let index = 0; index < outbound.length; index += PULSE_MAX_RECORDS_PER_BATCH) {
    const batch: PulseBatch = {
      batch_id: randomUUID(),
      day,
      sector_bucket: buckets.sector_bucket,
      region_bucket: buckets.region_bucket,
      records: outbound.slice(index, index + PULSE_MAX_RECORDS_PER_BATCH),
    };
    assertPulseBatch(batch);
    batches.push(batch);
  }
  return batches;
};

// The batches of one day, each with what it adds to the contribution statistics once XTM Hub accepts it: its records
// per entity type, and the objects whose first record it carries, so that an object split over two batches counts once.
export const buildPulseOutboxItems = (
  records: PulseKeyedRecord[],
  salt: string,
  day: string,
  buckets: { sector_bucket: PulseSectorBucketValue; region_bucket: PulseRegionBucketValue },
): PulseOutboxItem[] => {
  const counted = new Set<string>();
  return buildPulseBatches(records, salt, day, buckets).map((batch, index) => {
    const slice = records.slice(index * PULSE_MAX_RECORDS_PER_BATCH, (index + 1) * PULSE_MAX_RECORDS_PER_BATCH);
    const byType: Record<string, number> = {};
    let objects = 0;
    slice.forEach((record) => {
      const entityType = PULSE_ENTITY_TYPE_BY_OBJECT_TYPE[record.object_type];
      byType[entityType] = (byType[entityType] ?? 0) + 1;
      if (record.entity_id && !counted.has(record.entity_id)) {
        counted.add(record.entity_id);
        objects += 1;
      }
    });
    return { batch, stats: { records: slice.length, objects, by_type: byType } };
  });
};
