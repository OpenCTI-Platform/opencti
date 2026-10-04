import { randomUUID } from 'node:crypto';
import type { AuthContext, AuthUser } from '../../../types/user';
import type { BasicStoreRelation } from '../../../types/store';
import { FilterMode, FilterOperator, type FilterGroup } from '../../../generated/graphql';
import { fullEntitiesList, fullRelationsList } from '../../../database/middleware-loader';
import { elCount, elFindByIds } from '../../../database/engine';
import { READ_RELATIONSHIPS_INDICES_WITHOUT_INFERRED, READ_INDEX_STIX_DOMAIN_OBJECTS } from '../../../database/utils';
import { STIX_SIGHTING_RELATIONSHIP } from '../../../schema/stixSightingRelationship';
import { RELATION_OBJECT } from '../../../schema/stixRefRelationship';
import { ABSTRACT_STIX_CORE_RELATIONSHIP } from '../../../schema/general';
import { ENTITY_TYPE_IDENTITY_SECURITY_PLATFORM } from '../../securityPlatform/securityPlatform-types';
import { computeStableKeys, computeTransportHash, isValidPulseHash } from './pulse-hashing';
import { isPulseContributable, type PulseMarkingPolicy } from './pulse-settings';
import {
  PULSE_EVENT_KINDS,
  PULSE_MAX_RECORD_COUNT,
  PULSE_MAX_RECORDS_PER_BATCH,
  PULSE_OBJECT_TYPE_BY_ENTITY_TYPE,
  PULSE_REGION_BUCKETS,
  PULSE_SECTOR_BUCKETS,
  type BasicStorePulseEntity,
  type PulseBatch,
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

export const countPulseActivity = async (context: AuthContext, user: AuthUser, scopes: string[], since: Date, until: Date) => {
  const filters = createdInWindowFilter(since, until);
  const [created, sightings, references, relationships] = await Promise.all([
    elCount(context, user, READ_INDEX_STIX_DOMAIN_OBJECTS, { types: scopes, filters }),
    elCount(context, user, READ_RELATIONSHIPS_INDICES_WITHOUT_INFERRED, { types: [STIX_SIGHTING_RELATIONSHIP], filters }),
    elCount(context, user, READ_RELATIONSHIPS_INDICES_WITHOUT_INFERRED, { types: [RELATION_OBJECT], filters }),
    elCount(context, user, READ_RELATIONSHIPS_INDICES_WITHOUT_INFERRED, { types: [ABSTRACT_STIX_CORE_RELATIONSHIP], filters }),
  ]);
  return created + sightings + references + relationships;
};

// Local activity on in-scope objects during [since, until): creations, sightings (detections when sighted by a
// security platform), container references and new relationships.
export const collectPulseActivity = async (context: AuthContext, user: AuthUser, scopes: string[], since: Date, until: Date): Promise<PulseActivity> => {
  const activity: PulseActivity = new Map();
  if (scopes.length === 0) {
    return activity;
  }
  const filters = createdInWindowFilter(since, until);
  await fullEntitiesList<BasicStorePulseEntity>(context, user, scopes, {
    filters,
    baseData: true,
    callback: async (entities) => {
      entities.forEach((entity) => addActivity(activity, entity.internal_id, 'created', 1));
    },
  });
  await fullRelationsList<BasicStoreRelation>(context, user, STIX_SIGHTING_RELATIONSHIP, {
    fromTypes: scopes,
    filters,
    indices: READ_RELATIONSHIPS_INDICES_WITHOUT_INFERRED,
    callback: async (relations) => {
      relations.forEach((relation) => {
        const kind = relation.toType === ENTITY_TYPE_IDENTITY_SECURITY_PLATFORM ? 'detected' : 'sighted';
        addActivity(activity, relation.fromId, kind, Number(relation.attribute_count ?? 1));
      });
    },
  });
  await fullRelationsList<BasicStoreRelation>(context, user, RELATION_OBJECT, {
    toTypes: scopes,
    filters,
    indices: READ_RELATIONSHIPS_INDICES_WITHOUT_INFERRED,
    callback: async (relations) => {
      relations.forEach((relation) => addActivity(activity, relation.toId, 'referenced', 1));
    },
  });
  const coreRelationshipCallback = (side: 'from' | 'to') => async (relations: BasicStoreRelation[]) => {
    relations.forEach((relation) => {
      const targetType = side === 'from' ? relation.fromType : relation.toType;
      if (scopes.includes(targetType)) {
        addActivity(activity, side === 'from' ? relation.fromId : relation.toId, 'referenced', 1);
      }
    });
  };
  await fullRelationsList<BasicStoreRelation>(context, user, ABSTRACT_STIX_CORE_RELATIONSHIP, {
    fromTypes: scopes,
    filters,
    indices: READ_RELATIONSHIPS_INDICES_WITHOUT_INFERRED,
    callback: coreRelationshipCallback('from'),
  });
  await fullRelationsList<BasicStoreRelation>(context, user, ABSTRACT_STIX_CORE_RELATIONSHIP, {
    toTypes: scopes,
    filters,
    indices: READ_RELATIONSHIPS_INDICES_WITHOUT_INFERRED,
    callback: coreRelationshipCallback('to'),
  });
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
        totals.set(recordId, { key, object_type: objectType, event_kind: kind, count: Math.min(PULSE_MAX_RECORD_COUNT, (current?.count ?? 0) + count) });
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
