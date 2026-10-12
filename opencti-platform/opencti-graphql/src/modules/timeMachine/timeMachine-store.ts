import { v5 as uuidv5 } from 'uuid';
import { elConvertHits } from '../../database/engine-data-converter';
import { elIndexElements, elRawDeleteByQuery, elRawSearch } from '../../database/engine';
import { INDEX_INTERNAL_OBJECTS, INDEX_KNOWLEDGE_SNAPSHOTS, READ_INDEX_INTERNAL_OBJECTS, READ_INDEX_KNOWLEDGE_SNAPSHOTS } from '../../database/utils';
import { BASE_TYPE_ENTITY, ABSTRACT_BASIC_OBJECT, ABSTRACT_INTERNAL_OBJECT } from '../../schema/general';
import { generateStandardId } from '../../schema/identifier';
import { DatabaseError } from '../../config/errors';
import { executionContext, SYSTEM_USER } from '../../utils/access';
import { utcDate } from '../../utils/format';
import type { AuthContext } from '../../types/user';
import {
  type BasicStoreEntityKnowledgeSnapshot,
  type BasicStoreEntityUserVisit,
  type CompactDocument,
  ENTITY_TYPE_KNOWLEDGE_SNAPSHOT,
  ENTITY_TYPE_USER_VISIT,
} from './timeMachine-types';

// Namespace used to derive deterministic identifiers (one snapshot per entity and date, one visit per user and entity)
const TIME_MACHINE_NAMESPACE = '0c9c7f6e-2f1b-4a8e-9c8b-61d1b3c0f9a1';

const writeContext = () => executionContext('time_machine');

export const snapshotInternalId = (entityId: string, snapshotDate: string) => uuidv5(`${entityId}|${snapshotDate}`, TIME_MACHINE_NAMESPACE);
export const visitInternalId = (userId: string, entityId: string) => uuidv5(`${userId}|${entityId}`, TIME_MACHINE_NAMESPACE);

const search = async (context: AuthContext, index: string, type: string, body: any) => {
  const query = { index, track_total_hits: false, body };
  const data = await elRawSearch(context, SYSTEM_USER, type, query).catch((err: unknown) => {
    throw DatabaseError('Time machine search fail', { cause: err, type });
  });
  return elConvertHits<any>(data.hits?.hits ?? []);
};

// region Knowledge snapshots
export interface SnapshotInput {
  entityId: string;
  entityType: string;
  snapshotDate: string;
  historyCursor: string;
  document: CompactDocument;
}

export const buildSnapshotElement = (input: SnapshotInput) => {
  const internalId = snapshotInternalId(input.entityId, input.snapshotDate);
  const date = utcDate(input.snapshotDate).toDate();
  return {
    _index: INDEX_KNOWLEDGE_SNAPSHOTS,
    internal_id: internalId,
    standard_id: generateStandardId(ENTITY_TYPE_KNOWLEDGE_SNAPSHOT, { internal_id: internalId }),
    entity_type: ENTITY_TYPE_KNOWLEDGE_SNAPSHOT,
    parent_types: [ABSTRACT_BASIC_OBJECT, ABSTRACT_INTERNAL_OBJECT],
    base_type: BASE_TYPE_ENTITY,
    created_at: date,
    updated_at: date,
    entity_id: input.entityId,
    target_entity_type: input.entityType,
    snapshot_date: input.snapshotDate,
    history_cursor: input.historyCursor,
    snapshot_document: input.document,
  };
};

export const indexSnapshots = async (inputs: SnapshotInput[]) => {
  if (inputs.length === 0) return 0;
  const elements = inputs.map(buildSnapshotElement);
  return elIndexElements(writeContext(), SYSTEM_USER, ENTITY_TYPE_KNOWLEDGE_SNAPSHOT, elements);
};

const snapshotQuery = (entityId: string, range: Record<string, string>, order: 'asc' | 'desc', size: number) => ({
  size,
  query: {
    bool: {
      must: [
        { term: { 'entity_id.keyword': entityId } },
        ...(Object.keys(range).length > 0 ? [{ range: { snapshot_date: range } }] : []),
      ],
    },
  },
  sort: [{ snapshot_date: order }],
});

// Oldest snapshot taken at or after `date` (anchor for a backward replay)
export const findSnapshotAtOrAfter = async (context: AuthContext, entityId: string, date: string): Promise<BasicStoreEntityKnowledgeSnapshot | undefined> => {
  const [snapshot] = await search(context, READ_INDEX_KNOWLEDGE_SNAPSHOTS, ENTITY_TYPE_KNOWLEDGE_SNAPSHOT, snapshotQuery(entityId, { gte: date }, 'asc', 1));
  return snapshot;
};

// Most recent snapshot taken at or before `date` (anchor for a forward replay)
export const findSnapshotAtOrBefore = async (context: AuthContext, entityId: string, date: string): Promise<BasicStoreEntityKnowledgeSnapshot | undefined> => {
  const [snapshot] = await search(context, READ_INDEX_KNOWLEDGE_SNAPSHOTS, ENTITY_TYPE_KNOWLEDGE_SNAPSHOT, snapshotQuery(entityId, { lte: date }, 'desc', 1));
  return snapshot;
};

export const listSnapshotDates = async (context: AuthContext, entityId: string, max: number): Promise<string[]> => {
  const body = { ...snapshotQuery(entityId, {}, 'desc', max), _source: ['internal_id', 'snapshot_date'] };
  const snapshots = await search(context, READ_INDEX_KNOWLEDGE_SNAPSHOTS, ENTITY_TYPE_KNOWLEDGE_SNAPSHOT, body);
  return snapshots.map((snapshot: BasicStoreEntityKnowledgeSnapshot) => snapshot.snapshot_date);
};

export const deleteSnapshotsBefore = async (date: string): Promise<number> => {
  const result = await elRawDeleteByQuery({
    index: READ_INDEX_KNOWLEDGE_SNAPSHOTS,
    refresh: true,
    conflicts: 'proceed',
    body: { query: { range: { snapshot_date: { lt: date } } } },
  });
  return result?.deleted ?? 0;
};
// endregion

// region User visits
export const loadUserVisits = async (context: AuthContext, userId: string, entityIds: string[]): Promise<Map<string, BasicStoreEntityUserVisit>> => {
  const visits = new Map<string, BasicStoreEntityUserVisit>();
  if (entityIds.length === 0) return visits;
  const ids = entityIds.map((entityId) => visitInternalId(userId, entityId));
  const body = {
    size: ids.length,
    query: {
      bool: {
        must: [
          { terms: { 'entity_type.keyword': [ENTITY_TYPE_USER_VISIT] } },
          { terms: { 'internal_id.keyword': ids } },
        ],
      },
    },
  };
  const hits: BasicStoreEntityUserVisit[] = await search(context, READ_INDEX_INTERNAL_OBJECTS, ENTITY_TYPE_USER_VISIT, body);
  hits.forEach((visit) => visits.set(visit.entity_id, visit));
  return visits;
};

export const buildVisitElement = (
  userId: string,
  entityId: string,
  entityType: string,
  lastSeenAt: string,
  previousSeenAt: string | undefined,
  createdAt: string,
) => {
  const internalId = visitInternalId(userId, entityId);
  return {
    _index: INDEX_INTERNAL_OBJECTS,
    internal_id: internalId,
    standard_id: generateStandardId(ENTITY_TYPE_USER_VISIT, { internal_id: internalId }),
    entity_type: ENTITY_TYPE_USER_VISIT,
    parent_types: [ABSTRACT_BASIC_OBJECT, ABSTRACT_INTERNAL_OBJECT],
    base_type: BASE_TYPE_ENTITY,
    created_at: utcDate(createdAt).toDate(),
    updated_at: utcDate(lastSeenAt).toDate(),
    user_id: userId,
    entity_id: entityId,
    target_entity_type: entityType,
    last_seen_at: lastSeenAt,
    ...(previousSeenAt ? { previous_seen_at: previousSeenAt } : {}),
  };
};

export const indexVisit = async (element: ReturnType<typeof buildVisitElement>) => {
  return elIndexElements(writeContext(), SYSTEM_USER, ENTITY_TYPE_USER_VISIT, [element]);
};

const deleteVisitsByQuery = async (query: any): Promise<number> => {
  const result = await elRawDeleteByQuery({
    index: READ_INDEX_INTERNAL_OBJECTS,
    refresh: true,
    conflicts: 'proceed',
    body: {
      query: {
        bool: {
          must: [{ terms: { 'entity_type.keyword': [ENTITY_TYPE_USER_VISIT] } }, query],
        },
      },
    },
  });
  return result?.deleted ?? 0;
};

export const deleteUserVisits = async (userId: string): Promise<number> => {
  return deleteVisitsByQuery({ term: { 'user_id.keyword': userId } });
};

export const deleteVisitsBefore = async (date: string): Promise<number> => {
  return deleteVisitsByQuery({ range: { last_seen_at: { lt: date } } });
};
// endregion
