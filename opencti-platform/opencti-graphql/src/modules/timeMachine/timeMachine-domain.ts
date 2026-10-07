import conf, { logApp } from '../../config/conf';
import { FunctionalError, ValidationError } from '../../config/errors';
import { elAggregationCount, elCount } from '../../database/engine';
import { buildRelationsFilter, internalFindByIdsMapped, internalLoadById, topRelationsList } from '../../database/middleware-loader';
import { extractEntityRepresentativeName } from '../../database/entity-representative';
import { getEntitiesMapFromCache } from '../../database/cache';
import { READ_DATA_INDICES_WITHOUT_INTERNAL, READ_RELATIONSHIPS_INDICES_WITHOUT_INFERRED } from '../../database/utils';
import { ABSTRACT_STIX_CORE_OBJECT, ABSTRACT_STIX_CORE_RELATIONSHIP } from '../../schema/general';
import { ENTITY_TYPE_USER } from '../../schema/internalObject';
import { STIX_SIGHTING_RELATIONSHIP } from '../../schema/stixSightingRelationship';
import { RELATION_GRANTED_TO, RELATION_OBJECT_MARKING } from '../../schema/stixRefRelationship';
import { isStixDomainObjectContainer } from '../../schema/stixDomainObject';
import { schemaAttributesDefinition } from '../../schema/schema-attributes';
import { schemaRelationsRefDefinition } from '../../schema/schema-relationsRef';
import type { AttributeDefinition, RefAttribute } from '../../schema/attribute-definition';
import { isUserCanAccessStoreElement, isUserHasCapabilities, SYSTEM_USER } from '../../utils/access';
import { now, utcDate } from '../../utils/format';
import moment from 'moment';
import { listRules } from '../retentionRules/retentionRules-domain';
import type { BasicStoreEntityRetentionRule } from '../retentionRules/retentionRules-types';
import { DefaultFormating } from '../../utils/humanize';
import { getDraftContext } from '../../utils/draftContext';
import type { AuthContext, AuthUser } from '../../types/user';
import type { BasicStoreCommon, BasicStoreEntity, BasicStoreObject, BasicStoreRelation } from '../../types/store';
import { OrderingMode } from '../../generated/graphql';
import { addTimeMachineAsOfCount, addTimeMachineDiffCount, addTimeMachineVisitCount } from '../../manager/telemetryManager';
import {
  changeFieldKey,
  CONTAINER_OBJECTS_KEY,
  containerObjectIdsAt,
  containerObjectsNetChanges,
  currentContainerObjectIds,
  diffDocuments,
  extractAttributeValues,
  firstNumber,
  flagReplayBeyondWindow,
  normalizeDocument,
  rebuildElementAt,
  replayBackward,
  replayForward,
  rewindAccessReferences,
} from './timeMachine-replay';
import {
  fetchElementChangeFieldHistoryEvents,
  fetchElementHistoryEvents,
  fetchElementsHistoryEvents,
  fetchOldestHistoryDate,
  fetchRelationshipsHistoryEvents,
  findHistoryWatermark,
  inclusiveEndDate,
  isChangeInHistory,
} from './timeMachine-history';
import { buildVisitElement, findSnapshotAtOrAfter, findSnapshotAtOrBefore, indexVisit, listSnapshotDates, loadUserVisits, deleteUserVisits } from './timeMachine-store';
import { countSinceReferenceDates } from './timeMachine-counters';
import { buildRelationshipStates, relationshipStateActions, TIME_MACHINE_RELATIONSHIP_TYPES } from './timeMachine-relationships';
import type {
  AttributeValues,
  BasicStoreEntityKnowledgeSnapshot,
  BasicStoreEntityUserVisit,
  ContainerObjectChange,
  RelationshipChange,
  ReplayResult,
  TimeMachineHistoryEvent,
} from './timeMachine-types';

export const MAX_REPLAY_EVENTS: number = conf.get('time_machine:max_replay_events') || 5000;
export const MAX_REPLAY_DAYS: number = conf.get('time_machine:max_replay_days') || 90;
const MAX_DIFF_RELATIONSHIPS: number = conf.get('time_machine:max_diff_relationships') || 500;
const VISIT_SESSION_MINUTES: number = conf.get('time_machine:visit_session_minutes') || 30;
// Visits recorded less than a minute apart are not written again
const VISIT_WRITE_DEBOUNCE_SECONDS = 60;
const MAX_TIMELINE_EVENTS = 200;
const MAX_TIMELINE_SNAPSHOTS = 100;
const CONTAINER_OBJECTS_COUNT_BATCH_SIZE = 1000;

const RESTRICTED_VALUE = 'Restricted';
const DELETED_VALUE = 'Deleted';
const RELATIONSHIP_HISTORY_TRUNCATED = 'RELATIONSHIP_HISTORY_TRUNCATED';
// The current document kept changing, or its last change is not searchable in the history yet: reading again later helps
const DOCUMENT_CHANGED_DURING_READ = 'DOCUMENT_CHANGED_DURING_READ';
const HISTORY_NOT_INDEXED_YET = 'HISTORY_NOT_INDEXED_YET';
const HISTORY_NOT_RETAINED = 'HISTORY_NOT_RETAINED';
const RELATIONSHIP_HISTORY_NOT_RETAINED = 'RELATIONSHIP_HISTORY_NOT_RETAINED';

// Display order of the most meaningful attributes, other attributes follow alphabetically
const ATTRIBUTES_ORDER = [
  'name',
  'value',
  'description',
  'aliases',
  'x_opencti_aliases',
  'confidence',
  'x_opencti_score',
  'revoked',
  'objectMarking',
  'createdBy',
  'objectLabel',
  'first_seen',
  'last_seen',
  'published',
  'killChainPhases',
  'externalReferences',
];

// region Types returned to GraphQL
export interface TimeMachineValue {
  raw: string;
  display: string;
  entity_type: string | null;
  deleted: boolean;
  restricted: boolean;
}

export interface TimeMachineAttribute {
  key: string;
  label: string;
  type: string;
  multiple: boolean;
  values: TimeMachineValue[];
}

export interface TimeMachineRelationshipCount {
  relationship_type: string;
  count: number;
}

export interface EntityAsOfResult {
  entity_id: string;
  entity_type: string;
  date: string;
  representative: string;
  exists: boolean;
  deleted: boolean;
  deleted_at: string | null;
  restricted: boolean;
  complete: boolean;
  warnings: string[];
  anchor: 'current' | 'snapshot';
  anchor_date: string;
  replayed_events: number;
  history_start: string | null;
  attributes: TimeMachineAttribute[];
  relationships: TimeMachineRelationshipCount[];
  relationships_total: number;
  container_objects_count: number | null;
}

export interface EntityDiffAttributeChange {
  key: string;
  label: string;
  type: string;
  multiple: boolean;
  before: TimeMachineValue[];
  after: TimeMachineValue[];
  added: TimeMachineValue[];
  removed: TimeMachineValue[];
  changed_at: string | null;
  changed_by: string | null;
  changes_count: number;
}

export interface EntityDiffSummary {
  attributes_changed: number;
  relationships_added: number;
  relationships_removed: number;
  relationships_revoked: number;
  relationships_confidence_changed: number;
  container_objects_added: number;
  container_objects_removed: number;
  confidence_before: number | null;
  confidence_after: number | null;
  score_before: number | null;
  score_after: number | null;
  relationships_added_by_type: TimeMachineRelationshipCount[];
  relationships_removed_by_type: TimeMachineRelationshipCount[];
}

export interface EntityDiffResult {
  entity_id: string;
  entity_type: string;
  representative: string;
  from: string;
  to: string;
  existed_at_from: boolean;
  exists_at_to: boolean;
  restricted: boolean;
  complete: boolean;
  warnings: string[];
  summary: EntityDiffSummary;
  attributes: EntityDiffAttributeChange[];
  relationships: RelationshipChange[];
  relationships_truncated: boolean;
  container_objects: ContainerObjectChange[];
  container_objects_truncated: boolean;
}

export interface TimeMachineTimeline {
  entity_id: string;
  created_at: string | null;
  history_start: string | null;
  events: Array<{ date: string; event_scope: string }>;
  // More changes than the events returned: only the most recent ones are listed
  events_truncated: boolean;
  snapshots: string[];
  max_replay_days: number;
}

export interface SinceLastVisit {
  entity_id: string;
  first_visit: boolean;
  reference_date: string | null;
  last_seen_at: string | null;
  new_relationships: number;
  updates: number;
  new_container_objects: number;
}
// endregion

// region Helpers
const normalizeDate = (value: Date | string, field: string): string => {
  const date = utcDate(value);
  if (!date.isValid()) {
    throw ValidationError('Invalid date', field, { value: String(value) });
  }
  // The time machine never looks into the future
  return date.isAfter(utcDate()) ? now() : date.toISOString();
};

const resolveDefinition = (entityType: string, key: string): AttributeDefinition | RefAttribute | null => {
  return schemaAttributesDefinition.getAttribute(entityType, key) ?? schemaRelationsRefDefinition.getRelationRef(entityType, key);
};

const refNameForDatabaseName = (entityType: string, databaseName: string): string | null => {
  const ref = schemaRelationsRefDefinition.getRelationsRef(entityType).find((r) => r.databaseName === databaseName);
  return ref?.name ?? null;
};

const isIdDefinition = (definition: AttributeDefinition | RefAttribute | null) => {
  if (!definition) return false;
  return definition.type === 'ref' || (definition.type === 'string' && definition.format === 'id');
};

/**
 * The time machine only opens elements the user can access today: restricting an element (markings,
 * organization sharing) must also restrict its past states. The state at the requested date is then
 * checked as well (isAsOfDocumentAccessible), so access requires both.
 */
export const loadAccessibleElement = async (context: AuthContext, user: AuthUser, id: string) => {
  return internalLoadById<BasicStoreEntity>(context, user, id, { type: ABSTRACT_STIX_CORE_OBJECT });
};

const loadUserNames = async (context: AuthContext): Promise<Map<string, string>> => {
  const users = await getEntitiesMapFromCache<BasicStoreEntity>(context, SYSTEM_USER, ENTITY_TYPE_USER);
  const names = new Map<string, string>();
  users.forEach((u, key) => names.set(key, u.name));
  return names;
};

/**
 * Resolve the given ids for the user. Ids the user cannot access are flagged restricted
 * (their name and id are never returned), ids that no longer exist are flagged deleted (tombstones).
 */
export const resolveIdsForUser = async (context: AuthContext, user: AuthUser, ids: string[]) => {
  const uniqueIds = [...new Set(ids.filter((id) => !!id))];
  const resolved = new Map<string, { name: string; entity_type: string | null; deleted: boolean; restricted: boolean }>();
  if (uniqueIds.length === 0) return resolved;
  const accessible = await internalFindByIdsMapped<BasicStoreObject>(context, user, uniqueIds);
  const missing = uniqueIds.filter((id) => !accessible[id]);
  const existing = missing.length > 0 ? await internalFindByIdsMapped<BasicStoreObject>(context, SYSTEM_USER, missing, { baseData: true }) : {};
  for (let index = 0; index < uniqueIds.length; index += 1) {
    const id = uniqueIds[index];
    const element = accessible[id];
    if (element) {
      resolved.set(id, { name: extractEntityRepresentativeName(element), entity_type: element.entity_type, deleted: false, restricted: false });
    } else if (existing[id]) {
      resolved.set(id, { name: RESTRICTED_VALUE, entity_type: null, deleted: false, restricted: true });
    } else {
      resolved.set(id, { name: DELETED_VALUE, entity_type: null, deleted: true, restricted: false });
    }
  }
  return resolved;
};

const humanizeScalar = (definition: AttributeDefinition | RefAttribute | null, raw: string): string => {
  if (!definition) return raw;
  if (definition.type === 'boolean') return raw.toLowerCase() === 'true' ? 'true' : 'false';
  if (definition.type === 'object') {
    try {
      const parsed = JSON.parse(raw);
      return definition.representative?.(parsed, {}, DefaultFormating) ?? raw;
    } catch {
      return raw;
    }
  }
  return raw;
};

/**
 * Turn raw attribute values into displayable values with the current rights of the user.
 */
export const humanizeAttributeValues = async (
  context: AuthContext,
  user: AuthUser,
  entityType: string,
  documents: AttributeValues[],
): Promise<(key: string, raws: string[]) => TimeMachineValue[]> => {
  const idsToResolve: string[] = [];
  documents.forEach((document) => {
    Object.entries(document).forEach(([key, raws]) => {
      if (isIdDefinition(resolveDefinition(entityType, key))) idsToResolve.push(...raws);
    });
  });
  const resolved = await resolveIdsForUser(context, user, idsToResolve);
  return (key: string, raws: string[]) => {
    const definition = resolveDefinition(entityType, key);
    return raws.map((raw) => {
      if (isIdDefinition(definition)) {
        const info = resolved.get(raw);
        if (!info || info.restricted) {
          return { raw: '', display: RESTRICTED_VALUE, entity_type: null, deleted: false, restricted: true };
        }
        return { raw, display: info.name, entity_type: info.entity_type, deleted: info.deleted, restricted: false };
      }
      return { raw, display: humanizeScalar(definition, raw), entity_type: null, deleted: false, restricted: false };
    });
  };
};

const orderAttributeKeys = (keys: string[], entityType: string) => {
  return [...keys].sort((a, b) => {
    const indexA = ATTRIBUTES_ORDER.indexOf(a);
    const indexB = ATTRIBUTES_ORDER.indexOf(b);
    if (indexA >= 0 || indexB >= 0) {
      if (indexA < 0) return 1;
      if (indexB < 0) return -1;
      return indexA - indexB;
    }
    const labelA = resolveDefinition(entityType, a)?.label ?? a;
    const labelB = resolveDefinition(entityType, b)?.label ?? b;
    return labelA.localeCompare(labelB);
  });
};

/**
 * Documents are rebuilt from the history read as the system: attributes protected by capabilities
 * (removed from the history of users without them) are removed the same way before being returned.
 */
const visibleDocument = (user: AuthUser, entityType: string, document: AttributeValues): AttributeValues => {
  const visible: AttributeValues = {};
  Object.entries(document).forEach(([key, values]) => {
    if (isUserHasCapabilities(user, resolveDefinition(entityType, key)?.requiredCapabilities)) {
      visible[key] = values;
    }
  });
  return visible;
};

const definitionInfo = (entityType: string, key: string) => {
  const definition = resolveDefinition(entityType, key);
  return {
    label: definition?.label ?? key,
    type: definition?.type ?? 'string',
    multiple: definition?.multiple ?? false,
  };
};

const accessReferenceKeys = (entityType: string) => ({
  marking: refNameForDatabaseName(entityType, RELATION_OBJECT_MARKING),
  granted: refNameForDatabaseName(entityType, RELATION_GRANTED_TO),
});

// Change fields of the access references for every type, so a change recorded under another type is not missed
const accessChangeFields = (keys: { marking: string | null; granted: string | null }) => {
  const names = [keys.marking, keys.granted].filter((name): name is string => !!name);
  return schemaRelationsRefDefinition.getRegisteredTypes().flatMap((type) => names
    .filter((name) => !!schemaRelationsRefDefinition.getRelationRef(type, name))
    .map((name) => `${type}--${name}`));
};

/**
 * Access references of the element at `date` for the access check. A complete replay holds them exactly
 * (`exactDocument`); a replay that stopped early (window exceeded, merge) only reached an intermediate state, so
 * they are rewound from the current element with their own changes. Null when these changes exceed the replay
 * window: the access at that date cannot be established and no historical data is returned.
 */
const accessDocumentAt = async (context: AuthContext, element: BasicStoreEntity, date: string, exactDocument: AttributeValues | null) => {
  if (exactDocument) return exactDocument;
  const keys = accessReferenceKeys(element.entity_type);
  const [changes, merges] = await Promise.all([
    fetchElementChangeFieldHistoryEvents(context, SYSTEM_USER, element.internal_id, accessChangeFields(keys), { from: date, scopes: ['update'], max: MAX_REPLAY_EVENTS + 1 }),
    fetchElementHistoryEvents(context, SYSTEM_USER, element.internal_id, { from: date, scopes: ['merge'], max: 1 }),
  ]);
  if (changes.length > MAX_REPLAY_EVENTS) return null;
  return rewindAccessReferences(extractAttributeValues(element as any), element.entity_type, [...changes, ...merges], date, keys);
};

/**
 * Whether the state of the element at `date`, its access included, can be established. A state not changed since
 * `date` is the current one. Otherwise the history must reach that date: a history retention rule purges the oldest
 * events first, so the history is whole while the creation is retained, and only since the oldest retained event
 * otherwise (a purged access change cannot be replayed).
 */
export const isStateEstablishedAt = async (context: AuthContext, element: BasicStoreEntity, date: string) => {
  if (element.updated_at && !utcDate(date).isBefore(utcDate(element.updated_at))) return true;
  const [oldest] = await fetchElementHistoryEvents(context, SYSTEM_USER, element.internal_id, { max: 1, order: 'asc' });
  if (!oldest) return false;
  return oldest.event_scope === 'create' || !utcDate(date).isBefore(utcDate(oldest.timestamp));
};

/**
 * The as-of view is only returned if the user could access the element with its markings
 * and organization sharing at that date (checked with the current rights of the user).
 */
const isAsOfDocumentAccessible = async (context: AuthContext, user: AuthUser, element: BasicStoreEntity, document: AttributeValues | null) => {
  if (!document) return false;
  const markingKey = refNameForDatabaseName(element.entity_type, RELATION_OBJECT_MARKING);
  const grantedKey = refNameForDatabaseName(element.entity_type, RELATION_GRANTED_TO);
  const asOfElement = {
    ...element,
    [RELATION_OBJECT_MARKING]: markingKey ? (document[markingKey] ?? []) : (element as any)[RELATION_OBJECT_MARKING],
    [RELATION_GRANTED_TO]: grantedKey ? (document[grantedKey] ?? []) : (element as any)[RELATION_GRANTED_TO],
  } as unknown as BasicStoreCommon;
  return isUserCanAccessStoreElement(context, user, asOfElement);
};
// endregion

// region Reconstruction
interface Reconstruction {
  replay: ReplayResult;
  anchor: 'current' | 'snapshot';
  anchorDate: string;
  // The snapshot used as anchor, null when the anchor is the current document
  anchorSnapshot: BasicStoreEntityKnowledgeSnapshot | null;
}

// Reads of the current document and of its history before the pair is used even if the document keeps changing
const MAX_CURRENT_ANCHOR_READS = 3;

interface CurrentAnchor {
  document: AttributeValues;
  anchorDate: string;
  events: TimeMachineHistoryEvent[];
  consistent: boolean;
  // The history read holds the last change of the document
  covered: boolean;
}

// A document changed after `date` is rewound only once the history event of its last change is searchable
const isLastChangeCovered = async (context: AuthContext, element: BasicStoreEntity, date: string, anchorDate: string, events: TimeMachineHistoryEvent[]) => {
  if (!element.updated_at || !utcDate(element.updated_at).isAfter(utcDate(date))) return true;
  if (isChangeInHistory(element.updated_at, events.map((event) => event.timestamp), null)) return true;
  return isChangeInHistory(element.updated_at, [], await findHistoryWatermark(context, anchorDate));
};

/**
 * The current document and its history events, read from one point in time. The history is read up to a date taken
 * after the document was loaded, then the document is loaded again: an update written in between would otherwise be
 * rewound on a document that does not contain it. When the document changed, both are read again from the new one.
 * The history is indexed asynchronously, so the pair is only covered once the history holds the last change.
 */
export const readCurrentAnchor = async (context: AuthContext, element: BasicStoreEntity, date: string, reads = 1): Promise<CurrentAnchor> => {
  const anchorDate = now();
  const events = await fetchElementHistoryEvents(context, SYSTEM_USER, element.internal_id, {
    from: date,
    to: anchorDate,
    max: MAX_REPLAY_EVENTS + 1,
  });
  const reloaded = await internalLoadById<BasicStoreEntity>(context, SYSTEM_USER, element.internal_id, { type: ABSTRACT_STIX_CORE_OBJECT });
  const consistent = !reloaded || String(reloaded.updated_at) === String(element.updated_at);
  if (consistent || reads >= MAX_CURRENT_ANCHOR_READS) {
    const covered = await isLastChangeCovered(context, element, date, anchorDate, events);
    return { document: extractAttributeValues(element as any), anchorDate, events, consistent, covered };
  }
  return readCurrentAnchor(context, reloaded, date, reads + 1);
};

/**
 * Reconstruct the attributes of an element at `date`.
 * The anchor is the closest known state: the snapshot taken at or after `date` (or the current
 * document), rewound with reverse patches, or the snapshot taken before `date` moved forward
 * when it is closer and no merge happened in between. History is read as the system so the
 * reconstruction is exact; access to the result is checked by the callers.
 */
export const reconstructAt = async (context: AuthContext, element: BasicStoreEntity, date: string): Promise<Reconstruction> => {
  const currentDate = now();
  const after = await findSnapshotAtOrAfter(context, element.internal_id, date);
  const before = await findSnapshotAtOrBefore(context, element.internal_id, date);
  const backwardAnchorDate = after ? after.history_cursor : currentDate;
  const useForward = before && utcDate(date).diff(utcDate(before.history_cursor)) < utcDate(backwardAnchorDate).diff(utcDate(date));
  if (useForward && before) {
    const events = await fetchElementHistoryEvents(context, SYSTEM_USER, element.internal_id, {
      from: before.history_cursor,
      to: date,
      max: MAX_REPLAY_EVENTS + 1,
      order: 'asc',
    });
    // A merge cannot be replayed forward; the rewind from the newer anchor does not cross a merge made before `date`
    if (!events.some((event) => event.event_scope === 'merge')) {
      const beforeDocument = normalizeDocument(element.entity_type, before.snapshot_document.attributes);
      const replay = replayForward(beforeDocument, element.entity_type, events, before.history_cursor, date, MAX_REPLAY_EVENTS);
      flagReplayBeyondWindow(replay, before.history_cursor, date, MAX_REPLAY_DAYS);
      return {
        replay,
        anchor: 'snapshot',
        anchorDate: before.history_cursor,
        anchorSnapshot: before,
      };
    }
  }
  if (after) {
    const anchorDocument = normalizeDocument(element.entity_type, after.snapshot_document.attributes);
    const events = await fetchElementHistoryEvents(context, SYSTEM_USER, element.internal_id, {
      from: date,
      to: after.history_cursor,
      max: MAX_REPLAY_EVENTS + 1,
    });
    const replay = replayBackward(anchorDocument, element.entity_type, events, date, MAX_REPLAY_EVENTS);
    flagReplayBeyondWindow(replay, after.history_cursor, date, MAX_REPLAY_DAYS);
    return { replay, anchor: 'snapshot', anchorDate: after.history_cursor, anchorSnapshot: after };
  }
  const current = await readCurrentAnchor(context, element, date);
  const replay = replayBackward(current.document, element.entity_type, current.events, date, MAX_REPLAY_EVENTS);
  if (!current.consistent) {
    replay.complete = false;
    replay.warnings.push(DOCUMENT_CHANGED_DURING_READ);
  }
  if (!current.covered) {
    replay.complete = false;
    replay.warnings.push(HISTORY_NOT_INDEXED_YET);
  }
  flagReplayBeyondWindow(replay, current.anchorDate, date, MAX_REPLAY_DAYS);
  return { replay, anchor: 'current', anchorDate: current.anchorDate, anchorSnapshot: null };
};

// Relationships of an element by type, optionally restricted to the ones created after `startDate` or up to `endDate`
export const countRelationshipsByType = async (
  context: AuthContext,
  user: AuthUser,
  elementId: string,
  range: { startDate?: string; endDate?: string } = {},
) => {
  const args = buildRelationsFilter([ABSTRACT_STIX_CORE_RELATIONSHIP, STIX_SIGHTING_RELATIONSHIP], { fromOrToId: elementId });
  const buckets = await elAggregationCount(context, user, READ_RELATIONSHIPS_INDICES_WITHOUT_INFERRED, {
    ...args,
    field: 'entity_type',
    convertEntityTypeLabel: true,
    ...(range.startDate || range.endDate ? { startDate: range.startDate, endDate: range.endDate, dateAttribute: 'created_at' } : {}),
  } as any);
  const counts = new Map<string, number>();
  buckets.forEach((bucket) => counts.set(bucket.label, bucket.count));
  return counts;
};

const toSortedCounts = (byType: Map<string, number>): TimeMachineRelationshipCount[] => [...byType.entries()]
  .filter(([, count]) => count > 0)
  .map(([relationship_type, count]) => ({ relationship_type, count }))
  .sort((a, b) => b.count - a.count);

/**
 * Relationship counts at `date` from a snapshot whose relationship lists are complete: its relationship set is moved
 * to the date with the creations and deletions between the two only, read with the rights of the user, then counted
 * with the current rights of the user - the relationships deleted since only through the deletions the user can see.
 * Null when a list of the snapshot is capped: its relationship set is not fully known.
 */
const relationshipCountsFromSnapshot = async (context: AuthContext, user: AuthUser, elementId: string, date: string, snapshot: BasicStoreEntityKnowledgeSnapshot) => {
  const { relationships, relationships_count: snapshotCounts } = snapshot.snapshot_document;
  if (Object.entries(snapshotCounts).some(([type, count]) => (relationships[type]?.length ?? 0) < count)) return null;
  const anchorDate = snapshot.history_cursor;
  const forward = utcDate(anchorDate).isBefore(utcDate(date));
  const fetchedEvents = await fetchRelationshipsHistoryEvents(context, user, [elementId], {
    from: forward ? anchorDate : date,
    to: forward ? date : anchorDate,
    scopes: ['create', 'delete'],
    entityTypes: TIME_MACHINE_RELATIONSHIP_TYPES,
    max: MAX_REPLAY_EVENTS + 1,
  });
  const complete = fetchedEvents.length <= MAX_REPLAY_EVENTS;
  const events = fetchedEvents.slice(0, MAX_REPLAY_EVENTS);
  const types = new Map<string, string>();
  Object.entries(relationships).forEach(([type, ids]) => ids.forEach((id) => types.set(id, type)));
  events.forEach((event) => types.set(event.context_id, event.context_entity_type));
  const created = new Set(events.filter((event) => event.event_scope === 'create').map((event) => event.context_id));
  const deleted = events.filter((event) => event.event_scope === 'delete').map((event) => event.context_id);
  const atDate = new Set(Object.values(relationships).flat());
  if (forward) {
    created.forEach((id) => atDate.add(id));
    deleted.forEach((id) => atDate.delete(id));
  } else {
    created.forEach((id) => atDate.delete(id));
    deleted.filter((id) => !created.has(id)).forEach((id) => atDate.add(id));
  }
  const ids = [...atDate];
  const present = ids.length > 0
    ? await internalFindByIdsMapped<BasicStoreObject>(context, user, ids, { baseData: true, indices: READ_RELATIONSHIPS_INDICES_WITHOUT_INFERRED })
    : {};
  const missing = ids.filter((id) => !present[id]);
  const visibleDeletions = missing.length > 0 ? await fetchElementsHistoryEvents(context, user, missing, { scopes: ['delete'], max: missing.length }) : [];
  const countable = new Set([...ids.filter((id) => !!present[id]), ...visibleDeletions.map((event) => event.context_id)]);
  const byType = new Map<string, number>();
  countable.forEach((id) => {
    const type = types.get(id);
    if (type) byType.set(type, (byType.get(type) ?? 0) + 1);
  });
  return { counts: toSortedCounts(byType), complete, historyFrom: forward ? anchorDate : date };
};

/**
 * Oldest date the relationship history is still whole from: the most recent horizon of the active history retention
 * rules, a filtered rule included as it can purge relationship events. Null without any such rule.
 * Creating or deleting a relationship does not change its endpoints, so the history of an entity does not tell it.
 */
export const relationshipHistoryHorizon = async (context: AuthContext, currentDate: string = now()): Promise<string | null> => {
  const rules = await listRules(context, SYSTEM_USER) as BasicStoreEntityRetentionRule[];
  const horizons = rules
    .filter((rule) => rule.scope === 'history' && rule.active !== false && rule.max_retention > 0)
    .map((rule) => utcDate(currentDate).subtract(rule.max_retention, (rule.retention_unit ?? 'days') as moment.unitOfTime.DurationConstructor));
  return horizons.length > 0 ? moment.max(horizons).toISOString() : null;
};

const isRelationshipHistoryRetainedFrom = (horizon: string | null, historyFrom: string) => !horizon || !utcDate(historyFrom).isBefore(utcDate(horizon));

const relationshipCountsAt = async (context: AuthContext, user: AuthUser, elementId: string, date: string, anchorSnapshot: BasicStoreEntityKnowledgeSnapshot | null) => {
  const fromSnapshot = anchorSnapshot ? await relationshipCountsFromSnapshot(context, user, elementId, date, anchorSnapshot) : null;
  if (fromSnapshot) return fromSnapshot;
  const [current, createdAfter, fetchedEvents] = await Promise.all([
    countRelationshipsByType(context, user, elementId),
    countRelationshipsByType(context, user, elementId, { startDate: date }),
    fetchRelationshipsHistoryEvents(context, user, [elementId], {
      from: date,
      scopes: ['create', 'delete'],
      entityTypes: TIME_MACHINE_RELATIONSHIP_TYPES,
      max: MAX_REPLAY_EVENTS + 1,
    }),
  ]);
  // One extra event is read to detect that the relationship history of the period is incomplete
  const complete = fetchedEvents.length <= MAX_REPLAY_EVENTS;
  const events = fetchedEvents.slice(0, MAX_REPLAY_EVENTS);
  const createdAfterIds = new Set(events.filter((e) => e.event_scope === 'create').map((e) => e.context_id));
  const deletedExistingAtDate = new Map<string, number>();
  events.filter((e) => e.event_scope === 'delete' && !createdAfterIds.has(e.context_id)).forEach((e) => {
    deletedExistingAtDate.set(e.context_entity_type, (deletedExistingAtDate.get(e.context_entity_type) ?? 0) + 1);
  });
  const types = new Set([...current.keys(), ...deletedExistingAtDate.keys()]);
  const byType = new Map<string, number>();
  types.forEach((type) => {
    byType.set(type, (current.get(type) ?? 0) - (createdAfter.get(type) ?? 0) + (deletedExistingAtDate.get(type) ?? 0));
  });
  return { counts: toSortedCounts(byType), complete, historyFrom: date };
};

// Change fields of the contained objects for every container type, so a change recorded under another type is not missed
const containerObjectsChangeFields = () => schemaRelationsRefDefinition.getRegisteredTypes()
  .filter((type) => !!schemaRelationsRefDefinition.getRelationRef(type, CONTAINER_OBJECTS_KEY))
  .map((type) => `${type}--${CONTAINER_OBJECTS_KEY}`);

/**
 * Number of objects of a container at `date` that the user can access: its current objects rewound with the
 * `objects` changes since that date, counted with the rights of the user. Null when these changes exceed the
 * replay window: the objects of that date cannot be established.
 */
const accessibleContainerObjectsCountAt = async (context: AuthContext, user: AuthUser, element: BasicStoreEntity, date: string) => {
  const changes = await fetchElementChangeFieldHistoryEvents(context, SYSTEM_USER, element.internal_id, containerObjectsChangeFields(), {
    from: date,
    scopes: ['update'],
    max: MAX_REPLAY_EVENTS + 1,
  });
  if (changes.length > MAX_REPLAY_EVENTS) return null;
  // The changes made at the requested date are part of the state at that date
  const since = changes.filter((event) => utcDate(event.timestamp).isAfter(utcDate(date)));
  const ids = containerObjectIdsAt(currentContainerObjectIds(element as any), since);
  let count = 0;
  for (let index = 0; index < ids.length; index += CONTAINER_OBJECTS_COUNT_BATCH_SIZE) {
    count += await elCount(context, user, READ_DATA_INDICES_WITHOUT_INTERNAL, { ids: ids.slice(index, index + CONTAINER_OBJECTS_COUNT_BATCH_SIZE) });
  }
  return count;
};

// endregion

// region As of
export const entityAsOf = async (context: AuthContext, user: AuthUser, id: string, dateInput: Date | string): Promise<EntityAsOfResult> => {
  const date = normalizeDate(dateInput, 'date');
  const element = await loadAccessibleElement(context, user, id);
  if (!element) {
    // Deleted elements are only returned as tombstones, from the history the user can see
    const [deletion] = await fetchElementHistoryEvents(context, user, id, { scopes: ['delete'], max: 1 });
    if (!deletion) {
      throw FunctionalError('Element not found', { id });
    }
    return {
      entity_id: id,
      entity_type: deletion.context_entity_type,
      date,
      representative: deletion.context_entity_name,
      exists: false,
      deleted: true,
      deleted_at: deletion.timestamp,
      restricted: false,
      complete: true,
      warnings: [],
      anchor: 'current',
      anchor_date: deletion.timestamp,
      replayed_events: 0,
      history_start: null,
      attributes: [],
      relationships: [],
      relationships_total: 0,
      container_objects_count: null,
    };
  }
  const { replay, anchor, anchorDate, anchorSnapshot } = await reconstructAt(context, element, date);
  const historyStart = await fetchOldestHistoryDate(context, user, element.internal_id);
  const base = {
    entity_id: element.internal_id,
    entity_type: element.entity_type,
    date,
    deleted: false,
    deleted_at: null,
    complete: replay.complete,
    warnings: replay.warnings,
    anchor,
    anchor_date: anchorDate,
    replayed_events: replay.replayedEvents,
    history_start: historyStart,
  };
  const createdBeforeDate = !element.created_at || !utcDate(element.created_at).isAfter(utcDate(date));
  const exists = replay.exists && createdBeforeDate;
  if (!exists) {
    return {
      ...base,
      representative: extractEntityRepresentativeName(element),
      exists: false,
      restricted: false,
      attributes: [],
      relationships: [],
      relationships_total: 0,
      container_objects_count: null,
    };
  }
  const established = await isStateEstablishedAt(context, element, date);
  const accessDocument = established ? await accessDocumentAt(context, element, date, replay.complete ? replay.document : null) : null;
  const accessible = await isAsOfDocumentAccessible(context, user, element, accessDocument);
  if (!accessible) {
    return {
      ...base,
      representative: RESTRICTED_VALUE,
      exists: true,
      restricted: true,
      warnings: established ? base.warnings : [...base.warnings, HISTORY_NOT_RETAINED],
      attributes: [],
      relationships: [],
      relationships_total: 0,
      container_objects_count: null,
    };
  }
  const document = visibleDocument(user, element.entity_type, replay.document);
  const humanize = await humanizeAttributeValues(context, user, element.entity_type, [document]);
  const attributes = orderAttributeKeys(Object.keys(document), element.entity_type).map((key) => ({
    key,
    ...definitionInfo(element.entity_type, key),
    values: humanize(key, document[key]),
  }));
  const [relationshipCounts, horizon] = await Promise.all([
    relationshipCountsAt(context, user, element.internal_id, date, anchorSnapshot),
    relationshipHistoryHorizon(context),
  ]);
  const { counts: relationships, historyFrom } = relationshipCounts;
  const relationshipsRetained = isRelationshipHistoryRetainedFrom(horizon, historyFrom);
  const relationshipsComplete = relationshipCounts.complete && relationshipsRetained;
  const warnings = [
    ...base.warnings,
    ...(relationshipCounts.complete ? [] : [RELATIONSHIP_HISTORY_TRUNCATED]),
    ...(relationshipsRetained ? [] : [RELATIONSHIP_HISTORY_NOT_RETAINED]),
  ];
  const containerObjectsCount = isStixDomainObjectContainer(element.entity_type) ? await accessibleContainerObjectsCountAt(context, user, element, date) : null;
  const representative = extractEntityRepresentativeName(rebuildElementAt(element, replay.document));
  addTimeMachineAsOfCount();
  return {
    ...base,
    complete: base.complete && relationshipsComplete,
    warnings,
    representative,
    exists: true,
    restricted: false,
    attributes,
    relationships,
    relationships_total: relationships.reduce((total, r) => total + r.count, 0),
    container_objects_count: containerObjectsCount,
  };
};
// endregion

// region Diff
/**
 * Relationships that still exist but that the user cannot access today. The history events are authorized with the
 * access they had when they were recorded: a relationship restricted since then is left out of what they tell.
 * A relationship deleted since keeps the access rule of its history.
 */
export const relationshipsRestrictedToUser = async (context: AuthContext, user: AuthUser, ids: string[]) => {
  const uniqueIds = [...new Set(ids.filter((id) => !!id))];
  if (uniqueIds.length === 0) return new Set<string>();
  const opts = { baseData: true, indices: READ_RELATIONSHIPS_INDICES_WITHOUT_INFERRED };
  const existing = await internalFindByIdsMapped<BasicStoreObject>(context, SYSTEM_USER, uniqueIds, opts);
  const existingIds = uniqueIds.filter((id) => !!existing[id]);
  const accessible = existingIds.length > 0 ? await internalFindByIdsMapped<BasicStoreObject>(context, user, existingIds, opts) : {};
  return new Set(existingIds.filter((id) => !accessible[id]));
};

const countByType = (changes: RelationshipChange[], action: RelationshipChange['action']) => {
  const counts = new Map<string, number>();
  changes.filter((c) => c.action === action).forEach((c) => counts.set(c.relationship_type, (counts.get(c.relationship_type) ?? 0) + 1));
  return [...counts.entries()].map(([relationship_type, count]) => ({ relationship_type, count })).sort((a, b) => b.count - a.count);
};

export const computeRelationshipChanges = async (
  context: AuthContext,
  user: AuthUser,
  elementId: string,
  from: string,
  to: string,
  userNames: Map<string, string>,
) => {
  const filterArgs = buildRelationsFilter([ABSTRACT_STIX_CORE_RELATIONSHIP, STIX_SIGHTING_RELATIONSHIP], { fromOrToId: elementId });
  const createdArgs = {
    ...filterArgs,
    indices: READ_RELATIONSHIPS_INDICES_WITHOUT_INFERRED,
    startDate: from,
    endDate: inclusiveEndDate(to),
    dateAttribute: 'created_at',
  };
  const [createdTotal, createdRelations, fetchedEvents] = await Promise.all([
    elCount(context, user, READ_RELATIONSHIPS_INDICES_WITHOUT_INFERRED, createdArgs as any),
    topRelationsList<any>(context, user, [ABSTRACT_STIX_CORE_RELATIONSHIP, STIX_SIGHTING_RELATIONSHIP], {
      fromOrToId: elementId,
      indices: READ_RELATIONSHIPS_INDICES_WITHOUT_INFERRED,
      first: MAX_DIFF_RELATIONSHIPS,
      orderBy: 'created_at',
      orderMode: OrderingMode.Desc,
      startDate: from,
      endDate: inclusiveEndDate(to),
      dateAttribute: 'created_at',
    } as any),
    fetchRelationshipsHistoryEvents(context, user, [elementId], {
      from,
      to,
      scopes: ['create', 'delete', 'update'],
      entityTypes: TIME_MACHINE_RELATIONSHIP_TYPES,
      max: MAX_REPLAY_EVENTS + 1,
    }),
  ]);
  // One extra event is read to detect that the relationship history of the period is incomplete
  const eventsTruncated = fetchedEvents.length > MAX_REPLAY_EVENTS;
  const states = buildRelationshipStates(fetchedEvents.slice(0, MAX_REPLAY_EVENTS));
  const changes: RelationshipChange[] = [];
  // Relationships created in the period and still visible: the listed ones, then the ones beyond the listing cap, so
  // their later revocation and confidence changes are counted whatever the cap
  const addedIds = new Set<string>((createdRelations as BasicStoreRelation[]).map((relation) => relation.internal_id));
  const addedBeyondCap = [...states.entries()].filter(([id, state]) => state.created && !state.deleted && !addedIds.has(id)).map(([id]) => id);
  if (addedBeyondCap.length > 0) {
    const visible = await internalFindByIdsMapped<BasicStoreObject>(context, user, addedBeyondCap, { baseData: true, indices: READ_RELATIONSHIPS_INDICES_WITHOUT_INFERRED });
    addedBeyondCap.filter((id) => !!visible[id]).forEach((id) => addedIds.add(id));
  }
  const surviving = [...states.entries()].filter(([id, state]) => !state.deleted && !addedIds.has(id)).map(([id]) => id);
  const restricted = await relationshipsRestrictedToUser(context, user, surviving);
  restricted.forEach((id) => states.delete(id));
  (createdRelations as BasicStoreRelation[]).forEach((relation) => {
    const isSource = relation.fromId === elementId;
    changes.push({
      relationship_id: relation.internal_id,
      relationship_type: relation.entity_type,
      action: 'added',
      at: utcDate(relation.created_at).toISOString(),
      is_source: isSource,
      target_id: isSource ? relation.toId : relation.fromId,
      target_type: isSource ? relation.toType : relation.fromType,
      target_name: '',
      target_deleted: false,
      target_restricted: false,
      confidence_before: null,
      confidence_after: (relation as any).confidence ?? null,
      changed_by: (relation as any).creator_id?.[0] ? (userNames.get((relation as any).creator_id[0]) ?? null) : null,
    });
  });
  states.forEach((state, relationshipId) => {
    const isSource = state.from_id === elementId;
    const userName = (userId?: string) => (userId ? (userNames.get(userId) ?? null) : null);
    const base = {
      relationship_id: relationshipId,
      relationship_type: state.relationship_type,
      is_source: isSource,
      target_id: (isSource ? state.to_id : state.from_id) ?? null,
      target_type: null,
      target_name: state.name,
      target_deleted: false,
      target_restricted: false,
    };
    relationshipStateActions(state, addedIds.has(relationshipId)).forEach((action) => {
      if (action === 'removed') {
        changes.push({ ...base, action, at: state.deleted ?? to, confidence_before: null, confidence_after: null, changed_by: userName(state.deleted_by) });
      } else if (action === 'confidence_changed') {
        changes.push({
          ...base,
          action,
          at: state.confidence_at ?? to,
          confidence_before: state.confidence_before ?? null,
          confidence_after: state.confidence_after ?? null,
          changed_by: userName(state.confidence_by),
        });
      } else {
        changes.push({ ...base, action, at: state.revoked_at ?? to, confidence_before: null, confidence_after: null, changed_by: userName(state.revoked_by) });
      }
    });
  });
  // Resolve the targets with the current rights of the user, deleted targets are tombstones
  const resolved = await resolveIdsForUser(context, user, changes.map((c) => c.target_id ?? ''));
  changes.forEach((change) => {
    const info = change.target_id ? resolved.get(change.target_id) : undefined;
    if (!info) return;
    if (info.restricted) {
      Object.assign(change, { target_id: null, target_type: null, target_name: RESTRICTED_VALUE, target_restricted: true });
    } else if (info.deleted) {
      Object.assign(change, { target_deleted: true, target_name: info.name });
    } else {
      Object.assign(change, { target_name: info.name, target_type: info.entity_type ?? change.target_type });
    }
  });
  changes.sort((a, b) => utcDate(b.at).diff(utcDate(a.at)));
  const truncated = eventsTruncated || createdTotal > createdRelations.length || changes.length > MAX_DIFF_RELATIONSHIPS;
  return { changes: changes.slice(0, MAX_DIFF_RELATIONSHIPS), allChanges: changes, createdTotal, truncated, eventsTruncated };
};

export const entityDiff = async (context: AuthContext, user: AuthUser, id: string, fromInput: Date | string, toInput: Date | string): Promise<EntityDiffResult> => {
  const from = normalizeDate(fromInput, 'from');
  const to = normalizeDate(toInput, 'to');
  if (!utcDate(from).isBefore(utcDate(to))) {
    throw ValidationError('The start date must be before the end date', 'from', { from, to });
  }
  const element = await loadAccessibleElement(context, user, id);
  if (!element) {
    throw FunctionalError('Element not found', { id });
  }
  const existedAt = (date: string) => !element.created_at || !utcDate(element.created_at).isAfter(utcDate(date));
  const emptySummary: EntityDiffSummary = {
    attributes_changed: 0,
    relationships_added: 0,
    relationships_removed: 0,
    relationships_revoked: 0,
    relationships_confidence_changed: 0,
    container_objects_added: 0,
    container_objects_removed: 0,
    confidence_before: null,
    confidence_after: null,
    score_before: null,
    score_after: null,
    relationships_added_by_type: [],
    relationships_removed_by_type: [],
  };
  // One reconstruction at `to`, then rewind to `from` with the events of the period
  const atTo = await reconstructAt(context, element, to);
  if (!atTo.replay.exists || !existedAt(to)) {
    // The element did not exist yet at the end of the period: nothing changed during it
    return {
      entity_id: element.internal_id,
      entity_type: element.entity_type,
      representative: extractEntityRepresentativeName(element),
      from,
      to,
      existed_at_from: false,
      exists_at_to: false,
      restricted: false,
      complete: atTo.replay.complete,
      warnings: atTo.replay.warnings,
      summary: emptySummary,
      attributes: [],
      relationships: [],
      relationships_truncated: false,
      container_objects: [],
      container_objects_truncated: false,
    };
  }
  const periodEvents = await fetchElementHistoryEvents(context, SYSTEM_USER, element.internal_id, { from, to, max: MAX_REPLAY_EVENTS + 1 });
  const atFrom = replayBackward(atTo.replay.document, element.entity_type, periodEvents, from, MAX_REPLAY_EVENTS);
  const existedAtFrom = atFrom.exists && existedAt(from);
  const warnings = [...new Set([...atTo.replay.warnings, ...atFrom.warnings])];
  const complete = atTo.replay.complete && atFrom.complete;
  // The history must reach the start of the period, or the creation of an element created during it
  const periodStart = existedAt(from) || !element.created_at ? from : utcDate(element.created_at).toISOString();
  const established = await isStateEstablishedAt(context, element, periodStart);
  const [accessDocumentTo, accessDocumentFrom] = established ? await Promise.all([
    accessDocumentAt(context, element, to, atTo.replay.complete ? atTo.replay.document : null),
    existedAtFrom ? accessDocumentAt(context, element, from, atTo.replay.complete && atFrom.complete ? atFrom.document : null) : Promise.resolve(null),
  ]) : [null, null];
  const [accessibleTo, accessibleFrom] = await Promise.all([
    isAsOfDocumentAccessible(context, user, element, accessDocumentTo),
    existedAtFrom ? isAsOfDocumentAccessible(context, user, element, accessDocumentFrom) : Promise.resolve(true),
  ]);
  if (!accessibleTo || !accessibleFrom) {
    return {
      entity_id: element.internal_id,
      entity_type: element.entity_type,
      representative: RESTRICTED_VALUE,
      from,
      to,
      existed_at_from: existedAtFrom,
      exists_at_to: true,
      restricted: true,
      complete,
      warnings: established ? warnings : [...warnings, HISTORY_NOT_RETAINED],
      summary: emptySummary,
      attributes: [],
      relationships: [],
      relationships_truncated: false,
      container_objects: [],
      container_objects_truncated: false,
    };
  }
  const userNames = await loadUserNames(context);
  // Attributes
  const fromDocument = existedAtFrom ? visibleDocument(user, element.entity_type, atFrom.document) : {};
  const toDocument = visibleDocument(user, element.entity_type, atTo.replay.document);
  const deltas = diffDocuments(fromDocument, toDocument);
  const humanize = await humanizeAttributeValues(context, user, element.entity_type, [fromDocument, toDocument]);
  const lastChangeByKey = new Map<string, { at: string; user_id?: string; count: number }>();
  [...periodEvents].sort((a, b) => utcDate(a.timestamp).diff(utcDate(b.timestamp))).forEach((event) => {
    (event.changes ?? []).forEach((change) => {
      const key = changeFieldKey(change.field);
      const previous = lastChangeByKey.get(key);
      lastChangeByKey.set(key, { at: event.timestamp, user_id: event.user_id, count: (previous?.count ?? 0) + 1 });
    });
  });
  const orderedDeltas = orderAttributeKeys(deltas.map((d) => d.key), element.entity_type)
    .map((key) => deltas.find((d) => d.key === key))
    .filter((d): d is NonNullable<typeof d> => !!d);
  const attributes: EntityDiffAttributeChange[] = orderedDeltas.map((delta) => {
    const last = lastChangeByKey.get(delta.key);
    return {
      key: delta.key,
      ...definitionInfo(element.entity_type, delta.key),
      before: humanize(delta.key, delta.before),
      after: humanize(delta.key, delta.after),
      added: humanize(delta.key, delta.added),
      removed: humanize(delta.key, delta.removed),
      changed_at: last?.at ?? null,
      changed_by: last?.user_id ? (userNames.get(last.user_id) ?? null) : null,
      changes_count: last?.count ?? 0,
    };
  });
  // Relationships
  const [{ changes, allChanges, createdTotal, truncated, eventsTruncated }, horizon] = await Promise.all([
    computeRelationshipChanges(context, user, element.internal_id, from, to, userNames),
    relationshipHistoryHorizon(context),
  ]);
  const relationshipsRetained = isRelationshipHistoryRetainedFrom(horizon, from);
  const diffWarnings = [
    ...warnings,
    ...(eventsTruncated ? [RELATIONSHIP_HISTORY_TRUNCATED] : []),
    ...(relationshipsRetained ? [] : [RELATIONSHIP_HISTORY_NOT_RETAINED]),
  ];
  // Container objects
  let containerObjects: ContainerObjectChange[] = [];
  let containerAdded = 0;
  let containerRemoved = 0;
  if (isStixDomainObjectContainer(element.entity_type)) {
    const { added, removed } = containerObjectsNetChanges(periodEvents);
    containerAdded = added.size;
    containerRemoved = removed.size;
    const entries: Array<[string, string, 'added' | 'removed']> = [
      ...[...added.entries()].map(([objectId, at]) => [objectId, at, 'added'] as [string, string, 'added']),
      ...[...removed.entries()].map(([objectId, at]) => [objectId, at, 'removed'] as [string, string, 'removed']),
    ].slice(0, MAX_DIFF_RELATIONSHIPS);
    const resolved = await resolveIdsForUser(context, user, entries.map(([objectId]) => objectId));
    containerObjects = entries.map(([objectId, at, action]) => {
      const info = resolved.get(objectId);
      return {
        object_id: info?.restricted ? '' : objectId,
        object_type: info?.entity_type ?? null,
        object_name: info?.name ?? DELETED_VALUE,
        action,
        at,
        deleted: info?.deleted ?? true,
        restricted: info?.restricted ?? false,
      };
    });
  }
  const confidenceBefore = firstNumber(fromDocument.confidence);
  const confidenceAfter = firstNumber(toDocument.confidence);
  const scoreBefore = firstNumber(fromDocument.x_opencti_score);
  const scoreAfter = firstNumber(toDocument.x_opencti_score);
  const summary: EntityDiffSummary = {
    attributes_changed: attributes.length,
    relationships_added: createdTotal,
    relationships_removed: allChanges.filter((c) => c.action === 'removed').length,
    relationships_revoked: allChanges.filter((c) => c.action === 'revoked').length,
    relationships_confidence_changed: allChanges.filter((c) => c.action === 'confidence_changed').length,
    container_objects_added: containerAdded,
    container_objects_removed: containerRemoved,
    confidence_before: confidenceBefore,
    confidence_after: confidenceAfter,
    score_before: scoreBefore,
    score_after: scoreAfter,
    relationships_added_by_type: countByType(allChanges, 'added'),
    relationships_removed_by_type: countByType(allChanges, 'removed'),
  };
  addTimeMachineDiffCount();
  return {
    entity_id: element.internal_id,
    entity_type: element.entity_type,
    representative: extractEntityRepresentativeName(element),
    from,
    to,
    existed_at_from: existedAtFrom,
    exists_at_to: true,
    restricted: false,
    complete: complete && !eventsTruncated && relationshipsRetained,
    warnings: diffWarnings,
    summary,
    attributes,
    relationships: changes,
    relationships_truncated: truncated,
    container_objects: containerObjects,
    container_objects_truncated: containerAdded + containerRemoved > containerObjects.length,
  };
};
// endregion

// region Timeline
export const entityTimeMachineTimeline = async (context: AuthContext, user: AuthUser, id: string): Promise<TimeMachineTimeline> => {
  const element = await loadAccessibleElement(context, user, id);
  if (!element) {
    throw FunctionalError('Element not found', { id });
  }
  // One extra event is read to tell the slider that only the most recent changes are marked
  const [elementEvents, relationshipEvents, historyStart, snapshots] = await Promise.all([
    fetchElementHistoryEvents(context, user, element.internal_id, { max: MAX_TIMELINE_EVENTS + 1, scopes: ['create', 'update', 'merge'] }),
    // The relationships of the entity are part of its state at a date: their creations and deletions are changes too
    fetchRelationshipsHistoryEvents(context, user, [element.internal_id], {
      scopes: ['create', 'delete'],
      entityTypes: TIME_MACHINE_RELATIONSHIP_TYPES,
      max: MAX_TIMELINE_EVENTS + 1,
    }),
    fetchOldestHistoryDate(context, user, element.internal_id),
    listSnapshotDates(context, element.internal_id, MAX_TIMELINE_SNAPSHOTS),
  ]);
  const restricted = await relationshipsRestrictedToUser(context, user, relationshipEvents.map((event) => event.context_id));
  const fetchedEvents = [...elementEvents, ...relationshipEvents.filter((event) => !restricted.has(event.context_id))]
    .sort((a, b) => utcDate(b.timestamp).diff(utcDate(a.timestamp)));
  const events = fetchedEvents.slice(0, MAX_TIMELINE_EVENTS);
  return {
    entity_id: element.internal_id,
    created_at: element.created_at ? utcDate(element.created_at).toISOString() : null,
    history_start: historyStart,
    events: events.map((event) => ({ date: event.timestamp, event_scope: event.event_scope })),
    events_truncated: fetchedEvents.length > MAX_TIMELINE_EVENTS,
    snapshots,
    max_replay_days: MAX_REPLAY_DAYS,
  };
};
// endregion

// region Visits (new since your last visit)
const computeSinceLastVisit = async (
  context: AuthContext,
  user: AuthUser,
  elements: BasicStoreEntity[],
  visits: Map<string, BasicStoreEntityUserVisit>,
  reference: 'last_seen_at' | 'previous_seen_at',
): Promise<SinceLastVisit[]> => {
  const references = new Map<string, string>();
  elements.forEach((element) => {
    const visit = visits.get(element.internal_id);
    const referenceDate = visit?.[reference];
    if (referenceDate) references.set(element.internal_id, referenceDate);
  });
  const containerIds = elements.filter((e) => isStixDomainObjectContainer(e.entity_type)).map((e) => e.internal_id);
  const counters = await countSinceReferenceDates(context, user, references, new Set(containerIds));
  return elements.map((element) => {
    const visit = visits.get(element.internal_id);
    const referenceDate = references.get(element.internal_id) ?? null;
    const counter = counters.get(element.internal_id);
    return {
      entity_id: element.internal_id,
      first_visit: !referenceDate,
      reference_date: referenceDate,
      last_seen_at: visit?.last_seen_at ?? null,
      new_relationships: counter?.relationships ?? 0,
      updates: counter?.updates ?? 0,
      new_container_objects: counter?.containerObjects ?? 0,
    };
  });
};

export const recordEntityVisit = async (context: AuthContext, user: AuthUser, id: string): Promise<SinceLastVisit> => {
  const element = await loadAccessibleElement(context, user, id);
  if (!element) {
    throw FunctionalError('Element not found', { id });
  }
  const visits = await loadUserVisits(context, user.id, [element.internal_id]);
  const existing = visits.get(element.internal_id);
  const currentDate = now();
  const elapsedSeconds = existing ? utcDate(currentDate).diff(utcDate(existing.last_seen_at), 'seconds') : Number.POSITIVE_INFINITY;
  // Visits follow the main knowledge the markers are compared with: browsing a draft records none
  const isDraft = !!getDraftContext(context, user);
  let visit: BasicStoreEntityUserVisit | undefined = existing;
  if (!isDraft && !(existing && elapsedSeconds < VISIT_WRITE_DEBOUNCE_SECONDS)) {
    // A new visit session starts when the previous visit is older than the session duration:
    // the previous visit becomes the reference date of the "new since your last visit" counters.
    const isSameSession = existing && elapsedSeconds < VISIT_SESSION_MINUTES * 60;
    const previousSeenAt = isSameSession ? existing.previous_seen_at : existing?.last_seen_at;
    const document = buildVisitElement(user.id, element.internal_id, element.entity_type, currentDate, previousSeenAt, existing?.created_at
      ? utcDate(existing.created_at).toISOString() : currentDate);
    try {
      await indexVisit(document);
      addTimeMachineVisitCount();
    } catch (err) {
      // Non-fatal: the counters use the visit in memory and the next view records it again
      logApp.warn('[TIME MACHINE] Unable to record the visit', { cause: err, entity_id: element.internal_id });
    }
    visit = document as unknown as BasicStoreEntityUserVisit;
  }
  const [result] = await computeSinceLastVisit(context, user, [element], new Map(visit ? [[element.internal_id, visit]] : []), 'previous_seen_at');
  return result;
};

export const entitiesSinceLastVisit = async (context: AuthContext, user: AuthUser, ids: string[]): Promise<SinceLastVisit[]> => {
  const MAX_IDS = 100;
  if (ids.length > MAX_IDS) {
    throw ValidationError(`At most ${MAX_IDS} elements can be checked at once`, 'ids', { count: ids.length });
  }
  const uniqueIds = [...new Set(ids)];
  const accessible = await internalFindByIdsMapped<BasicStoreEntity>(context, user, uniqueIds, { type: ABSTRACT_STIX_CORE_OBJECT, baseData: true });
  const elements = uniqueIds.map((id) => accessible[id]).filter((element): element is BasicStoreEntity => !!element);
  const visits = await loadUserVisits(context, user.id, elements.map((e) => e.internal_id));
  return computeSinceLastVisit(context, user, elements, visits, 'last_seen_at');
};

export const purgeUserVisits = async (_context: AuthContext, user: AuthUser, userId?: string | null): Promise<number> => {
  const targetUserId = userId ?? user.id;
  return deleteUserVisits(targetUserId);
};
// endregion
