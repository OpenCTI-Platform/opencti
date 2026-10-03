import conf, { logApp } from '../../config/conf';
import { FunctionalError, ValidationError } from '../../config/errors';
import { elAggregationCount, elCount } from '../../database/engine';
import { buildRelationsFilter, internalFindByIdsMapped, internalLoadById, topRelationsList } from '../../database/middleware-loader';
import { extractEntityRepresentativeName } from '../../database/entity-representative';
import { getEntitiesMapFromCache } from '../../database/cache';
import { READ_RELATIONSHIPS_INDICES_WITHOUT_INFERRED } from '../../database/utils';
import { ABSTRACT_STIX_CORE_OBJECT, ABSTRACT_STIX_CORE_RELATIONSHIP } from '../../schema/general';
import { ENTITY_TYPE_USER } from '../../schema/internalObject';
import { STIX_SIGHTING_RELATIONSHIP } from '../../schema/stixSightingRelationship';
import { RELATION_GRANTED_TO, RELATION_OBJECT, RELATION_OBJECT_MARKING } from '../../schema/stixRefRelationship';
import { isStixDomainObjectContainer } from '../../schema/stixDomainObject';
import { schemaAttributesDefinition } from '../../schema/schema-attributes';
import { schemaRelationsRefDefinition } from '../../schema/schema-relationsRef';
import type { AttributeDefinition, RefAttribute } from '../../schema/attribute-definition';
import { isUserCanAccessStoreElement, SYSTEM_USER } from '../../utils/access';
import { now, utcDate } from '../../utils/format';
import { DefaultFormating } from '../../utils/humanize';
import type { AuthContext, AuthUser } from '../../types/user';
import type { BasicStoreCommon, BasicStoreEntity, BasicStoreObject, BasicStoreRelation } from '../../types/store';
import { OrderingMode } from '../../generated/graphql';
import { addTimeMachineAsOfCount, addTimeMachineDiffCount, addTimeMachineVisitCount } from '../../manager/telemetryManager';
import { CONTAINER_OBJECTS_KEY, changeFieldKey, diffDocuments, extractAttributeValues, firstNumber, replayBackward, replayForward } from './timeMachine-replay';
import { fetchElementHistoryEvents, fetchOldestHistoryDate, fetchRelationshipsHistoryEvents } from './timeMachine-history';
import { buildVisitElement, findSnapshotAtOrAfter, findSnapshotAtOrBefore, indexVisit, listSnapshotDates, loadUserVisits, deleteUserVisits } from './timeMachine-store';
import { countSinceReferenceDates } from './timeMachine-counters';
import { buildRelationshipStates, TIME_MACHINE_RELATIONSHIP_TYPES } from './timeMachine-relationships';
import type { AttributeValues, BasicStoreEntityUserVisit, ContainerObjectChange, RelationshipChange, ReplayResult, TimeMachineHistoryEvent } from './timeMachine-types';

export const MAX_REPLAY_EVENTS: number = conf.get('time_machine:max_replay_events') || 5000;
export const MAX_REPLAY_DAYS: number = conf.get('time_machine:max_replay_days') || 90;
const MAX_DIFF_RELATIONSHIPS: number = conf.get('time_machine:max_diff_relationships') || 500;
const VISIT_SESSION_MINUTES: number = conf.get('time_machine:visit_session_minutes') || 30;
// Visits recorded less than a minute apart are not written again
const VISIT_WRITE_DEBOUNCE_SECONDS = 60;
const MAX_TIMELINE_EVENTS = 200;
const MAX_TIMELINE_SNAPSHOTS = 100;

const RESTRICTED_VALUE = 'Restricted';
const DELETED_VALUE = 'Deleted';

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

const definitionInfo = (entityType: string, key: string) => {
  const definition = resolveDefinition(entityType, key);
  return {
    label: definition?.label ?? key,
    type: definition?.type ?? 'string',
    multiple: definition?.multiple ?? false,
  };
};

/**
 * The as-of view is only returned if the user could access the element with its markings
 * and organization sharing at that date (checked with the current rights of the user).
 */
const isAsOfDocumentAccessible = async (context: AuthContext, user: AuthUser, element: BasicStoreEntity, document: AttributeValues) => {
  const markingKey = refNameForDatabaseName(element.entity_type, RELATION_OBJECT_MARKING);
  const grantedKey = refNameForDatabaseName(element.entity_type, RELATION_GRANTED_TO);
  const asOfElement = {
    ...element,
    [RELATION_OBJECT_MARKING]: markingKey ? (document[markingKey] ?? []) : (element as any)[RELATION_OBJECT_MARKING],
    [RELATION_GRANTED_TO]: grantedKey && document[grantedKey] ? document[grantedKey] : (element as any)[RELATION_GRANTED_TO],
  } as unknown as BasicStoreCommon;
  return isUserCanAccessStoreElement(context, user, asOfElement);
};
// endregion

// region Reconstruction
interface Reconstruction {
  replay: ReplayResult;
  anchor: 'current' | 'snapshot';
  anchorDate: string;
  // Events of the element between the requested date and the anchor (system view, used for replay)
  events: TimeMachineHistoryEvent[];
}

/**
 * Reconstruct the attributes of an element at `date`.
 * The anchor is the closest known state: the snapshot taken at or after `date` (or the current
 * document), rewound with reverse patches, or the snapshot taken before `date` moved forward
 * when it is closer. History is read as the system so the reconstruction is exact; access to
 * the result is checked by the callers.
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
    const replay = replayForward(before.snapshot_document.attributes, element.entity_type, events, before.history_cursor, date, MAX_REPLAY_EVENTS);
    return { replay, anchor: 'snapshot', anchorDate: before.history_cursor, events };
  }
  const anchorDocument = after ? after.snapshot_document.attributes : extractAttributeValues(element as any);
  const events = await fetchElementHistoryEvents(context, SYSTEM_USER, element.internal_id, {
    from: date,
    to: backwardAnchorDate,
    max: MAX_REPLAY_EVENTS + 1,
  });
  const replay = replayBackward(anchorDocument, element.entity_type, events, date, MAX_REPLAY_EVENTS);
  if (utcDate(backwardAnchorDate).diff(utcDate(date), 'days') > MAX_REPLAY_DAYS && !replay.warnings.includes('REPLAY_BEYOND_WINDOW')) {
    replay.warnings.push('REPLAY_BEYOND_WINDOW');
  }
  return { replay, anchor: after ? 'snapshot' : 'current', anchorDate: backwardAnchorDate, events };
};

const countRelationshipsByType = async (context: AuthContext, user: AuthUser, elementId: string, startDate?: string) => {
  const args = buildRelationsFilter([ABSTRACT_STIX_CORE_RELATIONSHIP, STIX_SIGHTING_RELATIONSHIP], { fromOrToId: elementId });
  const buckets = await elAggregationCount(context, user, READ_RELATIONSHIPS_INDICES_WITHOUT_INFERRED, {
    ...args,
    field: 'entity_type',
    convertEntityTypeLabel: true,
    ...(startDate ? { startDate, dateAttribute: 'created_at' } : {}),
  } as any);
  const counts = new Map<string, number>();
  buckets.forEach((bucket) => counts.set(bucket.label, bucket.count));
  return counts;
};

const relationshipCountsAt = async (context: AuthContext, user: AuthUser, elementId: string, date: string) => {
  const [current, createdAfter, events] = await Promise.all([
    countRelationshipsByType(context, user, elementId),
    countRelationshipsByType(context, user, elementId, date),
    fetchRelationshipsHistoryEvents(context, user, [elementId], {
      from: date,
      scopes: ['create', 'delete'],
      entityTypes: TIME_MACHINE_RELATIONSHIP_TYPES,
      max: MAX_REPLAY_EVENTS,
    }),
  ]);
  const createdAfterIds = new Set(events.filter((e) => e.event_scope === 'create').map((e) => e.context_id));
  const deletedExistingAtDate = new Map<string, number>();
  events.filter((e) => e.event_scope === 'delete' && !createdAfterIds.has(e.context_id)).forEach((e) => {
    deletedExistingAtDate.set(e.context_entity_type, (deletedExistingAtDate.get(e.context_entity_type) ?? 0) + 1);
  });
  const types = new Set([...current.keys(), ...deletedExistingAtDate.keys()]);
  const counts: TimeMachineRelationshipCount[] = [];
  types.forEach((type) => {
    const count = (current.get(type) ?? 0) - (createdAfter.get(type) ?? 0) + (deletedExistingAtDate.get(type) ?? 0);
    if (count > 0) counts.push({ relationship_type: type, count });
  });
  return counts.sort((a, b) => b.count - a.count);
};

// Net additions and removals of container objects from the `objects` changes of the events
const containerObjectsNetChanges = (events: TimeMachineHistoryEvent[]) => {
  const added = new Map<string, string>();
  const removed = new Map<string, string>();
  const ascending = [...events].sort((a, b) => utcDate(a.timestamp).diff(utcDate(b.timestamp)));
  for (let index = 0; index < ascending.length; index += 1) {
    const event = ascending[index];
    if (event.event_scope === 'update') {
      const changes = (event.changes ?? []).filter((change) => changeFieldKey(change.field) === CONTAINER_OBJECTS_KEY);
      changes.forEach((change) => {
        (change.changes_added ?? []).forEach(({ raw }) => {
          if (removed.has(raw)) {
            removed.delete(raw);
          } else {
            added.set(raw, event.timestamp);
          }
        });
        (change.changes_removed ?? []).forEach(({ raw }) => {
          if (added.has(raw)) {
            added.delete(raw);
          } else {
            removed.set(raw, event.timestamp);
          }
        });
      });
    }
  }
  return { added, removed };
};

const currentContainerObjectsCount = (element: BasicStoreEntity) => {
  const objects = (element as any)[RELATION_OBJECT];
  return Array.isArray(objects) ? objects.length : 0;
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
  const { replay, anchor, anchorDate, events } = await reconstructAt(context, element, date);
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
  const accessible = await isAsOfDocumentAccessible(context, user, element, replay.document);
  if (!accessible) {
    return {
      ...base,
      representative: RESTRICTED_VALUE,
      exists: true,
      restricted: true,
      attributes: [],
      relationships: [],
      relationships_total: 0,
      container_objects_count: null,
    };
  }
  const humanize = await humanizeAttributeValues(context, user, element.entity_type, [replay.document]);
  const attributes = orderAttributeKeys(Object.keys(replay.document), element.entity_type).map((key) => ({
    key,
    ...definitionInfo(element.entity_type, key),
    values: humanize(key, replay.document[key]),
  }));
  const relationships = await relationshipCountsAt(context, user, element.internal_id, date);
  let containerObjectsCount: number | null = null;
  if (isStixDomainObjectContainer(element.entity_type)) {
    const afterDate = events.filter((event) => utcDate(event.timestamp).isAfter(utcDate(date)));
    const { added, removed } = containerObjectsNetChanges(afterDate);
    containerObjectsCount = anchor === 'current' ? Math.max(0, currentContainerObjectsCount(element) - added.size + removed.size) : null;
  }
  const nameKey = Object.prototype.hasOwnProperty.call(replay.document, 'name') ? 'name' : null;
  const representative = nameKey ? replay.document[nameKey][0] : extractEntityRepresentativeName(element);
  addTimeMachineAsOfCount();
  return {
    ...base,
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
    endDate: to,
    dateAttribute: 'created_at',
  };
  const [createdTotal, createdRelations, events] = await Promise.all([
    elCount(context, user, READ_RELATIONSHIPS_INDICES_WITHOUT_INFERRED, createdArgs as any),
    topRelationsList<any>(context, user, [ABSTRACT_STIX_CORE_RELATIONSHIP, STIX_SIGHTING_RELATIONSHIP], {
      fromOrToId: elementId,
      indices: READ_RELATIONSHIPS_INDICES_WITHOUT_INFERRED,
      first: MAX_DIFF_RELATIONSHIPS,
      orderBy: 'created_at',
      orderMode: OrderingMode.Desc,
      startDate: from,
      endDate: to,
      dateAttribute: 'created_at',
    } as any),
    fetchRelationshipsHistoryEvents(context, user, [elementId], {
      from,
      to,
      scopes: ['create', 'delete', 'update'],
      entityTypes: TIME_MACHINE_RELATIONSHIP_TYPES,
      max: MAX_REPLAY_EVENTS,
    }),
  ]);
  const states = buildRelationshipStates(events);
  const changes: RelationshipChange[] = [];
  const createdIds = new Set<string>();
  (createdRelations as BasicStoreRelation[]).forEach((relation) => {
    createdIds.add(relation.internal_id);
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
    if (createdIds.has(relationshipId) || (state.created && state.deleted)) {
      // Created in the period (already listed) or created and deleted in the period (no net change)
      return;
    }
    const isSource = state.from_id === elementId;
    const base = {
      relationship_id: relationshipId,
      relationship_type: state.relationship_type,
      is_source: isSource,
      target_id: (isSource ? state.to_id : state.from_id) ?? null,
      target_type: null,
      target_name: state.name,
      target_deleted: false,
      target_restricted: false,
      changed_by: state.user_id ? (userNames.get(state.user_id) ?? null) : null,
    };
    if (state.deleted) {
      changes.push({ ...base, action: 'removed', at: state.deleted, confidence_before: null, confidence_after: null });
      return;
    }
    if (state.created) {
      // Created in the period but not visible anymore in the knowledge for the user
      return;
    }
    if (state.revoked_after !== undefined && state.revoked_before !== state.revoked_after) {
      changes.push({
        ...base,
        action: state.revoked_after === 'true' ? 'revoked' : 'unrevoked',
        at: state.revoked_at ?? to,
        confidence_before: null,
        confidence_after: null,
      });
    }
    if (state.confidence_after !== undefined && state.confidence_before !== state.confidence_after) {
      changes.push({
        ...base,
        action: 'confidence_changed',
        at: state.confidence_at ?? to,
        confidence_before: state.confidence_before ?? null,
        confidence_after: state.confidence_after ?? null,
      });
    }
  });
  // Resolve the targets with the current rights of the user, deleted targets are tombstones
  const resolved = await resolveIdsForUser(context, user, changes.map((c) => c.target_id ?? ''));
  changes.forEach((change) => {
    const info = change.target_id ? resolved.get(change.target_id) : undefined;
    if (!info) return;
    if (info.restricted) {
      Object.assign(change, { target_id: null, target_type: null, target_name: RESTRICTED_VALUE, target_restricted: true });
    } else if (info.deleted) {
      Object.assign(change, { target_deleted: true, target_name: change.target_name || DELETED_VALUE });
    } else {
      Object.assign(change, { target_name: info.name, target_type: info.entity_type ?? change.target_type });
    }
  });
  changes.sort((a, b) => utcDate(b.at).diff(utcDate(a.at)));
  const truncated = createdTotal > createdRelations.length || changes.length > MAX_DIFF_RELATIONSHIPS;
  return { changes: changes.slice(0, MAX_DIFF_RELATIONSHIPS), allChanges: changes, createdTotal, truncated };
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
  // One reconstruction at `to`, then rewind to `from` with the events of the period
  const atTo = await reconstructAt(context, element, to);
  const periodEvents = await fetchElementHistoryEvents(context, SYSTEM_USER, element.internal_id, { from, to, max: MAX_REPLAY_EVENTS + 1 });
  const atFrom = replayBackward(atTo.replay.document, element.entity_type, periodEvents, from, MAX_REPLAY_EVENTS);
  const warnings = [...new Set([...atTo.replay.warnings, ...atFrom.warnings])];
  const complete = atTo.replay.complete && atFrom.complete;
  const [accessibleTo, accessibleFrom] = await Promise.all([
    isAsOfDocumentAccessible(context, user, element, atTo.replay.document),
    atFrom.exists ? isAsOfDocumentAccessible(context, user, element, atFrom.document) : Promise.resolve(true),
  ]);
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
  if (!accessibleTo || !accessibleFrom) {
    return {
      entity_id: element.internal_id,
      entity_type: element.entity_type,
      representative: RESTRICTED_VALUE,
      from,
      to,
      existed_at_from: atFrom.exists,
      restricted: true,
      complete,
      warnings,
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
  const fromDocument = atFrom.exists ? atFrom.document : {};
  const deltas = diffDocuments(fromDocument, atTo.replay.document);
  const humanize = await humanizeAttributeValues(context, user, element.entity_type, [fromDocument, atTo.replay.document]);
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
  const { changes, allChanges, createdTotal, truncated } = await computeRelationshipChanges(context, user, element.internal_id, from, to, userNames);
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
  const confidenceAfter = firstNumber(atTo.replay.document.confidence);
  const scoreBefore = firstNumber(fromDocument.x_opencti_score);
  const scoreAfter = firstNumber(atTo.replay.document.x_opencti_score);
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
    existed_at_from: atFrom.exists,
    restricted: false,
    complete,
    warnings,
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
  const [events, historyStart, snapshots] = await Promise.all([
    fetchElementHistoryEvents(context, user, element.internal_id, { max: MAX_TIMELINE_EVENTS, scopes: ['create', 'update', 'merge'] }),
    fetchOldestHistoryDate(context, user, element.internal_id),
    listSnapshotDates(context, element.internal_id, MAX_TIMELINE_SNAPSHOTS),
  ]);
  return {
    entity_id: element.internal_id,
    created_at: element.created_at ? utcDate(element.created_at).toISOString() : null,
    history_start: historyStart,
    events: events.map((event) => ({ date: event.timestamp, event_scope: event.event_scope })),
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
  let visit: BasicStoreEntityUserVisit;
  if (existing && elapsedSeconds < VISIT_WRITE_DEBOUNCE_SECONDS) {
    visit = existing;
  } else {
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
      logApp.error('[TIME MACHINE] Unable to record the visit', { cause: err, entity_id: element.internal_id });
    }
    visit = document as unknown as BasicStoreEntityUserVisit;
  }
  const [result] = await computeSinceLastVisit(context, user, [element], new Map([[element.internal_id, visit]]), 'previous_seen_at');
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
