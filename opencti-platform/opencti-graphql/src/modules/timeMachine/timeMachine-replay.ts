import * as jsonpatch from 'fast-json-patch';
import { schemaAttributesDefinition } from '../../schema/schema-attributes';
import { schemaRelationsRefDefinition } from '../../schema/schema-relationsRef';
import type { AttributeDefinition, RefAttribute } from '../../schema/attribute-definition';
import { FROM_START_STR, UNTIL_END_STR, utcDate } from '../../utils/format';
import { RELATION_OBJECT } from '../../schema/stixRefRelationship';
import type { AttributeDelta, AttributeValues, HistoryChange, ReplayResult, TimeMachineHistoryEvent } from './timeMachine-types';

// Attributes that are maintained by the platform itself and never describe the knowledge.
// They are excluded from as-of documents and diffs.
const TECHNICAL_ATTRIBUTES = new Set<string>([
  'id',
  'internal_id',
  'standard_id',
  'entity_type',
  'parent_types',
  'base_type',
  'x_opencti_stix_ids',
  'creator_id',
  'x_opencti_files',
  'metrics',
  'x_opencti_modified_at',
  'modified',
  'updated_at',
  'refreshed_at',
  'created_at',
  'lastEventId',
  'draft_ids',
  'draft_context',
  'draft_change',
  'x_opencti_graph_data',
  'x_opencti_inferences',
  'restricted_members',
  'authorized_authorities',
  'pir_information',
  'decay_history',
  'decay_applied_rule',
  'decay_next_reaction_date',
  'decay_base_score_date',
]);

// Container objects are reconstructed from the current objects and the history changes of the `objects`
// reference: they are not part of the replayed attributes nor of the compact documents.
export const CONTAINER_OBJECTS_KEY = 'objects';

export const isTimeMachineAttribute = (attribute: AttributeDefinition | RefAttribute): boolean => {
  if (TECHNICAL_ATTRIBUTES.has(attribute.name) || attribute.name.startsWith('i_')) {
    return false;
  }
  if (attribute.name === CONTAINER_OBJECTS_KEY || (attribute.type === 'ref' && attribute.databaseName === RELATION_OBJECT)) {
    return false;
  }
  if (attribute.type === 'object' && attribute.format === 'raw') {
    return false;
  }
  return true;
};

const resolveDefinition = (entityType: string, key: string): AttributeDefinition | RefAttribute | null => {
  const attribute = schemaAttributesDefinition.getAttribute(entityType, key);
  if (attribute) return attribute;
  return schemaRelationsRefDefinition.getRelationRef(entityType, key);
};

// The platform stores "no date" as the first and the last representable dates: these values are not set
const UNSET_DATES = new Set([FROM_START_STR, UNTIL_END_STR]);

const isDateAttribute = (entityType: string, key: string) => resolveDefinition(entityType, key)?.type === 'date';

/**
 * A stored document (knowledge snapshot) with the rules of the documents built today: technical attributes
 * dropped, dates that mean "not set" removed.
 */
export const normalizeDocument = (entityType: string, document: AttributeValues): AttributeValues => {
  const normalized: AttributeValues = {};
  Object.entries(document).forEach(([key, raws]) => {
    if (TECHNICAL_ATTRIBUTES.has(key) || key.startsWith('i_')) return;
    const kept = isDateAttribute(entityType, key) ? raws.filter((raw) => !UNSET_DATES.has(raw)) : raws;
    if (kept.length > 0) normalized[key] = kept;
  });
  return normalized;
};

export const isMultipleAttribute = (entityType: string, key: string): boolean => {
  const definition = resolveDefinition(entityType, key);
  return definition?.multiple ?? false;
};

// Raw encoding of a single value, aligned with the history change encoding (see database/data-changes.ts)
export const toRawValue = (definition: AttributeDefinition | RefAttribute, value: unknown): string | null => {
  if (value === null || value === undefined) return null;
  if (definition.type === 'ref') {
    if (typeof value === 'string') return value;
    const ref = value as { internal_id?: string; id?: string };
    return ref.internal_id ?? ref.id ?? null;
  }
  if (definition.type === 'object') {
    return typeof value === 'string' ? value : JSON.stringify(value);
  }
  if (definition.type === 'date') {
    const date = utcDate(value as string);
    if (!date.isValid()) return null;
    const iso = date.toISOString();
    return UNSET_DATES.has(iso) ? null : iso;
  }
  if (definition.type === 'boolean' || definition.type === 'numeric') {
    return String(value);
  }
  return typeof value === 'string' ? value : JSON.stringify(value);
};

const fromRawValue = (definition: AttributeDefinition, raw: string): unknown => {
  if (definition.type === 'numeric') {
    const value = Number(raw);
    return Number.isNaN(value) ? raw : value;
  }
  if (definition.type === 'boolean') return raw === 'true';
  if (definition.type === 'object') {
    try {
      return JSON.parse(raw);
    } catch {
      return raw;
    }
  }
  return raw;
};

/**
 * The element as it was in a rebuilt document: its attributes take their value at that date (absent when they were
 * empty), its other fields stay the current ones. Used to apply the representative rules of the type to a past state.
 */
export const rebuildElementAt = (element: { entity_type: string }, document: AttributeValues): Record<string, unknown> & { entity_type: string } => {
  const rebuilt: Record<string, unknown> & { entity_type: string } = { ...element };
  schemaAttributesDefinition.getAttributes(element.entity_type).forEach((attribute) => {
    if (!isTimeMachineAttribute(attribute)) return;
    const values = (document[attribute.name] ?? []).map((raw) => fromRawValue(attribute, raw));
    rebuilt[attribute.name] = attribute.multiple ? values : values[0];
  });
  return rebuilt;
};

const toRawValues = (definition: AttributeDefinition | RefAttribute, value: unknown): string[] => {
  const values = Array.isArray(value) ? value : [value];
  const raws: string[] = [];
  for (let index = 0; index < values.length; index += 1) {
    const raw = toRawValue(definition, values[index]);
    if (raw !== null && raw !== '') raws.push(raw);
  }
  return raws;
};

/**
 * Build the time machine document of a loaded store element.
 * References are read from the denormalized database names (ids only), never resolved.
 */
export const extractAttributeValues = (entity: Record<string, unknown> & { entity_type: string }): AttributeValues => {
  const { entity_type: entityType } = entity;
  const values: AttributeValues = {};
  const attributes = schemaAttributesDefinition.getAttributes(entityType);
  attributes.forEach((attribute) => {
    if (!isTimeMachineAttribute(attribute)) return;
    const raws = toRawValues(attribute, entity[attribute.name]);
    if (raws.length > 0) values[attribute.name] = raws;
  });
  const refs = schemaRelationsRefDefinition.getRelationsRef(entityType);
  for (let index = 0; index < refs.length; index += 1) {
    const ref = refs[index];
    if (isTimeMachineAttribute(ref)) {
      const raws = toRawValues(ref, entity[ref.databaseName] ?? entity[ref.name]);
      if (raws.length > 0) values[ref.name] = [...new Set(raws)];
    }
  }
  return values;
};

// History change fields are encoded as `<Entity-Type>--<attribute>`
export const changeFieldKey = (field: string): string => {
  const separatorIndex = field.indexOf('--');
  return separatorIndex >= 0 ? field.substring(separatorIndex + 2) : field;
};

// Net additions and removals of container objects from the `objects` changes of the events
export const containerObjectsNetChanges = (events: TimeMachineHistoryEvent[]) => {
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

export const currentContainerObjectIds = (element: Record<string, unknown>): string[] => {
  const objects = element[RELATION_OBJECT];
  return Array.isArray(objects) ? objects : [];
};

/**
 * Objects of a container at an earlier date than its current objects, rewound with the `objects` changes
 * of the events since that date.
 */
export const containerObjectIdsAt = (currentIds: string[], events: TimeMachineHistoryEvent[]): string[] => {
  const { added, removed } = containerObjectsNetChanges(events);
  const ids = new Set(currentIds.filter((id) => !added.has(id)));
  removed.forEach((_, id) => ids.add(id));
  return [...ids];
};

const rawsOf = (values?: { raw: string }[]) => (values ?? []).map((v) => v.raw).filter((raw) => raw !== null && raw !== undefined);

// Raw values of a change, without the dates that mean "not set"
const changeRaws = (entityType: string, key: string, values?: { raw: string }[]) => {
  const raws = rawsOf(values);
  return isDateAttribute(entityType, key) ? raws.filter((raw) => !UNSET_DATES.has(raw)) : raws;
};

const attributePath = (key: string) => `/${jsonpatch.escapePathComponent(key)}`;

/**
 * Compute the reverse JSON patch of a single history change against the current document.
 * Single valued attributes go back to the removed value, multiple valued attributes
 * remove the added values and restore the removed ones.
 */
export const reverseOperationsForChange = (
  document: AttributeValues,
  entityType: string,
  change: HistoryChange,
): jsonpatch.Operation[] => {
  const key = changeFieldKey(change.field);
  if (key === CONTAINER_OBJECTS_KEY || TECHNICAL_ATTRIBUTES.has(key) || key.startsWith('i_')) {
    return [];
  }
  const added = changeRaws(entityType, key, change.changes_added);
  const removed = changeRaws(entityType, key, change.changes_removed);
  const path = attributePath(key);
  const exists = Object.prototype.hasOwnProperty.call(document, key);
  let previous: string[];
  if (isMultipleAttribute(entityType, key)) {
    const addedSet = new Set(added);
    const kept = (document[key] ?? []).filter((value) => !addedSet.has(value));
    const keptSet = new Set(kept);
    previous = [...kept, ...removed.filter((value) => !keptSet.has(value))];
  } else {
    previous = removed;
  }
  if (previous.length === 0) {
    return exists ? [{ op: 'remove', path }] : [];
  }
  return [{ op: 'add', path, value: previous }];
};

/**
 * Compute the forward JSON patch of a single history change (used to verify the replay in tests
 * and to move a document forward in time from an older anchor).
 */
export const forwardOperationsForChange = (
  document: AttributeValues,
  entityType: string,
  change: HistoryChange,
): jsonpatch.Operation[] => {
  const key = changeFieldKey(change.field);
  if (key === CONTAINER_OBJECTS_KEY || TECHNICAL_ATTRIBUTES.has(key) || key.startsWith('i_')) {
    return [];
  }
  const added = changeRaws(entityType, key, change.changes_added);
  const removed = changeRaws(entityType, key, change.changes_removed);
  const path = attributePath(key);
  const exists = Object.prototype.hasOwnProperty.call(document, key);
  let next: string[];
  if (isMultipleAttribute(entityType, key)) {
    const removedSet = new Set(removed);
    const kept = (document[key] ?? []).filter((value) => !removedSet.has(value));
    const keptSet = new Set(kept);
    next = [...kept, ...added.filter((value) => !keptSet.has(value))];
  } else {
    next = added;
  }
  if (next.length === 0) {
    return exists ? [{ op: 'remove', path }] : [];
  }
  return [{ op: 'add', path, value: next }];
};

const applyOperations = (document: AttributeValues, operations: jsonpatch.Operation[]) => {
  if (operations.length === 0) return document;
  return jsonpatch.applyPatch(document, operations, false, true).newDocument;
};

/**
 * Rewind a document to `date` by applying, from the most recent to the oldest,
 * the reverse patch of every history event strictly after `date`, down to a merge at most.
 * `events` must contain the events of the element between `date` and the anchor of the document.
 */
export const replayBackward = (
  anchorDocument: AttributeValues,
  entityType: string,
  events: TimeMachineHistoryEvent[],
  date: string,
  maxEvents: number,
): ReplayResult => {
  const document: AttributeValues = structuredClone(anchorDocument);
  const warnings: string[] = [];
  const target = utcDate(date);
  const sortedEvents = [...events]
    .filter((event) => utcDate(event.timestamp).isAfter(target))
    .sort((a, b) => utcDate(b.timestamp).diff(utcDate(a.timestamp)));
  let exists = true;
  let complete = true;
  let replayedEvents = 0;
  for (let index = 0; index < sortedEvents.length; index += 1) {
    if (replayedEvents >= maxEvents) {
      complete = false;
      warnings.push('REPLAY_WINDOW_EXCEEDED');
      break;
    }
    const event = sortedEvents[index];
    replayedEvents += 1;
    if (event.event_scope === 'create') {
      // The element did not exist before its creation event
      exists = false;
      break;
    }
    if (event.event_scope === 'merge') {
      // What a merge brought is not in the history: older changes reversed on top of it would give a state that never
      // existed, the rewind stops right after the merge
      complete = false;
      warnings.push('MERGE_NOT_REVERSIBLE');
      break;
    }
    if (event.event_scope === 'update') {
      // Changes of a single event are reversed in reverse order
      const changes = [...(event.changes ?? [])].reverse();
      for (let changeIndex = 0; changeIndex < changes.length; changeIndex += 1) {
        const operations = reverseOperationsForChange(document, entityType, changes[changeIndex]);
        applyOperations(document, operations);
      }
    }
  }
  return { document, exists, complete, warnings, replayedEvents };
};

/**
 * Move a document forward to `date` by applying the forward patch of every event
 * between the anchor date (exclusive) and `date` (inclusive), up to a merge at most.
 */
export const replayForward = (
  anchorDocument: AttributeValues,
  entityType: string,
  events: TimeMachineHistoryEvent[],
  anchorDate: string,
  date: string,
  maxEvents: number,
): ReplayResult => {
  const document: AttributeValues = structuredClone(anchorDocument);
  const warnings: string[] = [];
  const start = utcDate(anchorDate);
  const target = utcDate(date);
  const sortedEvents = [...events]
    .filter((event) => {
      const time = utcDate(event.timestamp);
      return time.isAfter(start) && !time.isAfter(target);
    })
    .sort((a, b) => utcDate(a.timestamp).diff(utcDate(b.timestamp)));
  let exists = true;
  let complete = true;
  let replayedEvents = 0;
  for (let index = 0; index < sortedEvents.length; index += 1) {
    if (replayedEvents >= maxEvents) {
      complete = false;
      warnings.push('REPLAY_WINDOW_EXCEEDED');
      break;
    }
    const event = sortedEvents[index];
    replayedEvents += 1;
    if (event.event_scope === 'delete') {
      exists = false;
    } else if (event.event_scope === 'create') {
      exists = true;
    } else if (event.event_scope === 'merge') {
      // What a merge brought is not in the history: later changes applied to the older document would give a state that
      // never existed, the replay stops right before the merge
      complete = false;
      warnings.push('MERGE_NOT_REVERSIBLE');
      break;
    } else if (event.event_scope === 'update') {
      const changes = event.changes ?? [];
      for (let changeIndex = 0; changeIndex < changes.length; changeIndex += 1) {
        const operations = forwardOperationsForChange(document, entityType, changes[changeIndex]);
        applyOperations(document, operations);
      }
    }
  }
  return { document, exists, complete, warnings, replayedEvents };
};

/**
 * Flag a replay between its anchor and the requested date spanning more than `maxDays`, in either direction,
 * so the reconstruction is presented as a long replay.
 */
export const flagReplayBeyondWindow = (replay: ReplayResult, anchorDate: string, date: string, maxDays: number) => {
  const days = Math.abs(utcDate(anchorDate).diff(utcDate(date), 'days'));
  if (days > maxDays && !replay.warnings.includes('REPLAY_BEYOND_WINDOW')) {
    replay.warnings.push('REPLAY_BEYOND_WINDOW');
  }
  return replay;
};

/**
 * Rewind the access references of an element (markings, organization sharing) from their current values to `date`
 * with the changes of these references only, so the access check never relies on an intermediate replay state.
 * A merge after `date` cannot be reversed: the organization sharing before it is unknown and can only have been
 * narrower, so none is kept; the markings rewound across it can only be a superset of the real ones (restrictive).
 */
export const rewindAccessReferences = (
  current: AttributeValues,
  entityType: string,
  events: TimeMachineHistoryEvent[],
  date: string,
  keys: { marking: string | null; granted: string | null },
): AttributeValues => {
  const accessKeys = new Set([keys.marking, keys.granted].filter((key): key is string => !!key));
  const start: AttributeValues = {};
  accessKeys.forEach((key) => {
    if (current[key]) start[key] = current[key];
  });
  const accessEvents = events
    .filter((event) => event.event_scope === 'update')
    .map((event) => ({ ...event, changes: (event.changes ?? []).filter((change) => accessKeys.has(changeFieldKey(change.field))) }))
    .filter((event) => event.changes.length > 0);
  const { document } = replayBackward(start, entityType, accessEvents, date, accessEvents.length);
  const target = utcDate(date);
  const mergedAfter = events.some((event) => event.event_scope === 'merge' && utcDate(event.timestamp).isAfter(target));
  if (mergedAfter && keys.granted) {
    delete document[keys.granted];
  }
  return document;
};

const sameValues = (a: string[], b: string[]) => {
  if (a.length !== b.length) return false;
  const sortedA = [...a].sort();
  const sortedB = [...b].sort();
  return sortedA.every((value, index) => value === sortedB[index]);
};

export const diffDocuments = (before: AttributeValues, after: AttributeValues): AttributeDelta[] => {
  const keys = [...new Set([...Object.keys(before), ...Object.keys(after)])].sort();
  const deltas: AttributeDelta[] = [];
  for (let index = 0; index < keys.length; index += 1) {
    const key = keys[index];
    const beforeValues = before[key] ?? [];
    const afterValues = after[key] ?? [];
    if (!sameValues(beforeValues, afterValues)) {
      const beforeSet = new Set(beforeValues);
      const afterSet = new Set(afterValues);
      deltas.push({
        key,
        before: beforeValues,
        after: afterValues,
        added: afterValues.filter((value) => !beforeSet.has(value)),
        removed: beforeValues.filter((value) => !afterSet.has(value)),
      });
    }
  }
  return deltas;
};

export const firstNumber = (values: string[] | undefined): number | null => {
  if (!values || values.length === 0) return null;
  const parsed = Number(values[0]);
  return Number.isFinite(parsed) ? parsed : null;
};
