import type { StreamDataEvent, StreamDataEventType, UpdateEvent } from '../../types/event';
import { RELATION_IN_PIR } from '../../schema/internalRelationship';
import { isStixRelation } from '../../schema/stixRelationship';
import conf from '../../config/conf';
import type { FilterEventContext } from '../../utils/filtering/boolean-logic-engine';

export enum StreamDataEventTypeEnum {
  UPDATE = 'update',
  DELETE = 'delete',
  CREATE = 'create',
}

interface EventConfig {
  create?: boolean;
  create_rel?: boolean;
  update?: boolean;
  delete?: boolean;
}

const PLAYBOOK_DEBUG_ID_LIST = conf.get('playbook_manager:debug_id_list') || [];
export const isDebugPlaybook = (id: string) => {
  return PLAYBOOK_DEBUG_ID_LIST.includes(id);
};

export const isValidEventType = (eventType: StreamDataEventType, configuration: EventConfig) => {
  const {
    update,
    create,
    create_rel,
    delete: deletion,
  } = configuration;

  let validEventType = false;
  if (eventType === StreamDataEventTypeEnum.CREATE && create === true) validEventType = true;
  if (eventType === StreamDataEventTypeEnum.CREATE && create_rel === true) validEventType = true;
  if (eventType === StreamDataEventTypeEnum.UPDATE && update === true) validEventType = true;
  if (eventType === StreamDataEventTypeEnum.DELETE && deletion === true) validEventType = true;

  return validEventType;
};

/**
 * Build a FilterEventContext from an UpdateEvent.
 * Extracts the changed attribute names from context.changes.
 *
 * The changes[].field format is "EntityType--attributeName" (e.g., "Report--objectMarking").
 * We extract the attribute name part which corresponds directly to the filter key.
 */
export const buildFilterEventContext = (updateEvent: UpdateEvent): FilterEventContext => {
  const changedFields = (updateEvent.context?.changes ?? []).map((change) => {
    // Extract attribute name from "EntityType--attributeName" format
    const parts = change.field.split('--');
    return parts.length > 1 ? parts[1] : change.field;
  });
  // Deduplicate
  return { changedAttributes: [...new Set(changedFields)] };
};

/**
 * Checks if an event is about a relationship in-pir.
 * @param eventData The event.
 * @returns True if the event concerns a relationship in-pir.
 */
export const isEventInPirRelationship = (eventData: StreamDataEvent) => {
  const { data, scope } = eventData;
  return scope === 'internal' && isStixRelation(data) && data.relationship_type === RELATION_IN_PIR;
};

/**
 * Checks if an event is an update on an entity.
 * @param eventData The event.
 * @returns True if the event is an update of entity.
 */
export const isEventUpdateOnEntity = (eventData: StreamDataEvent) => {
  const { data, type } = eventData;
  return type === StreamDataEventTypeEnum.UPDATE && !isStixRelation(data);
};

/**
 * Checks if an event is a relationship creation.
 * @param eventData The event.
 * @returns True if the event is a relationship creation.
 */
export const isEventCreateRelationship = (eventData: StreamDataEvent) => {
  const { data, scope, type } = eventData;
  return scope === 'external' && isStixRelation(data) && type === StreamDataEventTypeEnum.CREATE;
};
