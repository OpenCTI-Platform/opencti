import type { StreamDataEvent, StreamDataEventType } from '../../types/event';
import { RELATION_IN_PIR } from '../../schema/internalRelationship';
import { isStixRelation } from '../../schema/stixRelationship';

export enum StreamDataEventTypeEnum {
  UPDATE = 'update',
  DELETE = 'delete',
  CREATE = 'create'
}

interface EventConfig {
  create?: boolean
  create_rel?: boolean
  update?: boolean
  delete?: boolean
}

export const isValidEventType = (eventType: StreamDataEventType, configuration: EventConfig) => {
  const {
    update,
    create,
    create_rel,
    delete: deletion
  } = configuration;

  let validEventType = false;
  if (eventType === StreamDataEventTypeEnum.CREATE && create === true) validEventType = true;
  if (eventType === StreamDataEventTypeEnum.CREATE && create_rel === true) validEventType = true;
  if (eventType === StreamDataEventTypeEnum.UPDATE && update === true) validEventType = true;
  if (eventType === StreamDataEventTypeEnum.DELETE && deletion === true) validEventType = true;

  return validEventType;
};

/**
 * Checks if an event is about a relationship in-pir.
 * @param eventData The event.
 * @returns True if the event concerns a relationship in-pir.
 */
export const isEventInPirRelationship = (eventData : StreamDataEvent) => {
  const { data, scope } = eventData;
  return scope === 'internal' && isStixRelation(data) && data.relationship_type === RELATION_IN_PIR;
};

/**
 * Checks if an event is an update on an entity.
 * @param eventData The event.
 * @returns True if the event is an update of entity.
 */
export const isEventUpdateOnEntity = (eventData : StreamDataEvent) => {
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
