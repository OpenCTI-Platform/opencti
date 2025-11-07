import { RELATION_IN_PIR } from '../../schema/internalRelationship';
import { isStixRelation } from '../../schema/stixRelationship';
import type { StreamDataEvent } from '../../types/event';

interface EventConfig {
  create?: boolean
  update?: boolean
  delete?: boolean
}

export const isValidEventType = (eventType: string, configuration: EventConfig) => {
  const {
    update,
    create,
    delete: deletion
  } = configuration;

  let validEventType = false;
  if (eventType === 'create' && create === true) validEventType = true;
  if (eventType === 'update' && update === true) validEventType = true;
  if (eventType === 'delete' && deletion === true) validEventType = true;

  return validEventType;
};

export const isEventInPir = (streamEvent : StreamDataEvent) => {
  const { data, scope } = streamEvent;
  return scope === 'internal' && isStixRelation(data) && data.relationship_type === RELATION_IN_PIR;
};
