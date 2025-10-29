import type { StreamDataEventType } from '../../types/event';

export enum StreamDataEventTypeEnum {
  UPDATE = 'update',
  DELETE = 'delete',
  CREATE = 'create'
}

interface EventConfig {
  create?: boolean
  update?: boolean
  delete?: boolean
}

export const isValidEventType = (eventType: StreamDataEventType, configuration: EventConfig) => {
  const {
    update,
    create,
    delete: deletion
  } = configuration;

  let validEventType = false;
  if (eventType === StreamDataEventTypeEnum.CREATE && create === true) validEventType = true;
  if (eventType === StreamDataEventTypeEnum.UPDATE && update === true) validEventType = true;
  if (eventType === StreamDataEventTypeEnum.DELETE && deletion === true) validEventType = true;

  return validEventType;
};
