import { STIX_EXT_OCTI } from '../../types/stix-extensions';
import { buildStixObject, cleanObject } from '../../database/stix-converter';
import type { StixNotification, StixTrigger, StoreEntityNotification, StoreEntityTrigger } from './notification-types';

// Outcomes

// Triggers
export const convertTriggerToStix = (instance: StoreEntityTrigger): StixTrigger => {
  const stixObject = buildStixObject(instance);
  return {
    ...stixObject,
    name: instance.name,
    description: instance.description,
    extensions: {
      [STIX_EXT_OCTI]: cleanObject({
        ...stixObject.extensions[STIX_EXT_OCTI],
        extension_type: 'new-sdo',
      })
    }
  };
};

// Notifications
export const convertNotificationToStix = (instance: StoreEntityNotification): StixNotification => {
  const stixObject = buildStixObject(instance);
  return {
    ...stixObject,
    messages: instance.messages,
    is_read: instance.is_read,
    extensions: {
      [STIX_EXT_OCTI]: cleanObject({
        ...stixObject.extensions[STIX_EXT_OCTI],
        extension_type: 'new-sdo',
      })
    }
  };
};
