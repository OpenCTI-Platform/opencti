import { v4 as uuidv4 } from 'uuid';
import notificationTypeDefs from './notification.graphql';
import { convertNotificationToStix, convertTriggerToStix } from './notification-converter';
import notificationResolvers from './notification-resolver';
import {
  ENTITY_TYPE_NOTIFICATION,
  ENTITY_TYPE_TRIGGER, StixNotification, StixTrigger,
  StoreEntityNotification,
  StoreEntityTrigger
} from './notification-types';
import type { ModuleDefinition } from '../../types/module';
import { registerDefinition } from '../../types/module';
import { ABSTRACT_INTERNAL_OBJECT } from '../../schema/general';

// Outcomes
// TODO

// Triggers
const TRIGGER_DEFINITION: ModuleDefinition<StoreEntityTrigger, StixTrigger> = {
  type: {
    id: 'triggers',
    name: ENTITY_TYPE_TRIGGER,
    category: ABSTRACT_INTERNAL_OBJECT
  },
  graphql: {
    schema: notificationTypeDefs,
    resolver: notificationResolvers,
  },
  identifier: {
    definition: {
      [ENTITY_TYPE_TRIGGER]: () => uuidv4(),
    },
  },
  attributes: [
    { name: 'name', type: 'string', multiple: false, upsert: false },
    { name: 'description', type: 'string', multiple: false, upsert: false },
    { name: 'event_types', type: 'string', multiple: true, upsert: false },
    { name: 'outcomes', type: 'string', multiple: true, upsert: false },
    { name: 'filters', type: 'string', multiple: false, upsert: false },
    { name: 'trigger_ids', type: 'string', multiple: true, upsert: false },
    { name: 'period', type: 'string', multiple: false, upsert: false },
    { name: 'trigger_time', type: 'string', multiple: false, upsert: false },
  ],
  relations: [],
  representative: (stix: StixTrigger) => {
    return stix.name;
  },
  converter: convertTriggerToStix
};
registerDefinition(TRIGGER_DEFINITION);

// Notifications
const NOTIFICATION_DEFINITION: ModuleDefinition<StoreEntityNotification, StixNotification> = {
  type: {
    id: 'notifications',
    name: ENTITY_TYPE_NOTIFICATION,
    category: ABSTRACT_INTERNAL_OBJECT
  },
  graphql: {
    schema: notificationTypeDefs,
    resolver: notificationResolvers,
  },
  identifier: {
    definition: {
      [ENTITY_TYPE_NOTIFICATION]: () => uuidv4(),
    },
  },
  attributes: [
    { name: 'notification_type', type: 'string', multiple: false, upsert: false },
    { name: 'content', type: 'dictionary', multiple: true, upsert: false },
    { name: 'is_read', type: 'boolean', multiple: false, upsert: true },
  ],
  relations: [],
  representative: (stix: StixNotification) => {
    return stix.messages.join(', ');
  },
  converter: convertNotificationToStix
};
registerDefinition(NOTIFICATION_DEFINITION);
