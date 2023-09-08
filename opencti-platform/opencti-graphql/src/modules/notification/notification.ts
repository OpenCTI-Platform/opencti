import { v4 as uuidv4 } from 'uuid';
import notificationTypeDefs from './notification.graphql';
import { convertNotificationToStix, convertTriggerToStix } from './notification-converter';
import notificationResolvers from './notification-resolver';
import {
  ENTITY_TYPE_NOTIFICATION,
  ENTITY_TYPE_TRIGGER,
  type StixNotification,
  type StixTrigger,
  type StoreEntityNotification,
  type StoreEntityTrigger
} from './notification-types';
import { ABSTRACT_INTERNAL_OBJECT } from '../../schema/general';
import type { ModuleDefinition } from '../../schema/module';
import { registerDefinition } from '../../schema/module';

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
    { name: 'name', type: 'string', mandatoryType: 'external', multiple: false, upsert: false },
    { name: 'description', type: 'string', mandatoryType: 'no', multiple: false, upsert: false },
    { name: 'event_types', type: 'string', mandatoryType: 'external', multiple: true, upsert: false },
    { name: 'trigger_scope', type: 'string', mandatoryType: 'internal', multiple: false, upsert: false },
    { name: 'notifiers', type: 'string', mandatoryType: 'external', multiple: true, upsert: false },
    { name: 'filters', type: 'string', mandatoryType: 'no', multiple: false, upsert: false },
    { name: 'recipients', type: 'string', mandatoryType: 'no', multiple: true, upsert: false },
    { name: 'trigger_ids', type: 'string', mandatoryType: 'no', multiple: true, upsert: false },
    { name: 'period', type: 'string', mandatoryType: 'no', multiple: false, upsert: false },
    { name: 'trigger_time', type: 'string', mandatoryType: 'no', multiple: false, upsert: false },
    { name: 'authorized_members', type: 'json', mandatoryType: 'no', multiple: true, upsert: false },
    { name: 'authorized_authorities', type: 'string', mandatoryType: 'no', multiple: true, upsert: false },
    { name: 'instance_trigger', type: 'boolean', mandatoryType: 'external', multiple: false, upsert: false },
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
    { name: 'notification_type', type: 'string', mandatoryType: 'internal', multiple: false, upsert: false },
    // TODO: modify content to content_notification
    // { name: 'content', type: 'dictionary', mandatoryType: 'internal', multiple: true, upsert: false },
    { name: 'is_read', type: 'boolean', mandatoryType: 'internal', multiple: false, upsert: true },
  ],
  relations: [],
  representative: (stix: StixNotification) => {
    return stix.messages.join(', ');
  },
  converter: convertNotificationToStix
};
registerDefinition(NOTIFICATION_DEFINITION);
