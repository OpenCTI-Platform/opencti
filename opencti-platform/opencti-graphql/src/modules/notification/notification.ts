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
import { authorizedAuthorities, authorizedMembers } from '../../schema/attribute-definition';

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
    { name: 'name', label: 'Name', type: 'string', mandatoryType: 'external', editDefault: true, multiple: false, upsert: false, isFilterable: true },
    { name: 'description', label: 'Description', type: 'string', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'created', type: 'date', mandatoryType: 'external', editDefault: false, multiple: false, upsert: false },
    { name: 'updated', type: 'date', mandatoryType: 'external', editDefault: false, multiple: false, upsert: false },
    { name: 'event_types', label: 'Event types', type: 'string', mandatoryType: 'external', editDefault: true, multiple: true, upsert: false, isFilterable: true },
    { name: 'trigger_scope', label: 'Trigger scope', type: 'string', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'trigger_type', type: 'string', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false },
    { name: 'outcomes', type: 'string', mandatoryType: 'external', editDefault: false, multiple: true, upsert: false },
    { name: 'notifiers', label: 'Notifiers', type: 'string', mandatoryType: 'external', editDefault: true, multiple: true, upsert: false, isFilterable: true },
    { name: 'filters', label: 'Filters', type: 'string', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'recipients', label: 'Recipients', type: 'string', mandatoryType: 'no', editDefault: false, multiple: true, upsert: false, isFilterable: false },
    { name: 'trigger_ids', label: 'Trigger IDs', type: 'string', mandatoryType: 'no', editDefault: false, multiple: true, upsert: false, isFilterable: false },
    { name: 'period', label: 'Period', type: 'string', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'trigger_time', label: 'Trigger time', type: 'string', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'trigger_type', label: 'Trigger type', type: 'string', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'instance_trigger', label: 'Instance trigger', type: 'boolean', mandatoryType: 'external', editDefault: true, multiple: false, upsert: false, isFilterable: true },
    authorizedMembers,
    authorizedAuthorities,
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
    { name: 'notification_type', type: 'string', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false },
    // TODO: modify content to content_notification
    // { name: 'content', type: 'dictionary', mandatoryType: 'internal', multiple: true, upsert: false },
    { name: 'is_read', type: 'boolean', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: true },
    { name: 'user_id', type: 'string', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false },
  ],
  relations: [],
  representative: (stix: StixNotification) => {
    return stix.messages.join(', ');
  },
  converter: convertNotificationToStix
};
registerDefinition(NOTIFICATION_DEFINITION);
