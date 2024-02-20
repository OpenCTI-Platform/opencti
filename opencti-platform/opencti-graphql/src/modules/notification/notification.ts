import { v4 as uuidv4 } from 'uuid';
import { convertNotificationToStix, convertTriggerToStix } from './notification-converter';
import {
  ENTITY_TYPE_NOTIFICATION,
  ENTITY_TYPE_TRIGGER,
  type StixNotification,
  type StixTrigger,
  type StoreEntityNotification,
  type StoreEntityTrigger
} from './notification-types';
import { ABSTRACT_INTERNAL_OBJECT, ABSTRACT_STIX_CORE_OBJECT } from '../../schema/general';
import type { ModuleDefinition } from '../../schema/module';
import { registerDefinition } from '../../schema/module';
import { authorizedAuthorities, authorizedMembers } from '../../schema/attribute-definition';
import { ENTITY_TYPE_GROUP, ENTITY_TYPE_USER } from '../../schema/internalObject';
import { ENTITY_TYPE_NOTIFIER } from '../notifier/notifier-types';
import { ENTITY_TYPE_IDENTITY_ORGANIZATION } from '../organization/organization-types';

// Outcomes
// TODO

// Triggers
const TRIGGER_DEFINITION: ModuleDefinition<StoreEntityTrigger, StixTrigger> = {
  type: {
    id: 'triggers',
    name: ENTITY_TYPE_TRIGGER,
    category: ABSTRACT_INTERNAL_OBJECT
  },
  identifier: {
    definition: {
      [ENTITY_TYPE_TRIGGER]: () => uuidv4(),
    },
  },
  attributes: [
    { name: 'name', label: 'Name', type: 'string', format: 'short', mandatoryType: 'external', editDefault: true, multiple: false, upsert: false, isFilterable: true },
    { name: 'description', label: 'Description', type: 'string', format: 'text', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'created', label: 'Created', type: 'date', mandatoryType: 'external', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'updated', label: 'Updated', type: 'date', mandatoryType: 'external', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'event_types', label: 'Event types', type: 'string', format: 'enum', values: ['create', 'update', 'delete'], mandatoryType: 'external', editDefault: true, multiple: true, upsert: false, isFilterable: true },
    { name: 'trigger_scope', label: 'Trigger scope', type: 'string', format: 'enum', values: ['knowledge', 'activity'], mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'outcomes', label: 'Outcomes', type: 'string', format: 'short', mandatoryType: 'external', editDefault: false, multiple: true, upsert: false, isFilterable: false },
    { name: 'notifiers', label: 'Notifiers', type: 'string', format: 'id', mandatoryType: 'external', editDefault: true, multiple: true, upsert: false, entityTypes: [ENTITY_TYPE_NOTIFIER], isFilterable: true },
    { name: 'filters', label: 'Filters', type: 'string', format: 'text', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'recipients', label: 'Recipients', type: 'string', format: 'id', entityTypes: [ENTITY_TYPE_USER, ENTITY_TYPE_GROUP, ENTITY_TYPE_IDENTITY_ORGANIZATION], mandatoryType: 'no', editDefault: false, multiple: true, upsert: false, isFilterable: false },
    { name: 'trigger_ids', label: 'Trigger IDs', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: true, upsert: false, isFilterable: false },
    { name: 'period', label: 'Period', type: 'string', format: 'enum', values: ['hour', 'day', 'week', 'month'], mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'trigger_time', label: 'Trigger time', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'trigger_type', label: 'Trigger type', type: 'string', format: 'enum', values: ['digest', 'live'], mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
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
  identifier: {
    definition: {
      [ENTITY_TYPE_NOTIFICATION]: () => uuidv4(),
    },
  },
  attributes: [
    { name: 'notification_type', label: 'Notification type', type: 'string', format: 'enum', values: ['live', 'digest'], mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    {
      name: 'notification_content',
      type: 'object',
      format: 'standard',
      label: 'Notification content',
      mandatoryType: 'internal',
      editDefault: false,
      multiple: true,
      upsert: false,
      isFilterable: true,
      mappings: [
        { name: 'title', label: 'Notification title', type: 'string', format: 'short', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: false },
        {
          name: 'events',
          label: 'Notification events',
          type: 'object',
          format: 'standard',
          mandatoryType: 'internal',
          editDefault: false,
          multiple: false,
          upsert: false,
          isFilterable: true,
          mappings: [
            { name: 'message', label: 'Notification message', type: 'string', format: 'text', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
            { name: 'instance_id', label: 'Notification related instance', type: 'string', format: 'id', entityTypes: [ABSTRACT_STIX_CORE_OBJECT], mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: false },
            { name: 'operation', label: 'Notification operation', type: 'string', format: 'enum', values: ['create', 'update', 'delete'], mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
          ]
        },
      ]
    },
    { name: 'is_read', label: 'Is read', type: 'boolean', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: true, isFilterable: true },
    {
      name: 'user_id',
      label: 'User',
      type: 'string',
      format: 'id',
      entityTypes: [ENTITY_TYPE_USER],
      mandatoryType: 'internal',
      editDefault: false,
      multiple: false,
      upsert: false,
      isFilterable: false
    },
  ],
  relations: [],
  representative: (stix: StixNotification) => {
    return stix.messages.join(', ');
  },
  converter: convertNotificationToStix
};
registerDefinition(NOTIFICATION_DEFINITION);
