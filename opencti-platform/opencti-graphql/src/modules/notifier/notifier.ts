import { v4 as uuidv4 } from 'uuid';
import notificationTypeDefs from './notifier.graphql';
import webhookResolvers from './notifier-resolver';
import { ENTITY_TYPE_NOTIFIER, type StixNotifier, type StoreEntityNotifier } from './notifier-types';
import { ABSTRACT_INTERNAL_OBJECT } from '../../schema/general';
import type { ModuleDefinition } from '../../schema/module';
import { registerDefinition } from '../../schema/module';
import { convertNotifierToStix } from './notifier-converter';
import { authorizedAuthorities, authorizedMembers } from '../../schema/attribute-definition';

const NOTIFIER_DEFINITION: ModuleDefinition<StoreEntityNotifier, StixNotifier> = {
  type: {
    id: 'notifiers',
    name: ENTITY_TYPE_NOTIFIER,
    category: ABSTRACT_INTERNAL_OBJECT
  },
  graphql: {
    schema: notificationTypeDefs,
    resolver: webhookResolvers,
  },
  identifier: {
    definition: {
      [ENTITY_TYPE_NOTIFIER]: () => uuidv4(),
    },
  },
  attributes: [
    { name: 'name', label: 'Name', type: 'string', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'created', type: 'date', mandatoryType: 'external', editDefault: false, multiple: false, upsert: true },
    { name: 'updated', type: 'date', mandatoryType: 'external', editDefault: false, multiple: false, upsert: false },
    { name: 'description', label: 'Description', type: 'string', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'built_in', label: 'Built-in', type: 'boolean', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'notifier_connector_id', label: 'Connector ID', type: 'string', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'notifier_configuration', label: 'Configuration', type: 'json', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    authorizedMembers,
    authorizedAuthorities,
  ],
  relations: [],
  representative: (stix: StixNotifier) => {
    return stix.name;
  },
  converter: convertNotifierToStix
};
registerDefinition(NOTIFIER_DEFINITION);
