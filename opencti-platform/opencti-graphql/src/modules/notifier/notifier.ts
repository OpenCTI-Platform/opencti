import { v4 as uuidv4 } from 'uuid';
import notificationTypeDefs from './notifier.graphql';
import webhookResolvers from './notifier-resolver';
import { ENTITY_TYPE_NOTIFIER, type StixNotifier, type StoreEntityNotifier } from './notifier-types';
import { ABSTRACT_INTERNAL_OBJECT } from '../../schema/general';
import type { ModuleDefinition } from '../../schema/module';
import { registerDefinition } from '../../schema/module';
import { convertNotifierToStix } from './notifier-converter';

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
    { name: 'name', type: 'string', mandatoryType: 'internal', multiple: false, upsert: false },
    { name: 'description', type: 'string', mandatoryType: 'no', multiple: false, upsert: false },
    { name: 'built_in', type: 'boolean', mandatoryType: 'no', multiple: false, upsert: false },
    { name: 'notifier_connector_id', type: 'string', mandatoryType: 'internal', multiple: false, upsert: false },
    { name: 'notifier_configuration', type: 'json', mandatoryType: 'no', multiple: false, upsert: false },
    { name: 'authorized_members', type: 'json', mandatoryType: 'no', multiple: true, upsert: false },
    { name: 'authorized_authorities', type: 'string', mandatoryType: 'no', multiple: true, upsert: false },
  ],
  relations: [],
  representative: (stix: StixNotifier) => {
    return stix.name;
  },
  converter: convertNotifierToStix
};
registerDefinition(NOTIFIER_DEFINITION);
