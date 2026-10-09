import { v4 as uuidv4 } from 'uuid';
import { ENTITY_TYPE_NOTIFIER } from './notifier-types';
import { ABSTRACT_INTERNAL_OBJECT } from '../../schema/general';
import type { InternalObjectModuleDefinition } from '../../schema/module';
import { registerInternalObjectDefinition } from '../../schema/module';
import { authorizedAuthorities, authorizedMembers, created } from '../../schema/attribute-definition';

const NOTIFIER_DEFINITION: InternalObjectModuleDefinition = {
  type: {
    id: 'notifiers',
    name: ENTITY_TYPE_NOTIFIER,
    category: ABSTRACT_INTERNAL_OBJECT,
  },
  identifier: {
    definition: {
      [ENTITY_TYPE_NOTIFIER]: () => uuidv4(),
    },
  },
  attributes: [
    { name: 'name', label: 'Name', type: 'string', format: 'short', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { ...created, mandatoryType: 'external', isFilterable: false },
    { name: 'updated', label: 'Updated', type: 'date', mandatoryType: 'external', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'description', label: 'Description', type: 'string', format: 'text', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'built_in', label: 'Built-in', type: 'boolean', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'notifier_connector_id', label: 'Notifier connector ID', type: 'string', format: 'short', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'notifier_configuration', label: 'Configuration', type: 'string', format: 'json', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    authorizedMembers,
    authorizedAuthorities,
  ],
  relations: [],
};
registerInternalObjectDefinition(NOTIFIER_DEFINITION);
