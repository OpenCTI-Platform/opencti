import { v4 as uuidv4 } from 'uuid';
import { ENTITY_TYPE_NOTIFIER } from './notifier-types';
import { ABSTRACT_INTERNAL_OBJECT } from '../../schema/general';
import { registerDefinition } from '../../schema/module';
import { convertNotifierToStix } from './notifier-converter';
import { authorizedAuthorities, authorizedMembers } from '../../schema/attribute-definition';
const NOTIFIER_DEFINITION = {
    type: {
        id: 'notifiers',
        name: ENTITY_TYPE_NOTIFIER,
        category: ABSTRACT_INTERNAL_OBJECT
    },
    identifier: {
        definition: {
            [ENTITY_TYPE_NOTIFIER]: () => uuidv4(),
        },
    },
    attributes: [
        { name: 'name', label: 'Name', type: 'string', format: 'short', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
        { name: 'created', label: 'Created', type: 'date', mandatoryType: 'external', editDefault: false, multiple: false, upsert: true, isFilterable: true },
        { name: 'updated', label: 'Updated', type: 'date', mandatoryType: 'external', editDefault: false, multiple: false, upsert: false, isFilterable: true },
        { name: 'description', label: 'Description', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
        { name: 'built_in', label: 'Built-in', type: 'boolean', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
        { name: 'notifier_connector_id', label: 'Connector ID', type: 'string', format: 'short', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: false },
        { name: 'notifier_configuration', label: 'Configuration', type: 'string', format: 'json', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
        authorizedMembers,
        authorizedAuthorities,
    ],
    relations: [],
    representative: (stix) => {
        return stix.name;
    },
    converter: convertNotifierToStix
};
registerDefinition(NOTIFIER_DEFINITION);
