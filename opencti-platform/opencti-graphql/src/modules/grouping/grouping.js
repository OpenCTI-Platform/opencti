import convertGroupingToStix from './grouping-converter';
import { NAME_FIELD, normalizeName } from '../../schema/identifier';
import { ENTITY_TYPE_CONTAINER_GROUPING } from './grouping-types';
import { ABSTRACT_STIX_DOMAIN_OBJECT } from '../../schema/general';
import { registerDefinition } from '../../schema/module';
const GROUPING_DEFINITION = {
    type: {
        id: 'groupings',
        name: ENTITY_TYPE_CONTAINER_GROUPING,
        category: ABSTRACT_STIX_DOMAIN_OBJECT,
        aliased: true
    },
    identifier: {
        definition: {
            [ENTITY_TYPE_CONTAINER_GROUPING]: [{ src: NAME_FIELD }, { src: 'context' }]
        },
        resolvers: {
            name(data) {
                return normalizeName(data);
            },
        },
    },
    attributes: [
        { name: 'name', label: 'Name', type: 'string', format: 'short', mandatoryType: 'external', editDefault: true, multiple: false, upsert: true, isFilterable: true },
        { name: 'description', label: 'Description', type: 'string', format: 'short', mandatoryType: 'customizable', editDefault: true, multiple: false, upsert: true, isFilterable: true },
        { name: 'content', label: 'Content', type: 'string', format: 'short', mandatoryType: 'customizable', editDefault: true, multiple: false, upsert: true, isFilterable: true },
        { name: 'content_mapping', label: 'Content mapping', format: 'short', type: 'string', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: true },
        { name: 'context', label: 'Content', type: 'string', format: 'short', mandatoryType: 'external', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    ],
    relations: [],
    representative: (stix) => {
        return stix.name;
    },
    converter: convertGroupingToStix
};
registerDefinition(GROUPING_DEFINITION);
