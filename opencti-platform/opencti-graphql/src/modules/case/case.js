import { ENTITY_TYPE_CONTAINER } from '../../schema/general';
import { NAME_FIELD, normalizeName } from '../../schema/identifier';
import { registerDefinition } from '../../schema/module';
import { objectOrganization } from '../../schema/stixRefRelationship';
import convertCaseToStix from './case-converter';
import { ENTITY_TYPE_CONTAINER_CASE } from './case-types';
const CASE_DEFINITION = {
    type: {
        id: 'cases',
        name: ENTITY_TYPE_CONTAINER_CASE,
        category: ENTITY_TYPE_CONTAINER,
        aliased: false
    },
    identifier: {
        definition: {
            [ENTITY_TYPE_CONTAINER_CASE]: [{ src: NAME_FIELD }, { src: 'created' }]
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
        { name: 'content_mapping', label: 'Content mapping', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: true },
        { name: 'caseTemplate', label: 'Case template', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: true },
    ],
    relations: [],
    relationsRefs: [objectOrganization],
    representative: (stix) => {
        return stix.name;
    },
    converter: convertCaseToStix
};
registerDefinition(CASE_DEFINITION);
