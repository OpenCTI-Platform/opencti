import { ENTITY_TYPE_CONTAINER_CASE } from '../case-types';
import { NAME_FIELD, normalizeName } from '../../../schema/identifier';
import { registerDefinition } from '../../../schema/module';
import { createdBy, objectAssignee, objectMarking, objectParticipant } from '../../../schema/stixRefRelationship';
import { ENTITY_TYPE_CONTAINER_CASE_RFI } from './case-rfi-types';
import convertCaseRfiToStix from './case-rfi-converter';
const CASE_RFI_DEFINITION = {
    type: {
        id: 'case-rfi',
        name: ENTITY_TYPE_CONTAINER_CASE_RFI,
        category: ENTITY_TYPE_CONTAINER_CASE,
        aliased: false
    },
    identifier: {
        definition: {
            [ENTITY_TYPE_CONTAINER_CASE_RFI]: [{ src: NAME_FIELD }, { src: 'created' }]
        },
        resolvers: {
            name(data) {
                return normalizeName(data);
            },
        },
    },
    attributes: [
        { name: 'name', label: 'Name', type: 'string', format: 'short', mandatoryType: 'external', editDefault: true, multiple: false, upsert: true, isFilterable: true },
        { name: 'created', label: 'Created', type: 'date', mandatoryType: 'external', editDefault: true, multiple: false, upsert: true, isFilterable: true },
        { name: 'information_types', label: 'Information types', type: 'string', format: 'short', mandatoryType: 'customizable', editDefault: true, multiple: true, upsert: true, isFilterable: true },
        { name: 'severity', label: 'Severity', type: 'string', format: 'short', mandatoryType: 'customizable', editDefault: true, multiple: false, upsert: true, isFilterable: true },
        { name: 'priority', label: 'Priority', type: 'string', format: 'short', mandatoryType: 'customizable', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    ],
    relations: [],
    relationsRefs: [createdBy, objectMarking, objectAssignee, objectParticipant],
    representative: (stix) => {
        return stix.name;
    },
    converter: convertCaseRfiToStix
};
registerDefinition(CASE_RFI_DEFINITION);
