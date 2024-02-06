import { ENTITY_TYPE_CONTAINER } from '../../schema/general';
import { NAME_FIELD, normalizeName } from '../../schema/identifier';
import { registerDefinition } from '../../schema/module';
import { objectAssignee, objectOrganization, objectParticipant } from '../../schema/stixRefRelationship';
import convertCaseTaskToStix from './task-converter';
import { ENTITY_TYPE_CONTAINER_TASK } from './task-types';
const CASE_TASK_DEFINITION = {
    type: {
        id: 'task',
        name: ENTITY_TYPE_CONTAINER_TASK,
        category: ENTITY_TYPE_CONTAINER
    },
    identifier: {
        definition: {
            [ENTITY_TYPE_CONTAINER_TASK]: [{ src: NAME_FIELD }, { src: 'created' }],
        },
        resolvers: {
            name(data) {
                return normalizeName(data);
            },
        },
    },
    attributes: [
        { name: 'name', label: 'Name', type: 'string', format: 'short', mandatoryType: 'external', editDefault: true, multiple: false, upsert: true, isFilterable: true },
        { name: 'description', label: 'Description', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: true },
        { name: 'due_date', label: 'Due date', type: 'date', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: true },
        { name: 'x_opencti_workflow_id', label: 'Workflow status', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: true },
    ],
    relations: [],
    relationsRefs: [
        objectOrganization,
        Object.assign(Object.assign({}, objectAssignee), { mandatoryType: 'no' }),
        objectParticipant
    ],
    representative: (stix) => {
        return stix.name;
    },
    converter: convertCaseTaskToStix
};
registerDefinition(CASE_TASK_DEFINITION);
