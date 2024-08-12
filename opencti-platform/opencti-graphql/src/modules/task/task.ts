import { ENTITY_TYPE_CONTAINER } from '../../schema/general';
import { NAME_FIELD, normalizeName } from '../../schema/identifier';
import { type ModuleDefinition, registerDefinition } from '../../schema/module';
import { objectAssignee, objectOrganization, objectParticipant } from '../../schema/stixRefRelationship';
import convertCaseTaskToStix from './task-converter';
import type { StixTask, StoreEntityTask } from './task-types';
import { ENTITY_TYPE_CONTAINER_TASK } from './task-types';

const CASE_TASK_DEFINITION: ModuleDefinition<StoreEntityTask, StixTask> = {
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
      name(data: object) {
        return normalizeName(data);
      },
    },
  },
  overviewLayoutCustomization: [
    { key: 'details', width: 6, label: 'Entity details' },
    { key: 'basicInformation', width: 6, label: 'Basic information' },
    { key: 'relatedEntities', width: 6, label: 'Related entities' },
    { key: 'mostRecentHistory', width: 6, label: 'Most recent history' },
    { key: 'notes', width: 12, label: 'Notes about this entity' },
  ],
  attributes: [
    { name: 'name', label: 'Name', type: 'string', format: 'short', mandatoryType: 'external', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    { name: 'description', label: 'Description', type: 'string', format: 'text', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: true },
    { name: 'due_date', label: 'Due date', type: 'date', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: true },
    { name: 'x_opencti_workflow_id', label: 'Workflow status', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: false },
  ],
  relations: [],
  relationsRefs: [
    objectOrganization,
    { ...objectAssignee, mandatoryType: 'no' },
    objectParticipant
  ],
  representative: (stix: StixTask) => {
    return stix.name;
  },
  converter: convertCaseTaskToStix
};
registerDefinition(CASE_TASK_DEFINITION);
