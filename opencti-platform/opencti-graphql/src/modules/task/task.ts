import { v4 as uuid } from 'uuid';
import { ENTITY_TYPE_CONTAINER } from '../../schema/general';
import { normalizeName } from '../../schema/identifier';
import { ModuleDefinition, registerDefinition } from '../../schema/module';
import { objectAssignee, objectOrganization } from '../../schema/stixRefRelationship';
import convertCaseTaskToStix from './task-converter';
import taskResolvers from './task-resolvers';
import type { StixTask, StoreEntityTask } from './task-types';
import { ENTITY_TYPE_CONTAINER_TASK } from './task-types';
import taskTypeDefs from './task.graphql';

const CASE_TASK_DEFINITION: ModuleDefinition<StoreEntityTask, StixTask> = {
  type: {
    id: 'task',
    name: ENTITY_TYPE_CONTAINER_TASK,
    category: ENTITY_TYPE_CONTAINER
  },
  graphql: {
    schema: taskTypeDefs,
    resolver: taskResolvers,
  },
  identifier: {
    definition: {
      [ENTITY_TYPE_CONTAINER_TASK]: () => uuid(),
    },
    resolvers: {
      name(data: object) {
        return normalizeName(data);
      },
    },
  },
  attributes: [
    { name: 'name', type: 'string', mandatoryType: 'external', multiple: false, upsert: true },
    { name: 'description', type: 'string', mandatoryType: 'no', multiple: false, upsert: true },
    { name: 'due_date', type: 'date', mandatoryType: 'no', multiple: false, upsert: true },
    { name: 'x_opencti_workflow_id', type: 'string', mandatoryType: 'no', multiple: false, upsert: true },
  ],
  relations: [],
  relationsRefs: [
    objectOrganization,
    { ...objectAssignee, mandatoryType: 'no' },
  ],
  representative: (stix: StixTask) => {
    return stix.name;
  },
  converter: convertCaseTaskToStix
};
registerDefinition(CASE_TASK_DEFINITION);
