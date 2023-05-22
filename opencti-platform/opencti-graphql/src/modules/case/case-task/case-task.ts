import { v4 as uuid } from 'uuid';
import { ENTITY_TYPE_CONTAINER } from '../../../schema/general';
import { normalizeName } from '../../../schema/identifier';
import { ModuleDefinition, registerDefinition } from '../../../schema/module';
import { objectAssignee } from '../../../schema/stixRefRelationship';
import convertCaseTaskToStix from './case-task-converter';
import caseTaskResolvers from './case-task-resolvers';
import type { StixCaseTask, StoreEntityCaseTask } from './case-task-types';
import { ENTITY_TYPE_CONTAINER_CASE_TASK } from './case-task-types';
import caseTaskTypeDefs from './case-task.graphql';

const CASE_TASK_DEFINITION: ModuleDefinition<StoreEntityCaseTask, StixCaseTask> = {
  type: {
    id: 'case-task',
    name: ENTITY_TYPE_CONTAINER_CASE_TASK,
    category: ENTITY_TYPE_CONTAINER
  },
  graphql: {
    schema: caseTaskTypeDefs,
    resolver: caseTaskResolvers,
  },
  identifier: {
    definition: {
      [ENTITY_TYPE_CONTAINER_CASE_TASK]: () => uuid(),
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
    { name: 'dueDate', type: 'date', mandatoryType: 'no', multiple: false, upsert: true },
    { name: 'useAsTemplate', type: 'boolean', mandatoryType: 'internal', multiple: false, upsert: true },
    { name: 'x_opencti_workflow_id', type: 'string', mandatoryType: 'no', multiple: false, upsert: true },
  ],
  relations: [],
  relationsRefs: [
    { ...objectAssignee, mandatoryType: 'no' },
  ],
  representative: (stix: StixCaseTask) => {
    return stix.name;
  },
  converter: convertCaseTaskToStix
};
registerDefinition(CASE_TASK_DEFINITION);
