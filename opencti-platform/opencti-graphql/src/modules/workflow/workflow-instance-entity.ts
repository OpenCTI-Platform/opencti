import { ABSTRACT_INTERNAL_OBJECT } from '../../schema/general';
import { type ModuleDefinition, registerDefinition } from '../../schema/module';
import convertWorkflowToStix from './workflow-converter';
import { ENTITY_TYPE_WORKFLOW_INSTANCE } from './workflow-types';

const WORKFLOW_INSTANCE_DEFINITION: ModuleDefinition<any, any> = {
  type: {
    id: 'workflowinstances',
    name: ENTITY_TYPE_WORKFLOW_INSTANCE,
    category: ABSTRACT_INTERNAL_OBJECT,
    aliased: false,
  },
  identifier: {
    definition: {
      [ENTITY_TYPE_WORKFLOW_INSTANCE]: [{ src: 'workflow_id' }, { src: 'currentState' }],
    },
    resolvers: {},
  },
  converter_2_1: convertWorkflowToStix,
  attributes: [
    { name: 'workflow_id', label: 'Workflow Definition ID', type: 'string', format: 'short', mandatoryType: 'external', editDefault: false, multiple: false, upsert: true, isFilterable: true },
    { name: 'currentState', label: 'Current State', type: 'string', format: 'short', mandatoryType: 'external', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    { name: 'history', label: 'History', type: 'string', format: 'json', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: false },
  ],
  relations: [],
  representative: (stix: any) => {
    return stix.currentState;
  },
};

registerDefinition(WORKFLOW_INSTANCE_DEFINITION);
