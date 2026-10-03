import { ABSTRACT_INTERNAL_OBJECT } from '../../../schema/general';
import { type InternalObjectModuleDefinition, registerInternalObjectDefinition } from '../../../schema/module';
import { ENTITY_TYPE_WORKFLOW_INSTANCE } from '../types/workflow-types';

const WORKFLOW_INSTANCE_DEFINITION: InternalObjectModuleDefinition = {
  type: {
    id: 'workflowinstances',
    name: ENTITY_TYPE_WORKFLOW_INSTANCE,
    category: ABSTRACT_INTERNAL_OBJECT,
    aliased: false,
  },
  identifier: {
    definition: {
      [ENTITY_TYPE_WORKFLOW_INSTANCE]: [{ src: 'entity_id' }],
    },
    resolvers: {},
  },
  attributes: [
    { name: 'entity_id', label: 'Entity ID', type: 'string', format: 'short', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: true, isFilterable: true },
    { name: 'workflow_id', label: 'Workflow Definition ID', type: 'string', format: 'short', mandatoryType: 'external', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'currentState', label: 'Current State', type: 'string', format: 'short', mandatoryType: 'external', editDefault: true, multiple: false, upsert: false, isFilterable: true },
    { name: 'history', label: 'History', type: 'string', format: 'json', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'pendingStatus', label: 'Pending Status', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'pendingError', label: 'Pending Error', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'pendingTransition', label: 'Pending Transition', type: 'string', format: 'json', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
  ],
  relations: [],
};

registerInternalObjectDefinition(WORKFLOW_INSTANCE_DEFINITION);
