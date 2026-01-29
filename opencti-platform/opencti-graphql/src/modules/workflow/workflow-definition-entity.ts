import { ABSTRACT_INTERNAL_OBJECT } from '../../schema/general';
import { type ModuleDefinition, registerDefinition } from '../../schema/module';
import convertWorkflowToStix from './workflow-converter';
import { ENTITY_TYPE_WORKFLOW_DEFINITION } from './workflow-types';

const WORKFLOW_DEFINITION_DEFINITION: ModuleDefinition<any, any> = {
  type: {
    id: 'workflowdefinitions',
    name: ENTITY_TYPE_WORKFLOW_DEFINITION,
    category: ABSTRACT_INTERNAL_OBJECT,
    aliased: false,
  },
  identifier: {
    definition: {
      [ENTITY_TYPE_WORKFLOW_DEFINITION]: [{ src: 'name' }],
    },
    resolvers: {},
  },
  converter_2_1: convertWorkflowToStix,
  attributes: [
    { name: 'name', label: 'Name', type: 'string', format: 'short', mandatoryType: 'external', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    { name: 'description', label: 'Description', type: 'string', format: 'text', mandatoryType: 'no', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    { name: 'workflow_content', label: 'Workflow content', type: 'string', format: 'json', mandatoryType: 'external', editDefault: true, multiple: false, upsert: true, isFilterable: false },
  ],
  relations: [],
  representative: (stix: any) => {
    return stix.name;
  },
};

registerDefinition(WORKFLOW_DEFINITION_DEFINITION);
