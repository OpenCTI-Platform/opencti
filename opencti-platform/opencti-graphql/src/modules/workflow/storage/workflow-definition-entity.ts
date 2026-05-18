import { ABSTRACT_INTERNAL_OBJECT } from '../../../schema/general';
import type { MappingDefinition } from '../../../schema/attribute-definition';
import { type ModuleDefinition, registerDefinition } from '../../../schema/module';
import convertWorkflowToStix from '../engine/workflow-converter';
import { ENTITY_TYPE_WORKFLOW_DEFINITION } from '../types/workflow-types';

const versionMappings: MappingDefinition<any>[] = [
  { name: 'id', label: 'Version ID', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: false },
  { name: 'timestamp', label: 'Timestamp', type: 'date', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: false },
  { name: 'createdBy', label: 'Created by', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: false },
  { name: 'content', label: 'Workflow schema', type: 'string', format: 'json', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: false },
  {
    name: 'validation_errors',
    label: 'Validation errors',
    type: 'object',
    format: 'nested',
    mandatoryType: 'no',
    editDefault: false,
    multiple: true,
    upsert: true,
    isFilterable: false,
    mappings: [
      { name: 'type', label: 'Error type', type: 'string', format: 'short', mandatoryType: 'external', editDefault: false, multiple: false, upsert: true, isFilterable: true },
      { name: 'message', label: 'Error message', type: 'string', format: 'text', mandatoryType: 'external', editDefault: false, multiple: false, upsert: true, isFilterable: true },
      {
        name: 'path',
        label: 'Affected entities',
        type: 'object',
        format: 'nested',
        mandatoryType: 'no',
        editDefault: false,
        multiple: true,
        upsert: true,
        isFilterable: false,
        mappings: [
          { name: 'id', label: 'Entity ID', type: 'string', format: 'short', mandatoryType: 'external', editDefault: false, multiple: false, upsert: true, isFilterable: false },
          { name: 'entity_type', label: 'Entity type', type: 'string', format: 'short', mandatoryType: 'external', editDefault: false, multiple: false, upsert: true, isFilterable: false },
        ],
      },
    ],
  },
];

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
    {
      name: 'published_version',
      label: 'Published Version',
      type: 'object',
      format: 'nested',
      mandatoryType: 'no',
      editDefault: false,
      multiple: false,
      upsert: true,
      isFilterable: false,
      mappings: versionMappings,
    },
    {
      name: 'draft_version',
      label: 'Draft Version',
      type: 'object',
      format: 'nested',
      mandatoryType: 'no',
      editDefault: false,
      multiple: false,
      upsert: true,
      isFilterable: false,
      mappings: versionMappings,
    },
    {
      name: 'all_versions',
      label: 'Version History',
      type: 'object',
      format: 'nested',
      mandatoryType: 'no',
      editDefault: false,
      multiple: true,
      upsert: true,
      isFilterable: false,
      mappings: versionMappings,
    },
  ],
  relations: [],
  representative: (stix: any) => {
    return stix.name;
  },
};

registerDefinition(WORKFLOW_DEFINITION_DEFINITION);
