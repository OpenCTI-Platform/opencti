import {
  type AttributeDefinition,
  baseType,
  createdAt,
  creators,
  entityType,
  id,
  type IdAttribute,
  internalId,
  parentTypes,
  relationshipType,
  standardId,
  updatedAt
} from '../../schema/attribute-definition';
import { schemaAttributesDefinition } from '../../schema/schema-attributes';
import { ABSTRACT_BASIC_RELATIONSHIP } from '../../schema/general';
import { INSTANCE_RELATION_FILTER } from '../../utils/filtering/filtering-constants';

export const connections: AttributeDefinition = {
  name: 'connections',
  label: 'Relations connections',
  type: 'object',
  format: 'nested',
  editDefault: false,
  mandatoryType: 'internal',
  multiple: true,
  upsert: false,
  update: false,
  isFilterable: false,
  mappings: [
    { ...internalId as IdAttribute,
      associatedFilterKeys: [
        { key: 'fromId', label: 'Source entity' },
        { key: 'toId', label: 'Target entity' },
        { key: INSTANCE_RELATION_FILTER, label: 'Related entity' }
      ]
    },
    { name: 'name', label: 'Name', type: 'string', format: 'short', editDefault: false, mandatoryType: 'no', multiple: true, upsert: true, isFilterable: false },
    { name: 'role', label: 'Role', type: 'string', format: 'short', editDefault: false, mandatoryType: 'no', multiple: true, upsert: true, isFilterable: false },
    { name: 'types', label: 'Types', type: 'string', format: 'short', editDefault: false, mandatoryType: 'no', multiple: true, upsert: true, isFilterable: false, associatedFilterKeys: [{ key: 'fromTypes', label: 'Source type' }, { key: 'toTypes', label: 'Target type' }] },
  ],
};

const basicRelationshipAttributes: Array<AttributeDefinition> = [
  id,
  internalId,
  standardId,
  parentTypes,
  baseType,
  { ...relationshipType, isFilterable: false },
  entityType,
  createdAt,
  updatedAt,
  creators,
  { name: 'i_inference_weight', label: 'Inference weight', type: 'numeric', precision: 'integer', update: false, editDefault: false, mandatoryType: 'no', multiple: false, upsert: false, isFilterable: false },
  connections,
];
schemaAttributesDefinition.registerAttributes(ABSTRACT_BASIC_RELATIONSHIP, basicRelationshipAttributes);
