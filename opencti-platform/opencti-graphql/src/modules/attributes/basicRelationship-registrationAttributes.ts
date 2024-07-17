import {
  type AttributeDefinition,
  baseType,
  createdAt,
  creators,
  entityType,
  iAttributes,
  id,
  liveId,
  type IdAttribute,
  internalId,
  parentTypes,
  relationshipType,
  standardId,
  updatedAt,
  draftIds,
  draftChange
} from '../../schema/attribute-definition';
import { schemaAttributesDefinition } from '../../schema/schema-attributes';
import { ABSTRACT_BASIC_RELATIONSHIP } from '../../schema/general';
import {
  INSTANCE_RELATION_TYPES_FILTER,
  INSTANCE_RELATION_FILTER,
  RELATION_FROM_FILTER,
  RELATION_FROM_TYPES_FILTER,
  RELATION_TO_FILTER,
  RELATION_TO_TYPES_FILTER
} from '../../utils/filtering/filtering-constants';

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
        { key: RELATION_FROM_FILTER, label: 'Source entity' },
        { key: RELATION_TO_FILTER, label: 'Target entity' },
        { key: INSTANCE_RELATION_FILTER, label: 'Related entity' }
      ]
    },
    { name: 'name', label: 'Name', type: 'string', format: 'short', editDefault: false, mandatoryType: 'no', multiple: true, upsert: true, isFilterable: false },
    { name: 'role', label: 'Role', type: 'string', format: 'short', editDefault: false, mandatoryType: 'no', multiple: true, upsert: true, isFilterable: false },
    { name: 'types', label: 'Types', type: 'string', format: 'short', editDefault: false, mandatoryType: 'no', multiple: true, upsert: true, isFilterable: false, associatedFilterKeys: [{ key: RELATION_FROM_TYPES_FILTER, label: 'Source type' }, { key: RELATION_TO_TYPES_FILTER, label: 'Target type' }, { key: INSTANCE_RELATION_TYPES_FILTER, label: 'Related type' }] },
  ],
};

const basicRelationshipAttributes: Array<AttributeDefinition> = [
  id,
  liveId,
  draftIds,
  draftChange,
  internalId,
  standardId,
  iAttributes,
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
