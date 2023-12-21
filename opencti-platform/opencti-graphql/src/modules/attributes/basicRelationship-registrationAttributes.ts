import {
  type AttributeDefinition,
  baseType,
  createdAt,
  creators,
  entityType,
  id,
  internalId,
  parentTypes,
  relationshipType,
  standardId,
  updatedAt
} from '../../schema/attribute-definition';
import { schemaAttributesDefinition } from '../../schema/schema-attributes';
import { ABSTRACT_BASIC_RELATIONSHIP } from '../../schema/general';

const basicRelationshipAttributes: Array<AttributeDefinition> = [
  id,
  internalId,
  standardId,
  parentTypes,
  baseType,
  relationshipType,
  entityType,
  createdAt,
  updatedAt,
  creators,
  { name: 'fromType', label: 'Source entity', type: 'string', editDefault: false, mandatoryType: 'internal', multiple: false, upsert: false, isFilterable: true }, // TODO to remove ?
  { name: 'toType', label: 'Target entity', type: 'string', editDefault: false, mandatoryType: 'internal', multiple: false, upsert: false, isFilterable: true }, // TODO to remove?
  { name: 'i_inference_weight', label: 'Inference weight', type: 'numeric', precision: 'integer', editDefault: false, mandatoryType: 'no', multiple: false, upsert: false, isFilterable: true },
  {
    name: 'connections',
    label: 'Relations connections',
    type: 'object',
    editDefault: false,
    nested: true,
    mandatoryType: 'internal',
    multiple: true,
    upsert: false,
    isFilterable: true,
    mappings: [
      { ...internalId, isFilterable: true, associatedFilterKeys: ['fromId', 'toId', 'elementId'] },
      { name: 'name', label: 'Name', type: 'string', editDefault: false, mandatoryType: 'no', multiple: true, upsert: true, isFilterable: false },
      { name: 'role', label: 'Role', type: 'string', editDefault: false, mandatoryType: 'no', multiple: true, upsert: true, isFilterable: false },
      { name: 'types', label: 'Types', type: 'string', editDefault: false, mandatoryType: 'no', multiple: true, upsert: true, isFilterable: true, associatedFilterKeys: ['fromTypes', 'toTypes'] },
    ],
  },
];
schemaAttributesDefinition.registerAttributes(ABSTRACT_BASIC_RELATIONSHIP, basicRelationshipAttributes);
