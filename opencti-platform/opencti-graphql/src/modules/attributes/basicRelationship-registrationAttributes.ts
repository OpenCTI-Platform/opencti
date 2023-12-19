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
  { name: 'fromType', type: 'string', editDefault: false, mandatoryType: 'internal', multiple: false, upsert: false },
  { name: 'toType', type: 'string', editDefault: false, mandatoryType: 'internal', multiple: false, upsert: false },
  { name: 'i_inference_weight', type: 'numeric', precision: 'integer', editDefault: false, mandatoryType: 'no', multiple: false, upsert: false },
  {
    name: 'connections',
    type: 'object',
    editDefault: false,
    nested: true,
    mandatoryType: 'internal',
    multiple: true,
    upsert: false,
    mappings: [
      internalId,
      { name: 'name', type: 'string', editDefault: false, mandatoryType: 'no', multiple: true, upsert: true },
      { name: 'role', type: 'string', editDefault: false, mandatoryType: 'no', multiple: true, upsert: true },
      { name: 'types', type: 'string', editDefault: false, mandatoryType: 'no', multiple: true, upsert: true },
    ]
  },
];
schemaAttributesDefinition.registerAttributes(ABSTRACT_BASIC_RELATIONSHIP, basicRelationshipAttributes);
