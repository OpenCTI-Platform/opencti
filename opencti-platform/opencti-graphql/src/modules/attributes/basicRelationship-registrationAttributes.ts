import {
  AttributeDefinition,
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
  { name: 'fromType', type: 'string', mandatoryType: 'internal', multiple: false, upsert: false },
  { name: 'toType', type: 'string', mandatoryType: 'internal', multiple: false, upsert: false },
  { name: 'i_inference_weight', type: 'numeric', precision: 'integer', mandatoryType: 'no', multiple: false, upsert: false },
  {
    name: 'connections',
    type: 'object',
    nested: true,
    mandatoryType: 'internal',
    multiple: true,
    upsert: false,
    mappings: [
      internalId,
      { name: 'name', type: 'string', mandatoryType: 'no', multiple: true, upsert: true },
      { name: 'role', type: 'string', mandatoryType: 'no', multiple: true, upsert: true },
      { name: 'types', type: 'string', mandatoryType: 'no', multiple: true, upsert: true },
    ]
  },
];
schemaAttributesDefinition.registerAttributes(ABSTRACT_BASIC_RELATIONSHIP, basicRelationshipAttributes);
