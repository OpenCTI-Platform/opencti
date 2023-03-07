import {
  AttributeDefinition,
  createdAt,
  entityType,
  internalId,
  standardId,
  updatedAt
} from '../../schema/attribute-definition';
import { schemaAttributesDefinition } from '../../schema/schema-attributes';
import { ABSTRACT_BASIC_RELATIONSHIP } from '../../schema/general';

const basicRelationshipAttributes: Array<AttributeDefinition> = [
  internalId,
  standardId,
  entityType,
  createdAt,
  updatedAt,
  { name: 'i_inference_weight', type: 'string', mandatoryType: 'no', multiple: false, upsert: false },
];
schemaAttributesDefinition.registerAttributes(ABSTRACT_BASIC_RELATIONSHIP, basicRelationshipAttributes);
