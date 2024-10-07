import {
  type AttributeDefinition,
  baseType,
  createdAt,
  creators,
  draftIds,
  entityType,
  iAttributes,
  id,
  internalId,
  parentTypes,
  standardId,
  updatedAt
} from '../../schema/attribute-definition';
import { schemaAttributesDefinition } from '../../schema/schema-attributes';
import { ABSTRACT_BASIC_OBJECT } from '../../schema/general';

const basicObjectAttributes: Array<AttributeDefinition> = [
  id,
  internalId,
  standardId,
  draftIds,
  iAttributes,
  parentTypes,
  baseType,
  entityType,
  createdAt,
  updatedAt,
  creators,
];
schemaAttributesDefinition.registerAttributes(ABSTRACT_BASIC_OBJECT, basicObjectAttributes);
