import {
  type AttributeDefinition,
  baseType,
  createdAt,
  creators,
  draftChange,
  draftIds,
  entityType,
  iAttributes,
  id,
  internalId,
  parentTypes,
  refreshedAt,
  standardId,
  updatedAt,
  metrics
} from '../../schema/attribute-definition';
import { schemaAttributesDefinition } from '../../schema/schema-attributes';
import { ABSTRACT_BASIC_OBJECT } from '../../schema/general';

const basicObjectAttributes: Array<AttributeDefinition> = [
  id,
  internalId,
  standardId,
  draftIds,
  draftChange,
  iAttributes,
  parentTypes,
  baseType,
  entityType,
  createdAt,
  updatedAt,
  refreshedAt,
  creators,
  metrics,
];
schemaAttributesDefinition.registerAttributes(ABSTRACT_BASIC_OBJECT, basicObjectAttributes);
