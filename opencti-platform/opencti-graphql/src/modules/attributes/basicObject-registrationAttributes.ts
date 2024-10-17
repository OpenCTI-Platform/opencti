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
  liveId,
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
  liveId,
  draftIds,
  draftChange,
  iAttributes,
  parentTypes,
  baseType,
  entityType,
  createdAt,
  updatedAt,
  creators,
];
schemaAttributesDefinition.registerAttributes(ABSTRACT_BASIC_OBJECT, basicObjectAttributes);
