import type { AttributeDefinition } from '../../schema/attribute-definition';
import { schemaAttributesDefinition } from '../../schema/schema-attributes';
import { ABSTRACT_STIX_RELATIONSHIP } from '../../schema/general';
import {
  confidence,
  created,
  creators, lang,
  modified, relationshipType,
  revoked,
  specVersion,
  xOpenctiStixIds
} from '../../schema/attribute-definition';

const stixRelationshipAttributes: Array<AttributeDefinition> = [
  xOpenctiStixIds,
  specVersion,
  creators,
  created,
  modified,
  revoked,
  confidence,
  lang,
  relationshipType,
];
schemaAttributesDefinition.registerAttributes(ABSTRACT_STIX_RELATIONSHIP, stixRelationshipAttributes);
