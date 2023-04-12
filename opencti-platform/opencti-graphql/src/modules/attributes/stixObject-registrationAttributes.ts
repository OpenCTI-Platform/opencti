import {
  AttributeDefinition,
  created,
  creators, modified,
  specVersion,
  xOpenctiStixIds
} from '../../schema/attribute-definition';
import { schemaAttributesDefinition } from '../../schema/schema-attributes';
import { ABSTRACT_STIX_OBJECT } from '../../schema/general';

const stixObjectAttributes: Array<AttributeDefinition> = [
  xOpenctiStixIds,
  specVersion,
  creators,
  created,
  modified,
];
schemaAttributesDefinition.registerAttributes(ABSTRACT_STIX_OBJECT, stixObjectAttributes);
