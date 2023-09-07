import {
  type AttributeDefinition,
  created,
  files,
  modified,
  specVersion,
  xOpenctiStixIds
} from '../../schema/attribute-definition';
import { schemaAttributesDefinition } from '../../schema/schema-attributes';
import { ABSTRACT_STIX_OBJECT } from '../../schema/general';

const stixObjectAttributes: Array<AttributeDefinition> = [
  xOpenctiStixIds,
  specVersion,
  created,
  modified,
  files,
];
schemaAttributesDefinition.registerAttributes(ABSTRACT_STIX_OBJECT, stixObjectAttributes);
