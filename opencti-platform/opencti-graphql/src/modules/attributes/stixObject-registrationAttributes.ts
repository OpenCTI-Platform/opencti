import { type AttributeDefinition, files, xOpenctiStixIds } from '../../schema/attribute-definition';
import { schemaAttributesDefinition } from '../../schema/schema-attributes';
import { ABSTRACT_STIX_OBJECT } from '../../schema/general';

const stixObjectAttributes: Array<AttributeDefinition<any>> = [
  xOpenctiStixIds,
  files,
];
schemaAttributesDefinition.registerAttributes(ABSTRACT_STIX_OBJECT, stixObjectAttributes);
