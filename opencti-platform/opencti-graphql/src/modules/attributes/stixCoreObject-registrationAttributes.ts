import { schemaAttributesDefinition } from '../../schema/schema-attributes';
import { ABSTRACT_STIX_CORE_OBJECT } from '../../schema/general';
import type { AttributeDefinition } from '../../schema/attribute-definition';

const stixCoreObjectAttributes: Array<AttributeDefinition> = [];
schemaAttributesDefinition.registerAttributes(ABSTRACT_STIX_CORE_OBJECT, stixCoreObjectAttributes);
