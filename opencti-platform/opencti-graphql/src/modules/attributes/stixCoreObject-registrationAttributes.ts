import { schemaAttributesDefinition } from '../../schema/schema-attributes';
import { ABSTRACT_STIX_CORE_OBJECT, ABSTRACT_STIX_CYBER_OBSERVABLE, ABSTRACT_STIX_DOMAIN_OBJECT } from '../../schema/general';
import type { AttributeDefinition } from '../../schema/attribute-definition';
import { schemaTypesDefinition } from '../../schema/schema-types';

const stixCoreObjectAttributes: Array<AttributeDefinition> = [];
schemaTypesDefinition.add(
  ABSTRACT_STIX_CORE_OBJECT,
  [ABSTRACT_STIX_DOMAIN_OBJECT, ABSTRACT_STIX_CYBER_OBSERVABLE],
);
schemaAttributesDefinition.registerAttributes(ABSTRACT_STIX_CORE_OBJECT, stixCoreObjectAttributes);
