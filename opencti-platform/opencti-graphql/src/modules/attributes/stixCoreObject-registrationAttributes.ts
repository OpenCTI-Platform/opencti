import { schemaAttributesDefinition } from '../../schema/schema-attributes';
import { ABSTRACT_STIX_CORE_OBJECT } from '../../schema/general';
import type { AttributeDefinition } from '../../schema/attribute-definition';
import { schemaTypesDefinition } from '../../schema/schema-types';
import { STIX_CYBER_OBSERVABLES } from '../../schema/stixCyberObservable';
import { STIX_DOMAIN_OBJECTS } from '../../schema/stixDomainObject';

const stixCoreObjectAttributes: Array<AttributeDefinition> = [];
schemaTypesDefinition.register(ABSTRACT_STIX_CORE_OBJECT, STIX_CYBER_OBSERVABLES.concat(STIX_DOMAIN_OBJECTS));
schemaAttributesDefinition.registerAttributes(ABSTRACT_STIX_CORE_OBJECT, stixCoreObjectAttributes);
