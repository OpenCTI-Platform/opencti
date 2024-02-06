import { schemaAttributesDefinition } from '../../schema/schema-attributes';
import { ABSTRACT_STIX_CORE_OBJECT } from '../../schema/general';
const stixCoreObjectAttributes = []; // TODO add all the attributes
schemaAttributesDefinition.registerAttributes(ABSTRACT_STIX_CORE_OBJECT, stixCoreObjectAttributes);
