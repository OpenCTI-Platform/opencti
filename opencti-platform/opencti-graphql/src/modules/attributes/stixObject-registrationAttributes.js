import { created, files, modified, xOpenctiStixIds } from '../../schema/attribute-definition';
import { schemaAttributesDefinition } from '../../schema/schema-attributes';
import { ABSTRACT_STIX_OBJECT } from '../../schema/general';
const stixObjectAttributes = [
    xOpenctiStixIds,
    created,
    modified,
    files,
];
schemaAttributesDefinition.registerAttributes(ABSTRACT_STIX_OBJECT, stixObjectAttributes);
