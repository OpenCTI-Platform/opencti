import { ENTITY_TYPE_INTERNAL_FILE } from '../../../schema/internalObject';
import { schemaAttributesDefinition } from '../../../schema/schema-attributes';
import type { AttributeDefinition } from '../../../schema/attribute-definition';

// Register at minimum lastModified attribute
// This way the search engine is able to order by lastModified
const attributes: Array<AttributeDefinition> = [
  { name: 'lastModified', label: 'Last modification date', type: 'date', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
];

schemaAttributesDefinition.registerAttributes(ENTITY_TYPE_INTERNAL_FILE, attributes);
