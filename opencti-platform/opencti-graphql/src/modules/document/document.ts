import { ENTITY_TYPE_INTERNAL_FILE } from '../../schema/internalObject';
import { schemaAttributesDefinition } from '../../schema/schema-attributes';
import type { AttributeDefinition } from '../../schema/attribute-definition';

const attributes: Array<AttributeDefinition> = [
  { name: 'lastModified', type: 'date', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false },
];

schemaAttributesDefinition.registerAttributes(ENTITY_TYPE_INTERNAL_FILE, attributes);
