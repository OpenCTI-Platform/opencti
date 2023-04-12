import type { AttributeDefinition } from '../../schema/attribute-definition';
import { schemaAttributesDefinition } from '../../schema/schema-attributes';
import { ABSTRACT_STIX_REF_RELATIONSHIP } from '../../schema/general';

// -- ATTRIBUTES -

const stixRefRelationshipsAttributes: AttributeDefinition[] = [
  { name: 'start_time', type: 'date', mandatoryType: 'no', multiple: false, upsert: false },
  { name: 'stop_time', type: 'date', mandatoryType: 'no', multiple: false, upsert: false },
];

schemaAttributesDefinition.registerAttributes(ABSTRACT_STIX_REF_RELATIONSHIP, stixRefRelationshipsAttributes);
