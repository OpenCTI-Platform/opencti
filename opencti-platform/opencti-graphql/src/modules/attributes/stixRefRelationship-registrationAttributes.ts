import type { AttributeDefinition, NestedObjectAttribute } from '../../schema/attribute-definition';
import { schemaAttributesDefinition } from '../../schema/schema-attributes';
import { ABSTRACT_STIX_REF_RELATIONSHIP } from '../../schema/general';
import { connections } from './basicRelationship-registrationAttributes';

// -- ATTRIBUTES -

const stixRefRelationshipsAttributes: AttributeDefinition[] = [
  {
    ...connections as NestedObjectAttribute,
    isFilterable: true,
  },
  { name: 'start_time', label: 'Start date', type: 'date', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: true },
  { name: 'stop_time', label: 'End date', type: 'date', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: true },
];

schemaAttributesDefinition.registerAttributes(ABSTRACT_STIX_REF_RELATIONSHIP, stixRefRelationshipsAttributes);
