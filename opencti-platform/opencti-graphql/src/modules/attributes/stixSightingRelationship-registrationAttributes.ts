import type { AttributeDefinition } from '../../schema/attribute-definition';
import { entityType } from '../../schema/attribute-definition';
import { schemaAttributesDefinition } from '../../schema/schema-attributes';
import { STIX_SIGHTING_RELATIONSHIP } from '../../schema/stixSightingRelationship';
import { connections } from './basicRelationship-registrationAttributes';
import { workflowId } from './stixDomainObject-registrationAttributes';

export const stixSightingRelationshipsAttributes: Array<AttributeDefinition> = [
  { ...entityType, isFilterable: false },
  { name: 'attribute_count', label: 'Count', type: 'numeric', precision: 'integer', mandatoryType: 'external', editDefault: true, multiple: false, upsert: true, isFilterable: true },
  { name: 'first_seen', label: 'First seen', type: 'date', mandatoryType: 'customizable', editDefault: true, multiple: false, upsert: true, isFilterable: true },
  { name: 'last_seen', label: 'Last seen', type: 'date', mandatoryType: 'customizable', editDefault: true, multiple: false, upsert: true, isFilterable: true },
  { name: 'description', label: 'Description', type: 'string', format: 'text', mandatoryType: 'customizable', editDefault: true, multiple: false, upsert: true, isFilterable: true },
  { name: 'x_opencti_negative', label: 'False positive', type: 'boolean', mandatoryType: 'customizable', editDefault: true, multiple: false, upsert: false, isFilterable: true },
  workflowId,
  { ...connections, isFilterable: true },
];

schemaAttributesDefinition.registerAttributes(STIX_SIGHTING_RELATIONSHIP, stixSightingRelationshipsAttributes);
