import { ABSTRACT_STIX_CORE_RELATIONSHIP } from '../../schema/general';
import type { AttributeDefinition } from '../../schema/attribute-definition';
import { schemaAttributesDefinition } from '../../schema/schema-attributes';
import { STIX_CORE_RELATIONSHIPS } from '../../schema/stixCoreRelationship';

export const stixCoreRelationshipsAttributes: Array<AttributeDefinition> = [
  { name: 'start_time', type: 'date', mandatoryType: 'customizable', multiple: false, upsert: false, label: 'first obs.' },
  { name: 'stop_time', type: 'date', mandatoryType: 'customizable', multiple: false, upsert: false, label: 'last obs.' },
  { name: 'description', type: 'string', mandatoryType: 'customizable', multiple: false, upsert: false },
  { name: 'x_opencti_workflow_id', type: 'string', mandatoryType: 'no', multiple: false, upsert: false },
];
schemaAttributesDefinition.registerAttributes(ABSTRACT_STIX_CORE_RELATIONSHIP, stixCoreRelationshipsAttributes);
STIX_CORE_RELATIONSHIPS.map((type) => schemaAttributesDefinition.registerAttributes(type, stixCoreRelationshipsAttributes));
