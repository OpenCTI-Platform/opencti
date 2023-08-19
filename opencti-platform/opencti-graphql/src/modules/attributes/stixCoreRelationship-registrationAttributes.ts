import { ABSTRACT_STIX_CORE_RELATIONSHIP } from '../../schema/general';
import type { AttributeDefinition } from '../../schema/attribute-definition';
import { schemaAttributesDefinition } from '../../schema/schema-attributes';

export const stixCoreRelationshipsAttributes: Array<AttributeDefinition> = [
  { name: 'start_time', type: 'date', mandatoryType: 'customizable', editDefault: true, multiple: false, upsert: false, label: 'first obs.' },
  { name: 'stop_time', type: 'date', mandatoryType: 'customizable', editDefault: true, multiple: false, upsert: false, label: 'last obs.' },
  { name: 'description', type: 'string', mandatoryType: 'customizable', editDefault: true, multiple: false, upsert: true },
  { name: 'x_opencti_workflow_id', type: 'string', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false },
];
schemaAttributesDefinition.registerAttributes(ABSTRACT_STIX_CORE_RELATIONSHIP, stixCoreRelationshipsAttributes);
