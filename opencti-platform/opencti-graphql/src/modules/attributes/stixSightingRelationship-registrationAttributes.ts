import * as R from 'ramda';
import type { AttributeDefinition } from '../../schema/attribute-definition';
import { schemaAttributesDefinition } from '../../schema/schema-attributes';
import { STIX_SIGHTING_RELATIONSHIP } from '../../schema/stixSightingRelationship';

export const stixSightingRelationshipsAttributes: { [k: string]: Array<AttributeDefinition> } = {
  [STIX_SIGHTING_RELATIONSHIP]: [
    { name: 'attribute_count', label: 'Count', type: 'numeric', precision: 'integer', mandatoryType: 'external', editDefault: true, multiple: false, upsert: false, isFilterable: true },
    { name: 'first_seen', label: 'First seen', type: 'date', mandatoryType: 'customizable', editDefault: true, multiple: false, upsert: false, isFilterable: true },
    { name: 'last_seen', label: 'Last seen', type: 'date', mandatoryType: 'customizable', editDefault: true, multiple: false, upsert: false, isFilterable: true },
    { name: 'description', label: 'Description', type: 'string', format: 'short', mandatoryType: 'customizable', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    { name: 'x_opencti_negative', label: 'False positive', type: 'boolean', mandatoryType: 'customizable', editDefault: true, multiple: false, upsert: false, isFilterable: true },
    { name: 'x_opencti_workflow_id', label: 'Workflow status', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
  ],
};
R.forEachObjIndexed((value, key) => schemaAttributesDefinition.registerAttributes(key as string, value), stixSightingRelationshipsAttributes);
