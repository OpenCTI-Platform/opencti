import * as R from 'ramda';
import type { AttributeDefinition } from '../../schema/attribute-definition';
import { schemaAttributesDefinition } from '../../schema/schema-attributes';
import { STIX_SIGHTING_RELATIONSHIP } from '../../schema/stixSightingRelationship';

export const stixSightingRelationshipsAttributes: { [k: string]: Array<AttributeDefinition> } = {
  [STIX_SIGHTING_RELATIONSHIP]: [
    { name: 'description', type: 'string', mandatoryType: 'no', multiple: false, upsert: false },
    { name: 'first_seen', type: 'date', mandatoryType: 'no', multiple: false, upsert: false },
    { name: 'last_seen', type: 'date', mandatoryType: 'no', multiple: false, upsert: false },
    { name: 'attribute_count', type: 'numeric', mandatoryType: 'external', multiple: false, upsert: false },
    { name: 'x_opencti_negative', type: 'boolean', mandatoryType: 'no', multiple: false, upsert: false },
    { name: 'x_opencti_workflow_id', type: 'string', mandatoryType: 'no', multiple: false, upsert: false },
  ],
};
R.forEachObjIndexed((value, key) => schemaAttributesDefinition.registerAttributes(key as string, value), stixSightingRelationshipsAttributes);
