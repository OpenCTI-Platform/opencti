import * as R from 'ramda';
import { schemaTypes } from './general';

export const STIX_SIGHTING_RELATIONSHIP = 'stix-sighting-relationship';

export const isStixSightingRelationship = (type: string): boolean => type === STIX_SIGHTING_RELATIONSHIP;

export const stixSightingRelationshipsAttributes: { [k: string]: Array<string> } = {
  [STIX_SIGHTING_RELATIONSHIP]: [
    'internal_id',
    'standard_id',
    'entity_type',
    'created_at',
    'i_created_at_day',
    'i_created_at_month',
    'i_created_at_year',
    'updated_at',
    'x_opencti_stix_ids',
    'spec_version',
    'revoked',
    'confidence',
    'lang',
    'created',
    'modified',
    'relationship_type',
    'description',
    'first_seen',
    'i_first_seen_day',
    'i_first_seen_month',
    'i_first_seen_year',
    'last_seen',
    'i_last_seen_day',
    'i_last_seen_month',
    'i_last_seen_year',
    'attribute_count',
    'x_opencti_negative',
    'i_inference_weight',
    'x_opencti_workflow_id',
  ],
};
R.forEachObjIndexed((value, key) => schemaTypes.registerAttributes(key, value), stixSightingRelationshipsAttributes);
