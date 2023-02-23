import * as R from 'ramda';
import {
  AttributeDefinition,
  confidence, created,
  createdAt,
  entityType,
  IcreatedAtDay,
  IcreatedAtMonth,
  IcreatedAtYear,
  internalId, lang, modified, relationshipType, revoked, specVersion,
  standardId, updatedAt, xOpenctiStixIds
} from './attribute-definition';
import { schemaAttributesDefinition } from './schema-attributes';

export const STIX_SIGHTING_RELATIONSHIP = 'stix-sighting-relationship';

export const isStixSightingRelationship = (type: string): boolean => type === STIX_SIGHTING_RELATIONSHIP;

export const stixSightingRelationshipsAttributes: { [k: string]: Array<AttributeDefinition> } = {
  [STIX_SIGHTING_RELATIONSHIP]: [
    internalId,
    standardId,
    entityType,
    createdAt,
    IcreatedAtDay,
    IcreatedAtMonth,
    IcreatedAtYear,
    updatedAt,
    xOpenctiStixIds,
    specVersion,
    revoked,
    confidence,
    lang,
    created,
    modified,
    relationshipType,
    { name: 'description', type: 'string', mandatoryType: 'no', multiple: false, upsert: false },
    { name: 'first_seen', type: 'date', mandatoryType: 'no', multiple: false, upsert: false },
    { name: 'i_first_seen_day', type: 'date', mandatoryType: 'no', multiple: false, upsert: false },
    { name: 'i_first_seen_month', type: 'date', mandatoryType: 'no', multiple: false, upsert: false },
    { name: 'i_first_seen_year', type: 'string', mandatoryType: 'no', multiple: false, upsert: false }, //  Not in add Input
    { name: 'last_seen', type: 'date', mandatoryType: 'no', multiple: false, upsert: false },
    { name: 'i_last_seen_day', type: 'date', mandatoryType: 'no', multiple: false, upsert: false }, //
    { name: 'i_last_seen_month', type: 'date', mandatoryType: 'no', multiple: false, upsert: false }, //
    { name: 'i_last_seen_year', type: 'string', mandatoryType: 'no', multiple: false, upsert: false }, //
    { name: 'attribute_count', type: 'numeric', mandatoryType: 'internal', multiple: false, upsert: false },
    { name: 'x_opencti_negative', type: 'boolean', mandatoryType: 'no', multiple: false, upsert: false },
    { name: 'i_inference_weight', type: 'string', mandatoryType: 'no', multiple: false, upsert: false },
    { name: 'x_opencti_workflow_id', type: 'string', mandatoryType: 'no', multiple: false, upsert: false },
  ],
};
R.forEachObjIndexed((value, key) => schemaAttributesDefinition.registerAttributes(key as string, value), stixSightingRelationshipsAttributes);
