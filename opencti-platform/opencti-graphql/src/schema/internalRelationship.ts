import * as R from 'ramda';
import { ABSTRACT_INTERNAL_RELATIONSHIP, schemaTypes } from './general';

export const RELATION_MIGRATES = 'migrates';
export const RELATION_MEMBER_OF = 'member-of';
export const RELATION_PARTICIPATE_TO = 'participate-to';
export const RELATION_ALLOWED_BY = 'allowed-by';
export const RELATION_HAS_ROLE = 'has-role';
export const RELATION_HAS_CAPABILITY = 'has-capability';
export const RELATION_ACCESSES_TO = 'accesses-to';
export const RELATION_HAS_REFERENCE = 'has-reference';
export const INTERNAL_RELATIONSHIPS = [
  RELATION_MIGRATES,
  RELATION_MEMBER_OF,
  RELATION_ALLOWED_BY,
  RELATION_HAS_ROLE,
  RELATION_HAS_CAPABILITY,
  RELATION_ACCESSES_TO,
  RELATION_PARTICIPATE_TO,
  RELATION_HAS_REFERENCE,
];
schemaTypes.register(ABSTRACT_INTERNAL_RELATIONSHIP, INTERNAL_RELATIONSHIPS);
export const isInternalRelationship = (type: string) => R.includes(type, INTERNAL_RELATIONSHIPS);

export const internalRelationshipsAttributes = {
  [RELATION_PARTICIPATE_TO]: [
    'internal_id',
    'standard_id',
    'entity_type',
    'start_time',
    'stop_time',
    'confidence',
    'i_inference_weight',
  ],
  [RELATION_ACCESSES_TO]: [
    'internal_id',
    'standard_id',
    'entity_type',
    'created_at',
    'i_created_at_day',
    'i_created_at_month',
    'i_created_at_year',
    'updated_at',
  ],
  [RELATION_MIGRATES]: [
    'internal_id',
    'standard_id',
    'entity_type',
    'created_at',
    'i_created_at_day',
    'i_created_at_month',
    'i_created_at_year',
    'updated_at',
  ],
  [RELATION_MEMBER_OF]: [
    'internal_id',
    'standard_id',
    'entity_type',
    'created_at',
    'i_created_at_day',
    'i_created_at_month',
    'i_created_at_year',
    'updated_at',
  ],
  [RELATION_ALLOWED_BY]: [
    'internal_id',
    'standard_id',
    'entity_type',
    'created_at',
    'i_created_at_day',
    'i_created_at_month',
    'i_created_at_year',
    'updated_at',
    'grant',
  ],
  [RELATION_HAS_ROLE]: [
    'internal_id',
    'standard_id',
    'entity_type',
    'created_at',
    'i_created_at_day',
    'i_created_at_month',
    'i_created_at_year',
    'updated_at',
  ],
  [RELATION_HAS_CAPABILITY]: [
    'internal_id',
    'standard_id',
    'entity_type',
    'created_at',
    'i_created_at_day',
    'i_created_at_month',
    'i_created_at_year',
    'updated_at',
  ],
  [RELATION_HAS_REFERENCE]: [
    'internal_id',
    'standard_id',
    'entity_type',
    'created_at',
    'i_created_at_day',
    'i_created_at_month',
    'i_created_at_year',
    'updated_at',
  ],
};
R.forEachObjIndexed((value, key) => schemaTypes.registerAttributes(key, value), internalRelationshipsAttributes);
