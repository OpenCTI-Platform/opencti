import * as R from 'ramda';
import { ABSTRACT_INTERNAL_RELATIONSHIP } from './general';
import { AttributeDefinition, createdAt, entityType, internalId, standardId, updatedAt } from './attribute-definition';
import { schemaAttributesDefinition } from './schema-attributes';

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
schemaAttributesDefinition.register(ABSTRACT_INTERNAL_RELATIONSHIP, INTERNAL_RELATIONSHIPS);
export const isInternalRelationship = (type: string) => schemaAttributesDefinition.isTypeIncludedIn(type, ABSTRACT_INTERNAL_RELATIONSHIP)
|| type === ABSTRACT_INTERNAL_RELATIONSHIP;

export const internalRelationshipsAttributes: { [k: string]: Array<AttributeDefinition> } = {
  [RELATION_PARTICIPATE_TO]: [
    internalId,
    standardId,
    entityType,

    { name: 'start_time', type: 'date', mandatoryType: 'no', multiple: false, upsert: false },
    { name: 'stop_time', type: 'date', mandatoryType: 'no', multiple: false, upsert: false },
    { name: 'confidence', type: 'numeric', mandatoryType: 'no', multiple: false, upsert: false },
    { name: 'i_inference_weight', type: 'string', mandatoryType: 'no', multiple: false, upsert: false },
  ],
  [RELATION_ACCESSES_TO]: [
    internalId,
    standardId,
    entityType,
    createdAt,
    updatedAt,

    { name: 'i_created_at_day', type: 'date', mandatoryType: 'no', multiple: false, upsert: false },
    { name: 'i_created_at_month', type: 'date', mandatoryType: 'no', multiple: false, upsert: false },
    { name: 'i_created_at_year', type: 'string', mandatoryType: 'no', multiple: false, upsert: false }
  ],
  [RELATION_MIGRATES]: [
    internalId,
    standardId,
    entityType,
    createdAt,
    updatedAt,

    { name: 'i_created_at_day', type: 'date', mandatoryType: 'no', multiple: false, upsert: false },
    { name: 'i_created_at_month', type: 'date', mandatoryType: 'no', multiple: false, upsert: false },
    { name: 'i_created_at_year', type: 'string', mandatoryType: 'no', multiple: false, upsert: false }
  ],
  [RELATION_MEMBER_OF]: [
    internalId,
    standardId,
    entityType,
    createdAt,
    updatedAt,

    { name: 'i_created_at_day', type: 'date', mandatoryType: 'no', multiple: false, upsert: false },
    { name: 'i_created_at_month', type: 'date', mandatoryType: 'no', multiple: false, upsert: false },
    { name: 'i_created_at_year', type: 'string', mandatoryType: 'no', multiple: false, upsert: false }
  ],
  [RELATION_ALLOWED_BY]: [
    internalId,
    standardId,
    entityType,
    createdAt,
    updatedAt,

    { name: 'i_created_at_day', type: 'date', mandatoryType: 'no', multiple: false, upsert: false },
    { name: 'i_created_at_month', type: 'date', mandatoryType: 'no', multiple: false, upsert: false },
    { name: 'i_created_at_year', type: 'string', mandatoryType: 'no', multiple: false, upsert: false },
    { name: 'grant', type: 'string', mandatoryType: 'no', multiple: true, upsert: false }
  ],
  [RELATION_HAS_ROLE]: [
    internalId,
    standardId,
    entityType,
    createdAt,
    updatedAt,

    { name: 'i_created_at_day', type: 'date', mandatoryType: 'no', multiple: false, upsert: false },
    { name: 'i_created_at_month', type: 'date', mandatoryType: 'no', multiple: false, upsert: false },
    { name: 'i_created_at_year', type: 'string', mandatoryType: 'no', multiple: false, upsert: false }
  ],
  [RELATION_HAS_CAPABILITY]: [
    internalId,
    standardId,
    entityType,
    createdAt,
    updatedAt,

    { name: 'i_created_at_day', type: 'date', mandatoryType: 'no', multiple: false, upsert: false },
    { name: 'i_created_at_month', type: 'date', mandatoryType: 'no', multiple: false, upsert: false },
    { name: 'i_created_at_year', type: 'string', mandatoryType: 'no', multiple: false, upsert: false }
  ],
  [RELATION_HAS_REFERENCE]: [
    internalId,
    standardId,
    entityType,
    createdAt,
    updatedAt,

    { name: 'i_created_at_day', type: 'date', mandatoryType: 'no', multiple: false, upsert: false },
    { name: 'i_created_at_month', type: 'date', mandatoryType: 'no', multiple: false, upsert: false },
    { name: 'i_created_at_year', type: 'string', mandatoryType: 'no', multiple: false, upsert: false }
  ],
};
R.forEachObjIndexed((value, key) => schemaAttributesDefinition.registerAttributes(key as string, value), internalRelationshipsAttributes);
