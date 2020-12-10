import * as R from 'ramda';
import { ABSTRACT_STIX_META_RELATIONSHIP, schemaTypes } from './general';

export const RELATION_CREATED_BY = 'created-by';
export const RELATION_OBJECT_MARKING = 'object-marking';
export const RELATION_OBJECT_LABEL = 'object-label';
export const RELATION_OBJECT = 'object';
export const RELATION_EXTERNAL_REFERENCE = 'external-reference';
export const RELATION_KILL_CHAIN_PHASE = 'kill-chain-phase';
const STIX_META_RELATIONSHIPS = [RELATION_CREATED_BY, RELATION_OBJECT_MARKING, RELATION_OBJECT];
const STIX_INTERNAL_META_RELATIONSHIPS = [
  RELATION_OBJECT_LABEL,
  RELATION_EXTERNAL_REFERENCE,
  RELATION_KILL_CHAIN_PHASE,
];
schemaTypes.register(ABSTRACT_STIX_META_RELATIONSHIP, [
  ...STIX_META_RELATIONSHIPS,
  ...STIX_INTERNAL_META_RELATIONSHIPS,
]);
export const isStixMetaRelationship = (type) =>
  R.includes(type, STIX_META_RELATIONSHIPS) ||
  R.includes(type, STIX_INTERNAL_META_RELATIONSHIPS) ||
  type === ABSTRACT_STIX_META_RELATIONSHIP;
export const isStixInternalMetaRelationship = (type) =>
  R.includes(type, STIX_INTERNAL_META_RELATIONSHIPS) || type === ABSTRACT_STIX_META_RELATIONSHIP;
