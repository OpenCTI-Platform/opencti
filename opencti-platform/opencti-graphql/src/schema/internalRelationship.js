import * as R from 'ramda';

export const RELATION_AUTHORIZED_BY = 'authorized-by';
export const RELATION_MIGRATES = 'migrates';
export const RELATION_MEMBER_OF = 'member-of';
export const RELATION_ALLOWED_BY = 'allowed-by';
export const RELATION_HAS_ROLE = 'has-role';
export const RELATION_HAS_CAPABILITY = 'has-capability';
const INTERNAL_RELATIONSHIPS = [
  RELATION_AUTHORIZED_BY,
  RELATION_MIGRATES,
  RELATION_MEMBER_OF,
  RELATION_ALLOWED_BY,
  RELATION_HAS_ROLE,
  RELATION_HAS_CAPABILITY,
];
export const isInternalRelationship = (type) => R.includes(type, INTERNAL_RELATIONSHIPS);
