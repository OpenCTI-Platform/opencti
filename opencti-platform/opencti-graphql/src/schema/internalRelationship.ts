import { ABSTRACT_INTERNAL_RELATIONSHIP } from './general';
import { schemaTypesDefinition } from './schema-types';
import type { StoreCommon } from '../types/store';
import type { StoreRelationPir } from '../modules/pir/pir-types';

export const RELATION_MIGRATES = 'migrates';
export const RELATION_MEMBER_OF = 'member-of';
export const RELATION_PARTICIPATE_TO = 'participate-to';
export const RELATION_ALLOWED_BY = 'allowed-by';
export const RELATION_HAS_ROLE = 'has-role';
export const RELATION_HAS_CAPABILITY = 'has-capability';
export const RELATION_ACCESSES_TO = 'accesses-to';
export const RELATION_IN_PIR = 'in-pir';

export const INTERNAL_RELATIONSHIPS = [
  RELATION_MIGRATES,
  RELATION_MEMBER_OF,
  RELATION_ALLOWED_BY,
  RELATION_HAS_ROLE,
  RELATION_HAS_CAPABILITY,
  RELATION_ACCESSES_TO,
  RELATION_PARTICIPATE_TO,
  RELATION_IN_PIR,
];

schemaTypesDefinition.register(ABSTRACT_INTERNAL_RELATIONSHIP, INTERNAL_RELATIONSHIPS);

export const isInternalRelationship = (type: string) => schemaTypesDefinition.isTypeIncludedIn(type, ABSTRACT_INTERNAL_RELATIONSHIP)
|| type === ABSTRACT_INTERNAL_RELATIONSHIP;

export const isStoreRelationPir = (instance: StoreCommon): instance is StoreRelationPir => {
  return (instance as StoreRelationPir).entity_type === RELATION_IN_PIR;
};
