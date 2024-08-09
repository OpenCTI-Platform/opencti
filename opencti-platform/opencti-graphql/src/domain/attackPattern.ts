import { createEntity } from '../database/middleware';
import { BUS_TOPICS, logApp } from '../config/conf';
import { notify } from '../database/redis';
import { ENTITY_TYPE_ATTACK_PATTERN, ENTITY_TYPE_COURSE_OF_ACTION, ENTITY_TYPE_DATA_COMPONENT } from '../schema/stixDomainObject';
import { ABSTRACT_STIX_DOMAIN_OBJECT } from '../schema/general';
import { RELATION_DETECTS, RELATION_MITIGATES, RELATION_SUBTECHNIQUE_OF } from '../schema/stixCoreRelationship';
import {
  batchListEntitiesThroughRelationsPaginated,
  type EntityOptions,
  findEntitiesIdsWithRelations,
  listEntities,
  listEntitiesThroughRelationsPaginated,
  storeLoadById
} from '../database/middleware-loader';
import type { AuthContext, AuthUser } from '../types/user';
import type { BasicStoreCommon } from '../types/store';
import type { AttackPatternAddInput } from '../generated/graphql';

export const findById = (context: AuthContext, user: AuthUser, attackPatternId: string) => {
  return storeLoadById(context, user, attackPatternId, ENTITY_TYPE_ATTACK_PATTERN);
};

export const findAll = (context: AuthContext, user: AuthUser, args: EntityOptions<BasicStoreCommon>) => {
  return listEntities(context, user, [ENTITY_TYPE_ATTACK_PATTERN], args);
};

export const addAttackPattern = async (context: AuthContext, user: AuthUser, attackPattern: AttackPatternAddInput) => {
  const created = await createEntity(context, user, attackPattern, ENTITY_TYPE_ATTACK_PATTERN);
  return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].ADDED_TOPIC, created, user);
};

export const parentAttackPatternsPaginated = async (context: AuthContext, user: AuthUser, attackPatternId: string, args: EntityOptions<BasicStoreCommon>) => {
  return listEntitiesThroughRelationsPaginated(context, user, attackPatternId, RELATION_SUBTECHNIQUE_OF, ENTITY_TYPE_ATTACK_PATTERN, false, args);
};
export const batchParentAttackPatternsPaginated = async (context: AuthContext, user: AuthUser, attackPatternsIds: string[], args: EntityOptions<BasicStoreCommon>) => {
  return batchListEntitiesThroughRelationsPaginated(context, user, attackPatternsIds, RELATION_SUBTECHNIQUE_OF, ENTITY_TYPE_ATTACK_PATTERN, false, args);
};

export const childAttackPatternsPaginated = async (context: AuthContext, user: AuthUser, attackPatternId: string, args: EntityOptions<BasicStoreCommon>) => {
  return listEntitiesThroughRelationsPaginated(context, user, attackPatternId, RELATION_SUBTECHNIQUE_OF, ENTITY_TYPE_ATTACK_PATTERN, true, args);
};
export const batchChildAttackPatternsPaginated = async (context: AuthContext, user: AuthUser, attackPatternsIds: string[], args: EntityOptions<BasicStoreCommon>) => {
  return batchListEntitiesThroughRelationsPaginated(context, user, attackPatternsIds, RELATION_SUBTECHNIQUE_OF, ENTITY_TYPE_ATTACK_PATTERN, true, args);
};

export const isSubAttackPattern = async (context: AuthContext, user: AuthUser, attackPatternId: string) => {
  const pagination = await parentAttackPatternsPaginated(context, user, attackPatternId, { first: 1 });
  return pagination.edges.length > 0;
};
export const batchIsSubAttackPattern = async (context: AuthContext, user: AuthUser, attackPatternsIds: string[]) => {
  const resultIds = await findEntitiesIdsWithRelations(context, user, attackPatternsIds, RELATION_SUBTECHNIQUE_OF, ENTITY_TYPE_ATTACK_PATTERN, false);
  logApp.info('===== DEBUG ===== batchIsSubAttackPattern', { resultIds });
  return attackPatternsIds.map((id) => {
    return resultIds.includes(id);
  });
};

export const coursesOfActionPaginated = async (context: AuthContext, user: AuthUser, attackPatternId: string, args: EntityOptions<BasicStoreCommon>) => {
  return listEntitiesThroughRelationsPaginated(context, user, attackPatternId, RELATION_MITIGATES, ENTITY_TYPE_COURSE_OF_ACTION, true, args);
};

export const dataComponentsPaginated = async (context: AuthContext, user: AuthUser, attackPatternId: string, args: EntityOptions<BasicStoreCommon>) => {
  return listEntitiesThroughRelationsPaginated(context, user, attackPatternId, RELATION_DETECTS, ENTITY_TYPE_DATA_COMPONENT, true, args);
};
