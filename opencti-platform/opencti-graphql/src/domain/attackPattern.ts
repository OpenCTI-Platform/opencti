import { batchListThroughGetFrom, batchListThroughGetTo, createEntity } from '../database/middleware';
import { BUS_TOPICS } from '../config/conf';
import { notify } from '../database/redis';
import { ENTITY_TYPE_ATTACK_PATTERN, ENTITY_TYPE_COURSE_OF_ACTION, ENTITY_TYPE_DATA_COMPONENT } from '../schema/stixDomainObject';
import { ABSTRACT_STIX_DOMAIN_OBJECT } from '../schema/general';
import { RELATION_DETECTS, RELATION_MITIGATES, RELATION_SUBTECHNIQUE_OF } from '../schema/stixCoreRelationship';
import { EntityOptions, listEntities, storeLoadById } from '../database/middleware-loader';
import type { AuthContext, AuthUser } from '../types/user';
import type { BasicStoreCommon } from '../types/store';
import type { AttackPattern, AttackPatternAddInput } from '../generated/graphql';

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

export const batchCoursesOfAction = (context: AuthContext, user: AuthUser, attackPatternIds: Array<string>) => {
  return batchListThroughGetFrom(context, user, attackPatternIds, RELATION_MITIGATES, ENTITY_TYPE_COURSE_OF_ACTION);
};

export const batchParentAttackPatterns = (context: AuthContext, user: AuthUser, attackPatternIds: Array<string>) => {
  return batchListThroughGetTo(context, user, attackPatternIds, RELATION_SUBTECHNIQUE_OF, ENTITY_TYPE_ATTACK_PATTERN);
};

export const batchSubAttackPatterns = (context: AuthContext, user: AuthUser, attackPatternIds: Array<string>) => {
  return batchListThroughGetFrom(context, user, attackPatternIds, RELATION_SUBTECHNIQUE_OF, ENTITY_TYPE_ATTACK_PATTERN);
};

export const batchIsSubAttackPattern = async (context: AuthContext, user: AuthUser, attackPatternIds: Array<string>) => {
  const batchAttackPatterns = await batchListThroughGetTo(
    context,
    user,
    attackPatternIds,
    RELATION_SUBTECHNIQUE_OF,
    ENTITY_TYPE_ATTACK_PATTERN,
    { paginate: false }
  );
  return batchAttackPatterns.map((b: AttackPattern[]) => b.length > 0);
};

export const batchDataComponents = async (context: AuthContext, user: AuthUser, attackPatternIds: Array<string>) => {
  return batchListThroughGetFrom(context, user, attackPatternIds, RELATION_DETECTS, ENTITY_TYPE_DATA_COMPONENT);
};
