import { batchListThroughGetFrom, createEntity, batchListThroughGetTo, storeLoadById } from '../database/middleware';
import { BUS_TOPICS } from '../config/conf';
import { notify } from '../database/redis';
import { ENTITY_TYPE_ATTACK_PATTERN, ENTITY_TYPE_COURSE_OF_ACTION } from '../schema/stixDomainObject';
import { ABSTRACT_STIX_DOMAIN_OBJECT } from '../schema/general';
import { RELATION_MITIGATES, RELATION_SUBTECHNIQUE_OF } from '../schema/stixCoreRelationship';
import { listEntities } from '../database/middleware-loader';

export const findById = (user, attackPatternId) => {
  return storeLoadById(user, attackPatternId, ENTITY_TYPE_ATTACK_PATTERN);
};

export const findAll = (user, args) => {
  return listEntities(user, [ENTITY_TYPE_ATTACK_PATTERN], args);
};

export const addAttackPattern = async (user, attackPattern) => {
  const created = await createEntity(user, attackPattern, ENTITY_TYPE_ATTACK_PATTERN);
  return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].ADDED_TOPIC, created, user);
};

export const batchCoursesOfAction = (user, attackPatternIds) => {
  return batchListThroughGetFrom(user, attackPatternIds, RELATION_MITIGATES, ENTITY_TYPE_COURSE_OF_ACTION);
};

export const batchParentAttackPatterns = (user, attackPatternIds) => {
  return batchListThroughGetTo(user, attackPatternIds, RELATION_SUBTECHNIQUE_OF, ENTITY_TYPE_ATTACK_PATTERN);
};

export const batchSubAttackPatterns = (user, attackPatternIds) => {
  return batchListThroughGetFrom(user, attackPatternIds, RELATION_SUBTECHNIQUE_OF, ENTITY_TYPE_ATTACK_PATTERN);
};

export const batchIsSubAttackPattern = async (user, attackPatternIds) => {
  const batchAttackPatterns = await batchListThroughGetTo(
    user,
    attackPatternIds,
    RELATION_SUBTECHNIQUE_OF,
    ENTITY_TYPE_ATTACK_PATTERN,
    { paginate: false }
  );
  return batchAttackPatterns.map((b) => b.length > 0);
};
