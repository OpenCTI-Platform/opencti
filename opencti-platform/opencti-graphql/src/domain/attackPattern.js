import { batchListThroughGetFrom, createEntity, batchListThroughGetTo, storeLoadById } from '../database/middleware';
import { BUS_TOPICS } from '../config/conf';
import { notify } from '../database/redis';
import { ENTITY_TYPE_ATTACK_PATTERN, ENTITY_TYPE_COURSE_OF_ACTION } from '../schema/stixDomainObject';
import { ABSTRACT_STIX_DOMAIN_OBJECT } from '../schema/general';
import { RELATION_MITIGATES, RELATION_SUBTECHNIQUE_OF } from '../schema/stixCoreRelationship';
import { listEntities } from '../database/middleware-loader';

export const findById = (context, user, attackPatternId) => {
  return storeLoadById(context, user, attackPatternId, ENTITY_TYPE_ATTACK_PATTERN);
};

export const findAll = (context, user, args) => {
  return listEntities(context, user, [ENTITY_TYPE_ATTACK_PATTERN], args);
};

export const addAttackPattern = async (context, user, attackPattern) => {
  const created = await createEntity(context, user, attackPattern, ENTITY_TYPE_ATTACK_PATTERN);
  return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].ADDED_TOPIC, created, user);
};

export const batchCoursesOfAction = (context, user, attackPatternIds) => {
  return batchListThroughGetFrom(context, user, attackPatternIds, RELATION_MITIGATES, ENTITY_TYPE_COURSE_OF_ACTION);
};

export const batchParentAttackPatterns = (context, user, attackPatternIds) => {
  return batchListThroughGetTo(context, user, attackPatternIds, RELATION_SUBTECHNIQUE_OF, ENTITY_TYPE_ATTACK_PATTERN);
};

export const batchSubAttackPatterns = (context, user, attackPatternIds) => {
  return batchListThroughGetFrom(context, user, attackPatternIds, RELATION_SUBTECHNIQUE_OF, ENTITY_TYPE_ATTACK_PATTERN);
};

export const batchIsSubAttackPattern = async (context, user, attackPatternIds) => {
  const batchAttackPatterns = await batchListThroughGetTo(
    context,
    user,
    attackPatternIds,
    RELATION_SUBTECHNIQUE_OF,
    ENTITY_TYPE_ATTACK_PATTERN,
    { paginate: false }
  );
  return batchAttackPatterns.map((b) => b.length > 0);
};
