import { batchListThroughGetFrom, createEntity, listEntities, batchListThroughGetTo, loadById } from '../database/middleware';
import { BUS_TOPICS } from '../config/conf';
import { notify } from '../database/redis';
import { ENTITY_TYPE_ATTACK_PATTERN, ENTITY_TYPE_COURSE_OF_ACTION } from '../schema/stixDomainObject';
import { ABSTRACT_STIX_DOMAIN_OBJECT } from '../schema/general';
import { RELATION_MITIGATES, RELATION_SUBTECHNIQUE_OF } from '../schema/stixCoreRelationship';

export const findById = (attackPatternId) => {
  return loadById(attackPatternId, ENTITY_TYPE_ATTACK_PATTERN);
};

export const findAll = (args) => {
  return listEntities([ENTITY_TYPE_ATTACK_PATTERN], args);
};

export const addAttackPattern = async (user, attackPattern) => {
  const created = await createEntity(user, attackPattern, ENTITY_TYPE_ATTACK_PATTERN);
  return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].ADDED_TOPIC, created, user);
};

export const batchCoursesOfAction = (attackPatternIds) => {
  return batchListThroughGetFrom(attackPatternIds, RELATION_MITIGATES, ENTITY_TYPE_COURSE_OF_ACTION);
};

export const batchParentAttackPatterns = (attackPatternIds) => {
  return batchListThroughGetTo(attackPatternIds, RELATION_SUBTECHNIQUE_OF, ENTITY_TYPE_ATTACK_PATTERN);
};

export const batchSubAttackPatterns = (attackPatternIds) => {
  return batchListThroughGetFrom(attackPatternIds, RELATION_SUBTECHNIQUE_OF, ENTITY_TYPE_ATTACK_PATTERN);
};

export const batchIsSubAttackPattern = async (attackPatternIds) => {
  const batchAttackPatterns = await batchListThroughGetTo(
    attackPatternIds,
    RELATION_SUBTECHNIQUE_OF,
    ENTITY_TYPE_ATTACK_PATTERN,
    { paginated: false }
  );
  return batchAttackPatterns.map((b) => b.length > 0);
};
