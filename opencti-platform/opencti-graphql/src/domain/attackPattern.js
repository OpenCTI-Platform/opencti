import {
  listThroughGetFroms,
  createEntity,
  escapeString,
  getSingleValueNumber,
  listEntities,
  listFromEntitiesThroughRelation,
  listToEntitiesThroughRelation,
  loadById,
} from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';
import { notify } from '../database/redis';
import { ENTITY_TYPE_ATTACK_PATTERN } from '../schema/stixDomainObject';
import { ABSTRACT_STIX_DOMAIN_OBJECT } from '../schema/general';
import { RELATION_MITIGATES, RELATION_SUBTECHNIQUE_OF } from '../schema/stixCoreRelationship';

export const findById = (attackPatternId) => {
  return loadById(attackPatternId, ENTITY_TYPE_ATTACK_PATTERN);
};

export const findAll = (args) => {
  return listEntities([ENTITY_TYPE_ATTACK_PATTERN], ['name', 'description', 'x_mitre_id', 'aliases'], args);
};

export const addAttackPattern = async (user, attackPattern) => {
  const created = await createEntity(user, attackPattern, ENTITY_TYPE_ATTACK_PATTERN);
  return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].ADDED_TOPIC, created, user);
};

export const batchCoursesOfAction = (attackPatternIds) => {
  return listThroughGetFroms(attackPatternIds, RELATION_MITIGATES, ENTITY_TYPE_ATTACK_PATTERN);
};

export const parentAttackPatterns = (attackPatternId) => {
  return listToEntitiesThroughRelation(attackPatternId, null, RELATION_SUBTECHNIQUE_OF, ENTITY_TYPE_ATTACK_PATTERN);
};

export const subAttackPatterns = (attackPatternId) => {
  return listFromEntitiesThroughRelation(attackPatternId, null, RELATION_SUBTECHNIQUE_OF, ENTITY_TYPE_ATTACK_PATTERN);
};

export const isSubAttackPattern = async (attackPatternId) => {
  const numberOfParents = await getSingleValueNumber(
    `match $parent isa ${ENTITY_TYPE_ATTACK_PATTERN}; 
    $rel(${RELATION_SUBTECHNIQUE_OF}_from:$subattackpattern, ${RELATION_SUBTECHNIQUE_OF}_to:$parent) isa ${RELATION_SUBTECHNIQUE_OF}; 
    $subattackpattern has internal_id "${escapeString(attackPatternId)}"; get; count;`
  );
  return numberOfParents > 0;
};
