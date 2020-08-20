import { createEntity, listEntities, listFromEntitiesThroughRelation, loadEntityById } from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';
import { notify } from '../database/redis';
import {
  ABSTRACT_STIX_DOMAIN_OBJECT,
  ENTITY_TYPE_ATTACK_PATTERN,
  ENTITY_TYPE_COURSE_OF_ACTION,
  RELATION_MITIGATES,
} from '../utils/idGenerator';

export const findById = (attackPatternId) => {
  return loadEntityById(attackPatternId, ENTITY_TYPE_ATTACK_PATTERN);
};

export const findAll = (args) => {
  return listEntities([ENTITY_TYPE_ATTACK_PATTERN], ['name', 'description', 'aliases'], args);
};

export const addAttackPattern = async (user, attackPattern) => {
  const created = await createEntity(user, attackPattern, ENTITY_TYPE_ATTACK_PATTERN);
  return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].ADDED_TOPIC, created, user);
};

export const coursesOfAction = async (attackPatternId) => {
  return listFromEntitiesThroughRelation(
    attackPatternId,
    ENTITY_TYPE_ATTACK_PATTERN,
    RELATION_MITIGATES,
    ENTITY_TYPE_COURSE_OF_ACTION
  );
};
