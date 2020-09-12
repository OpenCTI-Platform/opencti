import { isNil, map } from 'ramda';
import {
  createEntity,
  listEntities,
  listToEntitiesThroughRelation,
  loadById,
  updateAttribute,
} from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';
import { notify } from '../database/redis';
import { ENTITY_TYPE_ATTACK_PATTERN, ENTITY_TYPE_COURSE_OF_ACTION } from '../schema/stixDomainObject';
import { ABSTRACT_STIX_DOMAIN_OBJECT } from '../schema/general';
import { RELATION_MITIGATES } from '../schema/stixCoreRelationship';

export const findById = (courseOfActionId) => {
  return loadById(courseOfActionId, ENTITY_TYPE_COURSE_OF_ACTION);
};

export const findAll = (args) => {
  return listEntities([ENTITY_TYPE_COURSE_OF_ACTION], ['name', 'description'], args);
};

export const addCourseOfAction = async (user, courseOfAction) => {
  const created = await createEntity(user, courseOfAction, ENTITY_TYPE_COURSE_OF_ACTION);
  if (courseOfAction.update === true) {
    const fieldsToUpdate = ['description'];
    await Promise.all(
      map((field) => {
        if (!isNil(courseOfAction[field])) {
          return updateAttribute(user, created.id, created.entity_type, { key: field, value: [courseOfAction[field]] });
        }
        return true;
      }, fieldsToUpdate)
    );
  }
  return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].ADDED_TOPIC, created, user);
};

export const attackPatterns = async (courseOfActionId) => {
  return listToEntitiesThroughRelation(courseOfActionId, null, RELATION_MITIGATES, ENTITY_TYPE_ATTACK_PATTERN);
};
