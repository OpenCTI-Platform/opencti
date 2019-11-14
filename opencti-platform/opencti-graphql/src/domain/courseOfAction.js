import { assoc } from 'ramda';
import { createEntity, listEntities, loadEntityById } from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';
import { notify } from '../database/redis';

export const findById = courseOfActionId => {
  return loadEntityById(courseOfActionId);
};
export const findAll = args => {
  const typedArgs = assoc('types', ['Course-Of-Action'], args);
  return listEntities(['name', 'alias'], typedArgs);
};

export const addCourseOfAction = async (user, courseOfAction) => {
  const created = await createEntity(courseOfAction, 'Course-Of-Action');
  return notify(BUS_TOPICS.StixDomainEntity.ADDED_TOPIC, created, user);
};
