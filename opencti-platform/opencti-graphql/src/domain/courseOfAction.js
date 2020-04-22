import {
  createEntity,
  escapeString,
  findWithConnectedRelations,
  listEntities,
  loadEntityById,
  loadEntityByStixId,
} from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';
import { notify } from '../database/redis';
import { buildPagination } from '../database/utils';

export const findById = (courseOfActionId) => {
  if (courseOfActionId.match(/[a-z-]+--[\w-]{36}/g)) {
    return loadEntityByStixId(courseOfActionId, 'Course-Of-Action');
  }
  return loadEntityById(courseOfActionId, 'Course-Of-Action');
};
export const findAll = (args) => {
  return listEntities(['Course-Of-Action'], ['name', 'alias'], args);
};

export const addCourseOfAction = async (user, courseOfAction) => {
  const created = await createEntity(user, courseOfAction, 'Course-Of-Action');
  return notify(BUS_TOPICS.StixDomainEntity.ADDED_TOPIC, created, user);
};

export const attackPatterns = async (courseOfActionId) => {
  return findWithConnectedRelations(
    `match $to isa Attack-Pattern; $rel(problem:$to, mitigation:$from) isa mitigates;
    $from has internal_id_key "${escapeString(courseOfActionId)}"; get;`,
    'to',
    { extraRelKey: 'rel' }
  ).then((data) => buildPagination(0, 0, data, data.length));
};
