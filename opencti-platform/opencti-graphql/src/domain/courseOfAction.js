import {
  createEntity,
  escapeString,
  findWithConnectedRelations,
  listEntities,
  loadEntityById,
} from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';
import { notify } from '../database/redis';
import { buildPagination } from '../database/utils';
import { ENTITY_TYPE_COURSE } from '../utils/idGenerator';

export const findById = (courseOfActionId) => {
  return loadEntityById(courseOfActionId, ENTITY_TYPE_COURSE);
};
export const findAll = (args) => {
  return listEntities([ENTITY_TYPE_COURSE], ['name', 'alias'], args);
};

export const addCourseOfAction = async (user, courseOfAction) => {
  const created = await createEntity(user, courseOfAction, ENTITY_TYPE_COURSE);
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
