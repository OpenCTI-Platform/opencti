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
import { ABSTRACT_STIX_DOMAIN_OBJECT, ENTITY_TYPE_COURSE_OF_ACTION, RELATION_MITIGATES } from '../utils/idGenerator';

export const findById = (courseOfActionId) => {
  return loadEntityById(courseOfActionId, ENTITY_TYPE_COURSE_OF_ACTION);
};

export const findAll = (args) => {
  return listEntities([ENTITY_TYPE_COURSE_OF_ACTION], ['name', 'description'], args);
};

export const addCourseOfAction = async (user, courseOfAction) => {
  const created = await createEntity(user, courseOfAction, ENTITY_TYPE_COURSE_OF_ACTION);
  return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].ADDED_TOPIC, created, user);
};

export const attackPatterns = async (courseOfActionId) => {
  return findWithConnectedRelations(
    `match $to isa Attack-Pattern; 
    $rel(${RELATION_MITIGATES}_from:$from, ${RELATION_MITIGATES}_to:$to) isa ${RELATION_MITIGATES};
    $from has internal_id "${escapeString(courseOfActionId)}";
    get;`,
    'to',
    { extraRelKey: 'rel' }
  ).then((data) => buildPagination(0, 0, data, data.length));
};
