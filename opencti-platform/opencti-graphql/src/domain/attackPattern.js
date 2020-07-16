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
import { ENTITY_TYPE_ATTACK_PATTERN } from '../utils/idGenerator';

export const findById = (attackPatternId) => {
  return loadEntityById(attackPatternId, 'Attack-Pattern');
};
export const findAll = (args) => {
  return listEntities(['Attack-Pattern'], ['name', 'alias'], args);
};

export const addAttackPattern = async (user, attackPattern) => {
  const created = await createEntity(user, attackPattern, ENTITY_TYPE_ATTACK_PATTERN);
  return notify(BUS_TOPICS.StixDomainEntity.ADDED_TOPIC, created, user);
};

export const coursesOfAction = async (attackPatternId) => {
  return findWithConnectedRelations(
    `match $to isa Course-Of-Action; $rel(mitigation:$to, problem:$from) isa mitigates;
   $from isa Attack-Pattern, has internal_id "${escapeString(attackPatternId)}"; get;`,
    'to',
    { extraRelKey: 'rel' }
  ).then((data) => buildPagination(0, 0, data, data.length));
};
