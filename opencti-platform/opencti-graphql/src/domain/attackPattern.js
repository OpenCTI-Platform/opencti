import { assoc } from 'ramda';
import { createEntity, escapeString, findWithConnectedRelations, listEntities, loadEntityById } from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';
import { notify } from '../database/redis';
import { buildPagination } from '../database/utils';

export const findById = attackPatternId => {
  return loadEntityById(attackPatternId);
};
export const findAll = args => {
  const typedArgs = assoc('types', ['Attack-Pattern'], args);
  return listEntities(['name', 'alias'], typedArgs);
};

export const addAttackPattern = async (user, attackPattern) => {
  const created = await createEntity(attackPattern, 'Attack-Pattern');
  return notify(BUS_TOPICS.StixDomainEntity.ADDED_TOPIC, created, user);
};

export const coursesOfAction = async attackPatternId => {
  return findWithConnectedRelations(
    `match $to isa Course-Of-Action; $rel(mitigation:$to, problem:$from) isa mitigates;
   $from has internal_id_key "${escapeString(attackPatternId)}"; get;`,
    'to',
    'rel'
  ).then(data => buildPagination(0, 0, data, data.length));
};
