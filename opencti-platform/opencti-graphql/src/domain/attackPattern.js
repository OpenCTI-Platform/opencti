import { assoc } from 'ramda';
import { createEntity, listEntities, loadEntityById } from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';
import { notify } from '../database/redis';

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
