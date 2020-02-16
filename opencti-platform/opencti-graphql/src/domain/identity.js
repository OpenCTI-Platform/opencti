import { dissoc } from 'ramda';
import { createEntity, listEntities, loadEntityById, loadEntityByStixId } from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';
import { notify } from '../database/redis';

export const findById = identityId => {
  if (identityId.match(/[a-z-]+--[\w-]{36}/g)) {
    return loadEntityByStixId(identityId, 'Identity');
  }
  return loadEntityById(identityId, 'Identity');
};
export const findAll = args => {
  const noTypes = !args.types || args.types.length === 0;
  const entityTypes = noTypes ? ['Identity'] : args.types;
  return listEntities(entityTypes, ['name', 'alias'], args);
};

export const addIdentity = async (user, identity) => {
  const identityToCreate = dissoc('type', identity);
  const created = await createEntity(identityToCreate, identity.type, {
    stixIdType: identity.type !== 'Threat-Actor' ? 'identity' : 'threat-actor'
  });
  return notify(BUS_TOPICS.StixDomainEntity.ADDED_TOPIC, created, user);
};
