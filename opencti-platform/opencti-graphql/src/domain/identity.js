import { assoc, dissoc } from 'ramda';
import { createEntity, listEntities, loadEntityById } from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';
import { notify } from '../database/redis';

export const findById = async (identityId) => {
  return loadEntityById(identityId, 'Identity');
};

export const findAll = async (args) => {
  const noTypes = !args.types || args.types.length === 0;
  const entityTypes = noTypes ? ['Identity'] : args.types;
  const finalArgs = assoc('parentType', 'Stix-Domain-Entity', args);
  return listEntities(entityTypes, ['name', 'description', 'aliases'], finalArgs);
};

export const addIdentity = async (user, identity) => {
  const identityToCreate = dissoc('type', identity);
  const created = await createEntity(user, identityToCreate, identity.type);
  return notify(BUS_TOPICS.StixDomainEntity.ADDED_TOPIC, created, user);
};
