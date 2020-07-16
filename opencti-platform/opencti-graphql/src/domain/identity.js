import { assoc, dissoc } from 'ramda';
import { createEntity, listEntities, loadEntityById } from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';
import { notify } from '../database/redis';
import { ENTITY_TYPE_IDENTITY } from '../utils/idGenerator';

export const findById = async (identityId) => {
  return loadEntityById(identityId, ENTITY_TYPE_IDENTITY);
};

export const findAll = async (args) => {
  const noTypes = !args.types || args.types.length === 0;
  const entityTypes = noTypes ? [ENTITY_TYPE_IDENTITY] : args.types;
  const finalArgs = assoc('parentType', 'Stix-Object', args);
  return listEntities(entityTypes, ['name', 'description', 'aliases'], finalArgs);
};

export const addIdentity = async (user, identity) => {
  const identityToCreate = dissoc('type', identity);
  const created = await createEntity(user, identityToCreate, identity.type);
  return notify(BUS_TOPICS.StixDomainEntity.ADDED_TOPIC, created, user);
};
