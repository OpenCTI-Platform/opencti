import { createEntity, listEntities, loadEntityById } from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';
import { notify } from '../database/redis';
import { ENTITY_TYPE_IDENTITY_INDIVIDUAL } from '../utils/idGenerator';

export const findById = (individualId) => {
  return loadEntityById(individualId, ENTITY_TYPE_IDENTITY_INDIVIDUAL);
};

export const findAll = (args) => {
  return listEntities([ENTITY_TYPE_IDENTITY_INDIVIDUAL], ['name', 'description', 'aliases'], args);
};

export const addIndividual = async (user, individual) => {
  const created = await createEntity(user, individual, ENTITY_TYPE_IDENTITY_INDIVIDUAL);
  return notify(BUS_TOPICS.stixDomainObject.ADDED_TOPIC, created, user);
};
