import { createEntity, listEntities, loadEntityById } from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';
import { notify } from '../database/redis';
import { ENTITY_TYPE_INFRASTRUCTURE } from '../utils/idGenerator';

export const findById = (infrastructureId) => {
  return loadEntityById(infrastructureId, ENTITY_TYPE_INFRASTRUCTURE);
};

export const findAll = (args) => {
  return listEntities([ENTITY_TYPE_INFRASTRUCTURE], ['name', 'description', 'aliases'], args);
};

export const addInfrastructure = async (user, infrastructure) => {
  const created = await createEntity(user, infrastructure, ENTITY_TYPE_INFRASTRUCTURE);
  return notify(BUS_TOPICS.stixDomainObject.ADDED_TOPIC, created, user);
};
