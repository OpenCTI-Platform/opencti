import { createEntity, listEntities, loadEntityById } from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';
import { notify } from '../database/redis';
import { ABSTRACT_STIX_DOMAIN_OBJECT, ENTITY_TYPE_CONTAINER_OBSERVED_DATA } from '../utils/idGenerator';

export const findById = (observedDataId) => {
  return loadEntityById(observedDataId, ENTITY_TYPE_CONTAINER_OBSERVED_DATA);
};

export const findAll = (args) => {
  return listEntities([ENTITY_TYPE_CONTAINER_OBSERVED_DATA], ['name', 'description'], args);
};

export const addObservedData = async (user, observedData) => {
  const created = await createEntity(user, observedData, ENTITY_TYPE_CONTAINER_OBSERVED_DATA);
  return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].ADDED_TOPIC, created, user);
};
