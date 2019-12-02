import { assoc } from 'ramda';
import {
  createEntity,
  listEntities,
  loadEntityById,
  loadEntityByStixId,
  TYPE_STIX_DOMAIN_ENTITY
} from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';
import { notify } from '../database/redis';

export const findById = cityId => {
  if (cityId.match(/[a-z-]+--[\w-]{36}/g)) {
    return loadEntityByStixId(cityId);
  }
  return loadEntityById(cityId);
};
export const findAll = args => {
  const typedArgs = assoc('types', ['City'], args);
  return listEntities(['name', 'alias'], typedArgs);
};

export const addCity = async (user, city) => {
  const created = await createEntity(city, 'City', { modelType: TYPE_STIX_DOMAIN_ENTITY, stixIdType: 'identity' });
  return notify(BUS_TOPICS.StixDomainEntity.ADDED_TOPIC, created, user);
};
