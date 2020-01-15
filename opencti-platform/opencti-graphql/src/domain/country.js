import {
  createEntity,
  listEntities,
  loadEntityById,
  loadEntityByStixId,
  TYPE_STIX_DOMAIN_ENTITY
} from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';
import { notify } from '../database/redis';

export const findById = countryId => {
  if (countryId.match(/[a-z-]+--[\w-]{36}/g)) {
    return loadEntityByStixId(countryId);
  }
  return loadEntityById(countryId);
};
export const findAll = args => {
  return listEntities(['Country'], ['name', 'alias'], args);
};

export const addCountry = async (user, country) => {
  const created = await createEntity(country, 'Country', {
    modelType: TYPE_STIX_DOMAIN_ENTITY,
    stixIdType: 'identity'
  });
  return notify(BUS_TOPICS.StixDomainEntity.ADDED_TOPIC, created, user);
};
