import { assoc } from 'ramda';
import { createEntity, listEntities, loadEntityById, TYPE_STIX_DOMAIN_ENTITY } from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';
import { notify } from '../database/redis';

export const findById = countryId => {
  return loadEntityById(countryId);
};
export const findAll = args => {
  const typedArgs = assoc('types', ['Country'], args);
  return listEntities(['name', 'alias'], typedArgs);
};

export const addCountry = async (user, country) => {
  const created = await createEntity(country, 'Country', TYPE_STIX_DOMAIN_ENTITY, 'identity');
  return notify(BUS_TOPICS.StixDomainEntity.ADDED_TOPIC, created, user);
};
