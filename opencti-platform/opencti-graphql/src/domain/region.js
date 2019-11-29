import { assoc } from 'ramda';
import { createEntity, listEntities, loadEntityById, TYPE_STIX_DOMAIN_ENTITY } from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';
import { notify } from '../database/redis';

export const findById = regionId => {
  return loadEntityById(regionId);
};
export const findAll = args => {
  const typedArgs = assoc('types', ['Region'], args);
  return listEntities(['name', 'alias'], typedArgs);
};

export const addRegion = async (user, region) => {
  const created = await createEntity(region, 'Region', { modelType: TYPE_STIX_DOMAIN_ENTITY, stixIdType: 'identity' });
  return notify(BUS_TOPICS.StixDomainEntity.ADDED_TOPIC, created, user);
};
