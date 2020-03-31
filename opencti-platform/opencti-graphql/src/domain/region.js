import { createEntity, listEntities, loadEntityById, loadEntityByStixId } from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';
import { notify } from '../database/redis';
import { TYPE_STIX_DOMAIN_ENTITY } from '../database/utils';

export const findById = (regionId) => {
  if (regionId.match(/[a-z-]+--[\w-]{36}/g)) {
    return loadEntityByStixId(regionId, 'Region');
  }
  return loadEntityById(regionId, 'Region');
};
export const findAll = (args) => {
  return listEntities(['Region'], ['name', 'alias'], args);
};

export const addRegion = async (user, region) => {
  const created = await createEntity(region, 'Region', { modelType: TYPE_STIX_DOMAIN_ENTITY, stixIdType: 'identity' });
  return notify(BUS_TOPICS.StixDomainEntity.ADDED_TOPIC, created, user);
};
