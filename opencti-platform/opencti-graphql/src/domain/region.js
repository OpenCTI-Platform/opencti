import { assoc } from 'ramda';
import { createEntity, loadEntityById, TYPE_STIX_DOMAIN_ENTITY } from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';
import { elPaginate } from '../database/elasticSearch';
import { notify } from '../database/redis';

export const findById = regionId => {
  return loadEntityById(regionId);
};
export const findAll = args => {
  return elPaginate('stix_domain_entities', assoc('type', 'region', args));
};

export const addRegion = async (user, region) => {
  const created = await createEntity(region, 'Region', TYPE_STIX_DOMAIN_ENTITY, 'identity');
  return notify(BUS_TOPICS.StixDomainEntity.ADDED_TOPIC, created, user);
};
