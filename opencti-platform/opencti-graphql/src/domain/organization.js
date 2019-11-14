import { assoc } from 'ramda';
import { createEntity, loadEntityById, TYPE_STIX_DOMAIN_ENTITY } from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';
import { elPaginate } from '../database/elasticSearch';
import { notify } from '../database/redis';

export const findById = organizationId => {
  return loadEntityById(organizationId);
};
export const findAll = args => {
  return elPaginate('stix_domain_entities', assoc('type', 'organization', args));
};

export const addOrganization = async (user, organization) => {
  const created = await createEntity(organization, 'Organization', TYPE_STIX_DOMAIN_ENTITY, 'identity');
  return notify(BUS_TOPICS.StixDomainEntity.ADDED_TOPIC, created, user);
};
