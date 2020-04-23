import {
  createEntity,
  escapeString,
  findWithConnectedRelations,
  listEntities,
  loadEntityById,
  loadEntityByStixId,
} from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';
import { notify } from '../database/redis';
import { buildPagination, TYPE_STIX_DOMAIN_ENTITY } from '../database/utils';

export const findById = (organizationId) => {
  if (organizationId.match(/[a-z-]+--[\w-]{36}/g)) {
    return loadEntityByStixId(organizationId, 'Organization');
  }
  return loadEntityById(organizationId, 'Organization');
};
export const findAll = (args) => {
  return listEntities(['Organization'], ['name', 'alias'], args);
};
export const sectors = (organizationId) => {
  return findWithConnectedRelations(
    `match $to isa Sector; $rel(part_of:$from, gather:$to) isa gathering;
     $from has internal_id_key "${escapeString(organizationId)}"; get;`,
    'to',
    { extraRelKey: 'rel' }
  ).then((data) => buildPagination(0, 0, data, data.length));
};

export const addOrganization = async (user, organization) => {
  const created = await createEntity(user, organization, 'Organization', {
    modelType: TYPE_STIX_DOMAIN_ENTITY,
    stixIdType: 'identity',
  });
  return notify(BUS_TOPICS.StixDomainEntity.ADDED_TOPIC, created, user);
};
