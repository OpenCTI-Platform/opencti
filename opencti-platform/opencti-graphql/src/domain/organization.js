import {
  createEntity,
  escapeString,
  findWithConnectedRelations,
  listEntities,
  loadEntityById,
} from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';
import { notify } from '../database/redis';
import { buildPagination } from '../database/utils';
import { ENTITY_TYPE_ORGA } from '../utils/idGenerator';

export const findById = (organizationId) => {
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
  const created = await createEntity(user, organization, ENTITY_TYPE_ORGA);
  return notify(BUS_TOPICS.StixDomainEntity.ADDED_TOPIC, created, user);
};
