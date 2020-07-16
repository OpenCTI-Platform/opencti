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
import { ENTITY_TYPE_IDENTITY_ORGANIZATION, RELATION_PART_OF } from '../utils/idGenerator';

export const findById = (organizationId) => {
  return loadEntityById(organizationId, ENTITY_TYPE_IDENTITY_ORGANIZATION);
};

export const findAll = (args) => {
  return listEntities([ENTITY_TYPE_IDENTITY_ORGANIZATION], ['name', 'aliases'], args);
};

export const sectors = (organizationId) => {
  return findWithConnectedRelations(
    `match $to isa Sector; 
    $rel(${RELATION_PART_OF}_from:$from, ${RELATION_PART_OF}_to:$to) isa ${RELATION_PART_OF};
    $from has internal_id "${escapeString(organizationId)}"; get;`,
    'to',
    { extraRelKey: 'rel' }
  ).then((data) => buildPagination(0, 0, data, data.length));
};

export const addOrganization = async (user, organization) => {
  const created = await createEntity(user, organization, ENTITY_TYPE_IDENTITY_ORGANIZATION);
  return notify(BUS_TOPICS.stixDomainObject.ADDED_TOPIC, created, user);
};