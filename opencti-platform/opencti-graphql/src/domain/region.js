import {
  createEntity,
  escapeString,
  findWithConnectedRelations,
  getSingleValueNumber,
  listEntities,
  loadEntityById,
} from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';
import { notify } from '../database/redis';
import { buildPagination } from '../database/utils';
import { ENTITY_TYPE_LOCATION_REGION, RELATION_LOCATED_AT } from '../utils/idGenerator';

export const findById = (regionId) => {
  return loadEntityById(regionId, ENTITY_TYPE_LOCATION_REGION);
};

export const findAll = (args) => {
  return listEntities([ENTITY_TYPE_LOCATION_REGION], ['name', 'description', 'x_openctièaliases'], args);
};

export const parentRegions = (regionId) => {
  return findWithConnectedRelations(
    `match $to isa Region; 
    $rel(${RELATION_LOCATED_AT}_from:$from, ${RELATION_LOCATED_AT}_to:$to) isa ${RELATION_LOCATED_AT};
    $from has internal_id "${escapeString(regionId)}"; get;`,
    'to',
    { extraRelKey: 'rel' }
  ).then((data) => buildPagination(0, 0, data, data.length));
};

export const subRegions = (regionId) => {
  return findWithConnectedRelations(
    `match $to isa Region; 
    $rel(${RELATION_LOCATED_AT}_from:$from, ${RELATION_LOCATED_AT}_to:$to) isa ${RELATION_LOCATED_AT};
    $from has internal_id "${escapeString(regionId)}"; get;`,
    'to',
    { extraRelKey: 'rel' }
  ).then((data) => buildPagination(0, 0, data, data.length));
};

export const isSubRegion = async (regionId, args) => {
  const numberOfParents = await getSingleValueNumber(
    `match $parent isa Region; 
    $rel(${RELATION_LOCATED_AT}_from:$subregion, ${RELATION_LOCATED_AT}_to:$parent) isa ${RELATION_LOCATED_AT}; 
    $subregion has internal_id "${escapeString(regionId)}"; get; count;`,
    args
  );
  return numberOfParents > 0;
};

export const addRegion = async (user, region) => {
  const created = await createEntity(user, region, ENTITY_TYPE_LOCATION_REGION);
  return notify(BUS_TOPICS.stixDomainObject.ADDED_TOPIC, created, user);
};
