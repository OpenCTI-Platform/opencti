import { assoc } from 'ramda';
import {
  createEntity,
  escapeString,
  getSingleValueNumber,
  listEntities,
  listFromEntitiesThroughRelation,
  listToEntitiesThroughRelation,
  loadEntityById,
} from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';
import { notify } from '../database/redis';
import { ABSTRACT_STIX_DOMAIN_OBJECT, ENTITY_TYPE_LOCATION_REGION, RELATION_LOCATED_AT } from '../utils/idGenerator';

export const findById = (regionId) => {
  return loadEntityById(regionId, ENTITY_TYPE_LOCATION_REGION);
};

export const findAll = (args) => {
  return listEntities([ENTITY_TYPE_LOCATION_REGION], ['name', 'description', 'x_opencti_aliases'], args);
};

export const parentRegions = (regionId) => {
  return listToEntitiesThroughRelation(regionId, null, RELATION_LOCATED_AT, ENTITY_TYPE_LOCATION_REGION);
};

export const subRegions = (regionId) => {
  return listFromEntitiesThroughRelation(regionId, null, RELATION_LOCATED_AT, ENTITY_TYPE_LOCATION_REGION);
};

export const isSubRegion = async (regionId, args) => {
  const numberOfParents = await getSingleValueNumber(
    `match $parent isa Region; 
    $rel(${RELATION_LOCATED_AT}_from:$subregion, ${RELATION_LOCATED_AT}_to:$parent) isa ${RELATION_LOCATED_AT}; 
    $subregion has internal_id "${escapeString(regionId)}"; 
    get; count;`,
    args
  );
  return numberOfParents > 0;
};

export const addRegion = async (user, region) => {
  const created = await createEntity(
    user,
    assoc('x_opencti_location_type', ENTITY_TYPE_LOCATION_REGION, region),
    ENTITY_TYPE_LOCATION_REGION
  );
  return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].ADDED_TOPIC, created, user);
};
