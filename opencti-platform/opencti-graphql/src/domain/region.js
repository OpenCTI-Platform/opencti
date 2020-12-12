import { assoc } from 'ramda';
import {
  createEntity,
  listEntities,
  batchListThroughGetFrom,
  batchListThroughGetTo,
  loadById,
  batchLoadThroughGetTo,
} from '../database/middleware';
import { BUS_TOPICS } from '../config/conf';
import { notify } from '../database/redis';
import { ENTITY_TYPE_LOCATION_COUNTRY, ENTITY_TYPE_LOCATION_REGION } from '../schema/stixDomainObject';
import { RELATION_LOCATED_AT } from '../schema/stixCoreRelationship';
import { ABSTRACT_STIX_DOMAIN_OBJECT } from '../schema/general';

export const findById = (regionId) => {
  return loadById(regionId, ENTITY_TYPE_LOCATION_REGION);
};

export const findAll = (args) => {
  return listEntities([ENTITY_TYPE_LOCATION_REGION], args);
};

export const batchParentRegions = (regionIds) => {
  return batchListThroughGetTo(regionIds, RELATION_LOCATED_AT, ENTITY_TYPE_LOCATION_REGION);
};

export const batchSubRegions = (regionIds) => {
  return batchListThroughGetFrom(regionIds, RELATION_LOCATED_AT, ENTITY_TYPE_LOCATION_REGION);
};

export const batchCountries = (regionIds) => {
  return batchListThroughGetFrom(regionIds, RELATION_LOCATED_AT, ENTITY_TYPE_LOCATION_COUNTRY);
};

export const batchIsSubRegion = async (regionIds) => {
  const batchRegions = await batchLoadThroughGetTo(regionIds, RELATION_LOCATED_AT, ENTITY_TYPE_LOCATION_REGION);
  return batchRegions.map((b) => b !== undefined);
};

export const addRegion = async (user, region) => {
  const created = await createEntity(
    user,
    assoc('x_opencti_location_type', ENTITY_TYPE_LOCATION_REGION, region),
    ENTITY_TYPE_LOCATION_REGION
  );
  return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].ADDED_TOPIC, created, user);
};
