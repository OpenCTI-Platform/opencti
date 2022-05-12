import { assoc } from 'ramda';
import {
  createEntity,
  batchListThroughGetFrom,
  batchListThroughGetTo,
  storeLoadById,
  batchLoadThroughGetTo,
} from '../database/middleware';
import { listEntities } from '../database/middleware-loader';
import { BUS_TOPICS } from '../config/conf';
import { notify } from '../database/redis';
import { ENTITY_TYPE_LOCATION_COUNTRY, ENTITY_TYPE_LOCATION_REGION } from '../schema/stixDomainObject';
import { RELATION_LOCATED_AT } from '../schema/stixCoreRelationship';
import { ABSTRACT_STIX_DOMAIN_OBJECT } from '../schema/general';

export const findById = (user, regionId) => {
  return storeLoadById(user, regionId, ENTITY_TYPE_LOCATION_REGION);
};

export const findAll = (user, args) => {
  return listEntities(user, [ENTITY_TYPE_LOCATION_REGION], args);
};

export const batchParentRegions = (user, regionIds) => {
  return batchListThroughGetTo(user, regionIds, RELATION_LOCATED_AT, ENTITY_TYPE_LOCATION_REGION);
};

export const batchSubRegions = (user, regionIds) => {
  return batchListThroughGetFrom(user, regionIds, RELATION_LOCATED_AT, ENTITY_TYPE_LOCATION_REGION);
};

export const batchCountries = (user, regionIds) => {
  return batchListThroughGetFrom(user, regionIds, RELATION_LOCATED_AT, ENTITY_TYPE_LOCATION_COUNTRY);
};

export const batchIsSubRegion = async (user, regionIds) => {
  const batchRegions = await batchLoadThroughGetTo(user, regionIds, RELATION_LOCATED_AT, ENTITY_TYPE_LOCATION_REGION);
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
