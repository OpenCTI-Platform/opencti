import { assoc } from 'ramda';
import {
  createEntity,
  batchListThroughGetFrom,
  batchListThroughGetTo,
  batchLoadThroughGetTo,
} from '../database/middleware';
import { listEntities, storeLoadById } from '../database/middleware-loader';
import { BUS_TOPICS } from '../config/conf';
import { notify } from '../database/redis';
import { ENTITY_TYPE_LOCATION_COUNTRY, ENTITY_TYPE_LOCATION_REGION } from '../schema/stixDomainObject';
import { RELATION_LOCATED_AT } from '../schema/stixCoreRelationship';
import { ABSTRACT_STIX_DOMAIN_OBJECT } from '../schema/general';

export const findById = (context, user, regionId) => {
  return storeLoadById(context, user, regionId, ENTITY_TYPE_LOCATION_REGION);
};

export const findAll = (context, user, args) => {
  return listEntities(context, user, [ENTITY_TYPE_LOCATION_REGION], args);
};

export const batchParentRegions = (context, user, regionIds) => {
  return batchListThroughGetTo(context, user, regionIds, RELATION_LOCATED_AT, ENTITY_TYPE_LOCATION_REGION);
};

export const batchSubRegions = (context, user, regionIds) => {
  return batchListThroughGetFrom(context, user, regionIds, RELATION_LOCATED_AT, ENTITY_TYPE_LOCATION_REGION);
};

export const batchCountries = (context, user, regionIds) => {
  return batchListThroughGetFrom(context, user, regionIds, RELATION_LOCATED_AT, ENTITY_TYPE_LOCATION_COUNTRY);
};

export const batchIsSubRegion = async (context, user, regionIds) => {
  const batchRegions = await batchLoadThroughGetTo(context, user, regionIds, RELATION_LOCATED_AT, ENTITY_TYPE_LOCATION_REGION);
  return batchRegions.map((b) => b !== undefined);
};

export const addRegion = async (context, user, region) => {
  const created = await createEntity(
    context,
    user,
    assoc('x_opencti_location_type', ENTITY_TYPE_LOCATION_REGION, region),
    ENTITY_TYPE_LOCATION_REGION
  );
  return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].ADDED_TOPIC, created, user);
};
