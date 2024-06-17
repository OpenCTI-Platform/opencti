import { assoc } from 'ramda';
import { createEntity } from '../database/middleware';
import { listEntities, listEntitiesThroughRelationsPaginated, storeLoadById } from '../database/middleware-loader';
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

export const parentRegionsPaginated = async (context, user, regionId, args) => {
  return listEntitiesThroughRelationsPaginated(context, user, regionId, RELATION_LOCATED_AT, ENTITY_TYPE_LOCATION_REGION, false, false, args);
};

export const childRegionsPaginated = async (context, user, regionId, args) => {
  return listEntitiesThroughRelationsPaginated(context, user, regionId, RELATION_LOCATED_AT, ENTITY_TYPE_LOCATION_REGION, true, false, args);
};

export const countriesPaginated = async (context, user, elementId, args) => {
  const element = await findById(context, user, elementId);
  if (element) {
    return listEntitiesThroughRelationsPaginated(context, user, elementId, RELATION_LOCATED_AT, ENTITY_TYPE_LOCATION_COUNTRY, true, false, args);
  }
  return listEntitiesThroughRelationsPaginated(context, user, elementId, RELATION_LOCATED_AT, ENTITY_TYPE_LOCATION_COUNTRY, false, false, args);
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
