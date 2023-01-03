import { assoc } from 'ramda';
import { batchLoadThroughGetTo, createEntity } from '../database/middleware';
import { BUS_TOPICS } from '../config/conf';
import { notify } from '../database/redis';
import { ENTITY_TYPE_LOCATION_CITY, ENTITY_TYPE_LOCATION_COUNTRY } from '../schema/stixDomainObject';
import { RELATION_LOCATED_AT } from '../schema/stixCoreRelationship';
import { ABSTRACT_STIX_DOMAIN_OBJECT } from '../schema/general';
import { listEntities, storeLoadById } from '../database/middleware-loader';

export const findById = (context, user, cityId) => {
  return storeLoadById(context, user, cityId, ENTITY_TYPE_LOCATION_CITY);
};

export const findAll = (context, user, args) => {
  return listEntities(context, user, [ENTITY_TYPE_LOCATION_CITY], args);
};

export const batchCountry = async (context, user, cityIds) => {
  return batchLoadThroughGetTo(context, user, cityIds, RELATION_LOCATED_AT, ENTITY_TYPE_LOCATION_COUNTRY);
};

export const addCity = async (context, user, city) => {
  const cityToCreate = assoc('x_opencti_location_type', ENTITY_TYPE_LOCATION_CITY, city);
  const created = await createEntity(context, user, cityToCreate, ENTITY_TYPE_LOCATION_CITY);
  return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].ADDED_TOPIC, created, user);
};
