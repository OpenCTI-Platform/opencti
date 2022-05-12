import { assoc } from 'ramda';
import { batchLoadThroughGetTo, createEntity, storeLoadById } from '../database/middleware';
import { BUS_TOPICS } from '../config/conf';
import { notify } from '../database/redis';
import { ENTITY_TYPE_LOCATION_CITY, ENTITY_TYPE_LOCATION_COUNTRY } from '../schema/stixDomainObject';
import { RELATION_LOCATED_AT } from '../schema/stixCoreRelationship';
import { ABSTRACT_STIX_DOMAIN_OBJECT } from '../schema/general';
import { listEntities } from '../database/middleware-loader';

export const findById = (user, cityId) => {
  return storeLoadById(user, cityId, ENTITY_TYPE_LOCATION_CITY);
};

export const findAll = (user, args) => {
  return listEntities(user, [ENTITY_TYPE_LOCATION_CITY], args);
};

export const batchCountry = async (user, cityIds) => {
  return batchLoadThroughGetTo(user, cityIds, RELATION_LOCATED_AT, ENTITY_TYPE_LOCATION_COUNTRY);
};

export const addCity = async (user, city) => {
  const cityToCreate = assoc('x_opencti_location_type', ENTITY_TYPE_LOCATION_CITY, city);
  const created = await createEntity(user, cityToCreate, ENTITY_TYPE_LOCATION_CITY);
  return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].ADDED_TOPIC, created, user);
};
