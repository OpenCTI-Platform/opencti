import { assoc } from 'ramda';
import { createEntity, storeLoadById, batchLoadThroughGetTo } from '../database/middleware';
import { listEntities } from '../database/middleware-loader';
import { BUS_TOPICS } from '../config/conf';
import { notify } from '../database/redis';
import { ENTITY_TYPE_LOCATION_COUNTRY, ENTITY_TYPE_LOCATION_REGION } from '../schema/stixDomainObject';
import { RELATION_LOCATED_AT } from '../schema/stixCoreRelationship';
import { ABSTRACT_STIX_DOMAIN_OBJECT } from '../schema/general';

export const findById = (user, countryId) => {
  return storeLoadById(user, countryId, ENTITY_TYPE_LOCATION_COUNTRY);
};

export const findAll = (user, args) => {
  return listEntities(user, [ENTITY_TYPE_LOCATION_COUNTRY], args);
};

export const batchRegion = async (user, countryIds) => {
  return batchLoadThroughGetTo(user, countryIds, RELATION_LOCATED_AT, ENTITY_TYPE_LOCATION_REGION);
};

export const addCountry = async (user, country) => {
  const created = await createEntity(
    user,
    assoc('x_opencti_location_type', ENTITY_TYPE_LOCATION_COUNTRY, country),
    ENTITY_TYPE_LOCATION_COUNTRY
  );
  return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].ADDED_TOPIC, created, user);
};
