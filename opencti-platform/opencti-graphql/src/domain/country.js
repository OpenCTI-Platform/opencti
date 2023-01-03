import { assoc } from 'ramda';
import { createEntity, batchLoadThroughGetTo } from '../database/middleware';
import { listEntities, storeLoadById } from '../database/middleware-loader';
import { BUS_TOPICS } from '../config/conf';
import { notify } from '../database/redis';
import { ENTITY_TYPE_LOCATION_COUNTRY, ENTITY_TYPE_LOCATION_REGION } from '../schema/stixDomainObject';
import { RELATION_LOCATED_AT } from '../schema/stixCoreRelationship';
import { ABSTRACT_STIX_DOMAIN_OBJECT } from '../schema/general';

export const findById = (context, user, countryId) => {
  return storeLoadById(context, user, countryId, ENTITY_TYPE_LOCATION_COUNTRY);
};

export const findAll = (context, user, args) => {
  return listEntities(context, user, [ENTITY_TYPE_LOCATION_COUNTRY], args);
};

export const batchRegion = async (context, user, countryIds) => {
  return batchLoadThroughGetTo(context, user, countryIds, RELATION_LOCATED_AT, ENTITY_TYPE_LOCATION_REGION);
};

export const addCountry = async (context, user, country) => {
  const created = await createEntity(
    context,
    user,
    assoc('x_opencti_location_type', ENTITY_TYPE_LOCATION_COUNTRY, country),
    ENTITY_TYPE_LOCATION_COUNTRY
  );
  return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].ADDED_TOPIC, created, user);
};
