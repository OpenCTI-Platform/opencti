import { assoc } from 'ramda';
import { createEntity, listEntities, loadById, batchLoadThroughGetTo } from '../database/middleware';
import { BUS_TOPICS } from '../config/conf';
import { notify } from '../database/redis';
import { ENTITY_TYPE_LOCATION_COUNTRY, ENTITY_TYPE_LOCATION_REGION } from '../schema/stixDomainObject';
import { RELATION_LOCATED_AT } from '../schema/stixCoreRelationship';
import { ABSTRACT_STIX_DOMAIN_OBJECT } from '../schema/general';

export const findById = (countryId) => {
  return loadById(countryId, ENTITY_TYPE_LOCATION_COUNTRY);
};

export const findAll = (args) => {
  return listEntities([ENTITY_TYPE_LOCATION_COUNTRY], args);
};

export const batchRegion = async (countryIds) => {
  return batchLoadThroughGetTo(countryIds, RELATION_LOCATED_AT, ENTITY_TYPE_LOCATION_REGION);
};

export const addCountry = async (user, country) => {
  const created = await createEntity(
    user,
    assoc('x_opencti_location_type', ENTITY_TYPE_LOCATION_COUNTRY, country),
    ENTITY_TYPE_LOCATION_COUNTRY
  );
  return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].ADDED_TOPIC, created, user);
};
