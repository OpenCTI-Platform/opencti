import { createEntity } from '../database/middleware';
import { BUS_TOPICS } from '../config/conf';
import { notify } from '../database/redis';
import { ENTITY_TYPE_LOCATION_CITY, ENTITY_TYPE_LOCATION_COUNTRY } from '../schema/stixDomainObject';
import { ABSTRACT_STIX_DOMAIN_OBJECT } from '../schema/general';
import { listEntities, loadEntityThroughRelationsPaginated, storeLoadById } from '../database/middleware-loader';
import { RELATION_LOCATED_AT } from '../schema/stixCoreRelationship';

export const findById = (context, user, cityId) => {
  return storeLoadById(context, user, cityId, ENTITY_TYPE_LOCATION_CITY);
};

export const findAll = (context, user, args) => {
  return listEntities(context, user, [ENTITY_TYPE_LOCATION_CITY], args);
};

export const locatedAtCountry = async (context, user, stixCoreObjectId) => {
  return loadEntityThroughRelationsPaginated(context, user, stixCoreObjectId, RELATION_LOCATED_AT, ENTITY_TYPE_LOCATION_COUNTRY, false);
};

export const addCity = async (context, user, city) => {
  const created = await createEntity(
    context,
    user,
    { ...city, x_opencti_location_type: ENTITY_TYPE_LOCATION_CITY },
    ENTITY_TYPE_LOCATION_CITY
  );
  return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].ADDED_TOPIC, created, user);
};
