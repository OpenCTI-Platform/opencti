import { createEntity } from '../database/middleware';
import { listEntities, loadEntityThroughRelationsPaginated, storeLoadById } from '../database/middleware-loader';
import { BUS_TOPICS } from '../config/conf';
import { notify } from '../database/redis';
import { ENTITY_TYPE_LOCATION_COUNTRY, ENTITY_TYPE_LOCATION_REGION } from '../schema/stixDomainObject';
import { ABSTRACT_STIX_DOMAIN_OBJECT } from '../schema/general';
import { RELATION_LOCATED_AT } from '../schema/stixCoreRelationship';

export const findById = (context, user, countryId) => {
  return storeLoadById(context, user, countryId, ENTITY_TYPE_LOCATION_COUNTRY);
};

export const findAll = (context, user, args) => {
  return listEntities(context, user, [ENTITY_TYPE_LOCATION_COUNTRY], args);
};

export const locatedAtRegion = async (context, user, stixCoreObjectId) => {
  return loadEntityThroughRelationsPaginated(context, user, stixCoreObjectId, RELATION_LOCATED_AT, ENTITY_TYPE_LOCATION_REGION, false);
};

export const addCountry = async (context, user, country) => {
  const created = await createEntity(
    context,
    user,
    { ...country, x_opencti_location_type: ENTITY_TYPE_LOCATION_COUNTRY },
    ENTITY_TYPE_LOCATION_COUNTRY
  );
  return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].ADDED_TOPIC, created, user);
};
