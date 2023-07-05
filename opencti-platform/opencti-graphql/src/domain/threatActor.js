import { batchListThroughGetFrom } from '../database/middleware';
import { listEntities, storeLoadById } from '../database/middleware-loader';
import { ENTITY_TYPE_LOCATION_COUNTRY } from '../schema/stixDomainObject';
import { ENTITY_TYPE_LOCATION, ENTITY_TYPE_THREAT_ACTOR } from '../schema/general';
import { RELATION_ORIGINATES_FROM } from '../schema/stixCoreRelationship';

export const findById = (context, user, threatActorId) => {
  return storeLoadById(context, user, threatActorId, ENTITY_TYPE_THREAT_ACTOR);
};

export const findAll = (context, user, args) => {
  return listEntities(context, user, [ENTITY_TYPE_THREAT_ACTOR], args);
};

export const batchLocations = (context, user, threatActorGroupIds) => {
  return batchListThroughGetFrom(context, user, threatActorGroupIds, RELATION_ORIGINATES_FROM, ENTITY_TYPE_LOCATION);
};

export const batchCountries = (context, user, threatActorGroupIds) => {
  return batchListThroughGetFrom(context, user, threatActorGroupIds, RELATION_ORIGINATES_FROM, ENTITY_TYPE_LOCATION_COUNTRY);
};
