import { listEntities, listEntitiesThroughRelationsPaginated, storeLoadById } from '../database/middleware-loader';
import { ENTITY_TYPE_LOCATION_COUNTRY } from '../schema/stixDomainObject';
import { ENTITY_TYPE_LOCATION, ENTITY_TYPE_THREAT_ACTOR } from '../schema/general';
import { RELATION_LOCATED_AT } from '../schema/stixCoreRelationship';

export const findById = (context, user, threatActorId) => {
  return storeLoadById(context, user, threatActorId, ENTITY_TYPE_THREAT_ACTOR);
};

export const findAll = (context, user, args) => {
  return listEntities(context, user, [ENTITY_TYPE_THREAT_ACTOR], args);
};

export const threatActorLocationsPaginated = async (context, user, threatActorId, opts) => {
  return listEntitiesThroughRelationsPaginated(context, user, threatActorId, RELATION_LOCATED_AT, ENTITY_TYPE_LOCATION, false, false, opts);
};

export const threatActorCountriesPaginated = async (context, user, threatActorId, opts) => {
  return listEntitiesThroughRelationsPaginated(context, user, threatActorId, RELATION_LOCATED_AT, ENTITY_TYPE_LOCATION_COUNTRY, true, false, opts);
};
