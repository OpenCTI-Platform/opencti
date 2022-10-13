import { createEntity, batchListThroughGetFrom } from '../database/middleware';
import { listEntities, storeLoadById } from '../database/middleware-loader';
import { BUS_TOPICS } from '../config/conf';
import { notify } from '../database/redis';
import { ENTITY_TYPE_LOCATION_COUNTRY, ENTITY_TYPE_THREAT_ACTOR } from '../schema/stixDomainObject';
import { ABSTRACT_STIX_DOMAIN_OBJECT, ENTITY_TYPE_LOCATION } from '../schema/general';
import { RELATION_ORIGINATES_FROM } from '../schema/stixCoreRelationship';

export const findById = (context, user, threatActorId) => {
  return storeLoadById(context, user, threatActorId, ENTITY_TYPE_THREAT_ACTOR);
};

export const findAll = (context, user, args) => {
  return listEntities(context, user, [ENTITY_TYPE_THREAT_ACTOR], args);
};

export const addThreatActor = async (context, user, threatActor) => {
  const created = await createEntity(context, user, threatActor, ENTITY_TYPE_THREAT_ACTOR);
  return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].ADDED_TOPIC, created, user);
};

export const batchLocations = (context, user, threatActorIds) => {
  return batchListThroughGetFrom(context, user, threatActorIds, RELATION_ORIGINATES_FROM, ENTITY_TYPE_LOCATION);
};

export const batchCountries = (context, user, threatActorIds) => {
  return batchListThroughGetFrom(context, user, threatActorIds, RELATION_ORIGINATES_FROM, ENTITY_TYPE_LOCATION_COUNTRY);
};
