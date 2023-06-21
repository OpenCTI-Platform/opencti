import { createEntity, batchListThroughGetFrom } from '../database/middleware';
import { listEntities, storeLoadById } from '../database/middleware-loader';
import { BUS_TOPICS } from '../config/conf';
import { notify } from '../database/redis';
import { ENTITY_TYPE_LOCATION_COUNTRY, ENTITY_TYPE_THREAT_ACTOR_GROUP } from '../schema/stixDomainObject';
import { ABSTRACT_STIX_DOMAIN_OBJECT, ENTITY_TYPE_LOCATION } from '../schema/general';
import { RELATION_ORIGINATES_FROM } from '../schema/stixCoreRelationship';

export const findById = (context, user, threatActorGroupId) => {
  return storeLoadById(context, user, threatActorGroupId, ENTITY_TYPE_THREAT_ACTOR_GROUP);
};

export const findAll = (context, user, args) => {
  return listEntities(context, user, [ENTITY_TYPE_THREAT_ACTOR_GROUP], args);
};

export const addThreatActorGroup = async (context, user, threatActorGroup) => {
  const created = await createEntity(context, user, threatActorGroup, ENTITY_TYPE_THREAT_ACTOR_GROUP);
  return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].ADDED_TOPIC, created, user);
};

export const batchLocations = (context, user, threatActorGroupIds) => {
  return batchListThroughGetFrom(context, user, threatActorGroupIds, RELATION_ORIGINATES_FROM, ENTITY_TYPE_LOCATION);
};

export const batchCountries = (context, user, threatActorGroupIds) => {
  return batchListThroughGetFrom(context, user, threatActorGroupIds, RELATION_ORIGINATES_FROM, ENTITY_TYPE_LOCATION_COUNTRY);
};
