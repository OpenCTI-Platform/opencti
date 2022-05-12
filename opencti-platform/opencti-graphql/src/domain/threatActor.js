import { createEntity, batchListThroughGetFrom, storeLoadById } from '../database/middleware';
import { listEntities } from '../database/middleware-loader';
import { BUS_TOPICS } from '../config/conf';
import { notify } from '../database/redis';
import { ENTITY_TYPE_THREAT_ACTOR } from '../schema/stixDomainObject';
import { ABSTRACT_STIX_DOMAIN_OBJECT } from '../schema/general';
import { RELATION_ORIGINATES_FROM } from '../schema/stixCoreRelationship';

export const findById = (user, threatActorId) => {
  return storeLoadById(user, threatActorId, ENTITY_TYPE_THREAT_ACTOR);
};

export const findAll = (user, args) => {
  return listEntities(user, [ENTITY_TYPE_THREAT_ACTOR], args);
};

export const addThreatActor = async (user, threatActor) => {
  const created = await createEntity(user, threatActor, ENTITY_TYPE_THREAT_ACTOR);
  return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].ADDED_TOPIC, created, user);
};

export const batchLocations = (user, threatActorIds) => {
  return batchListThroughGetFrom(user, threatActorIds, RELATION_ORIGINATES_FROM, ENTITY_TYPE_THREAT_ACTOR);
};
