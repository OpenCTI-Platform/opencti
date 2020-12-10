import { createEntity, listEntities, listThroughGetFroms, loadById } from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';
import { notify } from '../database/redis';
import { ENTITY_TYPE_THREAT_ACTOR } from '../schema/stixDomainObject';
import { ABSTRACT_STIX_DOMAIN_OBJECT } from '../schema/general';
import { RELATION_ORIGINATES_FROM } from '../schema/stixCoreRelationship';

export const findById = (threatActorId) => {
  return loadById(threatActorId, ENTITY_TYPE_THREAT_ACTOR);
};

export const findAll = (args) => {
  return listEntities([ENTITY_TYPE_THREAT_ACTOR], ['name', 'alias'], args);
};

export const addThreatActor = async (user, threatActor) => {
  const created = await createEntity(user, threatActor, ENTITY_TYPE_THREAT_ACTOR);
  return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].ADDED_TOPIC, created, user);
};

export const locations = (threatActorId) => {
  return listThroughGetFroms(threatActorId, RELATION_ORIGINATES_FROM, ENTITY_TYPE_THREAT_ACTOR);
};
