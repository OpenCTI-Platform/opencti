import { createEntity, listEntities, loadEntityById } from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';
import { notify } from '../database/redis';
import { ENTITY_TYPE_THREAT_ACTOR } from '../utils/idGenerator';

export const findById = (threatActorId) => {
  return loadEntityById(threatActorId, ENTITY_TYPE_THREAT_ACTOR);
};

export const findAll = (args) => {
  return listEntities([ENTITY_TYPE_THREAT_ACTOR], ['name', 'alias'], args);
};

export const addThreatActor = async (user, threatActor) => {
  const created = await createEntity(user, threatActor, ENTITY_TYPE_THREAT_ACTOR);
  return notify(BUS_TOPICS.stixDomainObject.ADDED_TOPIC, created, user);
};
