import { createEntity, listEntities, loadEntityById, loadEntityByStixId } from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';
import { notify } from '../database/redis';
import { TYPE_STIX_DOMAIN_ENTITY } from '../database/utils';

export const findById = (threatActorId) => {
  if (threatActorId.match(/[a-z-]+--[\w-]{36}/g)) {
    return loadEntityByStixId(threatActorId, 'Threat-Actor');
  }
  return loadEntityById(threatActorId, 'Threat-Actor');
};
export const findAll = (args) => {
  return listEntities(['Threat-Actor'], ['name', 'alias'], args);
};

export const addThreatActor = async (user, threatActor) => {
  const created = await createEntity(user, threatActor, 'Threat-Actor', { modelType: TYPE_STIX_DOMAIN_ENTITY });
  return notify(BUS_TOPICS.StixDomainEntity.ADDED_TOPIC, created, user);
};
