import { createEntity, storeLoadById } from '../database/middleware';
import { listEntities } from '../database/middleware-loader';
import { BUS_TOPICS } from '../config/conf';
import { notify } from '../database/redis';
import { ENTITY_TYPE_INFRASTRUCTURE } from '../schema/stixDomainObject';
import { ABSTRACT_STIX_DOMAIN_OBJECT } from '../schema/general';

export const findById = (user, infrastructureId) => {
  return storeLoadById(user, infrastructureId, ENTITY_TYPE_INFRASTRUCTURE);
};

export const findAll = (user, args) => {
  return listEntities(user, [ENTITY_TYPE_INFRASTRUCTURE], args);
};

export const addInfrastructure = async (user, infrastructure) => {
  const created = await createEntity(user, infrastructure, ENTITY_TYPE_INFRASTRUCTURE);
  return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].ADDED_TOPIC, created, user);
};
