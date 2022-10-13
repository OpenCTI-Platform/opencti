import { createEntity } from '../database/middleware';
import { listEntities, storeLoadById } from '../database/middleware-loader';
import { BUS_TOPICS } from '../config/conf';
import { notify } from '../database/redis';
import { ENTITY_TYPE_INFRASTRUCTURE } from '../schema/stixDomainObject';
import { ABSTRACT_STIX_DOMAIN_OBJECT } from '../schema/general';

export const findById = (context, user, infrastructureId) => {
  return storeLoadById(context, user, infrastructureId, ENTITY_TYPE_INFRASTRUCTURE);
};

export const findAll = (context, user, args) => {
  return listEntities(context, user, [ENTITY_TYPE_INFRASTRUCTURE], args);
};

export const addInfrastructure = async (context, user, infrastructure) => {
  const created = await createEntity(context, user, infrastructure, ENTITY_TYPE_INFRASTRUCTURE);
  return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].ADDED_TOPIC, created, user);
};
