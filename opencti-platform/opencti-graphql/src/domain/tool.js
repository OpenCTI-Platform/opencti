import { createEntity } from '../database/middleware';
import { listEntities, storeLoadById } from '../database/middleware-loader';
import { BUS_TOPICS } from '../config/conf';
import { notify } from '../database/redis';
import { ENTITY_TYPE_TOOL } from '../schema/stixDomainObject';
import { ABSTRACT_STIX_DOMAIN_OBJECT } from '../schema/general';

export const findById = (context, user, toolId) => {
  return storeLoadById(context, user, toolId, ENTITY_TYPE_TOOL);
};

export const findAll = (context, user, args) => {
  return listEntities(context, user, [ENTITY_TYPE_TOOL], args);
};

export const addTool = async (context, user, tool) => {
  const created = await createEntity(context, user, tool, ENTITY_TYPE_TOOL);
  return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].ADDED_TOPIC, created, user);
};
