import { createEntity, listEntities, loadById } from '../database/middleware';
import { BUS_TOPICS } from '../config/conf';
import { notify } from '../database/redis';
import { ENTITY_TYPE_TOOL } from '../schema/stixDomainObject';
import { ABSTRACT_STIX_DOMAIN_OBJECT } from '../schema/general';

export const findById = (toolId) => {
  return loadById(toolId, ENTITY_TYPE_TOOL);
};

export const findAll = (args) => {
  return listEntities([ENTITY_TYPE_TOOL], args);
};

export const addTool = async (user, tool) => {
  const created = await createEntity(user, tool, ENTITY_TYPE_TOOL);
  return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].ADDED_TOPIC, created, user);
};
