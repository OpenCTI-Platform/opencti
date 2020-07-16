import { createEntity, listEntities, loadEntityById } from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';
import { notify } from '../database/redis';
import { ENTITY_TYPE_TOOL } from '../utils/idGenerator';

export const findById = (toolId) => {
  return loadEntityById(toolId, ENTITY_TYPE_TOOL);
};

export const findAll = (args) => {
  return listEntities([ENTITY_TYPE_TOOL], ['name', 'alias'], args);
};

export const addTool = async (user, tool) => {
  const created = await createEntity(user, tool, ENTITY_TYPE_TOOL);
  return notify(BUS_TOPICS.StixDomainEntity.ADDED_TOPIC, created, user);
};
